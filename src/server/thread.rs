// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{
    collections::BTreeMap,
    io,
    net::SocketAddr,
    rc::Rc,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use ahash::HashMap;
use crossbeam::channel::{Receiver, Sender, TryRecvError};
use ed25519_dalek::{SigningKey, VerifyingKey};
use mio::{Events, Interest, Poll, Waker};
use rand::thread_rng;
use siphasher::sip::SipHasher;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::common::{
    channel::{scheduler::ChannelConfiguration, Channel, Pop, IDS_EXHAUSTED},
    congestion::CongestionConfiguration,
    crypto::Crypto,
    error::ProtocolViolation,
    events::EventSender,
    packets::{
        acks::Acks,
        client_hello::ClientHello,
        connection_request::ConnectionRequest,
        connection_response::ConnectionResponse,
        disconnect::{self, Disconnect},
        info_request::InfoRequest,
        info_response::InfoResponse,
        latency_discovery::LatencyDiscovery,
        latency_discovery_response::LatencyDiscoveryResponse,
        latency_discovery_response_2::LatencyDiscoveryResponse2,
        login_request::LoginRequest,
        login_response::LoginResponse,
        reliable_payload::ReliablePayload,
        server_hello::{self, ServerHello},
        unreliable_payload::UnreliablePayload,
        PacketIdentifier,
    },
    socket::net_sym::NetworkSimulator,
    stats::Stats,
    timed_event_queue::TimedEventQueue,
    AllowedClientVersions, Cipher, ClientVersion, RECV_TOKEN, WAKE_TOKEN,
};

use super::{
    auth::{AuthCmd, AuthResult, LoginAttempt},
    connection::Connection,
    rate_limit::RateLimiter,
    Event, Socket,
};

/// Timeouts are checked this many times per timeout duration.
const TIMEOUT_CHECKS: u32 = 4;
const RATE_LIMIT_PRUNE_INTERVAL: Duration = Duration::from_secs(10);
/// How long handshake state is kept to answer retransmitted requests.
const HANDSHAKE_STATE_TTL: Duration = Duration::from_secs(8);

/// A ConnectionResponse was sent, the LoginRequest is outstanding.
pub struct PendingLogin {
    crypto: Crypto,
    /// The client's x25519 key and HKDF salt, to recognize a retransmitted request.
    request: [u8; 64],
    response: Vec<u8>,
}

pub enum Cmd<R: AuthResult> {
    SetSimulator(Option<Box<dyn NetworkSimulator>>),
    Shutdown(Vec<u8>),
    Disconnect(SocketAddr, Vec<u8>),
    SetInfo(Vec<u8>),
    AuthSuccess(LoginAttempt, R),
    AuthFailed(LoginAttempt, Vec<u8>),
    Send(SocketAddr, Channel, Vec<u8>),
    Stats(SocketAddr, Sender<Option<Stats>>),
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum TimedEventKey {
    RemoveExpectingLoginRequest(LoginAttempt),
    RemoveAnsweredLogin(LoginAttempt),
    CheckForTimeouts,
    DiscoverLatencies,
    Send(SocketAddr),
    SendAcks(SocketAddr, u8),
    CloseDeadline(SocketAddr),
    PruneRateLimits,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TimedEventData {
    Nothing,
}

pub struct ServerThreadState<R: AuthResult> {
    pub event_tx: EventSender<Event<R>>,
    pub cmds: Receiver<Cmd<R>>,
    pub socket: Socket,
    pub poll: Poll,
    pub _waker: Arc<Waker>,
    pub timed_events: TimedEventQueue<TimedEventKey, TimedEventData>,
    pub buf: [u8; 1201],

    pub info: Vec<u8>,
    pub allowed_client_versions: fn(ClientVersion) -> Result<(), AllowedClientVersions>,
    pub cipher: Cipher,
    pub auth_salt: [u8; 16],
    pub signing_key: SigningKey,
    pub veryifying_key: VerifyingKey,
    pub siphasher: SipHasher,

    pub connection_request_max_timestamp_age: Duration,
    pub disable_timestamp_age_check: bool,
    pub timeout_dur: Duration,
    pub max_connections: Option<usize>,
    pub max_recv_msg_size: usize,
    pub is_checking_for_timeouts: bool,
    pub latency_discovery_interval: Duration,

    /// Limits new key exchanges per client IP.
    pub connection_requests: RateLimiter,
    pub auth_cmd_tx: Sender<AuthCmd>,
    pub expecting_login_requests: HashMap<LoginAttempt, PendingLogin>,
    pub expecting_auth_result: HashMap<LoginAttempt, Crypto>,
    /// Sent LoginResponses, resent for retransmitted LoginRequests.
    pub answered_logins: HashMap<LoginAttempt, Vec<u8>>,
    pub connections: HashMap<SocketAddr, Connection>,

    pub latency_discoveries_sent: BTreeMap<u32, Instant>,
    pub is_discovering_latencies: bool,

    pub channel_config: ChannelConfiguration,
    pub congestion_config: CongestionConfiguration,

    pub close_linger: Duration,
    pub shutting_down: bool,
}

impl<R: AuthResult> ServerThreadState<R> {
    pub fn run(&mut self) -> Result<(), io::Error> {
        let mut events = Events::with_capacity(16);
        self.poll
            .registry()
            .register(self.socket.mio_socket(), RECV_TOKEN, Interest::READABLE)?;

        loop {
            if self.handle_all_cmds()? {
                break;
            }
            self.handle_all_events();
            if self.shutting_down && self.connections.is_empty() {
                break;
            }
            let max_poll_time = self.timed_events.next().map(|deadline| {
                deadline
                    .saturating_duration_since(Instant::now())
                    .max(Duration::from_millis(1))
            });
            self.poll.poll(&mut events, max_poll_time)?;
            for event in events.iter() {
                match event.token() {
                    RECV_TOKEN => self.handle_all_recvs()?,
                    WAKE_TOKEN => {}
                    _ => unreachable!(),
                }
            }
        }
        Ok(())
    }

    fn handle_all_cmds(&mut self) -> Result<bool, io::Error> {
        loop {
            let cmd = match self.cmds.try_recv() {
                Ok(cmd) => cmd,
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return Ok(true),
            };

            match cmd {
                Cmd::Shutdown(reason) => {
                    self.shutting_down = true;
                    let reason: Rc<[u8]> = reason.into();
                    let addrs: Vec<SocketAddr> = self.connections.keys().copied().collect();
                    for addr in addrs {
                        self.start_close(addr, reason.clone());
                    }
                }
                Cmd::Disconnect(addr, reason) => self.start_close(addr, reason.into()),
                Cmd::SetInfo(info) => {
                    self.info = info;
                }
                Cmd::AuthSuccess(attempt, auth_result) => {
                    self.handle_cmd_auth_success(attempt, auth_result);
                }
                Cmd::AuthFailed(attempt, vec) => {
                    self.handle_cmd_auth_failure(attempt, vec);
                }
                Cmd::Send(socket_addr, channel, message) => {
                    let Some(connection) = self
                        .connections
                        .get_mut(&socket_addr)
                        .filter(|connection| connection.closing.is_none())
                    else {
                        continue;
                    };
                    connection.channels.push(channel, Rc::new(message));
                    self.timed_events.push(
                        TimedEventKey::Send(socket_addr),
                        connection.last_sent + connection.congestion.downtime_between_batches(),
                        TimedEventData::Nothing,
                    );
                }
                Cmd::Stats(addr, reply) => {
                    let _ = reply.send(self.connections.get(&addr).map(|connection| {
                        Stats::new(
                            &connection.congestion,
                            &connection.channels,
                            &connection.probe_loss,
                        )
                    }));
                }
                Cmd::SetSimulator(network_simulator) => {
                    if let Some(network_simulator) = network_simulator {
                        self.socket.set_network_simulator(network_simulator)?;
                        self.socket.set_use_simulator(true);
                    } else {
                        self.socket.set_use_simulator(false);
                    }
                }
            }
        }
        Ok(false)
    }

    fn handle_all_events(&mut self) {
        while self
            .timed_events
            .next()
            .map_or(false, |deadline| deadline <= Instant::now())
        {
            let (key, _event) = self.timed_events.pop().unwrap();
            match key {
                TimedEventKey::RemoveExpectingLoginRequest(attempt) => {
                    self.expecting_login_requests.remove(&attempt);
                }
                TimedEventKey::RemoveAnsweredLogin(attempt) => {
                    self.answered_logins.remove(&attempt);
                }
                TimedEventKey::CheckForTimeouts => {
                    self.handle_event_check_for_timeouts();
                }
                TimedEventKey::DiscoverLatencies => {
                    self.handle_event_discover_latencies();
                }
                TimedEventKey::Send(socket_addr) => {
                    self.handle_event_send(socket_addr);
                }
                TimedEventKey::SendAcks(socket_addr, channel_id) => {
                    self.handle_event_send_acks(socket_addr, channel_id);
                }
                TimedEventKey::CloseDeadline(socket_addr) => {
                    self.finish_close(socket_addr);
                }
                TimedEventKey::PruneRateLimits => {
                    self.connection_requests.prune(Instant::now());
                }
            }
        }
    }

    fn handle_all_recvs(&mut self) -> Result<(), io::Error> {
        while let Some((size, from)) = self.socket.recv_from(&mut self.buf)? {
            if size == 0 || size > 1200 {
                continue;
            }
            let Ok(packet_identifier) = PacketIdentifier::try_from(self.buf[0]) else {
                continue;
            };
            match packet_identifier {
                PacketIdentifier::ClientHello
                | PacketIdentifier::ConnectionRequest
                | PacketIdentifier::LoginRequest
                    if self.shutting_down =>
                {
                    continue
                }
                PacketIdentifier::InfoRequest => self.handle_packet_info_request(size, from),
                PacketIdentifier::ClientHello => self.handle_packet_client_hello(size, from),
                PacketIdentifier::ConnectionRequest => {
                    self.handle_packet_connection_request(size, from)
                }
                PacketIdentifier::LoginRequest => self.handle_packet_login_request(size, from),
                PacketIdentifier::Disconnect => self.handle_packet_disconnect(size, from),
                PacketIdentifier::LatencyDiscoveryResponse => {
                    self.handle_packet_latency_discovery_response(size, from)
                }
                PacketIdentifier::UnreliableStandalonePayload
                | PacketIdentifier::UnreliableFragmentedPayload
                | PacketIdentifier::UnreliableFragmentedPayloadLast
                | PacketIdentifier::UnreliableOrderedStandalonePayload
                | PacketIdentifier::UnreliableOrderedFragmentedPayload
                | PacketIdentifier::UnreliableOrderedFragmentedPayloadLast => {
                    self.handle_packet_unreliable_payload(size, from)
                }
                PacketIdentifier::ReliablePayloadNoAcks => {
                    self.handle_packet_reliable_payload(size, from)
                }
                PacketIdentifier::Acks => self.handle_packet_acks(size, from),
                _ => continue,
            }
        }
        Ok(())
    }

    fn handle_event_check_for_timeouts(&mut self) {
        let mut timed_outs = Vec::new();
        for (addr, connection) in &self.connections {
            if connection.last_received.elapsed() > self.timeout_dur {
                let disconnect = Disconnect { data: b"Timeout" };
                let size = disconnect.serialize(&connection.crypto, &mut self.buf);
                self.socket.send_to(*addr, &self.buf[..size]);
                self.event_tx.send(Event::TimedOut(*addr));
                timed_outs.push(*addr);
            }
        }
        for addr in timed_outs {
            self.connections.remove(&addr);
        }
        if self.connections.len() > 0 {
            self.timed_events.push(
                TimedEventKey::CheckForTimeouts,
                Instant::now() + self.timeout_dur / TIMEOUT_CHECKS,
                TimedEventData::Nothing,
            );
        } else {
            self.is_checking_for_timeouts = false;
        }
    }

    fn handle_event_discover_latencies(&mut self) {
        let sequence_number = self
            .latency_discoveries_sent
            .last_entry()
            .map_or(1, |kv| kv.key().checked_add(1).unwrap());
        let mut latency_discovery = LatencyDiscovery {
            sequence_number,
            truncated_siphash: 0,
        };
        self.latency_discoveries_sent
            .insert(sequence_number, Instant::now());
        if self.latency_discoveries_sent.len() > 63 {
            self.latency_discoveries_sent.pop_first();
        }
        for (addr, connection) in self.connections.iter_mut() {
            let size = latency_discovery.serialize(&connection.crypto, &mut self.buf);
            self.socket.send_to(*addr, &self.buf[..size]);
            connection.probe_loss.probe(sequence_number);
        }
        if self.connections.len() > 0 {
            self.timed_events.push(
                TimedEventKey::DiscoverLatencies,
                Instant::now() + self.latency_discovery_interval,
                TimedEventData::Nothing,
            );
        } else {
            self.is_discovering_latencies = false;
        }
    }

    fn handle_event_send(&mut self, to: SocketAddr) {
        let Some(connection) = self.connections.get_mut(&to) else {
            return;
        };
        let now = Instant::now();
        let downtime = connection.congestion.downtime_between_batches();
        while connection.congestion.can_send(now) {
            match connection.channels.pop(
                &mut connection.congestion,
                &connection.crypto,
                &mut self.buf,
            ) {
                Pop::Packet(size) => {
                    connection.last_sent = now;
                    self.socket.send_to(to, &self.buf[..size]);
                    connection.congestion.consume(size);
                }
                Pop::Wait(time_till_resend) => {
                    let deadline = (now + time_till_resend).max(connection.last_sent + downtime);
                    self.timed_events.push(
                        TimedEventKey::Send(to),
                        deadline,
                        TimedEventData::Nothing,
                    );
                    return;
                }
                Pop::Idle => {
                    if connection.closing.is_some() {
                        self.finish_close(to);
                    }
                    return;
                }
                Pop::Exhausted => {
                    let disconnect = Disconnect {
                        data: IDS_EXHAUSTED,
                    };
                    let size = disconnect.serialize(&connection.crypto, &mut self.buf);
                    self.socket.send_to(to, &self.buf[..size]);
                    self.connections.remove(&to);
                    self.event_tx
                        .send(Event::Disconnected(to, IDS_EXHAUSTED.to_vec()));
                    return;
                }
            }
        }
        self.timed_events.push(
            TimedEventKey::Send(to),
            now + connection.congestion.time_until_send().max(downtime),
            TimedEventData::Nothing,
        );
    }

    /// A client reconnecting from a connected address replaces its old connection.
    fn is_full_for(&self, client: SocketAddr) -> bool {
        self.max_connections
            .is_some_and(|max| self.connections.len() >= max)
            && !self.connections.contains_key(&client)
    }

    /// Starts a graceful disconnect: queued messages are flushed for up to `close_linger`.
    fn start_close(&mut self, addr: SocketAddr, reason: Rc<[u8]>) {
        let Some(connection) = self.connections.get_mut(&addr) else {
            return;
        };
        if connection.closing.is_some() {
            return;
        }
        connection.closing = Some(reason);
        let now = Instant::now();
        self.timed_events.push(
            TimedEventKey::CloseDeadline(addr),
            now + self.close_linger,
            TimedEventData::Nothing,
        );
        self.timed_events
            .push(TimedEventKey::Send(addr), now, TimedEventData::Nothing);
    }

    /// Ends a graceful disconnect: everything was sent and acked, or the linger ran out.
    fn finish_close(&mut self, addr: SocketAddr) {
        let Some(connection) = self
            .connections
            .remove(&addr)
            .filter(|connection| connection.closing.is_some())
        else {
            return;
        };
        self.timed_events
            .remove(&TimedEventKey::CloseDeadline(addr));
        let reason = connection.closing.as_deref().unwrap_or_default();
        let size = Disconnect { data: reason }.serialize(&connection.crypto, &mut self.buf);
        for _ in 0..disconnect::REPEATS {
            self.socket.send_to(addr, &self.buf[..size]);
        }
    }

    fn handle_event_send_acks(&mut self, to: SocketAddr, channel_id: u8) {
        let Some(connection) = self.connections.get_mut(&to) else {
            return;
        };
        let acks = connection.channels.acks(Channel::Reliable(channel_id));
        let size = acks.serialize(&connection.crypto, &mut self.buf);
        self.socket.send_to(to, &self.buf[..size]);
    }

    fn handle_cmd_auth_success(&mut self, attempt: LoginAttempt, auth_result: R) {
        let Some(crypto) = self.expecting_auth_result.remove(&attempt) else {
            return;
        };
        if self.shutting_down {
            return;
        }
        // The server filled up while authenticating.
        if self.is_full_for(attempt.0) {
            let login_response = LoginResponse::Failure {
                failure_data: b"Server full",
            };
            let size = login_response.serialize(&crypto, &mut self.buf);
            self.answer_login(attempt, size);
            return;
        }
        let from = attempt.0;
        let size = LoginResponse::Success.serialize(&crypto, &mut self.buf);
        self.answer_login(attempt, size);
        let connection = Connection::new(
            crypto,
            &self.channel_config,
            self.congestion_config,
            self.max_recv_msg_size,
        );
        // A new handshake from a connected address means the client lost its old session
        // (e.g. our LoginSuccess got lost and it started over).
        if self.connections.insert(from, connection).is_some() {
            self.event_tx.send(Event::Disconnected(from, Vec::new()));
        }
        self.event_tx.send(Event::Connected(from, auth_result));

        self.timed_events.push(
            TimedEventKey::DiscoverLatencies,
            Instant::now() + self.latency_discovery_interval,
            TimedEventData::Nothing,
        );

        self.timed_events.push(
            TimedEventKey::CheckForTimeouts,
            Instant::now() + self.timeout_dur / TIMEOUT_CHECKS,
            TimedEventData::Nothing,
        );
    }

    fn handle_cmd_auth_failure(&mut self, attempt: LoginAttempt, failure_data: Vec<u8>) {
        let Some(crypto) = self.expecting_auth_result.remove(&attempt) else {
            return;
        };
        let login_response = LoginResponse::Failure {
            failure_data: &failure_data,
        };
        let size = login_response.serialize(&crypto, &mut self.buf);
        self.answer_login(attempt, size);
    }

    /// Sends the LoginResponse in `buf` and keeps it for retransmitted LoginRequests.
    fn answer_login(&mut self, attempt: LoginAttempt, size: usize) {
        self.socket.send_to(attempt.0, &self.buf[..size]);
        self.answered_logins
            .insert(attempt, self.buf[..size].to_vec());
        self.timed_events.push(
            TimedEventKey::RemoveAnsweredLogin(attempt),
            Instant::now() + HANDSHAKE_STATE_TTL,
            TimedEventData::Nothing,
        );
    }

    fn handle_packet_info_request(&mut self, size: usize, from: SocketAddr) {
        let Ok(_) = InfoRequest::deserialize(&self.buf[..size]) else {
            return;
        };
        let info_response = InfoResponse::new(&self.info);
        let size = info_response.serialize(&mut self.buf);
        self.socket.send_to(from, &self.buf[..size]);
    }

    fn handle_packet_client_hello(&mut self, size: usize, from: SocketAddr) {
        let Ok(client_hello) = ClientHello::deserialize(&self.buf[..size]) else {
            return;
        };
        let server_hello = match (self.allowed_client_versions)(client_hello.client_version) {
            Ok(()) if self.is_full_for(from) => ServerHello::ServerFull {
                salt: client_hello.salt,
            },
            Ok(()) => {
                let time_stamp = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                ServerHello::VersionSupported {
                    salt: client_hello.salt,
                    timestamp: time_stamp.to_le_bytes(),
                    cipher: self.cipher,
                    server_ed25519_pubkey: self.veryifying_key,
                    siphash: None,
                    channel_counts: self.channel_config.counts(),
                }
            }
            Err(allowed_versions) => ServerHello::VersionNotSupported {
                salt: client_hello.salt,
                allowed_versions,
            },
        };
        let size = server_hello.serialize(&self.siphasher, from, &mut self.buf);
        self.socket.send_to(from, &self.buf[..size]);
    }

    fn handle_packet_connection_request(&mut self, size: usize, from: SocketAddr) {
        let Ok(connection_request) = ConnectionRequest::deserialize(&self.buf[..size]) else {
            return;
        };
        if connection_request.siphash
            != server_hello::cookie(&self.siphasher, &self.buf[1..45], from).to_le_bytes()
        {
            return;
        }
        if !self.disable_timestamp_age_check {
            let min_time_stamp = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .saturating_sub(self.connection_request_max_timestamp_age)
                .as_secs();
            let time_stamp = u64::from_le_bytes(connection_request.timestamp);
            if time_stamp < min_time_stamp {
                return;
            }
        }
        let attempt = (from, connection_request.salt);
        let request: [u8; 64] = self.buf[53..117].try_into().unwrap();
        if let Some(pending) = self.expecting_login_requests.get(&attempt) {
            // A retransmission must get the same keys, a different request is ignored.
            if pending.request == request {
                self.socket.send_to(from, &pending.response);
            }
            return;
        }
        // Each new request costs a key exchange and a signature.
        let now = Instant::now();
        if !self.connection_requests.allow(from.ip(), now) {
            return;
        }
        self.timed_events.push(
            TimedEventKey::PruneRateLimits,
            now + RATE_LIMIT_PRUNE_INTERVAL,
            TimedEventData::Nothing,
        );
        let x25519_secret_key = EphemeralSecret::random_from_rng(&mut thread_rng());
        let x25519_public_key = PublicKey::from(&x25519_secret_key);
        let shared_secret =
            x25519_secret_key.diffie_hellman(&connection_request.client_x25519_pubkey);
        let crypto = Crypto::new(
            shared_secret,
            connection_request.hkdf_salt,
            true,
            self.cipher,
        );

        let connection_response = ConnectionResponse {
            salt: connection_request.salt,
            server_x25519_pubkey: x25519_public_key,
            auth_salt: self.auth_salt,
        };
        let size = connection_response.serialize(&crypto, &self.signing_key, &mut self.buf);
        self.socket.send_to(from, &self.buf[..size]);
        self.expecting_login_requests.insert(
            attempt,
            PendingLogin {
                crypto,
                request,
                response: self.buf[..size].to_vec(),
            },
        );
        self.timed_events.push(
            TimedEventKey::RemoveExpectingLoginRequest(attempt),
            Instant::now() + HANDSHAKE_STATE_TTL,
            TimedEventData::Nothing,
        );
    }

    fn handle_packet_login_request(&mut self, size: usize, from: SocketAddr) {
        let Some(salt) = LoginRequest::deserialize_salt(&self.buf[..size]) else {
            return;
        };
        let attempt = (from, salt);
        if let Some(response) = self.answered_logins.get(&attempt) {
            self.socket.send_to(from, response);
            return;
        }
        let Some(pending) = self.expecting_login_requests.get(&attempt) else {
            return;
        };
        let Ok(login_request) = LoginRequest::deserialize(&pending.crypto, &mut self.buf[..size])
        else {
            return;
        };
        let auth_cmd = AuthCmd::Authenticate(attempt, login_request.auth_data.to_vec());
        let crypto = self
            .expecting_login_requests
            .remove(&attempt)
            .unwrap()
            .crypto;
        if self.auth_cmd_tx.try_send(auth_cmd).is_err() {
            let login_response = LoginResponse::Failure {
                failure_data: b"Server busy",
            };
            let size = login_response.serialize(&crypto, &mut self.buf);
            self.answer_login(attempt, size);
            return;
        }
        self.expecting_auth_result.insert(attempt, crypto);
    }

    fn handle_packet_disconnect(&mut self, size: usize, from: SocketAddr) {
        let Some(connection) = self.connections.get(&from) else {
            return;
        };
        let Ok(disconnect) = Disconnect::deserialize(&connection.crypto, &mut self.buf[..size])
        else {
            return;
        };
        self.connections.remove(&from);
        self.event_tx
            .send(Event::Disconnected(from, disconnect.data.to_vec()));
    }

    fn handle_packet_latency_discovery_response(&mut self, size: usize, from: SocketAddr) {
        let Some(connection) = self.connections.get_mut(&from) else {
            return;
        };
        let Ok(latency_discovery_response) =
            LatencyDiscoveryResponse::deserialize(&connection.crypto, &mut self.buf[..size])
        else {
            return;
        };
        if latency_discovery_response.sequence_number <= connection.last_latency_discovery_response
        {
            return;
        }
        let Some(sent) = self
            .latency_discoveries_sent
            .get(&latency_discovery_response.sequence_number)
        else {
            // TODO: Think about what to do with really, really bad connections
            return;
        };
        connection.last_latency_discovery_response = latency_discovery_response.sequence_number;
        connection
            .probe_loss
            .answered(latency_discovery_response.sequence_number);
        let latency = sent.elapsed();
        connection.congestion.update_latency(latency);

        let mut latency_discovery_response_2 = LatencyDiscoveryResponse2 {
            sequence_number: latency_discovery_response.sequence_number,
            truncated_siphash: 0,
        };
        let size = latency_discovery_response_2.serialize(&connection.crypto, &mut self.buf);
        self.socket.send_to(from, &self.buf[..size]);

        connection.last_received = Instant::now();
    }

    fn handle_packet_unreliable_payload(&mut self, size: usize, from: SocketAddr) {
        if !self.event_tx.has_room() {
            return;
        }
        let Some(connection) = self
            .connections
            .get_mut(&from)
            .filter(|connection| connection.closing.is_none())
        else {
            return;
        };
        let Ok(packet) = UnreliablePayload::deserialize(&connection.crypto, &mut self.buf[0..size])
        else {
            return;
        };
        connection.last_received = Instant::now();
        match connection.channels.handle_unreliable(packet) {
            Ok(Some(message)) => self.event_tx.send(Event::Received(from, message)),
            Ok(None) => {}
            Err(violation) => self.handle_violation(from, violation),
        }
    }

    fn handle_packet_reliable_payload(&mut self, size: usize, from: SocketAddr) {
        if !self.event_tx.has_room() {
            return;
        }
        let Some(connection) = self
            .connections
            .get_mut(&from)
            .filter(|connection| connection.closing.is_none())
        else {
            return;
        };
        let Ok(packet) = ReliablePayload::deserialize(&connection.crypto, &mut self.buf[..size])
        else {
            return;
        };
        connection.last_received = Instant::now();
        if packet.channel_id() as usize >= self.channel_config.weights_reliable.len() {
            return;
        }
        self.timed_events.push(
            TimedEventKey::SendAcks(from, packet.channel_id()),
            Instant::now() + connection.congestion.ack_delay(),
            TimedEventData::Nothing,
        );
        match connection.channels.handle_reliable(packet) {
            Ok(messages) => {
                for message in messages {
                    self.event_tx.send(Event::Received(from, message));
                }
            }
            Err(violation) => self.handle_violation(from, violation),
        }
    }

    fn handle_packet_acks(&mut self, size: usize, from: SocketAddr) {
        let Some(connection) = self.connections.get_mut(&from) else {
            return;
        };
        let Ok(packet) = Acks::deserialize(&connection.crypto, &self.buf[..size]) else {
            return;
        };
        connection.last_received = Instant::now();
        connection
            .channels
            .handle_acks(packet, &mut connection.congestion);
        // Acks can open the window or reveal losses.
        self.timed_events.push(
            TimedEventKey::Send(from),
            connection.last_sent + connection.congestion.downtime_between_batches(),
            TimedEventData::Nothing,
        );
    }

    fn handle_violation(&mut self, addr: SocketAddr, violation: ProtocolViolation) {
        let Some(connection) = self.connections.remove(&addr) else {
            return;
        };
        let reason = violation.to_string();
        let disconnect = Disconnect {
            data: reason.as_bytes(),
        };
        let size = disconnect.serialize(&connection.crypto, &mut self.buf);
        self.socket.send_to(addr, &self.buf[..size]);
        self.event_tx.send(Event::Violation(addr, violation));
    }
}
