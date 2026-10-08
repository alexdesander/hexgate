// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{
    io,
    net::SocketAddr,
    rc::Rc,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, PoisonError,
    },
    time::{Duration, Instant},
};

use ahash::HashMap;
use crossbeam::channel::{Receiver, Sender, TryRecvError};
use ed25519_dalek::{SigningKey, VerifyingKey};
use mio::{Events, Interest, Poll, Waker};
use rand::thread_rng;
use siphasher::sip::SipHasher;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::common::{
    channel::Channel,
    crypto::Crypto,
    error::RecvError,
    events::EventSender,
    packets::{
        client_hello::ClientHello,
        connection_request::ConnectionRequest,
        connection_response::{self, ConnectionResponse, Transcript},
        info_request::InfoRequest,
        info_response::InfoResponse,
        login_request::LoginRequest,
        login_response::LoginResponse,
        rejected,
        server_hello::{self, ServerHello},
        PacketIdentifier,
    },
    socket::sim::Simulator,
    stats::Stats,
    timed_event_queue::TimedEventQueue,
    transport::{self, Connection, Output},
    AllowedClientVersions, Cipher, ClientVersion, PROTOCOL_VERSION, RECV_TOKEN, WAKE_TOKEN,
};

use super::{
    auth::{AuthCmd, AuthResult, LoginAttempt},
    rate_limit::RateLimiter,
    ConnectedSet, Event, Socket,
};

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
    SetSimulator(Simulator),
    Shutdown(Vec<u8>),
    Disconnect(SocketAddr, Vec<u8>),
    SetInfo(Vec<u8>),
    AuthSuccess(LoginAttempt, R),
    AuthFailed(LoginAttempt, Vec<u8>),
    Send(Recipients, Channel, Vec<u8>),
    Flush,
    Stats(SocketAddr, Sender<Option<Stats>>),
    /// The authenticator panicked, the server shuts down and reports this.
    Failed(RecvError),
}

type VersionCheck = Box<dyn Fn(ClientVersion) -> Result<(), AllowedClientVersions> + Send>;

pub enum Recipients {
    One(SocketAddr),
    Many(Vec<SocketAddr>),
    All,
}

/// A connected client.
pub struct Peer {
    connection: Connection,
    /// Its send rate, shared with `Server::budget_for`.
    rate: Arc<AtomicU64>,
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum TimedEventKey {
    RemoveExpectingLoginRequest(LoginAttempt),
    RemoveAnsweredLogin(LoginAttempt),
    /// The connection's timers (`Connection::timeout`).
    Connection(SocketAddr),
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
    pub allowed_client_versions: VersionCheck,
    pub cipher: Cipher,
    pub auth_salt: [u8; 16],
    pub signing_key: SigningKey,
    pub veryifying_key: VerifyingKey,
    pub siphasher: SipHasher,

    /// Handshake cookie timestamps are milliseconds since this instant.
    pub cookie_epoch: Instant,
    pub connection_request_max_timestamp_age: Duration,
    pub max_connections: Option<usize>,

    /// Limit answered ClientHellos and new key exchanges per client IP.
    pub client_hellos: RateLimiter,
    pub connection_requests: RateLimiter,
    pub auth_cmd_tx: Sender<AuthCmd>,
    pub expecting_login_requests: HashMap<LoginAttempt, PendingLogin>,
    pub expecting_auth_result: HashMap<LoginAttempt, Crypto>,
    /// Sent LoginResponses, resent for retransmitted LoginRequests.
    pub answered_logins: HashMap<LoginAttempt, Vec<u8>>,
    pub connections: HashMap<SocketAddr, Peer>,
    /// Connected clients that aren't being closed, shared with `Server`.
    pub connected: ConnectedSet,
    pub config: transport::Config,
    /// Connections with something new to send.
    pub dirty: Vec<SocketAddr>,
    pub outputs: Vec<Output>,

    pub close_linger: Duration,
    pub shutting_down: bool,
    /// Reported once the network thread stops.
    pub failure: Option<RecvError>,
}

impl<R: AuthResult> ServerThreadState<R> {
    pub fn run(&mut self) -> Result<(), RecvError> {
        let mut events = Events::with_capacity(16);
        self.poll
            .registry()
            .register(self.socket.mio_socket(), RECV_TOKEN, Interest::READABLE)?;

        loop {
            if self.handle_all_cmds() {
                break;
            }
            self.handle_all_events();
            self.service_dirty();
            if self.shutting_down && self.connections.is_empty() {
                break;
            }
            let deadline = self
                .timed_events
                .next()
                .into_iter()
                .chain(self.socket.next_deadline())
                .min();
            let max_poll_time =
                deadline.map(|deadline| deadline.saturating_duration_since(Instant::now()));
            // A signal handler ran, nothing happened on the socket.
            match self.poll.poll(&mut events, max_poll_time) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                result => result?,
            }
            self.socket.flush();
            let readable = events.iter().any(|event| event.token() == RECV_TOKEN);
            debug_assert!(events
                .iter()
                .all(|event| [RECV_TOKEN, WAKE_TOKEN].contains(&event.token())));
            if readable || self.socket.inbound_due() {
                self.handle_all_recvs()?;
            }
        }
        self.failure.take().map_or(Ok(()), Err)
    }

    /// Sends what the connections touched since the last call have to send.
    fn service_dirty(&mut self) {
        let now = Instant::now();
        for addr in std::mem::take(&mut self.dirty) {
            self.service(addr, now);
        }
    }

    /// Sends what the connection has to send, then removes it if it closed or reschedules
    /// its timers.
    fn service(&mut self, addr: SocketAddr, now: Instant) {
        let Some(peer) = self.connections.get_mut(&addr) else {
            return;
        };
        while let Some(size) = peer.connection.poll_transmit(now, &mut self.buf) {
            self.socket.send_to(addr, &self.buf[..size]);
        }
        peer.rate
            .store(peer.connection.rate() as u64, Ordering::Relaxed);
        if peer.connection.is_closed() {
            log!(debug, %addr, "closed");
            self.remove(addr);
            return;
        }
        match peer.connection.timeout(now) {
            Some(deadline) => self.timed_events.set(
                TimedEventKey::Connection(addr),
                deadline,
                TimedEventData::Nothing,
            ),
            None => self.timed_events.remove(&TimedEventKey::Connection(addr)),
        }
    }

    fn remove(&mut self, addr: SocketAddr) {
        self.connections.remove(&addr);
        self.timed_events.remove(&TimedEventKey::Connection(addr));
        self.set_connected(addr, None);
    }

    /// Returns true once all `Server` handles are gone.
    fn handle_all_cmds(&mut self) -> bool {
        loop {
            let cmd = match self.cmds.try_recv() {
                Ok(cmd) => cmd,
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return true,
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
                Cmd::Failed(error) => self.failure = Some(error),
                Cmd::SetInfo(info) => {
                    self.info = info;
                }
                Cmd::AuthSuccess(attempt, auth_result) => {
                    self.handle_cmd_auth_success(attempt, auth_result);
                }
                Cmd::AuthFailed(attempt, vec) => {
                    self.handle_cmd_auth_failure(attempt, vec);
                }
                Cmd::Send(recipients, channel, message) => {
                    let message = Rc::new(message);
                    let now = Instant::now();
                    let mut queue = |addr: SocketAddr, peer: &mut Peer| {
                        peer.connection.push(channel, message.clone(), now);
                        self.dirty.push(addr);
                    };
                    match recipients {
                        Recipients::One(addr) => {
                            if let Some(peer) = self.connections.get_mut(&addr) {
                                queue(addr, peer);
                            }
                        }
                        Recipients::Many(addrs) => {
                            for addr in addrs {
                                if let Some(peer) = self.connections.get_mut(&addr) {
                                    queue(addr, peer);
                                }
                            }
                        }
                        Recipients::All => {
                            for (addr, peer) in &mut self.connections {
                                queue(*addr, peer);
                            }
                        }
                    }
                }
                Cmd::Flush => {
                    for (addr, peer) in &mut self.connections {
                        peer.connection.flush();
                        self.dirty.push(*addr);
                    }
                }
                Cmd::Stats(addr, reply) => {
                    let _ = reply.send(
                        self.connections
                            .get(&addr)
                            .map(|peer| peer.connection.stats()),
                    );
                }
                Cmd::SetSimulator(simulator) => self.socket.set_simulator(simulator),
            }
        }
        false
    }

    fn handle_all_events(&mut self) {
        while self
            .timed_events
            .next()
            .is_some_and(|deadline| deadline <= Instant::now())
        {
            let (key, _event) = self.timed_events.pop().unwrap();
            match key {
                TimedEventKey::RemoveExpectingLoginRequest(attempt) => {
                    self.expecting_login_requests.remove(&attempt);
                }
                TimedEventKey::RemoveAnsweredLogin(attempt) => {
                    self.answered_logins.remove(&attempt);
                }
                TimedEventKey::Connection(addr) => self.handle_event_connection(addr),
                TimedEventKey::PruneRateLimits => {
                    let now = Instant::now();
                    self.client_hellos.prune(now);
                    self.connection_requests.prune(now);
                }
            }
        }
    }

    fn handle_event_connection(&mut self, addr: SocketAddr) {
        let now = Instant::now();
        let Some(peer) = self.connections.get_mut(&addr) else {
            return;
        };
        if peer.connection.on_timeout(now) {
            let closing = peer.connection.is_closing();
            let size = peer.connection.close_now(b"Timeout", now, &mut self.buf);
            self.socket.send_to(addr, &self.buf[..size]);
            self.remove(addr);
            log!(debug, %addr, "timed out");
            if !closing {
                self.event_tx.send(Event::TimedOut(addr));
            }
            return;
        }
        self.service(addr, now);
    }

    fn handle_all_recvs(&mut self) -> Result<(), io::Error> {
        while let Some((size, from)) = self.socket.recv_from(&mut self.buf)? {
            if size == 0 || size > 1200 {
                log!(trace, %from, size, "dropped datagram of invalid size");
                continue;
            }
            let Ok(packet_identifier) = PacketIdentifier::try_from(self.buf[0])
                .inspect_err(|e| rejected("datagram", from, *e))
            else {
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
                PacketIdentifier::Data | PacketIdentifier::DataAckNow => {
                    self.handle_packet_data(size, from)
                }
                _ => continue,
            }
        }
        self.service_dirty();
        Ok(())
    }

    fn handle_packet_data(&mut self, size: usize, from: SocketAddr) {
        let Some(peer) = self.connections.get_mut(&from) else {
            return;
        };
        let now = Instant::now();
        let accept = self.event_tx.has_room();
        // Closed by us (kicked, shutdown): the app hears nothing more about it.
        let closing = peer.connection.is_closing();
        let handled = peer
            .connection
            .handle(now, &mut self.buf[..size], accept, &mut self.outputs);
        if let Err(error) = handled {
            rejected("DATA", from, error);
            return;
        }
        self.dirty.push(from);
        for output in std::mem::take(&mut self.outputs) {
            match output {
                Output::Message(message) => self.event_tx.send(Event::Received(from, message)),
                Output::Closed(reason) => {
                    log!(debug, %from, "disconnected by client");
                    // Acknowledges the CLOSE.
                    self.service(from, now);
                    self.remove(from);
                    if !closing {
                        self.event_tx.send(Event::Disconnected(from, reason));
                    }
                    return;
                }
                Output::Violation(violation) => {
                    log!(warn, %from, %violation, "protocol violation");
                    if let Some(peer) = self.connections.get_mut(&from) {
                        let reason = violation.to_string();
                        let size = peer
                            .connection
                            .close_now(reason.as_bytes(), now, &mut self.buf);
                        self.socket.send_to(from, &self.buf[..size]);
                    }
                    self.remove(from);
                    self.event_tx.send(Event::Violation(from, violation));
                    return;
                }
            }
        }
    }

    /// Updates the clients the app can send to (`Server::connections`), before the event that
    /// tells it.
    fn set_connected(&self, addr: SocketAddr, rate: Option<Arc<AtomicU64>>) {
        let mut set = self
            .connected
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        match rate {
            Some(rate) => set.insert(addr, rate),
            None => set.remove(&addr),
        };
    }

    fn schedule_rate_limit_prune(&mut self, now: Instant) {
        self.timed_events.push(
            TimedEventKey::PruneRateLimits,
            now + RATE_LIMIT_PRUNE_INTERVAL,
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
        let Some(peer) = self.connections.get_mut(&addr) else {
            return;
        };
        if peer.connection.is_closing() {
            return;
        }
        peer.connection
            .close(reason, self.close_linger, Instant::now());
        self.set_connected(addr, None);
        log!(debug, %addr, "closing");
        self.dirty.push(addr);
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
            log!(debug, from = %attempt.0, "server full after login");
            let login_response = LoginResponse::Failure {
                failure_data: b"Server full",
            };
            let size = login_response.serialize(&crypto, &mut self.buf);
            self.answer_login(attempt, size);
            return;
        }
        let from = attempt.0;
        let size = LoginResponse::Success.serialize(&crypto, &mut self.buf);
        let rate = Arc::new(AtomicU64::new(0));
        // The connection is inserted before the next command, so sends can go to it as soon as
        // the client is connected.
        self.set_connected(from, Some(rate.clone()));
        self.answer_login(attempt, size);
        let peer = Peer {
            connection: Connection::new(crypto, &self.config, Instant::now()),
            rate,
        };
        // A new handshake from a connected address means the client lost its old session
        // (e.g. our LoginSuccess got lost and it started over).
        if self.connections.insert(from, peer).is_some() {
            self.event_tx.send(Event::Disconnected(from, Vec::new()));
        }
        log!(debug, %from, "connected");
        self.event_tx.send(Event::Connected(from, auth_result));
        self.dirty.push(from);
    }

    fn handle_cmd_auth_failure(&mut self, attempt: LoginAttempt, failure_data: Vec<u8>) {
        let Some(crypto) = self.expecting_auth_result.remove(&attempt) else {
            return;
        };
        log!(debug, from = %attempt.0, "login denied");
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
        let Ok(_) = InfoRequest::deserialize(&self.buf[..size])
            .inspect_err(|e| rejected("InfoRequest", from, *e))
        else {
            return;
        };
        let info_response = InfoResponse::new(&self.info);
        let size = info_response.serialize(&mut self.buf);
        self.socket.send_to(from, &self.buf[..size]);
    }

    fn handle_packet_client_hello(&mut self, size: usize, from: SocketAddr) {
        let client_hello = match ClientHello::deserialize(&self.buf[..size]) {
            Ok(client_hello) => Ok(client_hello),
            Err(e) => match ClientHello::other_protocol_salt(&self.buf[..size]) {
                Some(salt) => Err(salt),
                None => {
                    rejected("ClientHello", from, e);
                    return;
                }
            },
        };
        let now = Instant::now();
        if !self.client_hellos.allow(from.ip(), now) {
            log!(trace, %from, "rate-limited ClientHello");
            return;
        }
        self.schedule_rate_limit_prune(now);
        let client_hello = match client_hello {
            Ok(client_hello) => client_hello,
            Err(salt) => {
                log!(debug, %from, "protocol version mismatch");
                let mismatch = ServerHello::ProtocolMismatch {
                    salt,
                    server_version: PROTOCOL_VERSION,
                };
                let size = mismatch.serialize(&self.siphasher, from, &mut self.buf);
                self.socket.send_to(from, &self.buf[..size]);
                return;
            }
        };
        let server_hello = match (self.allowed_client_versions)(client_hello.client_version) {
            Ok(()) if self.is_full_for(from) => {
                log!(debug, %from, "server full");
                ServerHello::ServerFull {
                    salt: client_hello.salt,
                }
            }
            Ok(()) => {
                let timestamp = self.cookie_epoch.elapsed().as_millis() as u64;
                ServerHello::VersionSupported {
                    salt: client_hello.salt,
                    timestamp: timestamp.to_le_bytes(),
                    cipher: self.cipher,
                    server_ed25519_pubkey: self.veryifying_key,
                    siphash: None,
                    channel_counts: self.config.channels.counts(),
                }
            }
            Err(allowed_versions) => {
                log!(debug, %from, version = %client_hello.client_version, "client version not allowed");
                ServerHello::VersionNotSupported {
                    salt: client_hello.salt,
                    allowed_versions,
                }
            }
        };
        let size = server_hello.serialize(&self.siphasher, from, &mut self.buf);
        self.socket.send_to(from, &self.buf[..size]);
    }

    fn handle_packet_connection_request(&mut self, size: usize, from: SocketAddr) {
        let Ok(connection_request) = ConnectionRequest::deserialize(&self.buf[..size])
            .inspect_err(|e| rejected("ConnectionRequest", from, *e))
        else {
            return;
        };
        if connection_request.siphash
            != server_hello::cookie(&self.siphasher, &self.buf[1..45], from).to_le_bytes()
        {
            log!(debug, %from, "invalid handshake cookie");
            return;
        }
        let issued = Duration::from_millis(u64::from_le_bytes(connection_request.timestamp));
        if self.cookie_epoch.elapsed().saturating_sub(issued)
            > self.connection_request_max_timestamp_age
        {
            log!(debug, %from, "expired handshake cookie");
            return;
        }
        let attempt = (from, connection_request.salt);
        let signed_request: [u8; 116] = self.buf[connection_response::SIGNED_REQUEST]
            .try_into()
            .unwrap();
        let request: [u8; 64] = signed_request[52..].try_into().unwrap();
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
            log!(debug, %from, "rate-limited key exchange");
            return;
        }
        self.schedule_rate_limit_prune(now);
        log!(debug, %from, "key exchange");
        let x25519_secret_key = EphemeralSecret::random_from_rng(thread_rng());
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
        let transcript = Transcript {
            request: &signed_request,
            cipher: self.cipher,
            channel_counts: self.config.channels.counts(),
        };
        let size =
            connection_response.serialize(&crypto, &self.signing_key, &transcript, &mut self.buf);
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
            .inspect_err(|e| rejected("LoginRequest", from, *e))
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
            log!(warn, %from, "authenticator busy, login refused");
            let login_response = LoginResponse::Failure {
                failure_data: b"Server busy",
            };
            let size = login_response.serialize(&crypto, &mut self.buf);
            self.answer_login(attempt, size);
            return;
        }
        log!(debug, %from, "authenticating");
        self.expecting_auth_result.insert(attempt, crypto);
    }
}
