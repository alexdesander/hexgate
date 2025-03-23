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
use either::Either;
use mio::{Events, Interest, Poll, Waker};
use rand::thread_rng;
use siphasher::sip::SipHasher;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::common::{
    channel::{scheduler::ChannelConfiguration, Channel},
    congestion::CongestionConfiguration,
    crypto::Crypto,
    packets::{
        acks::Acks, client_hello::ClientHello, connection_request::ConnectionRequest,
        connection_response::ConnectionResponse, disconnect::Disconnect, info_request::InfoRequest,
        info_response::InfoResponse, latency_discovery::LatencyDiscovery,
        latency_discovery_response::LatencyDiscoveryResponse,
        latency_discovery_response_2::LatencyDiscoveryResponse2, login_request::LoginRequest,
        login_response::LoginResponse, reliable_payload::ReliablePayload,
        server_hello::ServerHello, unreliable_payload::UnreliablePayload, PacketIdentifier,
    },
    socket::net_sym::NetworkSimulator,
    timed_event_queue::TimedEventQueue,
    AllowedClientVersions, Cipher, ClientVersion, RECV_TOKEN, WAKE_TOKEN,
};

use super::{
    auth::{AuthCmd, AuthResult},
    connection::Connection,
    Event, Socket,
};

pub enum Cmd<R: AuthResult> {
    SetSimulator(Option<Box<dyn NetworkSimulator>>),
    Shutdown(Vec<u8>),
    SetInfo(Vec<u8>),
    AuthSuccess(SocketAddr, R),
    AuthFailed(SocketAddr, Vec<u8>),
    Send(SocketAddr, Channel, Vec<u8>),
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum TimedEventKey {
    RemoveExpectingLoginRequest(SocketAddr, [u8; 4]),
    CheckForTimeouts,
    DiscoverLatencies,
    Send(SocketAddr),
    SendAcks(SocketAddr, u8),
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TimedEventData {
    Nothing,
}

pub struct ServerThreadState<R: AuthResult> {
    pub event_tx: Sender<Event<R>>,
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

    pub timeout_dur: Duration,
    pub is_checking_for_timeouts: bool,
    pub latency_discovery_interval: Duration,

    pub auth_cmd_tx: Sender<AuthCmd>,
    pub expecting_login_requests: HashMap<(SocketAddr, [u8; 4]), Crypto>,
    pub expecting_auth_result: HashMap<SocketAddr, Crypto>,
    pub connections: HashMap<SocketAddr, Connection>,

    pub latency_discoveries_sent: BTreeMap<u32, Instant>,
    pub is_discovering_latencies: bool,

    pub channel_config: ChannelConfiguration,
    pub congestion_config: CongestionConfiguration,
}

impl<R: AuthResult> ServerThreadState<R> {
    pub fn run(&mut self) -> Result<(), io::Error> {
        let mut events = Events::with_capacity(16);
        self.poll
            .registry()
            .register(self.socket.mio_socket(), RECV_TOKEN, Interest::READABLE)?;

        loop {
            if self.handle_all_cmds()? || self.handle_all_events()? {
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
                    let disconnect = Disconnect { data: &reason };
                    for (addr, connection) in self.connections.drain() {
                        let size = disconnect.serialize(&connection.crypto, &mut self.buf);
                        self.socket.send_to(addr, &self.buf[..size])?;
                    }
                    return Ok(true);
                }
                Cmd::SetInfo(info) => {
                    assert!(info.len() <= 256, "Info can be at most 256 bytes");
                    self.info = info;
                }
                Cmd::AuthSuccess(socket_addr, auth_result) => {
                    self.handle_cmd_auth_success(socket_addr, auth_result)?;
                }
                Cmd::AuthFailed(socket_addr, vec) => {
                    self.handle_cmd_auth_failure(socket_addr, vec)?;
                }
                Cmd::Send(socket_addr, channel, message) => {
                    let Some(connection) = self.connections.get_mut(&socket_addr) else {
                        continue;
                    };
                    connection.channels.push(channel, Rc::new(message));
                    self.timed_events.push(
                        TimedEventKey::Send(socket_addr),
                        connection.last_sent + connection.congestion.downtime_between_batches(),
                        TimedEventData::Nothing,
                    );
                }
                Cmd::SetSimulator(network_simulator) => {
                    if let Some(network_simulator) = network_simulator {
                        self.socket
                            .set_network_simulator(network_simulator)
                            .unwrap();
                        self.socket.set_use_simulator(true);
                    } else {
                        self.socket.set_use_simulator(false);
                    }
                }
            }
        }
        Ok(false)
    }

    fn handle_all_events(&mut self) -> Result<bool, io::Error> {
        while self
            .timed_events
            .next()
            .map_or(false, |deadline| deadline <= Instant::now())
        {
            let (key, _event) = self.timed_events.pop().unwrap();
            match key {
                TimedEventKey::RemoveExpectingLoginRequest(socket_addr, salt) => {
                    self.expecting_login_requests.remove(&(socket_addr, salt));
                }
                TimedEventKey::CheckForTimeouts => {
                    self.handle_event_check_for_timeouts()?;
                }
                TimedEventKey::DiscoverLatencies => {
                    self.handle_event_discover_latencies()?;
                }
                TimedEventKey::Send(socket_addr) => {
                    self.handle_event_send(socket_addr)?;
                }
                TimedEventKey::SendAcks(socket_addr, channel_id) => {
                    self.handle_event_send_acks(socket_addr, channel_id)?;
                }
            }
        }
        Ok(false)
    }

    fn handle_all_recvs(&mut self) -> Result<(), io::Error> {
        loop {
            let (size, from) = match self.socket.mio_socket().recv_from(&mut self.buf) {
                Ok(x) => x,
                Err(ref e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    break
                }
                // Windows shenanigans
                Err(e) if e.kind() == io::ErrorKind::ConnectionReset => continue,
                Err(e) => return Err(e),
            };
            println!("RECEIVED A PACKET");
            if size == 0 || size > 1200 {
                continue;
            }
            let Ok(packet_identifier) = PacketIdentifier::try_from(self.buf[0]) else {
                continue;
            };
            match packet_identifier {
                PacketIdentifier::InfoRequest => self.handle_packet_info_request(size, from)?,
                PacketIdentifier::ClientHello => self.handle_packet_client_hello(size, from)?,
                PacketIdentifier::ConnectionRequest => {
                    self.handle_packet_connection_request(size, from)?
                }
                PacketIdentifier::LoginRequest => self.handle_packet_login_request(size, from)?,
                PacketIdentifier::Disconnect => self.handle_packet_disconnect(size, from)?,
                PacketIdentifier::LatencyDiscoveryResponse => {
                    self.handle_packet_latency_discovery_response(size, from)?
                }
                PacketIdentifier::UnreliableStandalonePayload
                | PacketIdentifier::UnreliableFragmentedPayload
                | PacketIdentifier::UnreliableFragmentedPayloadLast
                | PacketIdentifier::UnreliableOrderedStandalonePayload
                | PacketIdentifier::UnreliableOrderedFragmentedPayload
                | PacketIdentifier::UnreliableOrderedFragmentedPayloadLast => {
                    self.handle_packet_unreliable_payload(size, from)?
                }
                PacketIdentifier::ReliablePayloadNoAcks => {
                    self.handle_packet_reliable_payload(size, from)?
                }
                PacketIdentifier::Acks => self.handle_packet_acks(size, from)?,
                _ => continue,
            }
        }
        Ok(())
    }

    fn handle_event_check_for_timeouts(&mut self) -> Result<(), io::Error> {
        let mut timed_outs = Vec::new();
        for (addr, connection) in &self.connections {
            if connection.last_received.elapsed() > self.timeout_dur {
                let disconnect = Disconnect { data: b"Timeout" };
                let size = disconnect.serialize(&connection.crypto, &mut self.buf);
                self.socket.send_to(*addr, &self.buf[..size])?;
                let _ = self.event_tx.send(Event::TimedOut(*addr));
                timed_outs.push(*addr);
            }
        }
        for addr in timed_outs {
            self.connections.remove(&addr);
        }
        if self.connections.len() > 0 {
            self.timed_events.push(
                TimedEventKey::CheckForTimeouts,
                Instant::now() + self.timeout_dur + Duration::from_secs(1),
                TimedEventData::Nothing,
            );
        } else {
            self.is_checking_for_timeouts = false;
        }
        Ok(())
    }

    fn handle_event_discover_latencies(&mut self) -> Result<(), io::Error> {
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
        for (addr, connection) in self.connections.iter() {
            let size = latency_discovery.serialize(&connection.crypto, &mut self.buf);
            self.socket.send_to(*addr, &self.buf[..size])?;
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
        Ok(())
    }

    fn handle_event_send(&mut self, to: SocketAddr) -> Result<(), io::Error> {
        let Some(connection) = self.connections.get_mut(&to) else {
            return Ok(());
        };
        let now = Instant::now();
        let mut batch_size = connection.congestion.allowed_to_send_this_batch();
        while batch_size > 0 {
            match connection.channels.pop(
                &self.channel_config,
                &mut connection.congestion,
                &connection.crypto,
                &mut self.buf,
            ) {
                Either::Left(size) => {
                    connection.last_sent = now;
                    self.socket.send_to(to, &self.buf[..size])?;
                    batch_size = batch_size.saturating_sub(size as u32);
                }
                Either::Right(Some(time_till_resend)) => {
                    let mut new_deadline = now + time_till_resend;
                    new_deadline = new_deadline.max(
                        connection.last_sent + connection.congestion.downtime_between_batches(),
                    );
                    self.timed_events.push(
                        TimedEventKey::Send(to),
                        new_deadline,
                        TimedEventData::Nothing,
                    );

                    break;
                }
                Either::Right(None) => {
                    return Ok(());
                }
            }
        }
        self.timed_events.push(
            TimedEventKey::Send(to),
            now + connection.congestion.downtime_between_batches(),
            TimedEventData::Nothing,
        );
        Ok(())
    }

    fn handle_event_send_acks(&mut self, to: SocketAddr, channel_id: u8) -> Result<(), io::Error> {
        let Some(connection) = self.connections.get_mut(&to) else {
            return Ok(());
        };
        let acks = connection.channels.acks(Channel::Reliable(channel_id));
        let size = acks.serialize(&connection.crypto, &mut self.buf);
        self.socket.send_to(to, &self.buf[..size])?;
        Ok(())
    }

    fn handle_cmd_auth_success(
        &mut self,
        from: SocketAddr,
        auth_result: R,
    ) -> Result<(), io::Error> {
        println!("HANDLING AUTH SUCCESS");
        let Some(crypto) = self.expecting_auth_result.remove(&from) else {
            return Ok(());
        };
        let login_response = LoginResponse::Success;
        let size = login_response.serialize(&crypto, &mut self.buf);
        self.socket.send_to(from, &self.buf[..size])?;
        if let Some(_old_connection) = self.connections.insert(
            from,
            Connection::new(crypto, &self.channel_config, self.congestion_config),
        ) {
            todo!("Handle old connection");
        };
        let _ = self.event_tx.send(Event::Connected(from, auth_result));

        self.timed_events.push(
            TimedEventKey::DiscoverLatencies,
            Instant::now() + self.latency_discovery_interval,
            TimedEventData::Nothing,
        );

        self.timed_events.push(
            TimedEventKey::CheckForTimeouts,
            Instant::now() + self.timeout_dur + Duration::from_secs(1),
            TimedEventData::Nothing,
        );
        Ok(())
    }

    fn handle_cmd_auth_failure(
        &mut self,
        from: SocketAddr,
        failure_data: Vec<u8>,
    ) -> Result<(), io::Error> {
        println!("HANDLING AUTH FAILURE");
        let Some(crypto) = self.expecting_auth_result.remove(&from) else {
            return Ok(());
        };
        let login_response = LoginResponse::Failure {
            failure_data: &failure_data,
        };
        let size = login_response.serialize(&crypto, &mut self.buf);
        self.socket.send_to(from, &self.buf[..size])?;
        Ok(())
    }

    fn handle_packet_info_request(
        &mut self,
        size: usize,
        from: SocketAddr,
    ) -> Result<(), io::Error> {
        let Ok(_) = InfoRequest::deserialize(&self.buf[..size]) else {
            return Ok(());
        };
        let info_response = InfoResponse::new(&self.info);
        let size = info_response.serialize(&mut self.buf);
        self.socket.send_to(from, &self.buf[..size])?;
        Ok(())
    }

    fn handle_packet_client_hello(
        &mut self,
        size: usize,
        from: SocketAddr,
    ) -> Result<(), io::Error> {
        println!("HANDLING CLIENT HELLO");
        let Ok(client_hello) = ClientHello::deserialize(&self.buf[..size]) else {
            return Ok(());
        };
        let server_hello = match (self.allowed_client_versions)(client_hello.client_version) {
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
                }
            }
            Err(allowed_versions) => ServerHello::VersionNotSupported {
                salt: client_hello.salt,
                allowed_versions,
            },
        };
        let size = server_hello.serialize(&self.siphasher, &mut self.buf);
        self.socket.send_to(from, &self.buf[..size])?;
        Ok(())
    }

    fn handle_packet_connection_request(
        &mut self,
        size: usize,
        from: SocketAddr,
    ) -> Result<(), io::Error> {
        println!("HANDLING CONNECTION REQUEST");
        let Ok(connection_request) = ConnectionRequest::deserialize(&self.buf[..size]) else {
            return Ok(());
        };
        if connection_request.siphash != self.siphasher.hash(&self.buf[1..45]).to_le_bytes() {
            return Ok(());
        }
        let min_time_stamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 5;
        if connection_request.timestamp < min_time_stamp.to_le_bytes() {
            return Ok(());
        }
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
        self.socket.send_to(from, &self.buf[..size])?;
        self.expecting_login_requests
            .insert((from, connection_request.salt), crypto);
        self.timed_events.push(
            TimedEventKey::RemoveExpectingLoginRequest(from, connection_request.salt),
            Instant::now() + Duration::from_secs(8),
            TimedEventData::Nothing,
        );
        Ok(())
    }

    fn handle_packet_login_request(
        &mut self,
        size: usize,
        from: SocketAddr,
    ) -> Result<(), io::Error> {
        println!("HANDLING LOGIN REQUEST");
        let Some(salt) = LoginRequest::deserialize_salt(&self.buf[..size]) else {
            return Ok(());
        };
        let Some(crypto) = self.expecting_login_requests.get_mut(&(from, salt)) else {
            return Ok(());
        };
        let Ok(login_request) = LoginRequest::deserialize(&crypto, &mut self.buf[..size]) else {
            return Ok(());
        };
        let crypto = self.expecting_login_requests.remove(&(from, salt)).unwrap();
        self.expecting_auth_result.insert(from, crypto);
        self.auth_cmd_tx
            .send(AuthCmd::Authenticate(
                from,
                login_request.auth_data.to_vec(),
            ))
            .unwrap();
        Ok(())
    }

    fn handle_packet_disconnect(&mut self, size: usize, from: SocketAddr) -> Result<(), io::Error> {
        let Some(connection) = self.connections.get(&from) else {
            return Ok(());
        };
        let Ok(disconnect) = Disconnect::deserialize(&connection.crypto, &mut self.buf[..size])
        else {
            return Ok(());
        };
        self.connections.remove(&from);
        let _ = self
            .event_tx
            .send(Event::Disconnected(from, disconnect.data.to_vec()));
        Ok(())
    }

    fn handle_packet_latency_discovery_response(
        &mut self,
        size: usize,
        from: SocketAddr,
    ) -> Result<(), io::Error> {
        let Some(connection) = self.connections.get_mut(&from) else {
            return Ok(());
        };
        let Ok(latency_discovery_response) =
            LatencyDiscoveryResponse::deserialize(&connection.crypto, &mut self.buf[..size])
        else {
            return Ok(());
        };
        if latency_discovery_response.sequence_number <= connection.last_latency_discovery_response
        {
            return Ok(());
        }
        let Some(sent) = self
            .latency_discoveries_sent
            .get(&latency_discovery_response.sequence_number)
        else {
            // TODO: Think about what to do with really, really bad connections
            return Ok(());
        };
        connection.last_latency_discovery_response = latency_discovery_response.sequence_number;
        let latency = sent.elapsed();
        connection.congestion.update_latency(latency);

        let mut latency_discovery_response_2 = LatencyDiscoveryResponse2 {
            sequence_number: latency_discovery_response.sequence_number,
            truncated_siphash: 0,
        };
        let size = latency_discovery_response_2.serialize(&connection.crypto, &mut self.buf);
        self.socket.send_to(from, &self.buf[..size])?;

        connection.last_received = Instant::now();

        Ok(())
    }

    fn handle_packet_unreliable_payload(
        &mut self,
        size: usize,
        from: SocketAddr,
    ) -> Result<(), io::Error> {
        let Some(connection) = self.connections.get_mut(&from) else {
            return Ok(());
        };
        let Ok(packet) = UnreliablePayload::deserialize(&connection.crypto, &mut self.buf[0..size])
        else {
            return Ok(());
        };
        let Some(message) = connection.channels.handle_unreliable(packet) else {
            return Ok(());
        };
        let _ = self.event_tx.send(Event::Received(from, message));
        Ok(())
    }

    fn handle_packet_reliable_payload(
        &mut self,
        size: usize,
        from: SocketAddr,
    ) -> Result<(), io::Error> {
        let Some(connection) = self.connections.get_mut(&from) else {
            return Ok(());
        };
        let Ok(packet) = ReliablePayload::deserialize(&connection.crypto, &mut self.buf[..size])
        else {
            return Ok(());
        };
        if packet.channel_id() as usize >= self.channel_config.weights_reliable.len() {
            return Ok(());
        }
        self.timed_events.push(
            TimedEventKey::SendAcks(from, packet.channel_id()),
            Instant::now() + connection.congestion.ack_delay(),
            TimedEventData::Nothing,
        );
        for message in connection.channels.handle_reliable(packet) {
            self.event_tx.send(Event::Received(from, message)).unwrap();
        }
        Ok(())
    }

    fn handle_packet_acks(&mut self, size: usize, from: SocketAddr) -> Result<(), io::Error> {
        let Some(connection) = self.connections.get_mut(&from) else {
            return Ok(());
        };
        let Ok(packet) = Acks::deserialize(&connection.crypto, &mut self.buf[..size]) else {
            return Ok(());
        };
        connection.channels.handle_acks(packet);
        Ok(())
    }
}
