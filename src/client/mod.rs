// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{
    io::{self, ErrorKind},
    net::{SocketAddr, UdpSocket},
    sync::{mpsc, Arc},
    thread::JoinHandle,
    time::{Duration, Instant},
};

use argon2::{Argon2, Params};
use bon::bon;
use crossbeam::channel::{unbounded, Sender};
use ed25519_dalek::VerifyingKey;
use mio::{Events, Interest, Poll, Waker};
use rand::thread_rng;
use thread::{ClientThreadState, Cmd};
use x25519_dalek::{PublicKey, ReusableSecret};

use crate::common::{
    channel::{scheduler::ChannelConfiguration, Channel, Channels, SendLimits},
    congestion::{CongestionConfiguration, CongestionController},
    error::{ConfigError, ProtocolViolation, RecvError, SendError, TooLarge},
    events::{self, EventReceiver},
    packets::{
        client_hello::ClientHello,
        connection_request::ConnectionRequest,
        connection_response::ConnectionResponse,
        disconnect,
        info_request::InfoRequest,
        info_response::InfoResponse,
        login_request::{self, LoginRequest},
        login_response::LoginResponse,
        server_hello::ServerHello,
    },
    socket::{net_sym::NetworkSimulator, Socket},
    timed_event_queue::TimedEventQueue,
    AllowedClientVersions, ClientVersion, RECV_TOKEN, WAKE_TOKEN,
};

mod thread;

#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error("Some io error occurred: {0}")]
    IoError(#[from] io::Error),
    #[error("Client version not supported by server: {0:?}")]
    VersionNotSupported(AllowedClientVersions),
    #[error("Server denied login")]
    ServerDeniedLogin(Vec<u8>),
    #[error("The server's public key does not match the expected key (possible SECURITY IMPLICATIONS!!!)")]
    ServerKeyMismatch { received_key: [u8; 32] },
    #[error("Invalid configuration: {0}")]
    InvalidConfig(#[from] ConfigError),
    #[error("Auth data too large: {0}")]
    AuthDataTooLarge(TooLarge),
    /// Counts of unreliable ordered and reliable channels.
    #[error("Channel configuration differs from the server's (client: {client:?}, server: {server:?} unreliable ordered and reliable channels)")]
    ChannelMismatch { client: [u16; 2], server: [u16; 2] },
}

/// Request server infos from a list of servers.
/// This will block until duration has elapsed (even if all servers responded already).
/// This would normally be used to get data to display to the user in a server browser.
///
/// This does not handle lost packets, so it is possible that some servers will not respond.
/// This would easily be fixed by just sending the requests again for servers that did not respond yet.
pub fn request_infos(
    socket: &UdpSocket,
    duration: Duration,
    server_addrs: &[SocketAddr],
    results: mpsc::Sender<(SocketAddr, Vec<u8>)>,
) -> Result<(), io::Error> {
    // Send info requests
    let mut buf = [0u8; 257];
    let request = InfoRequest::new();
    request.serialize(&mut buf);

    for addr in server_addrs {
        socket.send_to(&buf, addr)?;
    }

    // Wait for responses
    let start = Instant::now();
    loop {
        if start.elapsed() >= duration {
            break;
        }
        socket.set_read_timeout(Some(duration.saturating_sub(start.elapsed())))?;
        let (size, server_addr) = match socket.recv_from(&mut buf) {
            Ok(x) => x,
            Err(ref e)
                if e.kind() == ErrorKind::WouldBlock
                    || e.kind() == ErrorKind::TimedOut
                    // Windows shenanigans
                    || e.kind() == ErrorKind::ConnectionReset =>
            {
                continue
            }
            Err(e) => return Err(e),
        };
        let Ok(info_response) = InfoResponse::deserialize(&buf[..size]) else {
            continue;
        };
        if results
            .send((server_addr, info_response.data.to_vec()))
            .is_err()
        {
            break;
        }
    }
    Ok(())
}

pub enum Event {
    Disconnected(Vec<u8>),
    TimedOut,
    Received(Vec<u8>),
    /// The server violated the protocol and was disconnected.
    Violation(ProtocolViolation),
}

#[derive(Clone)]
pub struct Client {
    send_limits: SendLimits,
    inner: Arc<ClientInner>,
}

impl Client {
    /// This is non-blocking, an error means the client has shut down.
    pub fn try_next(&self) -> Result<Option<Event>, RecvError> {
        self.inner.event_rx.try_next()
    }

    /// This is blocking, an error means the client has shut down.
    pub fn next(&self) -> Result<Event, RecvError> {
        self.inner.event_rx.next()
    }

    pub fn send(&self, channel: Channel, message: Vec<u8>) -> Result<(), SendError> {
        self.send_limits.check(channel, message.len())?;
        self.inner
            .cmd_tx
            .send(Cmd::Send(channel, message))
            .map_err(|_| SendError::Stopped)?;
        let _ = self.inner.waker.wake();
        Ok(())
    }

    /// Closes the connection once queued messages were sent and acknowledged, or after
    /// `close_linger`. Later sends are dropped. The data is sent to the server, at most 1183 bytes.
    pub fn disconnect(&self, data: Vec<u8>) -> Result<(), TooLarge> {
        TooLarge::check(data.len(), disconnect::MAX_DATA_SIZE)?;
        let _ = self.inner.cmd_tx.send(Cmd::Disconnect(data));
        let _ = self.inner.waker.wake();
        Ok(())
    }

    pub fn set_simulator(&self, simulator: Option<Box<dyn NetworkSimulator>>) {
        let _ = self.inner.cmd_tx.send(Cmd::SetSimulator(simulator));
        let _ = self.inner.waker.wake();
    }

    pub fn get_server_key(&self) -> [u8; 32] {
        self.inner.server_ed25519_pubkey.to_bytes()
    }
}

struct ClientInner {
    server_ed25519_pubkey: VerifyingKey,
    cmd_tx: Sender<Cmd>,
    event_rx: EventReceiver<Event>,
    waker: Arc<Waker>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for ClientInner {
    fn drop(&mut self) {
        let _ = self.cmd_tx.send(Cmd::Disconnect(vec![]));
        let _ = self.waker.wake();
        let _ = self.thread.take().unwrap().join();
    }
}

#[bon]
impl Client {
    /// Prepares the client and connects to the server (when connect is called).
    /// This is blocking as long as the handshake with the server is not done.
    /// You can freely run this on a different thread and then send the client back to your main thread.
    #[builder(finish_fn = connect)]
    pub fn prepare(
        #[builder(default = "0.0.0.0:0".parse().unwrap())] bind_addr: SocketAddr,
        server_socket_addr: SocketAddr,
        expected_server_key: Option<[u8; 32]>,
        /// At most 1177 bytes unless hashed.
        auth_data: Vec<u8>,
        hash_auth_data: bool,
        simulator: Option<Box<dyn NetworkSimulator>>,
        socket_buffer_size: Option<usize>,
        client_version: ClientVersion,
        #[builder(default = Duration::from_secs(10))] timeout_dur: Duration,
        /// Limit for queued, undrained events. While reached, received unreliable messages are
        /// dropped and reliable packets are left unacknowledged (the peer resends them later).
        /// Connection events are always delivered.
        #[builder(default = 1024)]
        max_events: usize,
        channel_config: ChannelConfiguration,
        #[builder(default)] congestion_config: CongestionConfiguration,
        /// Maximum size of a message that can be sent.
        #[builder(default = 1048576)]
        max_send_msg_size: usize,
        /// Maximum size of a received message. A peer sending a larger one violates the protocol
        /// and is disconnected.
        #[builder(default = 1048576)]
        max_recv_msg_size: usize,
        /// How long `disconnect()` (and dropping the client) waits for queued messages to be
        /// sent and acknowledged before the connection is closed.
        #[builder(default = Duration::from_secs(1))]
        close_linger: Duration,
        #[builder(default = Duration::from_secs(4))] handshake_timeout: Duration,
        #[builder(default = 2)] mut handshake_tries: u8,
    ) -> Result<Self, ConnectError> {
        let max_handshake_tries = handshake_tries;
        channel_config.validate()?;
        congestion_config.validate()?;
        if !hash_auth_data {
            TooLarge::check(auth_data.len(), login_request::MAX_AUTH_DATA_SIZE)
                .map_err(ConnectError::AuthDataTooLarge)?;
        }
        let send_limits = SendLimits::new(&channel_config, max_send_msg_size);

        let mut socket = Socket::builder()
            .bind_addr(bind_addr)
            .connected_to(server_socket_addr)
            .maybe_buffer_size_bytes(socket_buffer_size)
            .maybe_simulator(simulator)
            .build()?;
        let mut poll = Poll::new()?;
        poll.registry()
            .register(socket.mio_socket(), RECV_TOKEN, Interest::READABLE)?;
        let mut buf = [0u8; 1201];

        'outer: while handshake_tries > 0 {
            handshake_tries -= 1;
            // ClientHello -> ServerHello
            let real_salt: [u8; 4] = rand::random();
            let client_hello = ClientHello {
                salt: real_salt,
                client_version,
            };
            let size = client_hello.serialize(&mut buf);
            let server_hello = handshake_step(
                &mut socket,
                &mut poll,
                &buf[..size],
                handshake_timeout,
                |packet| match ServerHello::deserialize(packet).ok()? {
                    ServerHello::VersionNotSupported {
                        salt,
                        allowed_versions,
                    } => (salt == real_salt)
                        .then_some(Err(ConnectError::VersionNotSupported(allowed_versions))),
                    ServerHello::VersionSupported {
                        salt,
                        timestamp,
                        cipher,
                        server_ed25519_pubkey,
                        siphash,
                        channel_counts,
                    } => (salt == real_salt).then_some(Ok((
                        timestamp,
                        cipher,
                        server_ed25519_pubkey,
                        siphash,
                        channel_counts,
                    ))),
                },
            )?;
            let Some((timestamp, cipher, server_ed25519_pubkey, siphash, channel_counts)) =
                server_hello
            else {
                continue 'outer;
            };

            if let Some(expected_server_key) = expected_server_key {
                if server_ed25519_pubkey.to_bytes() != expected_server_key {
                    return Err(ConnectError::ServerKeyMismatch {
                        received_key: server_ed25519_pubkey.to_bytes(),
                    });
                }
            }
            if channel_counts != channel_config.counts() {
                return Err(ConnectError::ChannelMismatch {
                    client: channel_config.counts(),
                    server: channel_counts,
                });
            }

            // ConnectionRequest -> ConnectionResponse
            let client_x25519_key = ReusableSecret::random_from_rng(&mut thread_rng());
            let hkdf_salt: [u8; 32] = rand::random();
            let connection_request = ConnectionRequest {
                salt: real_salt,
                timestamp,
                server_ed25519_pubkey,
                siphash: siphash.unwrap().to_le_bytes(),
                client_x25519_pubkey: PublicKey::from(&client_x25519_key),
                hkdf_salt,
            };
            let size = connection_request.serialize(&mut buf);
            let connection_response = handshake_step(
                &mut socket,
                &mut poll,
                &buf[..size],
                handshake_timeout,
                |packet| {
                    let (response, crypto) = ConnectionResponse::deserialize(
                        packet,
                        server_ed25519_pubkey,
                        &client_x25519_key,
                        hkdf_salt,
                        cipher,
                    )
                    .ok()?;
                    (response.salt == real_salt).then_some(Ok((crypto, response.auth_salt)))
                },
            )?;
            let Some((crypto, auth_salt)) = connection_response else {
                continue 'outer;
            };

            // LoginRequest -> LoginResponse
            let hashed_auth_data;
            let login_auth_data = if hash_auth_data {
                let mut hashed = vec![0u8; 20];
                Argon2::new(
                    argon2::Algorithm::Argon2id,
                    argon2::Version::V0x13,
                    Params::new(65536, 2, 1, Some(20)).unwrap(),
                )
                .hash_password_into(&auth_data, &auth_salt, &mut hashed)
                .unwrap();
                hashed_auth_data = hashed;
                &hashed_auth_data
            } else {
                &auth_data
            };
            let login_request = LoginRequest {
                salt: real_salt,
                auth_data: login_auth_data,
            };
            let size = login_request.serialize(&crypto, &mut buf);
            let login = handshake_step(
                &mut socket,
                &mut poll,
                &buf[..size],
                handshake_timeout,
                |packet| match LoginResponse::deserialize(&crypto, packet).ok()? {
                    LoginResponse::Failure { failure_data } => {
                        Some(Err(ConnectError::ServerDeniedLogin(failure_data.to_vec())))
                    }
                    LoginResponse::Success => Some(Ok(())),
                },
            )?;
            if login.is_none() {
                continue 'outer;
            }

            // Handshake done, run thread
            let (event_tx, event_rx) = events::channel(max_events);
            let (cmd_tx, cmd_rx) = unbounded();
            let waker = Arc::new(Waker::new(poll.registry(), WAKE_TOKEN)?);
            let _waker = waker.clone();
            let thread = std::thread::spawn(move || {
                let mut state = ClientThreadState {
                    cmds: cmd_rx,
                    event_tx,
                    poll,
                    _waker,
                    socket,
                    buf: [0u8; 1201],

                    timed_events: TimedEventQueue::new(),
                    crypto,

                    latency_discoveries: Default::default(),
                    latencies: Default::default(),

                    last_received: Instant::now(),
                    timeout_dur,

                    channels: Channels::new(&channel_config, max_recv_msg_size),
                    channel_config,
                    congestion: CongestionController::new(congestion_config),
                    last_sent: Instant::now(),

                    close_linger,
                    closing: None,
                };
                if let Err(e) = state.run() {
                    state.event_tx.fail(e);
                }
            });

            return Ok(Client {
                send_limits,
                inner: Arc::new(ClientInner {
                    server_ed25519_pubkey,
                    cmd_tx,
                    event_rx,
                    waker,
                    thread: Some(thread),
                }),
            });
        }
        Err(ConnectError::IoError(io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "Hexgate Handshake timed out after {} tries",
                max_handshake_tries
            ),
        )))
    }
}

/// First retransmission interval of a handshake step, doubled up to the maximum.
const HANDSHAKE_RESEND_INTERVAL: Duration = Duration::from_millis(250);
const MAX_HANDSHAKE_RESEND_INTERVAL: Duration = Duration::from_secs(1);

/// Sends `packet` with backoff until `parse` accepts a response, `Ok(None)` after `timeout`.
fn handshake_step<T>(
    socket: &mut Socket,
    poll: &mut Poll,
    packet: &[u8],
    timeout: Duration,
    mut parse: impl FnMut(&mut [u8]) -> Option<Result<T, ConnectError>>,
) -> Result<Option<T>, ConnectError> {
    let mut events = Events::with_capacity(4);
    let mut buf = [0u8; 1201];
    let deadline = Instant::now() + timeout;
    let mut resend_interval = HANDSHAKE_RESEND_INTERVAL;
    let mut resend_at = Instant::now();
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Ok(None);
        }
        if now >= resend_at {
            socket.send(packet);
            resend_at = now + resend_interval;
            resend_interval = (resend_interval * 2).min(MAX_HANDSHAKE_RESEND_INTERVAL);
        }
        while let Some((size, _)) = socket.recv_from(&mut buf)? {
            if (1..=1200).contains(&size) {
                if let Some(result) = parse(&mut buf[..size]) {
                    return result.map(Some);
                }
            }
        }
        let wait = resend_at
            .min(deadline)
            .saturating_duration_since(Instant::now());
        match poll.poll(&mut events, Some(wait)) {
            Err(e) if e.kind() != ErrorKind::Interrupted => return Err(e.into()),
            _ => {}
        }
    }
}
