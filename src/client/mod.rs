// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{
    fmt,
    io::{self, ErrorKind},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket},
    panic::{self, AssertUnwindSafe},
    sync::{mpsc, Arc, OnceLock},
    thread::JoinHandle,
    time::{Duration, Instant},
};

use ahash::HashSet;
use bon::bon;
use crossbeam::channel::{bounded, unbounded, Sender};
use handshake::{Handshake, Link};
use mio::{Interest, Poll, Waker};
use thread::{ClientThreadState, Cmd};

use crate::common::{
    channel::{scheduler::ChannelConfiguration, Channel, Channels, SendLimits},
    congestion::{CongestionConfiguration, CongestionController},
    error::{ConfigError, ProtocolViolation, RecvError, SendError, TooLarge},
    events::{self, EventReceiver},
    packets::{disconnect, info_request::InfoRequest, info_response::InfoResponse, login_request},
    socket::{is_transient, net_sym::NetworkSimulator, Socket},
    stats::Stats,
    timed_event_queue::TimedEventQueue,
    AllowedClientVersions, ClientVersion, RECV_TOKEN, WAKE_TOKEN,
};

mod handshake;
mod thread;

#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error("Some io error occurred: {0}")]
    IoError(#[from] io::Error),
    #[error("Client version not supported by server, it allows {0}")]
    VersionNotSupported(AllowedClientVersions),
    #[error("Server denied login")]
    ServerDeniedLogin(Vec<u8>),
    #[error("Server is full")]
    ServerFull,
    /// The server speaks another version of the hexgate protocol.
    #[error("Hexgate protocol version {client} is not supported by the server (version {server})")]
    ProtocolMismatch { client: u8, server: u8 },
    #[error("The server's public key does not match the expected key (possible SECURITY IMPLICATIONS!!!)")]
    ServerKeyMismatch { received_key: [u8; 32] },
    #[error("Invalid configuration: {0}")]
    InvalidConfig(#[from] ConfigError),
    #[error("Auth data too large: {0}")]
    AuthDataTooLarge(TooLarge),
    /// Counts of unreliable ordered and reliable channels.
    #[error("Channel configuration differs from the server's (client: {client:?}, server: {server:?} unreliable ordered and reliable channels)")]
    ChannelMismatch { client: [u16; 2], server: [u16; 2] },
    #[error("The client was disconnected during the handshake")]
    Cancelled,
}

/// Requests the info of every server in `server_addrs` and sends each server's answer to
/// `results` once, e.g. for a server browser. Requests are resent every 500 ms to servers that
/// have not answered yet. Blocks until all servers answered, `duration` elapsed or `results` was
/// dropped. `socket` must be blocking, its read timeout is restored before returning.
/// Servers of another hexgate protocol version don't answer.
pub fn request_infos(
    socket: &UdpSocket,
    duration: Duration,
    server_addrs: &[SocketAddr],
    results: mpsc::Sender<(SocketAddr, Vec<u8>)>,
) -> Result<(), io::Error> {
    let read_timeout = socket.read_timeout()?;
    let result = query_infos(socket, duration, server_addrs, &results);
    socket.set_read_timeout(read_timeout)?;
    result
}

fn query_infos(
    socket: &UdpSocket,
    duration: Duration,
    server_addrs: &[SocketAddr],
    results: &mpsc::Sender<(SocketAddr, Vec<u8>)>,
) -> Result<(), io::Error> {
    const RESEND_INTERVAL: Duration = Duration::from_millis(500);
    let mut request = [0u8; 257];
    let request_size = InfoRequest::new().serialize(&mut request);
    // One byte more than the largest InfoResponse, so oversized datagrams are rejected.
    let mut buf = [0u8; 258];
    let mut pending: HashSet<SocketAddr> = server_addrs.iter().copied().collect();
    let deadline = Instant::now() + duration;
    let mut resend_at = Instant::now();
    while !pending.is_empty() {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        if now >= resend_at {
            for addr in &pending {
                // A server that can't be reached just doesn't answer.
                let _ = socket.send_to(&request[..request_size], addr);
            }
            resend_at = now + RESEND_INTERVAL;
        }
        let wait = resend_at.min(deadline) - now;
        socket.set_read_timeout(Some(wait.max(Duration::from_millis(1))))?;
        let (size, from) = match socket.recv_from(&mut buf) {
            Ok(received) => received,
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => continue,
            Err(e) if is_transient(&e) => continue,
            Err(e) => return Err(e),
        };
        if !pending.contains(&from) {
            continue;
        }
        let Ok(info_response) = InfoResponse::deserialize(&buf[..size]) else {
            continue;
        };
        pending.remove(&from);
        if results.send((from, info_response.data.to_vec())).is_err() {
            break;
        }
    }
    Ok(())
}

/// How the client verifies the server's identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerKey {
    /// The server's ed25519 public key (see `server::public_key`), shipped with the client or
    /// stored on first use. Connecting to a server with any other key fails with
    /// `ConnectError::ServerKeyMismatch`.
    Pinned([u8; 32]),
    /// Accepts any server. Anyone on the network path can impersonate it and read `auth_data`.
    /// For trust on first use, connect like this once, store `Client::get_server_key()` and pin
    /// it from then on.
    Unverified,
}

#[derive(Debug)]
pub enum Event {
    /// The handshake succeeded (`start()` only, `connect()` consumes it).
    Connected,
    /// The handshake failed (`start()` only), the client has stopped.
    ConnectFailed(ConnectError),
    Disconnected(Vec<u8>),
    TimedOut,
    Received(Vec<u8>),
    /// The server violated the protocol and was disconnected.
    Violation(ProtocolViolation),
}

#[derive(Clone)]
pub struct Client {
    send_limits: SendLimits,
    local_addr: SocketAddr,
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

    /// Asks the network thread for the connection statistics, `None` before it is connected
    /// and once it has stopped.
    pub fn stats(&self) -> Option<Stats> {
        let (reply_tx, reply_rx) = bounded(1);
        self.inner.cmd_tx.send(Cmd::Stats(reply_tx)).ok()?;
        let _ = self.inner.waker.wake();
        reply_rx.recv().ok()
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// The server's public key, `None` until connected.
    pub fn get_server_key(&self) -> Option<[u8; 32]> {
        self.inner.server_key.get().copied()
    }
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("local_addr", &self.local_addr)
            .field("server_key", &self.get_server_key())
            .finish_non_exhaustive()
    }
}

struct ClientInner {
    server_key: Arc<OnceLock<[u8; 32]>>,
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
    /// Prepares the client. `start()` returns right away and connects on the network thread,
    /// which reports `Event::Connected` or `Event::ConnectFailed`; messages sent before are
    /// queued. `connect()` blocks until the handshake is done instead.
    #[builder(finish_fn = start)]
    pub fn prepare<A: ToSocketAddrs>(
        /// Defaults to any address of the server's IP version, with a random port.
        bind_addr: Option<SocketAddr>,
        /// An address or a host name with port, e.g. `"example.com:44444"`. The first resolved
        /// address (of `bind_addr`'s IP version, if set) is used.
        server_socket_addr: A,
        server_key: ServerKey,
        /// At most 1177 bytes unless hashed.
        auth_data: Vec<u8>,
        /// Sends an Argon2id hash of `auth_data` (e.g. a password) instead, salted with the
        /// server's key and `auth_salt`. The hash is as good as the password for logging in to
        /// this server, so the server has to hash it again before storing it.
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
        #[builder(default = 2)] handshake_tries: u8,
    ) -> Result<Self, ConnectError> {
        channel_config.validate()?;
        congestion_config.validate()?;
        if !hash_auth_data {
            TooLarge::check(auth_data.len(), login_request::MAX_AUTH_DATA_SIZE)
                .map_err(ConnectError::AuthDataTooLarge)?;
        }
        let send_limits = SendLimits::new(&channel_config, max_send_msg_size);

        let server_socket_addr = server_socket_addr
            .to_socket_addrs()?
            .find(|addr| bind_addr.is_none_or(|bind_addr| bind_addr.is_ipv4() == addr.is_ipv4()))
            .ok_or_else(|| {
                io::Error::new(
                    ErrorKind::InvalidInput,
                    "the server address resolved to no address of bind_addr's IP version",
                )
            })?;
        let bind_addr = bind_addr.unwrap_or(match server_socket_addr {
            SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
            SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
        });
        let mut socket = Socket::builder()
            .bind_addr(bind_addr)
            .connected_to(server_socket_addr)
            .maybe_buffer_size_bytes(socket_buffer_size)
            .maybe_simulator(simulator)
            .build()?;
        let local_addr = socket.local_addr()?;
        let mut poll = Poll::new()?;
        poll.registry()
            .register(socket.mio_socket(), RECV_TOKEN, Interest::READABLE)?;

        let handshake = Handshake {
            server_key,
            auth_data,
            hash_auth_data,
            client_version,
            channel_counts: channel_config.counts(),
            timeout: handshake_timeout,
            tries: handshake_tries,
        };
        let (event_tx, event_rx) = events::channel(max_events);
        let fail_tx = event_tx.clone();
        let (cmd_tx, cmd_rx) = unbounded();
        let waker = Arc::new(Waker::new(poll.registry(), WAKE_TOKEN)?);
        let _waker = waker.clone();
        let server_key = Arc::new(OnceLock::new());
        let thread_server_key = server_key.clone();
        let thread = std::thread::Builder::new()
            .name("hexgate-client".into())
            .spawn(move || {
                let result = panic::catch_unwind(AssertUnwindSafe(|| {
                    let mut link = Link {
                        socket: &mut socket,
                        poll: &mut poll,
                        cmds: &cmd_rx,
                        pending: Vec::new(),
                    };
                    let (crypto, key) = match handshake.run(&mut link) {
                        Ok(connected) => connected,
                        Err(e) => {
                            event_tx.send(Event::ConnectFailed(e));
                            return Ok(());
                        }
                    };
                    let pending = link.pending;
                    let _ = thread_server_key.set(key.to_bytes());
                    event_tx.send(Event::Connected);
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
                        probe_loss: Default::default(),

                        last_received: Instant::now(),
                        timeout_dur,

                        channels: Channels::new(&channel_config, max_recv_msg_size),
                        channel_config,
                        congestion: CongestionController::new(congestion_config),
                        last_sent: Instant::now(),

                        close_linger,
                        closing: None,
                    };
                    state.run(pending)
                }))
                .unwrap_or_else(|payload| Err(RecvError::panicked(payload)));
                if let Err(e) = result {
                    fail_tx.fail(e);
                }
            })?;

        Ok(Client {
            send_limits,
            local_addr,
            inner: Arc::new(ClientInner {
                server_key,
                cmd_tx,
                event_rx,
                waker,
                thread: Some(thread),
            }),
        })
    }
}

impl<A: ToSocketAddrs, S: client_prepare_builder::IsComplete> ClientPrepareBuilder<A, S> {
    /// Starts the client and blocks until the handshake is done (this consumes the
    /// `Event::Connected`). Can run on another thread, the client can be sent back afterwards.
    pub fn connect(self) -> Result<Client, ConnectError> {
        let client = self.start()?;
        match client.next() {
            Ok(Event::Connected) => Ok(client),
            Ok(Event::ConnectFailed(e)) => Err(e),
            Ok(event) => unreachable!("{event:?} before the handshake ended"),
            Err(e) => Err(io::Error::other(e).into()),
        }
    }
}
