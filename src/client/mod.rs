// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The client side: [`Client`], its events and the server browser query [`request_infos`].

use std::{
    fmt,
    io::{self, ErrorKind},
    net::{SocketAddr, ToSocketAddrs, UdpSocket},
    panic::{self, AssertUnwindSafe},
    sync::{
        Arc, OnceLock, PoisonError, RwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

use ahash::HashSet;
use bon::bon;
use crossbeam_channel::{Sender, bounded};
use handshake::Handshake;
use mio::{Poll, Waker};
use thread::{ClientThreadState, Cmd};

#[cfg(feature = "sim")]
use crate::common::socket::sim::Simulator;
use crate::common::{
    AllowedClientVersions, ClientVersion, WAKE_TOKEN,
    channel::{Channel, SendLimits, scheduler::ChannelConfiguration},
    congestion::CongestionConfig,
    error::{ConfigError, ProtocolViolation, RecvError, SendError, TooLarge},
    events::{self, EventReceiver, Payload},
    packets::{info_request::InfoRequest, info_response::InfoResponse, login_request},
    send::{self, Admission, Message, SendOptions, SendOutcome, SendQueueLimits},
    socket::{Socket, is_transient},
    stats::{ChannelStats, Stats},
    transport::{self, Connection},
};

mod handshake;
mod startup;
mod thread;

/// Why the client couldn't connect.
#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    /// A socket error, an unresolvable server address, or no answer within `handshake_tries`
    /// (`ErrorKind::TimedOut`).
    #[error("Some io error occurred: {0}")]
    IoError(#[from] io::Error),
    /// The server's `allowed_client_versions` rejected `client_version`.
    #[error("Client version not supported by server, it allows {0}")]
    VersionNotSupported(AllowedClientVersions),
    /// The authenticator refused the login, with its failure data.
    #[error("Server denied login")]
    ServerDeniedLogin(Vec<u8>),
    /// The server has `max_connections` clients.
    #[error("Server is full")]
    ServerFull,
    /// The server speaks another version of the hexgate protocol.
    #[error("Hexgate protocol version {client} is not supported by the server (version {server})")]
    ProtocolMismatch {
        /// This client's protocol version.
        client: u8,
        /// The server's protocol version.
        server: u8,
    },
    /// The server's key isn't the pinned one: a different server, or someone impersonating it.
    #[error(
        "The server's public key does not match the expected key (possible SECURITY IMPLICATIONS!!!)"
    )]
    ServerKeyMismatch {
        /// The key the server presented.
        received_key: [u8; 32],
    },
    /// An invalid builder setting.
    #[error("Invalid configuration: {0}")]
    InvalidConfig(#[from] ConfigError),
    /// `auth_data` exceeds 1177 bytes without `hash_auth_data`.
    #[error("Auth data too large: {0}")]
    AuthDataTooLarge(TooLarge),
    /// Counts of unreliable ordered and reliable channels.
    #[error(
        "Channel configuration differs from the server's (client: {client:?}, server: {server:?} unreliable ordered and reliable channels)"
    )]
    ChannelMismatch {
        /// This client's counts.
        client: [u16; 2],
        /// The server's counts.
        server: [u16; 2],
    },
    /// `disconnect()` was called, or the client dropped, during the handshake.
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

/// What happened on the connection, see [`Client::next`].
#[derive(Debug)]
pub enum Event {
    /// The handshake succeeded (`start()` only, `connect()` consumes it).
    Connected,
    /// The handshake failed (`start()` only), the client has stopped.
    ConnectFailed(ConnectError),
    /// The server closed the connection, with its reason.
    Disconnected(Vec<u8>),
    /// Nothing was received from the server for `timeout_dur`.
    TimedOut,
    /// A message from the server.
    Received(Channel, Vec<u8>),
    /// Feedback for an optional send receipt, independent of application processing
    SendResult(u64, SendOutcome),
    /// The server violated the protocol and was disconnected.
    Violation(ProtocolViolation),
}

impl Payload for Event {
    fn payload_len(&self) -> usize {
        match self {
            Event::Received(_, message) => message.len(),
            _ => 0,
        }
    }
}

/// A connection to a server. Cloning gives another handle to the same connection; dropping the
/// last one disconnects gracefully.
#[derive(Clone)]
pub struct Client {
    send_limits: SendLimits,
    inner: Arc<ClientInner>,
}

impl Client {
    /// The next event if there is one. An error means the network thread has stopped, the
    /// first one says why.
    pub fn try_next(&self) -> Result<Option<Event>, RecvError> {
        let event = self.inner.event_rx.try_next()?;
        if event.is_some() {
            let _ = self.inner.waker.wake();
        }
        Ok(event)
    }

    /// Waits for the next event. An error means the network thread has stopped, the first one
    /// says why.
    pub fn next(&self) -> Result<Event, RecvError> {
        let event = self.inner.event_rx.next()?;
        let _ = self.inner.waker.wake();
        Ok(event)
    }

    /// Queues a message for the server. Messages sent while connecting (`start()`) are sent
    /// once connected.
    pub fn send(&self, channel: Channel, message: Vec<u8>) -> Result<(), SendError> {
        self.send_with(channel, message, SendOptions::default())
    }

    /// Queues a message with optional freshness and delivery feedback
    pub fn send_with(
        &self,
        channel: Channel,
        message: Vec<u8>,
        options: SendOptions,
    ) -> Result<(), SendError> {
        let submitted = Instant::now();
        self.send_limits.check(channel, message.len())?;
        options.validate(channel)?;
        let reservation = self.inner.admission.reserve(channel, message.capacity())?;
        self.command(Cmd::Send(
            channel,
            Message {
                data: Arc::new(message),
                submitted,
                options,
                reservation: Some(reservation),
            },
        ))
    }

    fn command(&self, command: Cmd) -> Result<(), SendError> {
        self.inner
            .cmd_tx
            .try_send(command)
            .map_err(send::command_error)?;
        let _ = self.inner.waker.wake();
        Ok(())
    }

    /// Abandons queued transfers on this reliable channel and starts a new generation
    /// Data received before the reset reaches the peer may still be delivered
    pub fn reset_channel(&self, channel: u8) -> Result<(), SendError> {
        self.send_limits.check(Channel::Reliable(channel), 0)?;
        self.command(Cmd::ResetChannel(channel))
    }

    /// Changes a channel's priority; larger values run first, with occasional lower-priority service
    pub fn set_priority(&self, channel: Channel, priority: i8) -> Result<(), SendError> {
        self.send_limits.check(channel, 0)?;
        self.command(Cmd::SetPriority(channel, priority))
    }

    /// Queue state on one channel, unavailable while connecting or when the command queue is full
    pub fn channel_stats(&self, channel: Channel) -> Option<ChannelStats> {
        self.inner.server_key.get()?;
        self.send_limits.check(channel, 0).ok()?;
        let (tx, rx) = bounded(1);
        self.command(Cmd::ChannelStats(channel, tx)).ok()?;
        rx.recv().ok().flatten()
    }

    /// Ends a tick: the messages sent since the last flush leave together, as one paced burst.
    /// Optional; once called, sent messages wait for the next flush (at most two tick
    /// intervals, or 100 ms). Without it, messages leave as soon as the send rate allows.
    pub fn flush(&self) -> Result<(), SendError> {
        self.command(Cmd::Flush)
    }

    /// Approximate gross packet bytes at the current rate over `tick`, including protocol
    /// overhead. This is a shared rate hint, not reserved payload credit; queued data and
    /// retransmissions also consume it.
    /// 0 before the connection is established.
    pub fn gross_send_budget(&self, tick: Duration) -> usize {
        (self.inner.rate.load(Ordering::Relaxed) as f64 * tick.as_secs_f64()) as usize
    }

    /// Closes the connection once queued messages were sent and acknowledged, or after
    /// `close_linger`. Later sends are dropped. The data is sent to the server, at most 1170 bytes.
    pub fn disconnect(&self, data: Vec<u8>) -> Result<(), SendError> {
        TooLarge::check(data.len(), transport::MAX_REASON_SIZE)
            .map_err(SendError::MessageTooLarge)?;
        self.command(Cmd::Disconnect(data))?;
        self.inner.cancel_connecting.store(true, Ordering::Relaxed);
        let _ = self.inner.waker.wake();
        Ok(())
    }

    /// Simulates network conditions for this client's packets, `Simulator::default()` turns it
    /// off. See [`crate::sim`].
    #[cfg(feature = "sim")]
    pub fn set_simulator(&self, simulator: Simulator) -> Result<(), SendError> {
        self.command(Cmd::SetSimulator(simulator))
    }

    /// Asks the network thread for the connection statistics, `None` before it is connected
    /// and once it has stopped.
    pub fn stats(&self) -> Option<Stats> {
        self.inner.server_key.get()?;
        let (reply_tx, reply_rx) = bounded(1);
        self.command(Cmd::Stats(reply_tx)).ok()?;
        reply_rx.recv().ok()
    }

    /// The bound address, unavailable until resolution and socket creation finish
    pub fn local_addr(&self) -> Option<SocketAddr> {
        *self
            .inner
            .local_addr
            .read()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// The server's public key, `None` until connected.
    pub fn get_server_key(&self) -> Option<[u8; 32]> {
        self.inner.server_key.get().copied()
    }
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("local_addr", &self.local_addr())
            .field("server_key", &self.get_server_key())
            .finish_non_exhaustive()
    }
}

struct ClientInner {
    admission: Arc<Admission>,
    local_addr: Arc<RwLock<Option<SocketAddr>>>,
    cancel_connecting: Arc<AtomicBool>,
    server_key: Arc<OnceLock<[u8; 32]>>,
    rate: Arc<AtomicU64>,
    cmd_tx: Sender<Cmd>,
    event_rx: EventReceiver<Event>,
    waker: Arc<Waker>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for ClientInner {
    fn drop(&mut self) {
        self.cancel_connecting.store(true, Ordering::Relaxed);
        let _ = self.waker.wake();
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
    pub fn prepare<A: ToSocketAddrs + Send + 'static>(
        /// Defaults to any address of the server's IP version, with a random port.
        bind_addr: Option<SocketAddr>,
        /// An address or host name with port, resolved on a worker thread
        /// Matching addresses are tried in order after transport failures
        server_socket_addr: A,
        /// How the server's identity is checked, see [`ServerKey`].
        server_key: ServerKey,
        /// At most 1177 bytes unless hashed.
        auth_data: Vec<u8>,
        /// Sends an Argon2id hash of `auth_data` (e.g. a password) instead, salted with the
        /// server's key and `auth_salt`. The hash is as good as the password for logging in to
        /// this server, so the server has to hash it again before storing it. Off by default.
        #[cfg(feature = "argon2")]
        #[builder(default)]
        hash_auth_data: bool,
        /// Simulates network conditions from the first packet on, see [`crate::sim`].
        #[cfg(feature = "sim")]
        simulator: Option<Simulator>,
        /// Send and receive buffer size of the socket, the OS default otherwise.
        socket_buffer_size: Option<usize>,
        /// The app's version, checked by the server's `allowed_client_versions`.
        client_version: ClientVersion,
        /// The connection times out when nothing arrives from the server for this long.
        #[builder(default = Duration::from_secs(10))]
        timeout_dur: Duration,
        /// Limit for queued message and receipt events, also bounded by 64 MiB of message data
        /// (at least 4 × `max_recv_msg_size`); connection events are always delivered
        /// Reliable receive credit resumes when the app polls; unreliable messages may be dropped
        #[builder(default = 65536)]
        max_events: usize,
        /// The channels, the counts must match the server's.
        channel_config: ChannelConfiguration,
        /// Send rate limits.
        #[builder(default)]
        congestion_config: CongestionConfig,
        /// Outgoing buffer and message limits per connection and channel
        #[builder(default)]
        send_queue_limits: SendQueueLimits,
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
        /// How long each handshake step is retransmitted (with backoff) before the handshake
        /// starts over.
        #[builder(default = Duration::from_secs(4))]
        handshake_timeout: Duration,
        /// How often the handshake starts over before the connect fails.
        #[builder(default = 2)]
        handshake_tries: u8,
    ) -> Result<Self, ConnectError> {
        channel_config.validate()?;
        send_queue_limits.validate()?;
        congestion_config.validate()?;
        #[cfg(not(feature = "argon2"))]
        let hash_auth_data = false;
        if !hash_auth_data {
            TooLarge::check(auth_data.len(), login_request::MAX_AUTH_DATA_SIZE)
                .map_err(ConnectError::AuthDataTooLarge)?;
        }
        let send_limits = SendLimits::new(&channel_config, max_send_msg_size);

        let mut poll = Poll::new()?;
        let local_addr = Arc::new(RwLock::new(None));
        let thread_local_addr = local_addr.clone();
        let cancel_connecting = Arc::new(AtomicBool::new(false));
        let thread_cancelled = cancel_connecting.clone();
        let handshake = Handshake {
            server_key,
            auth_data,
            #[cfg(feature = "argon2")]
            hash_auth_data,
            client_version,
            channel_counts: channel_config.counts(),
            timeout: handshake_timeout,
            tries: handshake_tries,
        };
        let (event_tx, event_rx) = events::channel(max_events, max_recv_msg_size);
        let fail_tx = event_tx.clone();
        let (cmd_tx, cmd_rx) = bounded(1024);
        let waker = Arc::new(Waker::new(poll.registry(), WAKE_TOKEN)?);
        let _waker = waker.clone();
        let server_key = Arc::new(OnceLock::new());
        let thread_server_key = server_key.clone();
        let rate = Arc::new(AtomicU64::new(0));
        let thread_rate = rate.clone();
        let config = transport::Config {
            channels: channel_config,
            congestion: congestion_config,
            max_recv_msg_size,
            timeout: timeout_dur,
        };
        let thread = std::thread::Builder::new()
            .name("hexgate-client".into())
            .spawn(move || {
                let result = panic::catch_unwind(AssertUnwindSafe(|| {
                    let connected = startup::connect(
                        server_socket_addr,
                        bind_addr,
                        socket_buffer_size,
                        #[cfg(feature = "sim")]
                        simulator,
                        &handshake,
                        &mut poll,
                        &cmd_rx,
                        &thread_cancelled,
                        &_waker,
                        &thread_local_addr,
                    );
                    let (socket, crypto, key, pending) = match connected {
                        Ok(connected) => connected,
                        Err(e) => {
                            log!(debug, error = %e, "connect failed");
                            event_tx.send(Event::ConnectFailed(e));
                            return Ok(());
                        }
                    };
                    let _ = thread_server_key.set(key.to_bytes());
                    log!(debug, "connected");
                    event_tx.send(Event::Connected);
                    let mut state = ClientThreadState {
                        cmds: cmd_rx,
                        event_tx,
                        poll,
                        _waker,
                        socket,
                        buf: [0u8; 1201],
                        connection: Connection::new(crypto, &config, Instant::now()),
                        rate: thread_rate,
                        close_linger,
                        outputs: Vec::new(),
                        receive_pending: false,
                    };
                    state.run(pending)
                }))
                .unwrap_or_else(|payload| Err(RecvError::panicked(payload)));
                *thread_local_addr
                    .write()
                    .unwrap_or_else(PoisonError::into_inner) = None;
                if let Err(e) = result {
                    log!(error, error = %e, "network thread stopped");
                    fail_tx.fail(e);
                }
            })?;

        Ok(Client {
            send_limits,
            inner: Arc::new(ClientInner {
                admission: Admission::new(send_queue_limits),
                local_addr,
                cancel_connecting,
                server_key,
                rate,
                cmd_tx,
                event_rx,
                waker,
                thread: Some(thread),
            }),
        })
    }
}

impl<A: ToSocketAddrs + Send + 'static, S: client_prepare_builder::IsComplete>
    ClientPrepareBuilder<A, S>
{
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
