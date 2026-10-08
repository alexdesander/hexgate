// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The server side: [`Server`], its events and the [`Authenticator`].

use std::{
    fmt, io,
    net::SocketAddr,
    panic::{self, AssertUnwindSafe},
    sync::{
        Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard,
        atomic::{AtomicU64, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

use ahash::{HashMap, HashSet};
use auth::AuthThreadState;
pub use auth::{AuthResult, Authenticator};
use bon::bon;
use crossbeam_channel::bounded;
use ed25519_dalek::SigningKey;
use handshake::HandshakeThreadState;
use mio::{Poll, Waker};
use rate_limit::RateLimiter;
use siphasher::sip::SipHasher;
use thread::{Cmd, ServerThreadState};

#[cfg(feature = "sim")]
use crate::common::socket::sim::Simulator;
use crate::common::{
    AllowedClientVersions, Cipher, ClientVersion, WAKE_TOKEN,
    channel::{Channel, SendLimits, scheduler::ChannelConfiguration},
    congestion::CongestionConfig,
    crypto::sym::SymCipher,
    error::{ConfigError, ProtocolViolation, RecvError, SendError, TooLarge},
    events::{self, EventReceiver, Payload},
    packets::info_response::MAX_INFO_SIZE,
    send::{self, Admission, Message, SendOptions, SendOutcome, SendQueueLimits},
    socket::Socket,
    stats::{ChannelStats, Stats},
    timed_event_queue::TimedEventQueue,
    transport,
};

mod auth;
mod handshake;
mod rate_limit;
mod thread;

/// New key exchanges allowed per client IP (IPv6: per /64): sustained rate and burst.
const CONNECTION_REQUESTS_PER_SECOND: f64 = 10.0;
const CONNECTION_REQUEST_BURST: f64 = 20.0;
/// ClientHellos answered per client IP (IPv6: per /64), including retransmissions.
const CLIENT_HELLOS_PER_SECOND: f64 = 20.0;
const CLIENT_HELLO_BURST: f64 = 40.0;

/// Connected clients that aren't being closed and their send rates, kept up to date by the
/// network thread.
type ConnectedSet = Arc<RwLock<HashMap<SocketAddr, Arc<PeerState>>>>;

struct PeerState {
    rate: AtomicU64,
    admission: Arc<Admission>,
}

/// The public key clients pin (`client::ServerKey::Pinned`) for a server's `secret_key`.
pub fn public_key(secret_key: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(secret_key)
        .verifying_key()
        .to_bytes()
}

/// Why the server couldn't start.
#[derive(Debug, thiserror::Error)]
pub enum StartError {
    /// Binding the socket or starting a thread failed.
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    /// An invalid builder setting.
    #[error("invalid configuration: {0}")]
    InvalidConfig(#[from] ConfigError),
}

/// What happened to a client, see [`Server::next`].
#[derive(Debug)]
pub enum Event<R: AuthResult> {
    /// A client logged in, with the authenticator's result. A client reconnecting from the same
    /// address replaces its old connection, which gets a `Disconnected` first.
    Connected(SocketAddr, R),
    /// The client disconnected, with its reason.
    Disconnected(SocketAddr, Vec<u8>),
    /// Nothing was received from the client for `timeout_dur`.
    TimedOut(SocketAddr),
    /// A message from the client.
    Received(SocketAddr, Channel, Vec<u8>),
    /// Feedback for an optional send receipt, independent of application processing
    SendResult(SocketAddr, u64, SendOutcome),
    /// The client violated the protocol and was disconnected.
    Violation(SocketAddr, ProtocolViolation),
}

impl<R: AuthResult> Payload for Event<R> {
    fn payload_len(&self) -> usize {
        match self {
            Event::Received(_, _, message) => message.len(),
            _ => 0,
        }
    }
}

/// A server and its connections, `R` being what the [`Authenticator`] returns for a client.
/// Cloning gives another handle to the same server; dropping the last one shuts it down
/// gracefully.
pub struct Server<R: AuthResult> {
    send_limits: SendLimits,
    local_addr: SocketAddr,
    inner: Arc<ServerInner<R>>,
}

impl<R: AuthResult> Clone for Server<R> {
    fn clone(&self) -> Self {
        Self {
            send_limits: self.send_limits,
            local_addr: self.local_addr,
            inner: self.inner.clone(),
        }
    }
}

impl<R: AuthResult> fmt::Debug for Server<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Server")
            .field("local_addr", &self.local_addr)
            .field("connections", &self.connected().len())
            .finish_non_exhaustive()
    }
}

struct ServerInner<R: AuthResult> {
    connected: ConnectedSet,
    event_rx: EventReceiver<Event<R>>,
    cmd_tx: crossbeam_channel::Sender<thread::Cmd<R>>,
    waker: Arc<Waker>,
    thread: Option<JoinHandle<()>>,
    auth_thread: Option<JoinHandle<()>>,
    handshake_thread: Option<JoinHandle<()>>,
}

impl<R: AuthResult> Server<R> {
    /// The address the server is bound to (e.g. the port chosen for `bind_addr` port 0).
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// The connected clients. A client is connected from its `Connected` event until it
    /// disconnects, times out or is disconnected with `disconnect`.
    pub fn connections(&self) -> Vec<SocketAddr> {
        self.connected().keys().copied().collect()
    }

    /// Whether `client` is in `connections()`.
    pub fn is_connected(&self, client: SocketAddr) -> bool {
        self.connected().contains_key(&client)
    }

    /// Approximate gross packet bytes at the current rate over `tick`, including protocol
    /// overhead. This is a shared rate hint, not reserved payload credit; queued data and
    /// retransmissions also consume it. `None` if the client is not connected.
    pub fn gross_send_budget(&self, client: SocketAddr, tick: Duration) -> Option<usize> {
        let rate = self.connected().get(&client)?.rate.load(Ordering::Relaxed);
        Some((rate as f64 * tick.as_secs_f64()) as usize)
    }

    /// Ends a server tick: the messages sent to each client since the last flush leave
    /// together, as one paced burst. Optional; once called, sent messages wait for the next
    /// flush (at most two tick intervals, or 100 ms).
    pub fn flush(&self) -> Result<(), SendError> {
        self.command(Cmd::Flush)
    }

    fn connected(&self) -> RwLockReadGuard<'_, HashMap<SocketAddr, Arc<PeerState>>> {
        self.inner
            .connected
            .read()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// `disconnect` and `shutdown` take effect for sends right away.
    fn connected_mut(&self) -> RwLockWriteGuard<'_, HashMap<SocketAddr, Arc<PeerState>>> {
        self.inner
            .connected
            .write()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Asks the network thread for a client's connection statistics, `None` if it isn't
    /// connected.
    pub fn stats(&self, client: SocketAddr) -> Option<Stats> {
        let (reply_tx, reply_rx) = bounded(1);
        self.command(Cmd::Stats(client, reply_tx)).ok()?;
        reply_rx.recv().ok().flatten()
    }

    /// Sets the info that will be sent to clients on info requests (for server list pings etc).
    /// Info can be at most 256 bytes.
    pub fn set_info(&self, info: Vec<u8>) -> Result<(), SendError> {
        TooLarge::check(info.len(), MAX_INFO_SIZE).map_err(SendError::MessageTooLarge)?;
        self.command(Cmd::SetInfo(info))
    }

    /// The next event if there is one. An error means the network thread has stopped, the
    /// first one says why.
    pub fn try_next(&self) -> Result<Option<Event<R>>, RecvError> {
        let event = self.inner.event_rx.try_next()?;
        if event.is_some() {
            let _ = self.inner.waker.wake();
        }
        Ok(event)
    }

    /// Waits for the next event. An error means the network thread has stopped, the first one
    /// says why.
    pub fn next(&self) -> Result<Event<R>, RecvError> {
        let event = self.inner.event_rx.next()?;
        let _ = self.inner.waker.wake();
        Ok(event)
    }

    /// Queues a message for a connected client.
    pub fn send(
        &self,
        to: SocketAddr,
        channel: Channel,
        message: Vec<u8>,
    ) -> Result<(), SendError> {
        self.send_with(to, channel, message, SendOptions::default())
    }

    /// Queues a message with optional freshness and delivery feedback
    pub fn send_with(
        &self,
        to: SocketAddr,
        channel: Channel,
        message: Vec<u8>,
        options: SendOptions,
    ) -> Result<(), SendError> {
        let submitted = Instant::now();
        self.send_limits.check(channel, message.len())?;
        options.validate(channel)?;
        let connected = self.connected();
        let peer = connected.get(&to).ok_or(SendError::NotConnected(to))?;
        let reservation = peer.admission.reserve(channel, message.capacity())?;
        self.command(Cmd::Send(
            vec![(
                to,
                Message {
                    data: Arc::new(message),
                    submitted,
                    options,
                    reservation: Some(reservation),
                },
            )],
            channel,
        ))
    }

    /// Shares one buffer among connected clients; admission succeeds for all or none
    pub fn broadcast(&self, channel: Channel, message: Vec<u8>) -> Result<(), SendError> {
        let connected = self.connected();
        self.send_shared(
            connected.iter().map(|(&addr, peer)| (addr, peer)),
            channel,
            message,
        )
    }

    /// Shares one buffer among the connected recipients; admission succeeds for all or none
    pub fn send_many(
        &self,
        clients: impl IntoIterator<Item = SocketAddr>,
        channel: Channel,
        message: Vec<u8>,
    ) -> Result<(), SendError> {
        let connected = self.connected();
        let mut seen = HashSet::default();
        self.send_shared(
            clients.into_iter().filter_map(|addr| {
                connected
                    .get(&addr)
                    .filter(|_| seen.insert(addr))
                    .map(|peer| (addr, peer))
            }),
            channel,
            message,
        )
    }

    fn send_shared<'a>(
        &self,
        peers: impl Iterator<Item = (SocketAddr, &'a Arc<PeerState>)>,
        channel: Channel,
        message: Vec<u8>,
    ) -> Result<(), SendError> {
        self.send_limits.check(channel, message.len())?;
        let data = Arc::new(message);
        let submitted = Instant::now();
        let mut targets = Vec::new();
        for (addr, peer) in peers {
            let reservation = peer.admission.reserve(channel, data.capacity())?;
            targets.push((
                addr,
                Message {
                    data: data.clone(),
                    submitted,
                    options: SendOptions::default(),
                    reservation: Some(reservation),
                },
            ));
        }
        if targets.is_empty() {
            return Ok(());
        }
        self.command(Cmd::Send(targets, channel))
    }

    fn command(&self, command: Cmd<R>) -> Result<(), SendError> {
        self.inner
            .cmd_tx
            .try_send(command)
            .map_err(send::command_error)?;
        let _ = self.inner.waker.wake();
        Ok(())
    }

    /// Abandons queued transfers on this reliable channel and starts a new generation
    /// Data received before the reset reaches the peer may still be delivered
    pub fn reset_channel(&self, client: SocketAddr, channel: Channel) -> Result<(), SendError> {
        self.send_limits.check_reset(channel)?;
        let peer = self
            .connected()
            .get(&client)
            .cloned()
            .ok_or(SendError::NotConnected(client))?;
        self.command(Cmd::ResetChannel(client, peer, channel))
    }

    /// Changes a channel's priority; larger values run first, with occasional lower-priority service
    pub fn set_priority(
        &self,
        client: SocketAddr,
        channel: Channel,
        priority: i8,
    ) -> Result<(), SendError> {
        self.send_limits.check(channel, 0)?;
        let peer = self
            .connected()
            .get(&client)
            .cloned()
            .ok_or(SendError::NotConnected(client))?;
        self.command(Cmd::SetPriority(client, peer, channel, priority))
    }

    /// Queue state on one channel, unavailable when disconnected or the command queue is full
    pub fn channel_stats(&self, client: SocketAddr, channel: Channel) -> Option<ChannelStats> {
        self.send_limits.check(channel, 0).ok()?;
        let (tx, rx) = bounded(1);
        self.command(Cmd::ChannelStats(client, channel, tx)).ok()?;
        rx.recv().ok().flatten()
    }

    /// Closes every connection once its queued messages were sent and acknowledged, or after
    /// `close_linger`, then stops. Later sends are dropped and no new clients are accepted.
    /// The reason is sent to every client, at most 1170 bytes.
    pub fn shutdown(&self, reason: Vec<u8>) -> Result<(), SendError> {
        TooLarge::check(reason.len(), transport::MAX_REASON_SIZE)
            .map_err(SendError::MessageTooLarge)?;
        let mut connected = self.connected_mut();
        self.command(Cmd::Shutdown(reason))?;
        connected.clear();
        Ok(())
    }

    /// Disconnects one client like `shutdown` does, without an event for it.
    /// The reason is sent to the client, at most 1170 bytes.
    pub fn disconnect(&self, client: SocketAddr, reason: Vec<u8>) -> Result<(), SendError> {
        TooLarge::check(reason.len(), transport::MAX_REASON_SIZE)
            .map_err(SendError::MessageTooLarge)?;
        let mut connected = self.connected_mut();
        let peer = connected
            .get(&client)
            .cloned()
            .ok_or(SendError::NotConnected(client))?;
        self.command(Cmd::Disconnect(client, peer, reason))?;
        connected.remove(&client);
        Ok(())
    }

    /// Simulates network conditions for the server's packets (of all clients),
    /// `Simulator::default()` turns it off. See [`crate::sim`].
    #[cfg(feature = "sim")]
    pub fn set_simulator(&self, simulator: Simulator) -> Result<(), SendError> {
        self.command(Cmd::SetSimulator(simulator))
    }
}

impl<R: AuthResult> Drop for ServerInner<R> {
    fn drop(&mut self) {
        let _ = self.cmd_tx.send(Cmd::Shutdown(vec![]));
        let _ = self.waker.wake();
        let _ = self.thread.take().unwrap().join();
        let _ = self.handshake_thread.take().unwrap().join();
        let auth_thread = self.auth_thread.take().unwrap();
        if auth_thread.is_finished() {
            let _ = auth_thread.join();
        }
    }
}

#[bon]
impl<R: AuthResult> Server<R> {
    /// Configures the server; `run()` binds the socket and starts the threads.
    #[builder(finish_fn = run)]
    pub fn prepare<A, V>(
        /// Decides which clients may log in, see [`Authenticator`].
        authenticator: A,
        /// The address to listen on, e.g. `0.0.0.0:44444` (port 0 picks a free port, see
        /// `local_addr`).
        bind_addr: SocketAddr,
        /// Send and receive buffer size of the socket, the OS default otherwise.
        socket_buffer_size: Option<usize>,
        /// Simulates network conditions from the first packet on, see [`crate::sim`].
        #[cfg(feature = "sim")]
        simulator: Option<Simulator>,
        /// At most 256 bytes.
        info: Vec<u8>,
        /// Decides which client versions may connect, e.g. `|_| Ok(())` or
        /// `move |version| allowed.check(version)` for an `AllowedClientVersions` range. Rejected
        /// clients get the returned range.
        allowed_client_versions: V,
        /// The cipher of all connections, by default the faster one on this CPU.
        cipher: Option<Cipher>,
        /// The server's ed25519 identity, see [`crate::keys`]. Clients pin its public key
        /// ([`public_key`]).
        secret_key: [u8; 32],
        /// Salts the Argon2 hash of clients with `hash_auth_data`, together with the server's
        /// public key. Changing either changes the hashes the authenticator receives.
        auth_salt: [u8; 16],
        /// A client that sends nothing for this long times out.
        #[builder(default = Duration::from_secs(10))]
        timeout_dur: Duration,
        /// Further clients are turned away (`ConnectError::ServerFull`). Unlimited by default.
        max_connections: Option<usize>,
        /// Limit for queued message and receipt events, also bounded by 64 MiB of message data
        /// (at least 4 × `max_recv_msg_size`); connection events are always delivered
        /// Reliable receive credit resumes when the app polls; unreliable messages may be dropped
        #[builder(default = 65536)]
        max_events: usize,
        /// The channels, clients need the same counts.
        channel_config: ChannelConfiguration,
        /// Send rate limits per connection.
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
        /// How long `shutdown()` (and dropping the server) waits for queued messages to be sent
        /// and acknowledged before the connections are closed.
        #[builder(default = Duration::from_secs(1))]
        close_linger: Duration,
        /// How long a handshake cookie from a ServerHello stays valid.
        #[builder(default = Duration::from_secs(10))]
        connection_request_max_timestamp_age: Duration,
    ) -> Result<Self, StartError>
    where
        A: Authenticator<R>,
        V: Fn(ClientVersion) -> Result<(), AllowedClientVersions> + Send + 'static,
    {
        TooLarge::check(info.len(), MAX_INFO_SIZE).map_err(ConfigError::InfoTooLarge)?;
        channel_config.validate()?;
        send_queue_limits.validate()?;
        congestion_config.validate()?;
        let send_limits = SendLimits::new(&channel_config, max_send_msg_size);
        let socket = Socket::builder()
            .bind_addr(bind_addr)
            .maybe_buffer_size_bytes(socket_buffer_size);
        #[cfg(feature = "sim")]
        let socket = socket.maybe_simulator(simulator);
        let socket = socket.build()?;
        let local_addr = socket.local_addr()?;
        let (event_tx, event_rx) = events::channel(max_events, max_recv_msg_size);
        let connected = ConnectedSet::default();
        let thread_connected = connected.clone();

        let cipher = cipher.unwrap_or_else(SymCipher::better);

        let (cmd_tx, cmd_rx) = bounded(1024);
        let poll = Poll::new()?;
        let waker = Arc::new(Waker::new(poll.registry(), WAKE_TOKEN)?);

        // Auth
        let (auth_cmd_tx, auth_cmd_rx) = bounded(256);
        let auth_state = AuthThreadState {
            phantom: std::marker::PhantomData,
            authenticator,
            main_cmds: cmd_tx.clone(),
            cmds: auth_cmd_rx,
            waker: waker.clone(),
        };
        let auth_thread = std::thread::Builder::new()
            .name("hexgate-auth".into())
            .spawn(move || auth::auth_thread(auth_state))?;

        let signing_key = SigningKey::from_bytes(&secret_key);
        let verifying_key = signing_key.verifying_key();
        let (key_exchanges, key_exchange_rx) = bounded(256);
        let (key_exchanged_tx, key_exchanged) = bounded(256);
        let handshake_state = HandshakeThreadState {
            signing_key,
            cipher,
            auth_salt,
            channel_counts: channel_config.counts(),
            requests: key_exchange_rx,
            results: key_exchanged_tx,
            waker: waker.clone(),
        };
        let handshake_thread = std::thread::Builder::new()
            .name("hexgate-handshake".into())
            .spawn(move || handshake::handshake_thread(handshake_state))?;

        let _waker = waker.clone();
        let thread = std::thread::Builder::new()
            .name("hexgate-server".into())
            .spawn(move || {
                let mut state = ServerThreadState {
                    event_tx,
                    cmds: cmd_rx,
                    socket,
                    poll,
                    _waker,
                    timed_events: TimedEventQueue::new(),
                    buf: [0; 1201],

                    info,
                    allowed_client_versions: Box::new(allowed_client_versions),
                    cipher,
                    verifying_key,

                    cookie_epoch: Instant::now(),
                    connection_request_max_timestamp_age,
                    max_connections,
                    send_queue_limits,

                    siphasher: SipHasher::new_with_key(&rand::random()),
                    client_hellos: RateLimiter::new(CLIENT_HELLOS_PER_SECOND, CLIENT_HELLO_BURST),
                    connection_requests: RateLimiter::new(
                        CONNECTION_REQUESTS_PER_SECOND,
                        CONNECTION_REQUEST_BURST,
                    ),
                    key_exchanges,
                    key_exchanged,
                    exchanging: Default::default(),
                    expecting_login_requests: Default::default(),
                    auth_cmd_tx,
                    expecting_auth_result: Default::default(),
                    next_generation: 0,
                    answered_logins: Default::default(),
                    connections: Default::default(),
                    connected: thread_connected,
                    config: transport::Config {
                        channels: channel_config,
                        congestion: congestion_config,
                        max_recv_msg_size,
                        timeout: timeout_dur,
                    },
                    dirty: Default::default(),
                    delivery_ready: Default::default(),
                    pending_work: None,
                    outputs: Vec::new(),
                    receive_pending: false,

                    close_linger,
                    shutting_down: false,
                    failure: None,
                };
                let result = panic::catch_unwind(AssertUnwindSafe(|| state.run()))
                    .unwrap_or_else(|payload| Err(RecvError::panicked(payload)));
                state
                    .connected
                    .write()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clear();
                if let Err(e) = result {
                    log!(error, error = %e, "network thread stopped");
                    state.event_tx.fail(e);
                }
            })?;

        Ok(Server {
            send_limits,
            local_addr,
            inner: Arc::new(ServerInner {
                connected,
                event_rx,
                cmd_tx,
                waker,
                thread: Some(thread),
                auth_thread: Some(auth_thread),
                handshake_thread: Some(handshake_thread),
            }),
        })
    }
}
