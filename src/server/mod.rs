// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{
    fmt, io,
    net::SocketAddr,
    panic::{self, AssertUnwindSafe},
    sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard},
    thread::JoinHandle,
    time::Duration,
};

use ahash::HashSet;
use auth::AuthThreadState;
pub use auth::{AuthResult, Authenticator};
use bon::bon;
use crossbeam::channel::{bounded, unbounded};
use ed25519_dalek::SigningKey;
use mio::{Poll, Waker};
use rate_limit::RateLimiter;
use siphasher::sip::SipHasher;
use thread::{Cmd, Recipients, ServerThreadState};

use crate::common::{
    channel::{scheduler::ChannelConfiguration, Channel, SendLimits},
    congestion::CongestionConfiguration,
    crypto::sym::SymCipher,
    error::{ConfigError, ProtocolViolation, RecvError, SendError, TooLarge},
    events::{self, EventReceiver},
    packets::{disconnect, info_response::MAX_INFO_SIZE},
    socket::{net_sym::NetworkSimulator, Socket},
    stats::Stats,
    timed_event_queue::TimedEventQueue,
    AllowedClientVersions, Cipher, ClientVersion, WAKE_TOKEN,
};

mod auth;
mod connection;
mod rate_limit;
mod thread;

/// New key exchanges allowed per client IP (IPv6: per /64): sustained rate and burst.
const CONNECTION_REQUESTS_PER_SECOND: f64 = 10.0;
const CONNECTION_REQUEST_BURST: f64 = 20.0;
/// ClientHellos answered per client IP (IPv6: per /64), including retransmissions.
const CLIENT_HELLOS_PER_SECOND: f64 = 20.0;
const CLIENT_HELLO_BURST: f64 = 40.0;

/// Connected clients that aren't being closed, kept up to date by the network thread.
type ConnectedSet = Arc<RwLock<HashSet<SocketAddr>>>;

/// The public key clients pin (`client::ServerKey::Pinned`) for a server's `secret_key`.
pub fn public_key(secret_key: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(secret_key)
        .verifying_key()
        .to_bytes()
}

#[derive(Debug, thiserror::Error)]
pub enum StartError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("invalid configuration: {0}")]
    InvalidConfig(#[from] ConfigError),
}

#[derive(Debug)]
pub enum Event<R: AuthResult> {
    Connected(SocketAddr, R),
    Disconnected(SocketAddr, Vec<u8>),
    TimedOut(SocketAddr),
    Received(SocketAddr, Vec<u8>),
    /// The client violated the protocol and was disconnected.
    Violation(SocketAddr, ProtocolViolation),
}

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
    cmd_tx: crossbeam::channel::Sender<thread::Cmd<R>>,
    waker: Arc<Waker>,
    thread: Option<JoinHandle<()>>,
    auth_thread: Option<JoinHandle<()>>,
}

impl<R: AuthResult> Server<R> {
    /// The address the server is bound to (e.g. the port chosen for `bind_addr` port 0).
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// The connected clients. A client is connected from its `Connected` event until it
    /// disconnects, times out or is disconnected with `disconnect`.
    pub fn connections(&self) -> Vec<SocketAddr> {
        self.connected().iter().copied().collect()
    }

    pub fn is_connected(&self, client: SocketAddr) -> bool {
        self.connected().contains(&client)
    }

    fn connected(&self) -> RwLockReadGuard<'_, HashSet<SocketAddr>> {
        self.inner
            .connected
            .read()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// `disconnect` and `shutdown` take effect for sends right away.
    fn connected_mut(&self) -> RwLockWriteGuard<'_, HashSet<SocketAddr>> {
        self.inner
            .connected
            .write()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Asks the network thread for a client's connection statistics, `None` if it isn't
    /// connected.
    pub fn stats(&self, client: SocketAddr) -> Option<Stats> {
        let (reply_tx, reply_rx) = bounded(1);
        self.inner.cmd_tx.send(Cmd::Stats(client, reply_tx)).ok()?;
        let _ = self.inner.waker.wake();
        reply_rx.recv().ok().flatten()
    }

    /// Sets the info that will be sent to clients on info requests (for server list pings etc).
    /// Info can be at most 256 bytes.
    pub fn set_info(&self, info: Vec<u8>) -> Result<(), TooLarge> {
        TooLarge::check(info.len(), MAX_INFO_SIZE)?;
        let _ = self.inner.cmd_tx.send(Cmd::SetInfo(info));
        let _ = self.inner.waker.wake();
        Ok(())
    }

    /// This is non-blocking, an error means the server has shut down.
    pub fn try_next(&self) -> Result<Option<Event<R>>, RecvError> {
        self.inner.event_rx.try_next()
    }

    /// This is blocking, an error means the server has shut down.
    pub fn next(&self) -> Result<Event<R>, RecvError> {
        self.inner.event_rx.next()
    }

    pub fn send(
        &self,
        to: SocketAddr,
        channel: Channel,
        message: Vec<u8>,
    ) -> Result<(), SendError> {
        self.send_limits.check(channel, message.len())?;
        if !self.is_connected(to) {
            return Err(SendError::NotConnected(to));
        }
        self.send_cmd(Recipients::One(to), channel, message)
    }

    /// Sends one message to every connected client, sharing one buffer.
    pub fn broadcast(&self, channel: Channel, message: Vec<u8>) -> Result<(), SendError> {
        self.send_limits.check(channel, message.len())?;
        self.send_cmd(Recipients::All, channel, message)
    }

    /// Sends one message to several clients, sharing one buffer. Clients that aren't connected
    /// are skipped.
    pub fn send_many(
        &self,
        clients: impl IntoIterator<Item = SocketAddr>,
        channel: Channel,
        message: Vec<u8>,
    ) -> Result<(), SendError> {
        self.send_limits.check(channel, message.len())?;
        let clients = clients.into_iter().collect();
        self.send_cmd(Recipients::Many(clients), channel, message)
    }

    fn send_cmd(
        &self,
        recipients: Recipients,
        channel: Channel,
        message: Vec<u8>,
    ) -> Result<(), SendError> {
        self.inner
            .cmd_tx
            .send(Cmd::Send(recipients, channel, message))
            .map_err(|_| SendError::Stopped)?;
        let _ = self.inner.waker.wake();
        Ok(())
    }

    /// Closes every connection once its queued messages were sent and acknowledged, or after
    /// `close_linger`, then stops. Later sends are dropped and no new clients are accepted.
    /// The reason is sent to every client, at most 1183 bytes.
    pub fn shutdown(&self, reason: Vec<u8>) -> Result<(), TooLarge> {
        TooLarge::check(reason.len(), disconnect::MAX_DATA_SIZE)?;
        self.connected_mut().clear();
        let _ = self.inner.cmd_tx.send(Cmd::Shutdown(reason));
        let _ = self.inner.waker.wake();
        Ok(())
    }

    /// Disconnects one client like `shutdown` does, without an event for it.
    /// The reason is sent to the client, at most 1183 bytes.
    pub fn disconnect(&self, client: SocketAddr, reason: Vec<u8>) -> Result<(), TooLarge> {
        TooLarge::check(reason.len(), disconnect::MAX_DATA_SIZE)?;
        self.connected_mut().remove(&client);
        let _ = self.inner.cmd_tx.send(Cmd::Disconnect(client, reason));
        let _ = self.inner.waker.wake();
        Ok(())
    }

    pub fn set_simulator(&self, simulator: Option<Box<dyn NetworkSimulator>>) {
        let _ = self.inner.cmd_tx.send(Cmd::SetSimulator(simulator));
        let _ = self.inner.waker.wake();
    }
}

impl<R: AuthResult> Drop for ServerInner<R> {
    fn drop(&mut self) {
        let _ = self.cmd_tx.send(Cmd::Shutdown(vec![]));
        let _ = self.waker.wake();
        let _ = self.thread.take().unwrap().join();
        let _ = self.auth_thread.take().unwrap().join();
    }
}

#[bon]
impl<R: AuthResult> Server<R> {
    #[builder(finish_fn = run)]
    pub fn prepare<A, V>(
        authenticator: A,
        bind_addr: SocketAddr,
        socket_buffer_size: Option<usize>,
        simulator: Option<Box<dyn NetworkSimulator>>,
        /// At most 256 bytes.
        info: Vec<u8>,
        /// Decides which client versions may connect, e.g. `|_| Ok(())` or
        /// `move |version| allowed.check(version)` for an `AllowedClientVersions` range. Rejected
        /// clients get the returned range.
        allowed_client_versions: V,
        cipher: Option<Cipher>,
        secret_key: [u8; 32],
        /// Salts the Argon2 hash of clients with `hash_auth_data`, together with the server's
        /// public key. Changing either changes the hashes the authenticator receives.
        auth_salt: [u8; 16],
        #[builder(default = Duration::from_secs(10))] timeout_dur: Duration,
        /// Further clients are turned away (`ConnectError::ServerFull`). Unlimited by default.
        max_connections: Option<usize>,
        #[builder(default = Duration::from_millis(500))] latency_discovery_interval: Duration,
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
        /// How long `shutdown()` (and dropping the server) waits for queued messages to be sent
        /// and acknowledged before the connections are closed.
        #[builder(default = Duration::from_secs(1))]
        close_linger: Duration,
        #[builder(default = false)] disable_timestamp_age_check: bool,
        #[builder(default = Duration::from_secs(10))]
        connection_request_max_timestamp_age: Duration,
    ) -> Result<Self, StartError>
    where
        A: Authenticator<R>,
        V: Fn(ClientVersion) -> Result<(), AllowedClientVersions> + Send + 'static,
    {
        TooLarge::check(info.len(), MAX_INFO_SIZE).map_err(ConfigError::InfoTooLarge)?;
        channel_config.validate()?;
        congestion_config.validate()?;
        let send_limits = SendLimits::new(&channel_config, max_send_msg_size);
        let socket = Socket::builder()
            .bind_addr(bind_addr)
            .maybe_buffer_size_bytes(socket_buffer_size)
            .maybe_simulator(simulator)
            .build()?;
        let local_addr = socket.local_addr()?;
        let (event_tx, event_rx) = events::channel(max_events);
        let connected = ConnectedSet::default();
        let thread_connected = connected.clone();

        let cipher = cipher.unwrap_or_else(SymCipher::better);

        // Has to be unbounded to prevent deadlocks
        let (cmd_tx, cmd_rx) = unbounded();
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
                    veryifying_key: signing_key.verifying_key(),
                    signing_key,
                    auth_salt,

                    connection_request_max_timestamp_age,
                    disable_timestamp_age_check,
                    timeout_dur,
                    max_connections,
                    max_recv_msg_size,
                    is_checking_for_timeouts: false,
                    latency_discovery_interval,

                    siphasher: SipHasher::new_with_key(&rand::random()),
                    client_hellos: RateLimiter::new(CLIENT_HELLOS_PER_SECOND, CLIENT_HELLO_BURST),
                    connection_requests: RateLimiter::new(
                        CONNECTION_REQUESTS_PER_SECOND,
                        CONNECTION_REQUEST_BURST,
                    ),
                    expecting_login_requests: Default::default(),
                    auth_cmd_tx,
                    expecting_auth_result: Default::default(),
                    answered_logins: Default::default(),
                    connections: Default::default(),
                    connected: thread_connected,

                    latency_discoveries_sent: Default::default(),
                    is_discovering_latencies: false,

                    channel_config,
                    congestion_config,

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
            }),
        })
    }
}
