// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{
    io, marker::PhantomData, net::SocketAddr, sync::Arc, thread::JoinHandle, time::Duration,
};

use auth::{AuthResult, AuthThreadState, Authenticator};
use bon::bon;
use crossbeam::channel::{bounded, unbounded, Receiver, TryRecvError};
use ed25519_dalek::SigningKey;
use mio::{Poll, Waker};
use siphasher::sip::SipHasher;
use thread::{Cmd, ServerThreadState};

use crate::common::{
    channel::{scheduler::ChannelConfiguration, Channel},
    congestion::CongestionConfiguration,
    socket::{net_sym::NetworkSimulator, Socket},
    timed_event_queue::TimedEventQueue,
    AllowedClientVersions, Cipher, ClientVersion, WAKE_TOKEN,
};

pub mod auth;
mod connection;
mod thread;

#[derive(Debug)]
pub enum Event<R: AuthResult> {
    Connected(SocketAddr, R),
    Disconnected(SocketAddr, Vec<u8>),
    TimedOut(SocketAddr),
    Received(SocketAddr, Vec<u8>),
}

pub struct Server<R: AuthResult, A: Authenticator<R>> {
    inner: Arc<ServerInner<R, A>>,
}

struct ServerInner<R: AuthResult, A: Authenticator<R>> {
    _phantom: PhantomData<A>,
    event_rx: Receiver<Event<R>>,
    cmd_tx: crossbeam::channel::Sender<thread::Cmd<R>>,
    waker: Arc<Waker>,
    thread: Option<JoinHandle<Result<(), io::Error>>>,
    auth_thread: Option<JoinHandle<()>>,
}

impl<R: AuthResult, A: Authenticator<R>> Server<R, A> {
    /// Sets the info that will be sent to clients on info requests (for server list pings etc).
    /// Info can be at most 256 bytes.
    pub fn set_info(&self, info: Vec<u8>) {
        let _ = self.inner.cmd_tx.send(Cmd::SetInfo(info));
        let _ = self.inner.waker.wake();
    }

    /// This is non-blocking, Err(()) means the server has shutdown
    pub fn try_next(&self) -> Result<Option<Event<R>>, ()> {
        match self.inner.event_rx.try_recv() {
            Ok(event) => Ok(Some(event)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(()),
        }
    }

    /// This is blocking, Err(()) means the server has shutdown
    pub fn next(&self) -> Result<Event<R>, ()> {
        self.inner.event_rx.recv().map_err(|_| ())
    }

    pub fn send(&self, to: SocketAddr, channel: Channel, message: Vec<u8>) -> Result<(), ()> {
        self.inner
            .cmd_tx
            .send(Cmd::Send(to, channel, message))
            .map_err(|_| ())?;
        let _ = self.inner.waker.wake();
        Ok(())
    }

    pub fn shutdown(&self, reason: Vec<u8>) {
        let _ = self.inner.cmd_tx.send(Cmd::Shutdown(reason));
        let _ = self.inner.waker.wake();
    }

    pub fn set_simulator(&self, simulator: Option<Box<dyn NetworkSimulator>>) {
        let _ = self.inner.cmd_tx.send(Cmd::SetSimulator(simulator));
        let _ = self.inner.waker.wake();
    }
}

impl<R: AuthResult, A: Authenticator<R>> Drop for ServerInner<R, A> {
    fn drop(&mut self) {
        let _ = self.cmd_tx.send(Cmd::Shutdown(vec![]));
        let _ = self.thread.take().unwrap().join();
        let _ = self.auth_thread.take().unwrap().join();
    }
}

#[bon]
impl<R: AuthResult, A: Authenticator<R>> Server<R, A> {
    #[builder(finish_fn = run)]
    pub fn prepare(
        authenticator: A,
        bind_addr: SocketAddr,
        socket_buffer_size: Option<usize>,
        simulator: Option<Box<dyn NetworkSimulator>>,
        info: Vec<u8>,
        allowed_client_versions: fn(ClientVersion) -> Result<(), AllowedClientVersions>,
        cipher: Option<Cipher>,
        secret_key: [u8; 32],
        auth_salt: [u8; 16],
        #[builder(default = Duration::from_secs(10))] timeout_dur: Duration,
        #[builder(default = Duration::from_millis(500))] latency_discovery_interval: Duration,
        #[builder(default = 1024)] max_events: usize,
        channel_config: ChannelConfiguration,
        #[builder(default)] congestion_config: CongestionConfiguration,
    ) -> Result<Self, io::Error> {
        assert!(info.len() <= 256, "Info can be at most 256 bytes");
        let socket = Socket::builder()
            .bind_addr(bind_addr)
            .maybe_buffer_size_bytes(socket_buffer_size)
            .maybe_simulator(simulator)
            .build()?;
        let (event_tx, event_rx) = bounded(max_events);

        // TODO: Benchmark for optimal cipher
        let cipher = cipher.unwrap_or(Cipher::AES256GCM);

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
        let auth_thread = std::thread::spawn(move || auth::auth_thread(auth_state));

        let signing_key = SigningKey::from_bytes(&secret_key);
        let _waker = waker.clone();
        let thread = std::thread::spawn(move || {
            let mut state = ServerThreadState {
                event_tx,
                cmds: cmd_rx,
                socket,
                poll,
                _waker: _waker,
                timed_events: TimedEventQueue::new(),
                buf: [0; 1201],

                info,
                allowed_client_versions,
                cipher,
                veryifying_key: signing_key.verifying_key(),
                signing_key,
                auth_salt,

                timeout_dur,
                is_checking_for_timeouts: false,
                latency_discovery_interval,

                siphasher: SipHasher::new_with_key(&rand::random()),
                expecting_login_requests: Default::default(),
                auth_cmd_tx,
                expecting_auth_result: Default::default(),
                connections: Default::default(),

                latency_discoveries_sent: Default::default(),
                is_discovering_latencies: false,

                channel_config,
                congestion_config,
            };
            state.run()
        });

        Ok(Server {
            inner: Arc::new(ServerInner {
                _phantom: PhantomData,
                event_rx,
                cmd_tx,
                waker,
                thread: Some(thread),
                auth_thread: Some(auth_thread),
            }),
        })
    }
}
