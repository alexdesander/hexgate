// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{
    collections::VecDeque,
    io,
    net::SocketAddr,
    rc::Rc,
    sync::{
        Arc, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use ahash::{HashMap, HashSet};
use crossbeam_channel::{Receiver, Sender, TryRecvError};
use ed25519_dalek::VerifyingKey;
use mio::{Events, Interest, Poll, Waker};
use sha2::{Digest, Sha256};
use siphasher::sip::SipHasher;

use crate::common::{
    AllowedClientVersions, Cipher, ClientVersion, PROTOCOL_VERSION, RECV_TOKEN, WAKE_TOKEN,
    channel::Channel,
    crypto::Crypto,
    error::RecvError,
    events::{DeliveryBudget, EventSender},
    packets::{
        PacketIdentifier,
        client_hello::ClientHello,
        connection_request::ConnectionRequest,
        connection_response,
        info_request::InfoRequest,
        info_response::InfoResponse,
        login_request::LoginRequest,
        login_response::LoginResponse,
        rejected,
        server_hello::{self, ServerHello},
    },
    send::{Admission, Message, SendQueueLimits},
    socket::sim::Simulator,
    stats::{ChannelStats, Stats},
    timed_event_queue::TimedEventQueue,
    transport::{self, Connection, Output},
};

use super::{
    ConnectedSet, Event, PeerState, Socket,
    auth::{AuthCmd, AuthResult, Exchange, LoginAttempt},
    handshake::{KeyExchange, KeyExchanged},
    rate_limit::RateLimiter,
};

const RATE_LIMIT_PRUNE_INTERVAL: Duration = Duration::from_secs(10);
/// How long handshake state is kept to answer retransmitted requests.
const HANDSHAKE_STATE_TTL: Duration = Duration::from_secs(8);

/// A ConnectionResponse was sent, the LoginRequest is outstanding.
pub struct PendingLogin {
    crypto: Crypto,
    generation: u64,
    /// The client's x25519 key and HKDF salt, to recognize a retransmitted request.
    request: [u8; 116],
    response: Vec<u8>,
    login_request: Option<[u8; 32]>,
}

pub struct AnsweredLogin {
    exchange: Exchange,
    request: [u8; 32],
    response: Vec<u8>,
}

pub enum Cmd<R: AuthResult> {
    SetSimulator(Simulator),
    Shutdown(Vec<u8>),
    Disconnect(SocketAddr, Arc<PeerState>, Vec<u8>),
    SetInfo(Vec<u8>),
    AuthSuccess(Exchange, R),
    AuthFailed(Exchange, Vec<u8>),
    Send(Vec<(SocketAddr, Message)>, Channel),
    Flush,
    Stats(SocketAddr, Sender<Option<Stats>>),
    ChannelStats(SocketAddr, Channel, Sender<Option<ChannelStats>>),
    ResetChannel(SocketAddr, Arc<PeerState>, u8),
    SetPriority(SocketAddr, Arc<PeerState>, Channel, i8),
    /// The authenticator panicked, the server shuts down and reports this.
    Failed(RecvError),
}

pub enum PendingWork {
    Send(Channel, std::vec::IntoIter<(SocketAddr, Message)>),
    Flush(std::vec::IntoIter<SocketAddr>),
    Close(Rc<[u8]>, std::vec::IntoIter<SocketAddr>),
}

type VersionCheck = Box<dyn Fn(ClientVersion) -> Result<(), AllowedClientVersions> + Send>;

#[derive(Default)]
pub struct ReadyQueue {
    queue: VecDeque<SocketAddr>,
    queued: HashSet<SocketAddr>,
}

impl ReadyQueue {
    fn push(&mut self, addr: SocketAddr) {
        if self.queued.insert(addr) {
            self.queue.push_back(addr);
        }
    }

    fn pop(&mut self) -> Option<SocketAddr> {
        let addr = self.queue.pop_front()?;
        self.queued.remove(&addr);
        Some(addr)
    }

    fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

/// A connected client.
pub struct Peer {
    connection: Connection,
    /// Its send rate, shared with `Server::gross_send_budget`.
    shared: Arc<PeerState>,
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum TimedEventKey {
    RemoveExpectingLoginRequest(Exchange),
    RemoveAnsweredLogin(Exchange),
    /// The connection's timers (`Connection::timeout`).
    Connection(SocketAddr),
    PruneRateLimits,
}

pub struct ServerThreadState<R: AuthResult> {
    pub event_tx: EventSender<Event<R>>,
    pub cmds: Receiver<Cmd<R>>,
    pub socket: Socket,
    pub poll: Poll,
    pub _waker: Arc<Waker>,
    pub timed_events: TimedEventQueue<TimedEventKey>,
    pub buf: [u8; 1201],

    pub info: Vec<u8>,
    pub allowed_client_versions: VersionCheck,
    pub cipher: Cipher,
    pub verifying_key: VerifyingKey,
    pub siphasher: SipHasher,

    /// Handshake cookie timestamps are milliseconds since this instant.
    pub cookie_epoch: Instant,
    pub connection_request_max_timestamp_age: Duration,
    pub max_connections: Option<usize>,

    /// Limit answered ClientHellos and new key exchanges per client IP.
    pub client_hellos: RateLimiter,
    pub connection_requests: RateLimiter,
    pub key_exchanges: Sender<KeyExchange>,
    pub key_exchanged: Receiver<KeyExchanged>,
    /// Requests on the handshake thread, to ignore their retransmissions until it answers.
    pub exchanging: HashMap<LoginAttempt, [u8; 116]>,
    pub auth_cmd_tx: Sender<AuthCmd>,
    pub expecting_login_requests: HashMap<LoginAttempt, PendingLogin>,
    pub expecting_auth_result: HashMap<LoginAttempt, PendingLogin>,
    pub next_generation: u64,
    /// Sent LoginResponses, resent for retransmitted LoginRequests.
    pub answered_logins: HashMap<LoginAttempt, AnsweredLogin>,
    pub connections: HashMap<SocketAddr, Peer>,
    /// Connected clients that aren't being closed, shared with `Server`.
    pub connected: ConnectedSet,
    pub config: transport::Config,
    /// Connections with something new to send.
    pub dirty: ReadyQueue,
    pub delivery_ready: ReadyQueue,
    pub send_queue_limits: SendQueueLimits,
    pub pending_work: Option<PendingWork>,
    pub outputs: Vec<Output>,
    pub receive_pending: bool,

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
            self.handle_key_exchanges();
            let mut budget = self.event_tx.budget();
            let before_delivery = (budget.messages, budget.work);
            self.handle_all_events(&mut budget);
            self.drain_received(&mut budget);
            self.service_dirty(&mut budget);
            if self.shutting_down && self.connections.is_empty() {
                break;
            }
            let deadline = self
                .timed_events
                .next()
                .into_iter()
                .chain(self.socket.next_deadline())
                .min();
            let delivery_pending = before_delivery != (budget.messages, budget.work)
                && !self.delivery_ready.is_empty()
                && self.event_tx.budget().messages > 0
                && self.event_tx.budget().bytes > 0;
            let max_poll_time = if self.receive_pending
                || delivery_pending
                || !self.dirty.is_empty()
                || self.pending_work.is_some()
                || !self.cmds.is_empty()
                || !self.key_exchanged.is_empty()
            {
                Some(Duration::ZERO)
            } else {
                deadline.map(|deadline| deadline.saturating_duration_since(Instant::now()))
            };
            // A signal handler ran, nothing happened on the socket.
            match self.poll.poll(&mut events, max_poll_time) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                result => result?,
            }
            self.socket.flush();
            let readable = events.iter().any(|event| event.token() == RECV_TOKEN);
            debug_assert!(
                events
                    .iter()
                    .all(|event| [RECV_TOKEN, WAKE_TOKEN].contains(&event.token()))
            );
            if self.receive_pending || readable || self.socket.inbound_due() {
                self.handle_all_recvs(&mut budget)?;
            }
        }
        self.failure.take().map_or(Ok(()), Err)
    }

    /// Sends what the connections touched since the last call have to send.
    fn service_dirty(&mut self, budget: &mut DeliveryBudget) {
        let now = Instant::now();
        for _ in 0..128 {
            let Some(addr) = self.dirty.pop() else { break };
            self.service(addr, now, budget);
        }
    }

    /// Sends what the connection has to send, then removes it if it closed or reschedules
    /// its timers.
    fn service(&mut self, addr: SocketAddr, now: Instant, budget: &mut DeliveryBudget) {
        let Some(peer) = self.connections.get_mut(&addr) else {
            return;
        };
        for _ in 0..64 {
            let Some(size) = peer.connection.poll_transmit(now, &mut self.buf) else {
                break;
            };
            self.socket.send_to(addr, &self.buf[..size]);
        }
        peer.shared
            .rate
            .store(peer.connection.rate() as u64, Ordering::Relaxed);
        peer.connection.take_send_results(budget, &mut self.outputs);
        if peer.connection.has_pending_delivery() {
            self.delivery_ready.push(addr);
        }
        let closed = peer.connection.is_closed();
        let closing = peer.connection.is_closing();
        self.handle_outputs(addr, now, closing, budget);
        if closed {
            log!(debug, %addr, "closed");
            self.remove(addr);
            return;
        }
        let Some(peer) = self.connections.get_mut(&addr) else {
            return;
        };
        match peer.connection.timeout(now) {
            Some(deadline) => self
                .timed_events
                .set(TimedEventKey::Connection(addr), deadline),
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
        for _ in 0..256 {
            if self.pending_work.is_some() {
                self.advance_work();
                continue;
            }
            let cmd = match self.cmds.try_recv() {
                Ok(cmd) => cmd,
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return true,
            };

            match cmd {
                Cmd::Shutdown(reason) => {
                    self.shutting_down = true;
                    let addrs: Vec<_> = self.connections.keys().copied().collect();
                    self.pending_work = Some(PendingWork::Close(reason.into(), addrs.into_iter()));
                }
                Cmd::Disconnect(addr, shared, reason) => {
                    if self
                        .connections
                        .get(&addr)
                        .is_some_and(|peer| Arc::ptr_eq(&peer.shared, &shared))
                    {
                        self.start_close(addr, reason.into());
                    }
                }
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
                Cmd::Send(recipients, channel) => {
                    self.pending_work = Some(PendingWork::Send(channel, recipients.into_iter()));
                }
                Cmd::Flush => {
                    let addrs: Vec<_> = self.connections.keys().copied().collect();
                    self.pending_work = Some(PendingWork::Flush(addrs.into_iter()));
                }
                Cmd::Stats(addr, reply) => {
                    let _ = reply.send(
                        self.connections
                            .get(&addr)
                            .map(|peer| peer.connection.stats()),
                    );
                }
                Cmd::ChannelStats(addr, channel, reply) => {
                    let _ =
                        reply.send(self.connections.get(&addr).and_then(|peer| {
                            peer.connection.channel_stats(channel, Instant::now())
                        }));
                }
                Cmd::ResetChannel(addr, shared, channel) => {
                    if let Some(peer) = self
                        .connections
                        .get_mut(&addr)
                        .filter(|peer| Arc::ptr_eq(&peer.shared, &shared))
                    {
                        peer.connection.reset_channel(channel);
                        self.dirty.push(addr);
                    }
                }
                Cmd::SetPriority(addr, shared, channel, priority) => {
                    if let Some(peer) = self
                        .connections
                        .get_mut(&addr)
                        .filter(|peer| Arc::ptr_eq(&peer.shared, &shared))
                    {
                        peer.connection.set_priority(channel, priority);
                        self.dirty.push(addr);
                    }
                }
                Cmd::SetSimulator(simulator) => self.socket.set_simulator(simulator),
            }
        }
        false
    }

    fn advance_work(&mut self) {
        let mut work = self.pending_work.take().unwrap();
        let remaining = match &mut work {
            PendingWork::Send(channel, recipients) => {
                if let Some((addr, message)) = recipients.next() {
                    if let Some(peer) = self.connections.get_mut(&addr) {
                        if message.reservation.as_ref().is_some_and(|reservation| {
                            Arc::ptr_eq(reservation.admission(), &peer.shared.admission)
                        }) {
                            peer.connection.push_message(*channel, message);
                            self.dirty.push(addr);
                        }
                    }
                }
                !recipients.as_slice().is_empty()
            }
            PendingWork::Flush(recipients) => {
                if let Some(addr) = recipients.next() {
                    if let Some(peer) = self.connections.get_mut(&addr) {
                        peer.connection.flush();
                        self.dirty.push(addr);
                    }
                }
                !recipients.as_slice().is_empty()
            }
            PendingWork::Close(reason, recipients) => {
                if let Some(addr) = recipients.next() {
                    self.start_close(addr, reason.clone());
                }
                !recipients.as_slice().is_empty()
            }
        };
        if remaining {
            self.pending_work = Some(work);
        }
    }

    fn handle_all_events(&mut self, budget: &mut DeliveryBudget) {
        for _ in 0..256 {
            if !self
                .timed_events
                .next()
                .is_some_and(|deadline| deadline <= Instant::now())
            {
                break;
            }
            let key = self.timed_events.pop().unwrap();
            match key {
                TimedEventKey::RemoveExpectingLoginRequest(exchange) => {
                    if self
                        .expecting_login_requests
                        .get(&exchange.attempt)
                        .is_some_and(|pending| pending.generation == exchange.generation)
                    {
                        self.expecting_login_requests.remove(&exchange.attempt);
                    }
                }
                TimedEventKey::RemoveAnsweredLogin(exchange) => {
                    if self
                        .answered_logins
                        .get(&exchange.attempt)
                        .is_some_and(|answer| answer.exchange == exchange)
                    {
                        self.answered_logins.remove(&exchange.attempt);
                    }
                }
                TimedEventKey::Connection(addr) => self.handle_event_connection(addr, budget),
                TimedEventKey::PruneRateLimits => {
                    let now = Instant::now();
                    self.client_hellos.prune(now);
                    self.connection_requests.prune(now);
                }
            }
        }
    }

    fn handle_event_connection(&mut self, addr: SocketAddr, budget: &mut DeliveryBudget) {
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
        self.service(addr, now, budget);
    }

    fn handle_all_recvs(&mut self, budget: &mut DeliveryBudget) -> Result<(), io::Error> {
        self.receive_pending = true;
        for _ in 0..128 {
            let Some((size, from)) = self.socket.recv_from(&mut self.buf)? else {
                self.receive_pending = false;
                break;
            };
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
                    continue;
                }
                PacketIdentifier::InfoRequest => self.handle_packet_info_request(size, from),
                PacketIdentifier::ClientHello => self.handle_packet_client_hello(size, from),
                PacketIdentifier::ConnectionRequest => {
                    self.handle_packet_connection_request(size, from)
                }
                PacketIdentifier::LoginRequest => self.handle_packet_login_request(size, from),
                PacketIdentifier::Data | PacketIdentifier::DataAckNow => {
                    self.handle_packet_data(size, from, budget)
                }
                _ => continue,
            }
        }
        self.service_dirty(budget);
        Ok(())
    }

    fn handle_packet_data(&mut self, size: usize, from: SocketAddr, budget: &mut DeliveryBudget) {
        let Some(peer) = self.connections.get_mut(&from) else {
            return;
        };
        let now = Instant::now();
        // Closed by us (kicked, shutdown): the app hears nothing more about it.
        let closing = peer.connection.is_closing();
        let handled = peer.connection.handle_with_budget(
            now,
            &mut self.buf[..size],
            budget,
            &mut self.outputs,
        );
        if let Err(error) = handled {
            rejected("DATA", from, error);
            return;
        }
        if peer.connection.has_pending_delivery() {
            self.delivery_ready.push(from);
        }
        self.dirty.push(from);
        self.handle_outputs(from, now, closing, budget);
    }

    fn handle_outputs(
        &mut self,
        from: SocketAddr,
        now: Instant,
        closing: bool,
        budget: &mut DeliveryBudget,
    ) {
        for output in std::mem::take(&mut self.outputs) {
            match output {
                Output::SendResult(cookie, outcome) => {
                    self.event_tx.send(Event::SendResult(from, cookie, outcome))
                }
                Output::Message(channel, message) => {
                    self.event_tx.send(Event::Received(from, channel, message))
                }
                Output::Closed(reason) => {
                    log!(debug, %from, "disconnected by client");
                    // Acknowledges the CLOSE.
                    self.service(from, now, budget);
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

    fn drain_received(&mut self, budget: &mut DeliveryBudget) -> bool {
        let before = (budget.messages, budget.work);
        let count = self.delivery_ready.queue.len().min(128);
        for _ in 0..count {
            if budget.messages == 0 || budget.work == 0 {
                break;
            }
            let addr = self.delivery_ready.pop().unwrap();
            let Some(peer) = self.connections.get_mut(&addr) else {
                continue;
            };
            peer.connection.drain_received(budget, &mut self.outputs);
            peer.connection.take_send_results(budget, &mut self.outputs);
            if peer.connection.has_pending_delivery() {
                self.delivery_ready.push(addr);
            }
            let closing = peer.connection.is_closing();
            self.handle_outputs(addr, Instant::now(), closing, budget);
            self.dirty.push(addr);
        }
        before != (budget.messages, budget.work)
    }

    /// Updates the clients the app can send to (`Server::connections`), before the event that
    /// tells it.
    fn set_connected(&self, addr: SocketAddr, rate: Option<Arc<PeerState>>) {
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

    /// The keys and LoginRequest hash of the authenticated attempt, `None` if it is gone or the
    /// server is shutting down.
    fn take_auth(&mut self, exchange: Exchange) -> Option<(Crypto, [u8; 32])> {
        let pending = self.expecting_auth_result.get(&exchange.attempt)?;
        if pending.generation != exchange.generation {
            return None;
        }
        let pending = self.expecting_auth_result.remove(&exchange.attempt)?;
        (!self.shutting_down).then(|| (pending.crypto, pending.login_request.unwrap()))
    }

    fn handle_cmd_auth_success(&mut self, exchange: Exchange, auth_result: R) {
        let attempt = exchange.attempt;
        let Some((crypto, request)) = self.take_auth(exchange) else {
            return;
        };
        // The server filled up while authenticating.
        if self.is_full_for(attempt.0) {
            log!(debug, from = %attempt.0, "server full after login");
            self.refuse_login(exchange, request, &crypto, b"Server full");
            return;
        }
        let from = attempt.0;
        let size = LoginResponse::Success.serialize(&crypto, &mut self.buf);
        let shared = Arc::new(PeerState {
            rate: AtomicU64::new(0),
            admission: Admission::new(self.send_queue_limits),
        });
        // The connection is inserted before the next command, so sends can go to it as soon as
        // the client is connected.
        self.set_connected(from, Some(shared.clone()));
        self.answer_login(exchange, request, size);
        let peer = Peer {
            connection: Connection::new(crypto, &self.config, Instant::now()),
            shared,
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

    fn handle_cmd_auth_failure(&mut self, exchange: Exchange, failure_data: Vec<u8>) {
        let Some((crypto, request)) = self.take_auth(exchange) else {
            return;
        };
        log!(debug, from = %exchange.attempt.0, "login denied");
        self.refuse_login(exchange, request, &crypto, &failure_data);
    }

    fn refuse_login(
        &mut self,
        exchange: Exchange,
        request: [u8; 32],
        crypto: &Crypto,
        failure_data: &[u8],
    ) {
        let size = LoginResponse::Failure { failure_data }.serialize(crypto, &mut self.buf);
        self.answer_login(exchange, request, size);
    }

    /// Sends the LoginResponse in `buf` and keeps it for retransmitted LoginRequests.
    fn answer_login(&mut self, exchange: Exchange, request: [u8; 32], size: usize) {
        self.socket.send_to(exchange.attempt.0, &self.buf[..size]);
        self.answered_logins.insert(
            exchange.attempt,
            AnsweredLogin {
                exchange,
                request,
                response: self.buf[..size].to_vec(),
            },
        );
        self.timed_events.push(
            TimedEventKey::RemoveAnsweredLogin(exchange),
            Instant::now() + HANDSHAKE_STATE_TTL,
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
                    server_ed25519_pubkey: self.verifying_key,
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
        let request: [u8; 116] = self.buf[connection_response::SIGNED_REQUEST]
            .try_into()
            .unwrap();
        if self.answered_logins.contains_key(&attempt) {
            return;
        }
        if let Some(pending) = self
            .expecting_login_requests
            .get(&attempt)
            .or_else(|| self.expecting_auth_result.get(&attempt))
        {
            // A retransmission must get the same keys, a different request is ignored.
            if pending.request == request {
                self.socket.send_to(from, &pending.response);
            }
            return;
        }
        if self.exchanging.contains_key(&attempt) {
            return;
        }
        // Each new request costs a key exchange and a signature.
        let now = Instant::now();
        if !self.connection_requests.allow(from.ip(), now) {
            log!(debug, %from, "rate-limited key exchange");
            return;
        }
        self.schedule_rate_limit_prune(now);
        let exchange = KeyExchange {
            attempt,
            request,
            client_x25519_pubkey: connection_request.client_x25519_pubkey,
            hkdf_salt: connection_request.hkdf_salt,
        };
        if self.key_exchanges.try_send(exchange).is_err() {
            log!(warn, %from, "handshake thread busy, key exchange dropped");
            return;
        }
        log!(debug, %from, "key exchange");
        self.exchanging.insert(attempt, request);
    }

    fn handle_key_exchanges(&mut self) {
        for _ in 0..256 {
            let Ok(exchanged) = self.key_exchanged.try_recv() else {
                return;
            };
            let attempt = exchanged.attempt;
            self.exchanging.remove(&attempt);
            if self.shutting_down {
                continue;
            }
            self.socket.send_to(attempt.0, &exchanged.response);
            let generation = self.next_generation;
            let Some(next) = generation.checked_add(1) else {
                continue;
            };
            self.next_generation = next;
            self.expecting_login_requests.insert(
                attempt,
                PendingLogin {
                    crypto: exchanged.crypto,
                    generation,
                    request: exchanged.request,
                    response: exchanged.response,
                    login_request: None,
                },
            );
            self.timed_events.push(
                TimedEventKey::RemoveExpectingLoginRequest(Exchange {
                    attempt,
                    generation,
                }),
                Instant::now() + HANDSHAKE_STATE_TTL,
            );
        }
    }

    fn handle_packet_login_request(&mut self, size: usize, from: SocketAddr) {
        let Some(salt) = LoginRequest::deserialize_salt(&self.buf[..size]) else {
            return;
        };
        let attempt = (from, salt);
        let request: [u8; 32] = Sha256::digest(&self.buf[..size]).into();
        if let Some(answer) = self.answered_logins.get(&attempt) {
            if answer.request == request {
                self.socket.send_to(from, &answer.response);
            }
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
        let exchange = Exchange {
            attempt,
            generation: pending.generation,
        };
        let auth_cmd = AuthCmd::Authenticate(exchange, login_request.auth_data.to_vec());
        let mut pending = self.expecting_login_requests.remove(&attempt).unwrap();
        pending.login_request = Some(request);
        self.timed_events
            .remove(&TimedEventKey::RemoveExpectingLoginRequest(exchange));
        if self.auth_cmd_tx.try_send(auth_cmd).is_err() {
            log!(warn, %from, "authenticator busy, login refused");
            self.refuse_login(exchange, request, &pending.crypto, b"Server busy");
            return;
        }
        log!(debug, %from, "authenticating");
        self.expecting_auth_result.insert(attempt, pending);
    }
}

#[cfg(test)]
mod tests {
    use std::{net::UdpSocket, sync::mpsc};

    use x25519_dalek::{PublicKey, ReusableSecret};

    use super::*;
    use crate::common::packets::connection_response::{ConnectionResponse, Transcript};
    use crate::{Authenticator, ChannelConfiguration, Server};

    struct PausedAuth {
        entered: mpsc::Sender<Vec<u8>>,
        release: mpsc::Receiver<()>,
    }

    impl Authenticator<Vec<u8>> for PausedAuth {
        fn authenticate(&mut self, _: SocketAddr, data: Vec<u8>) -> Result<Vec<u8>, Vec<u8>> {
            self.entered.send(data.clone()).unwrap();
            self.release.recv_timeout(Duration::from_secs(3)).unwrap();
            Ok(data)
        }
    }

    fn receive(socket: &UdpSocket) -> Vec<u8> {
        let mut buffer = [0; 1201];
        let size = socket.recv(&mut buffer).unwrap();
        buffer[..size].to_vec()
    }

    fn assert_no_reply(socket: &UdpSocket) {
        socket
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let error = socket.recv(&mut [0; 1201]).unwrap_err();
        assert!(matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ));
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
    }

    #[test]
    fn delayed_authentication_keeps_its_original_exchange_and_cached_reply() {
        let (entered_tx, entered) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        let channels = ChannelConfiguration::default();
        let server = Server::prepare()
            .bind_addr("127.0.0.1:0".parse().unwrap())
            .info(vec![])
            .allowed_client_versions(|_| Ok(()))
            .secret_key([7; 32])
            .auth_salt([0; 16])
            .authenticator(PausedAuth {
                entered: entered_tx,
                release: release_rx,
            })
            .channel_config(channels.clone())
            .close_linger(Duration::ZERO)
            .run()
            .unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.connect(server.local_addr()).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let salt = [3, 4, 5, 6];
        let mut buffer = [0; 1200];
        let size = ClientHello {
            salt,
            client_version: ClientVersion::ZERO,
        }
        .serialize(&mut buffer);
        socket.send(&buffer[..size]).unwrap();
        let ServerHello::VersionSupported {
            timestamp,
            cipher,
            server_ed25519_pubkey,
            siphash,
            channel_counts,
            ..
        } = ServerHello::deserialize(&receive(&socket)).unwrap()
        else {
            panic!("hello refused")
        };
        let secret = ReusableSecret::random_from_rng(&mut rand::rng());
        let hkdf_salt = [8; 32];
        let mut request = ConnectionRequest {
            salt,
            timestamp,
            server_ed25519_pubkey,
            siphash: siphash.unwrap().to_le_bytes(),
            client_x25519_pubkey: PublicKey::from(&secret),
            hkdf_salt,
        };
        let size = request.serialize(&mut buffer);
        let request_bytes = buffer[..size].to_vec();
        socket.send(&request_bytes).unwrap();
        let response = receive(&socket);
        let (_, crypto) = ConnectionResponse::deserialize(
            &response,
            server_ed25519_pubkey,
            &secret,
            hkdf_salt,
            &Transcript {
                request: &request_bytes[connection_response::SIGNED_REQUEST],
                cipher,
                channel_counts,
            },
        )
        .unwrap();
        let size = LoginRequest {
            salt,
            auth_data: b"account",
        }
        .serialize(&crypto, &mut buffer);
        let login = buffer[..size].to_vec();
        socket.send(&login).unwrap();
        assert_eq!(
            entered.recv_timeout(Duration::from_secs(3)).unwrap(),
            b"account"
        );

        socket.send(&request_bytes).unwrap();
        assert_eq!(receive(&socket), response);
        request.hkdf_salt = [9; 32];
        let size = request.serialize(&mut buffer);
        socket.send(&buffer[..size]).unwrap();
        assert_no_reply(&socket);
        request.client_x25519_pubkey =
            PublicKey::from(&ReusableSecret::random_from_rng(&mut rand::rng()));
        let size = request.serialize(&mut buffer);
        socket.send(&buffer[..size]).unwrap();
        assert_no_reply(&socket);
        socket.send(&login).unwrap();
        assert_no_reply(&socket);
        assert!(entered.try_recv().is_err());

        release.send(()).unwrap();
        let success = receive(&socket);
        assert!(matches!(
            LoginResponse::deserialize(&crypto, &mut success.clone()),
            Ok(LoginResponse::Success)
        ));
        assert!(matches!(server.next().unwrap(), Event::Connected(_, data) if data == b"account"));
        socket.send(&login).unwrap();
        assert_eq!(receive(&socket), success);
        let mut changed_login = login;
        changed_login[7] ^= 1;
        socket.send(&changed_login).unwrap();
        assert_no_reply(&socket);

        let mut connection = Connection::new(
            crypto,
            &transport::Config {
                channels,
                congestion: Default::default(),
                max_recv_msg_size: 1 << 20,
                timeout: Duration::from_secs(10),
            },
            Instant::now(),
        );
        connection.push(
            Channel::Reliable(0),
            Rc::new(b"bound session".to_vec()),
            Instant::now(),
        );
        let size = connection
            .poll_transmit(Instant::now(), &mut buffer)
            .unwrap();
        socket.send(&buffer[..size]).unwrap();
        assert!(
            matches!(server.next().unwrap(), Event::Received(_, Channel::Reliable(0), data) if data == b"bound session")
        );
    }

    #[test]
    fn ready_connections_are_unique_and_keep_fifo_continuation() {
        let first = "127.0.0.1:1".parse().unwrap();
        let second = "127.0.0.1:2".parse().unwrap();
        let mut queue = ReadyQueue::default();
        for _ in 0..1024 {
            queue.push(first);
            queue.push(second);
        }
        assert_eq!(queue.queue.len(), 2);
        assert_eq!(queue.pop(), Some(first));
        queue.push(first);
        assert_eq!(queue.pop(), Some(second));
        assert_eq!(queue.pop(), Some(first));
        assert!(queue.is_empty());
    }
}
