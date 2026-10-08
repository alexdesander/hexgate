// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! One run: a fresh server and client on a simulated connection, the workload's traffic, and
//! every message's send and arrival time.

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex, OnceLock, PoisonError},
    thread::JoinHandle,
    time::{Duration, Instant},
};

use crossbeam_channel::{Receiver, Sender, unbounded};
use hexgate::{
    Authenticator, Channel, Client, ClientVersion, Server, ServerKey, Stats, client,
    error::SendError,
    server,
    sim::{LinkStats, Profile, Simulator},
};
use rand::{Rng, SeedableRng};
use rand_distr::{Distribution, Exp1};
use rand_xoshiro::Xoshiro256PlusPlus;

use crate::workloads::{CONTROL, Dir, Pattern, Workload, channel_config};

const SECRET_KEY: [u8; 32] = [7; 32];
const HEADER: usize = 13;
/// Stream id of the end-of-run marker.
const STOP: u8 = u8::MAX;
/// hexgate's default maximum send rate, the "link rate" of unlimited links.
const UNLIMITED_RATE: f64 = 10_000.0 * 1024.0;
/// How often `Bulk` streams check hexgate's queue.
const BULK_CHECK: Duration = Duration::from_millis(1);
/// An unanswered ping is resent after this.
const PING_TIMEOUT: Duration = Duration::from_secs(1);
/// Drain ends early after this long without arrivals (and with all reliable messages there).
const QUIET: Duration = Duration::from_millis(300);

pub struct Settings {
    pub duration: Duration,
    pub drain: Duration,
    pub seed: u64,
}

#[derive(Clone, Copy)]
pub struct Arrival {
    pub seq: u32,
    pub sent_us: u64,
    pub recv_us: u64,
    pub len: u32,
}

#[derive(Default)]
pub struct StreamRecord {
    pub sent: u64,
    pub sent_bytes: u64,
    pub backpressured: u64,
    pub arrivals: Vec<Arrival>,
    pub corrupt: u64,
}

pub struct RawRun {
    pub connect: Result<Duration, String>,
    /// Why the connection ended before the run did.
    pub ended: Option<String>,
    /// The send phase, in µs since the bench started.
    pub start_us: u64,
    pub end_us: u64,
    pub streams: Vec<StreamRecord>,
    pub client_stats: Option<Stats>,
    pub server_stats: Option<Stats>,
    pub up: LinkStats,
    pub down: LinkStats,
}

pub fn now_us() -> u64 {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    EPOCH.get_or_init(Instant::now).elapsed().as_micros() as u64
}

struct AcceptAll;

impl Authenticator<()> for AcceptAll {
    fn authenticate(&mut self, _: SocketAddr, _: Vec<u8>) -> Result<(), Vec<u8>> {
        Ok(())
    }
}

/// `[stream][seq: u32][sent: u64 µs]`, then a fill derived from `seq` that the receiver checks.
fn message(stream: u8, seq: u32, size: usize) -> Vec<u8> {
    let mut message = Vec::with_capacity(size.max(HEADER));
    message.push(stream);
    message.extend_from_slice(&seq.to_le_bytes());
    message.extend_from_slice(&now_us().to_le_bytes());
    message.extend((HEADER..size).map(|i| fill(seq, i)));
    message
}

fn fill(seq: u32, i: usize) -> u8 {
    (seq as u8).wrapping_add(i as u8)
}

struct Header {
    stream: u8,
    seq: u32,
    sent_us: u64,
}

fn parse(message: &[u8]) -> Option<Header> {
    let header = message.get(..HEADER)?;
    Some(Header {
        stream: header[0],
        seq: u32::from_le_bytes(header[1..5].try_into().ok()?),
        sent_us: u64::from_le_bytes(header[5..13].try_into().ok()?),
    })
}

/// What one side's receiver thread saw.
#[derive(Default)]
struct Received {
    streams: Vec<StreamRecord>,
    ended: Option<String>,
}

type Shared = Arc<Mutex<Received>>;

fn lock(shared: &Shared) -> std::sync::MutexGuard<'_, Received> {
    shared.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Received {
    fn new(streams: usize) -> Shared {
        Arc::new(Mutex::new(Self {
            streams: (0..streams).map(|_| StreamRecord::default()).collect(),
            ended: None,
        }))
    }

    /// Returns the stream id, `None` for the end marker or garbage.
    fn record(&mut self, message: &[u8]) -> Option<u8> {
        let recv_us = now_us();
        let header = parse(message)?;
        let record = self.streams.get_mut(header.stream as usize)?;
        if message[HEADER..]
            .iter()
            .enumerate()
            .any(|(i, &byte)| byte != fill(header.seq, HEADER + i))
        {
            record.corrupt += 1;
            return Some(header.stream);
        }
        record.arrivals.push(Arrival {
            seq: header.seq,
            sent_us: header.sent_us,
            recv_us,
            len: message.len() as u32,
        });
        Some(header.stream)
    }
}

fn server_receiver(
    server: Server<()>,
    workload: Workload,
    shared: Shared,
    addr_tx: Sender<SocketAddr>,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        loop {
            let ended = match server.next() {
                Ok(server::Event::Connected(addr, ())) => {
                    let _ = addr_tx.send(addr);
                    continue;
                }
                Ok(server::Event::Received(from, _, message)) => {
                    let stream = parse(&message).map(|header| header.stream);
                    if stream == Some(STOP) {
                        return;
                    }
                    let spec = stream.and_then(|stream| workload.streams.get(stream as usize));
                    if let Some(spec) =
                        spec.filter(|spec| matches!(spec.pattern, Pattern::PingPong { .. }))
                    {
                        let _ = server.send(from, spec.channel, message);
                    } else {
                        lock(&shared).record(&message);
                    }
                    continue;
                }
                Ok(event) => format!("server: {event:?}"),
                Err(e) => format!("server: {e}"),
            };
            lock(&shared).ended.get_or_insert(ended);
            return;
        }
    })
}

/// Reports the arrivals of ping streams (`pings[stream]`) to `pong_tx`.
fn client_receiver(
    client: Client,
    shared: Shared,
    pings: Vec<bool>,
    pong_tx: Sender<u8>,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        loop {
            let ended = match client.next() {
                Ok(client::Event::Received(_, message)) => {
                    if parse(&message).is_some_and(|header| header.stream == STOP) {
                        return;
                    }
                    let stream = lock(&shared).record(&message);
                    if let Some(stream) = stream.filter(|&stream| pings[stream as usize]) {
                        let _ = pong_tx.send(stream);
                    }
                    continue;
                }
                Ok(event) => format!("client: {event:?}"),
                Err(e) => format!("client: {e}"),
            };
            lock(&shared).ended.get_or_insert(ended);
            return;
        }
    })
}

/// A stream's sending state.
struct StreamState {
    seq: u32,
    next_at: Instant,
    gap: Option<Duration>,
    rng: Xoshiro256PlusPlus,
    /// When the ping in flight was sent.
    ping: Option<Instant>,
    sent: u64,
    sent_bytes: u64,
    backpressured: u64,
}

struct Endpoints<'a> {
    client: &'a Client,
    server: &'a Server<()>,
    addr: SocketAddr,
}

impl Endpoints<'_> {
    fn send(&self, dir: Dir, channel: Channel, message: Vec<u8>) -> Result<(), SendError> {
        match dir {
            Dir::Up => self.client.send(channel, message),
            Dir::Down => self.server.send(self.addr, channel, message),
        }
    }

    fn queued(&self, dir: Dir) -> Option<usize> {
        let stats = match dir {
            Dir::Up => self.client.stats(),
            Dir::Down => self.server.stats(self.addr),
        };
        stats.map(|stats| stats.queued_bytes)
    }
}

/// Average rate of a link in bytes per second.
fn link_rate(profile: &Profile, dir: Dir) -> f64 {
    let link = match dir {
        Dir::Up => &profile.up,
        Dir::Down => &profile.down,
    };
    link.bottleneck
        .as_ref()
        .map_or(UNLIMITED_RATE, |bottleneck| {
            let total: Duration = bottleneck.rates.iter().map(|(duration, _)| *duration).sum();
            bottleneck
                .rates
                .iter()
                .map(|(duration, rate)| duration.as_secs_f64() * *rate as f64)
                .sum::<f64>()
                / total.as_secs_f64()
        })
}

pub fn run(workload: &Workload, profile: &Profile, settings: &Settings) -> RawRun {
    let streams = workload.streams.len();
    let server_side = Received::new(streams);
    let client_side = Received::new(streams);
    let (up, down) = profile.links(settings.seed);
    let mut raw = RawRun {
        connect: Err(String::new()),
        ended: None,
        start_us: 0,
        end_us: 0,
        streams: Vec::new(),
        client_stats: None,
        server_stats: None,
        up: LinkStats::default(),
        down: LinkStats::default(),
    };

    let server = Server::prepare()
        .bind_addr("127.0.0.1:0".parse().unwrap())
        .info(vec![])
        .allowed_client_versions(|_| Ok(()))
        .secret_key(SECRET_KEY)
        .auth_salt([0; 16])
        .authenticator(AcceptAll)
        .channel_config(channel_config())
        .run()
        .expect("server start");
    let (addr_tx, addr_rx) = unbounded();
    let server_thread = server_receiver(
        server.clone(),
        workload.clone(),
        server_side.clone(),
        addr_tx,
    );

    let connect_start = Instant::now();
    let client = Client::prepare()
        .client_version(ClientVersion::ZERO)
        .server_socket_addr(server.local_addr())
        .server_key(ServerKey::Pinned(server::public_key(&SECRET_KEY)))
        .auth_data(vec![])
        .hash_auth_data(false)
        .channel_config(channel_config())
        .simulator(Simulator::new(up.clone(), down.clone()))
        .connect();
    let client = match client {
        Ok(client) => client,
        Err(e) => {
            raw.connect = Err(e.to_string());
            return raw;
        }
    };
    raw.connect = Ok(connect_start.elapsed());
    let Ok(addr) = addr_rx.recv_timeout(Duration::from_secs(10)) else {
        raw.ended = Some("server never reported the client".into());
        return raw;
    };
    let (pong_tx, pong_rx) = unbounded();
    let pings = workload
        .streams
        .iter()
        .map(|spec| matches!(spec.pattern, Pattern::PingPong { .. }))
        .collect();
    let client_thread = client_receiver(client.clone(), client_side.clone(), pings, pong_tx);
    let endpoints = Endpoints {
        client: &client,
        server: &server,
        addr,
    };

    raw.start_us = now_us();
    let senders = send_phase(workload, profile, settings, &endpoints, &pong_rx);
    raw.end_us = now_us();
    raw.client_stats = client.stats();
    raw.server_stats = server.stats(addr);

    drain(
        workload,
        &senders,
        &server_side,
        &client_side,
        settings.drain,
    );
    raw.up = up.stats();
    raw.down = down.stats();

    // End both receivers through a clean link.
    client.set_simulator(Simulator::default()).unwrap();
    let _ = client.send(CONTROL, message(STOP, 0, HEADER));
    let _ = server.send(addr, CONTROL, message(STOP, 0, HEADER));
    let deadline = Instant::now() + Duration::from_secs(5);
    while !(server_thread.is_finished() && client_thread.is_finished()) && Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(5));
    }
    if !server_thread.is_finished() || !client_thread.is_finished() {
        let _ = server.disconnect(addr, vec![]);
    }

    let mut server_side = std::mem::take(&mut *lock(&server_side));
    let mut client_side = std::mem::take(&mut *lock(&client_side));
    raw.ended = server_side.ended.take().or(client_side.ended.take());
    raw.streams = workload
        .streams
        .iter()
        .zip(senders)
        .enumerate()
        .map(|(i, (spec, sender))| {
            let at_client =
                spec.dir == Dir::Down || matches!(spec.pattern, Pattern::PingPong { .. });
            let side = if at_client {
                &mut client_side
            } else {
                &mut server_side
            };
            let mut record = std::mem::take(&mut side.streams[i]);
            record.sent = sender.sent;
            record.sent_bytes = sender.sent_bytes;
            record.backpressured = sender.backpressured;
            record
        })
        .collect();
    raw
}

fn send_phase(
    workload: &Workload,
    profile: &Profile,
    settings: &Settings,
    endpoints: &Endpoints,
    pong_rx: &Receiver<u8>,
) -> Vec<StreamState> {
    let start = Instant::now();
    let end = start + settings.duration;
    let mut senders: Vec<StreamState> = workload
        .streams
        .iter()
        .enumerate()
        .map(|(i, spec)| {
            let mut rng = Xoshiro256PlusPlus::seed_from_u64(settings.seed ^ ((i as u64 + 1) << 32));
            let gap = match spec.pattern {
                Pattern::Periodic { hz, .. } => Some(Duration::from_secs_f64(1.0 / hz)),
                Pattern::Overload { factor, size } => Some(Duration::from_secs_f64(
                    size as f64 / (factor * link_rate(profile, spec.dir)),
                )),
                Pattern::Bursts { every, .. } => Some(every),
                _ => None,
            };
            // Ticks of different streams don't line up.
            let phase = gap.map_or(Duration::ZERO, |gap| gap.mul_f64(rng.r#gen()));
            StreamState {
                seq: 0,
                next_at: start + phase,
                gap,
                rng,
                ping: None,
                sent: 0,
                sent_bytes: 0,
                backpressured: 0,
            }
        })
        .collect();

    loop {
        let now = Instant::now();
        if now >= end {
            break;
        }
        for pong in pong_rx.try_iter() {
            if let Some(sender) = senders.get_mut(pong as usize) {
                sender.ping = None;
            }
        }
        let mut alive = true;
        for (i, (spec, sender)) in workload.streams.iter().zip(&mut senders).enumerate() {
            let mut send = |sender: &mut StreamState, size: usize| {
                let message = message(i as u8, sender.seq, size);
                match endpoints.send(spec.dir, spec.channel, message) {
                    Ok(()) => {
                        sender.seq += 1;
                        sender.sent += 1;
                        sender.sent_bytes += size as u64;
                    }
                    Err(SendError::Backpressure) => sender.backpressured += 1,
                    Err(_) => alive = false,
                }
            };
            match spec.pattern {
                Pattern::Periodic { size, .. } => {
                    while sender.next_at <= now {
                        let size = size.sample(sender.seq, &mut sender.rng);
                        send(sender, size);
                        sender.next_at += sender.gap.unwrap();
                    }
                }
                Pattern::Overload { size, .. } => {
                    while sender.next_at <= now {
                        send(sender, size);
                        sender.next_at += sender.gap.unwrap();
                    }
                }
                Pattern::Random { mean_gap, size } => {
                    while sender.next_at <= now {
                        let size = size.sample(sender.seq, &mut sender.rng);
                        send(sender, size);
                        let gap: f64 = Exp1.sample(&mut sender.rng);
                        sender.next_at += mean_gap.mul_f64(gap);
                    }
                }
                Pattern::Bursts { count, size, .. } => {
                    if sender.next_at <= now {
                        for _ in 0..count {
                            send(sender, size);
                        }
                        sender.next_at += sender.gap.unwrap();
                    }
                }
                Pattern::Bulk { size, max_queued } => {
                    if sender.next_at <= now {
                        let mut queued = endpoints.queued(spec.dir).unwrap_or(usize::MAX);
                        while queued < max_queued {
                            send(sender, size);
                            queued += size;
                        }
                        sender.next_at = now + BULK_CHECK;
                    }
                }
                Pattern::PingPong { size } => {
                    if sender.ping.is_none_or(|ping| now - ping >= PING_TIMEOUT) {
                        send(sender, size);
                        sender.ping = Some(now);
                        sender.next_at = now + PING_TIMEOUT;
                    }
                }
            }
        }
        if !alive {
            break;
        }
        let next = senders
            .iter()
            .map(|sender| sender.next_at)
            .min()
            .unwrap_or(end)
            .min(end);
        // A pong ends the wait early, it is handled in the next round.
        if let Ok(pong) = pong_rx.recv_timeout(next.saturating_duration_since(Instant::now())) {
            if let Some(sender) = senders.get_mut(pong as usize) {
                sender.ping = None;
            }
        }
    }
    senders
}

/// Waits until every reliable message has arrived and nothing else does, at most `max`.
fn drain(
    workload: &Workload,
    senders: &[StreamState],
    server_side: &Shared,
    client_side: &Shared,
    max: Duration,
) {
    let deadline = Instant::now() + max;
    let mut last_count = 0;
    let mut last_change = Instant::now();
    while Instant::now() < deadline {
        let (server_side, client_side) = (lock(server_side), lock(client_side));
        if server_side.ended.is_some() || client_side.ended.is_some() {
            return;
        }
        let mut count = 0;
        let mut complete = true;
        for (i, (spec, sender)) in workload.streams.iter().zip(senders).enumerate() {
            let side = match spec.dir {
                Dir::Down => &client_side,
                Dir::Up if matches!(spec.pattern, Pattern::PingPong { .. }) => &client_side,
                Dir::Up => &server_side,
            };
            let arrived = side.streams[i].arrivals.len();
            count += arrived;
            if matches!(spec.channel, Channel::Reliable(_))
                && !matches!(spec.pattern, Pattern::PingPong { .. })
            {
                complete &= arrived as u64 >= sender.sent;
            }
        }
        drop((server_side, client_side));
        if count != last_count {
            last_count = count;
            last_change = Instant::now();
        }
        if complete && last_change.elapsed() >= QUIET {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
