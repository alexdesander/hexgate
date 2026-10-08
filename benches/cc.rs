// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The congestion controller in virtual time: connections exchange packets through simulated
//! links without sockets or threads, so a minute of traffic takes about a second. For tuning;
//! `benches/network` measures the real thing.
//!
//! Tune on `perfect`, `good`, `average`, `clean`, `step` and `narrow`: a change must not regress
//! there. `bad`, `terrible`, `jitter` and `reverse` are robustness checks: a change only has to
//! avoid stalls and collapse there, and must not be made for their sake.
//!
//! ```text
//! cargo bench --features bench --bench cc -- [--seconds N] [--drain N] [--seed N] [--seeds N] [--trace]
//!     [--scenario NAME,..] [--profile NAME,..]
//! ```
//!
//! `--seeds N` reports each seed, means and worst tails. `--trace` prints the server's
//! (`TRACE_SIDE=client`: the client's) statistics of every pair every 250 ms (`TRACE_MS`).
//!
//! Besides delivery, goodput and latency percentiles, each run reports blackouts (gaps of a
//! periodic stream over its interval plus 100 ms), burst completion times (send to the last
//! message of a burst), expired unreliable messages, the peak heap of the connections and
//! simulator, and the CPU time per simulated second. Scenarios with more than 8 flows report
//! each stream name over all flows.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    net::SocketAddr,
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};

use hexgate::{
    Channel, ChannelConfiguration, CongestionConfig,
    bench::{Delivery, Pairs, Side},
    sim::{
        Bottleneck, Fate, Jitter, JitterDistribution, Link, LinkConfig, LinkStats,
        NetworkSimulator, Profile,
    },
};
use rand::{Rng, SeedableRng};
use rand_xoshiro::Xoshiro256PlusPlus;

const HEADER: usize = 14;
const KIB: usize = 1024;
/// A periodic stream with no arrival for its interval plus this long has a blackout.
const BLACKOUT: Duration = Duration::from_millis(100);
/// Scenarios with more flows report each stream name over all flows.
const MAX_LISTED_FLOWS: usize = 8;

// ---- Heap accounting ----------------------------------------

struct Counting;

static HEAP: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn allocated(size: usize) {
    let now = HEAP.fetch_add(size, Ordering::Relaxed) + size;
    PEAK.fetch_max(now, Ordering::Relaxed);
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            allocated(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        HEAP.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new = unsafe { System.realloc(ptr, layout, new_size) };
        if !new.is_null() {
            HEAP.fetch_sub(layout.size(), Ordering::Relaxed);
            allocated(new_size);
        }
        new
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// Starts a peak measurement, returns the current heap size.
fn reset_peak() -> usize {
    let now = HEAP.load(Ordering::Relaxed);
    PEAK.store(now, Ordering::Relaxed);
    now
}

// ---- Scenarios ----------------------------------------------

#[derive(Clone, Copy)]
enum Kind {
    /// Reliable messages of this size, keeping `queued` bytes waiting.
    Bulk { size: usize, queued: usize },
    /// Messages at a tick rate, sizes uniform in the range.
    Periodic { hz: f64, min: usize, max: usize },
    /// A tick of several messages (size ranges), then `flush()`.
    Tick {
        hz: f64,
        sizes: &'static [(usize, usize)],
    },
    /// One message in flight, echoed by the server: round trips.
    PingPong { size: usize },
    /// `count` reliable messages at once, every `every`.
    Burst {
        every: Duration,
        count: usize,
        size: usize,
    },
}

#[derive(Clone, Copy)]
struct StreamSpec {
    name: &'static str,
    from: Side,
    channel: Channel,
    kind: Kind,
    /// Starts this long after its flow.
    offset: Duration,
}

struct Scenario {
    name: &'static str,
    about: &'static str,
    /// Connections sharing the bottleneck, started this far apart.
    flows: usize,
    stagger: Duration,
    streams: &'static [StreamSpec],
    /// Added one-way delay in ms of each flow, repeated over the flows.
    delays: &'static [u64],
    /// Every flow gets its own links instead of sharing the bottleneck.
    independent: bool,
}

const SCENARIO: Scenario = Scenario {
    name: "",
    about: "",
    flows: 1,
    stagger: Duration::ZERO,
    streams: &[],
    delays: &[],
    independent: false,
};

const SNAPSHOTS: StreamSpec = StreamSpec {
    name: "snapshots",
    from: Side::Server,
    channel: Channel::UnreliableOrdered(0),
    kind: Kind::Periodic {
        hz: 64.0,
        min: 300,
        max: 1100,
    },
    offset: Duration::ZERO,
};
const INPUTS: StreamSpec = StreamSpec {
    name: "inputs",
    from: Side::Client,
    channel: Channel::UnreliableOrdered(0),
    kind: Kind::Periodic {
        hz: 64.0,
        min: 48,
        max: 80,
    },
    offset: Duration::ZERO,
};
const UPLOAD: StreamSpec = StreamSpec {
    name: "upload",
    from: Side::Client,
    channel: Channel::Reliable(0),
    kind: Kind::Bulk {
        size: 64 * KIB,
        queued: 1024 * KIB,
    },
    offset: Duration::ZERO,
};
const PINGS: [StreamSpec; 2] = [
    StreamSpec {
        name: "ping rel",
        from: Side::Client,
        channel: Channel::Reliable(0),
        kind: Kind::PingPong { size: 64 },
        offset: Duration::ZERO,
    },
    StreamSpec {
        name: "ping unrel",
        from: Side::Client,
        channel: Channel::Unreliable,
        kind: Kind::PingPong { size: 64 },
        offset: Duration::ZERO,
    },
];
const TICKS: StreamSpec = StreamSpec {
    name: "ticks",
    from: Side::Server,
    channel: Channel::UnreliableOrdered(0),
    kind: Kind::Tick {
        hz: 30.0,
        sizes: &[(800, 1100), (800, 1100), (50, 200), (50, 200)],
    },
    offset: Duration::ZERO,
};
const IDLE_BURSTS: StreamSpec = StreamSpec {
    name: "burst",
    from: Side::Server,
    channel: Channel::Reliable(0),
    kind: Kind::Burst {
        every: Duration::from_millis(1500),
        count: 100,
        size: 200,
    },
    offset: Duration::ZERO,
};
const DOWNLOAD: StreamSpec = StreamSpec {
    name: "download",
    from: Side::Server,
    channel: Channel::Reliable(0),
    kind: Kind::Bulk {
        size: 64 * KIB,
        queued: 1024 * KIB,
    },
    offset: Duration::ZERO,
};

const MOBA: [StreamSpec; 2] = [
    StreamSpec {
        name: "updates",
        kind: Kind::Periodic {
            hz: 30.0,
            min: 200,
            max: 800,
        },
        ..SNAPSHOTS
    },
    StreamSpec {
        name: "events",
        kind: Kind::Burst {
            every: Duration::from_millis(250),
            count: 1,
            size: 100,
        },
        ..DOWNLOAD
    },
];

/// Reliable kill feed, hits and round events.
const EVENTS: StreamSpec = StreamSpec {
    name: "events",
    kind: Kind::Burst {
        every: Duration::from_millis(500),
        count: 1,
        size: 200,
    },
    ..DOWNLOAD
};
const FPS: [StreamSpec; 3] = [SNAPSHOTS, INPUTS, EVENTS];

/// Unit orders from the client.
const COMMANDS: StreamSpec = StreamSpec {
    name: "commands",
    kind: Kind::Burst {
        every: Duration::from_millis(200),
        count: 1,
        size: 40,
    },
    ..UPLOAD
};
const MOBA_MIX: [StreamSpec; 3] = [MOBA[0], MOBA[1], COMMANDS];

/// A block game: entity updates, player movement, 512 KiB of chunks every 5 s and block
/// edits.
const SANDBOX: [StreamSpec; 4] = [
    StreamSpec {
        name: "entities",
        kind: Kind::Periodic {
            hz: 20.0,
            min: 100,
            max: 1500,
        },
        ..SNAPSHOTS
    },
    StreamSpec {
        name: "movement",
        kind: Kind::Periodic {
            hz: 20.0,
            min: 40,
            max: 60,
        },
        ..INPUTS
    },
    StreamSpec {
        name: "chunks",
        kind: Kind::Burst {
            every: Duration::from_secs(5),
            count: 32,
            size: 16 * KIB,
        },
        ..DOWNLOAD
    },
    StreamSpec {
        name: "edits",
        kind: Kind::Burst {
            every: Duration::from_secs(1),
            count: 1,
            size: 40,
        },
        ..UPLOAD
    },
];

/// Long app-limited phases: a lobby heartbeat, then a 2 MiB map download every 20 s, the
/// first after 10 s.
const LOBBY: [StreamSpec; 2] = [
    StreamSpec {
        name: "heartbeat",
        channel: Channel::Unreliable,
        kind: Kind::Periodic {
            hz: 2.0,
            min: 64,
            max: 64,
        },
        ..SNAPSHOTS
    },
    StreamSpec {
        name: "map",
        kind: Kind::Burst {
            every: Duration::from_secs(20),
            count: 32,
            size: 64 * KIB,
        },
        offset: Duration::from_secs(10),
        ..DOWNLOAD
    },
];

fn scenarios() -> Vec<Scenario> {
    vec![
        Scenario {
            name: "bulk",
            about: "one reliable download",
            flows: 1,
            stagger: Duration::ZERO,
            streams: &[DOWNLOAD],
            ..SCENARIO
        },
        Scenario {
            name: "game",
            about: "64 Hz snapshots down, inputs up",
            flows: 1,
            stagger: Duration::ZERO,
            streams: &[SNAPSHOTS, INPUTS],
            ..SCENARIO
        },
        Scenario {
            name: "mixed",
            about: "game traffic plus a download on the same connection",
            flows: 1,
            stagger: Duration::ZERO,
            streams: &[SNAPSHOTS, INPUTS, DOWNLOAD],
            ..SCENARIO
        },
        Scenario {
            name: "bidir",
            about: "a download and an upload at once",
            flows: 1,
            stagger: Duration::ZERO,
            streams: &[DOWNLOAD, UPLOAD],
            ..SCENARIO
        },
        Scenario {
            name: "pingpong",
            about: "reliable and unreliable round trips at once",
            flows: 1,
            stagger: Duration::ZERO,
            streams: &PINGS,
            ..SCENARIO
        },
        Scenario {
            name: "ticks",
            about: "30 Hz ticks of 4 messages with flush(), plus inputs",
            flows: 1,
            stagger: Duration::ZERO,
            streams: &[TICKS, INPUTS],
            ..SCENARIO
        },
        Scenario {
            name: "idle",
            about: "100 x 200 B reliable at once every 1.5 s",
            flows: 1,
            stagger: Duration::ZERO,
            streams: &[IDLE_BURSTS],
            ..SCENARIO
        },
        Scenario {
            name: "fair",
            about: "3 downloads sharing the bottleneck, started 5 s apart",
            flows: 3,
            stagger: Duration::from_secs(5),
            streams: &[DOWNLOAD],
            ..SCENARIO
        },
        Scenario {
            name: "crowd",
            about: "game traffic of 3 clients plus one download sharing the bottleneck",
            flows: 4,
            stagger: Duration::ZERO,
            streams: &[SNAPSHOTS, INPUTS],
            ..SCENARIO
        },
        Scenario {
            name: "fair-rtt",
            about: "3 downloads with 0/40/100 ms added RTT sharing the bottleneck",
            flows: 3,
            stagger: Duration::from_secs(5),
            streams: &[DOWNLOAD],
            delays: &[0, 20, 50],
            ..SCENARIO
        },
        Scenario {
            name: "scale",
            about: "32 clients sending snapshots and inputs through a shared bottleneck",
            flows: 32,
            stagger: Duration::ZERO,
            streams: &[SNAPSHOTS, INPUTS],
            ..SCENARIO
        },
        Scenario {
            name: "channels",
            about: "513 channels, each sending one 100-byte message at 10 Hz",
            flows: 1,
            stagger: Duration::ZERO,
            streams: &[],
            ..SCENARIO
        },
        Scenario {
            name: "moba",
            about: "30 Hz updates and reliable events every 250 ms",
            flows: 1,
            stagger: Duration::ZERO,
            streams: &MOBA,
            ..SCENARIO
        },
        Scenario {
            name: "mild",
            about: "64 Hz single-packet snapshots (use narrow profile and --seconds 120)",
            flows: 1,
            stagger: Duration::ZERO,
            streams: &[StreamSpec {
                kind: Kind::Periodic {
                    hz: 64.0,
                    min: 700,
                    max: 700,
                },
                ..SNAPSHOTS
            }],
            ..SCENARIO
        },
        Scenario {
            name: "fps",
            about: "64 Hz snapshots down, inputs up, reliable events every 500 ms",
            streams: &FPS,
            ..SCENARIO
        },
        Scenario {
            name: "moba-mix",
            about: "30 Hz updates, reliable events down and commands up",
            streams: &MOBA_MIX,
            ..SCENARIO
        },
        Scenario {
            name: "sandbox",
            about: "20 Hz entities and movement, 512 KiB chunk bursts every 5 s, block edits",
            streams: &SANDBOX,
            ..SCENARIO
        },
        Scenario {
            name: "lobby",
            about: "2 Hz heartbeat, a 2 MiB map every 20 s from 10 s (use --seconds 60)",
            streams: &LOBBY,
            ..SCENARIO
        },
        Scenario {
            name: "crowd-rtt",
            about: "7 fps clients with 0-100 ms added one-way delay plus one download, shared",
            flows: 8,
            streams: &FPS,
            delays: &[0, 5, 10, 20, 30, 50, 75, 100],
            ..SCENARIO
        },
        Scenario {
            name: "server64",
            about: "64 fps clients, each on its own link",
            flows: 64,
            streams: &FPS,
            independent: true,
            ..SCENARIO
        },
        Scenario {
            name: "server256",
            about: "256 fps clients, each on its own link",
            flows: 256,
            streams: &FPS,
            independent: true,
            ..SCENARIO
        },
    ]
}

fn mbit(mbit: f64) -> u64 {
    (mbit * 125_000.0) as u64
}

fn ms(ms: u64) -> Duration {
    Duration::from_millis(ms)
}

/// The presets plus links that isolate one effect.
fn profiles() -> Vec<(&'static str, Profile)> {
    let clean = |rate: f64, buffer: u64| LinkConfig {
        delay: ms(20),
        bottleneck: Some(Bottleneck::new(mbit(rate), ms(buffer))),
        ..LinkConfig::default()
    };
    let mut step = clean(20.0, 200);
    step.bottleneck.as_mut().unwrap().rates = vec![
        (Duration::from_secs(5), mbit(20.0)),
        (Duration::from_secs(5), mbit(5.0)),
    ];
    let mut jitter = clean(10.0, 200);
    jitter.jitter = Some(Jitter {
        distribution: JitterDistribution::ParetoNormal,
        mean: ms(10),
        correlation: ms(20),
    });
    vec![
        ("perfect", Profile::perfect()),
        ("good", Profile::good()),
        ("average", Profile::average()),
        ("bad", Profile::bad()),
        ("terrible", Profile::terrible()),
        (
            "clean",
            Profile {
                up: clean(10.0, 200),
                down: clean(10.0, 200),
            },
        ),
        (
            "step",
            Profile {
                up: clean(20.0, 200),
                down: step,
            },
        ),
        (
            "jitter",
            Profile {
                up: clean(10.0, 200),
                down: jitter,
            },
        ),
        (
            "reverse",
            Profile {
                up: clean(0.1, 200),
                down: clean(10.0, 200),
            },
        ),
        (
            "narrow",
            Profile {
                up: clean(1.0, 500),
                down: clean(0.384, 500),
            },
        ),
    ]
}

struct Stream {
    spec: StreamSpec,
    pair: usize,
    id: u16,
    next: Duration,
    start: Duration,
    rng: Xoshiro256PlusPlus,
    sent: u64,
    /// A ping is in flight since then.
    ping: Option<Duration>,
    /// Latencies in ms of the arrivals, arrival bytes during the run.
    latencies: Vec<f64>,
    /// Latencies in ms of the last message of each burst.
    completions: Vec<f64>,
    active_bytes: u64,
    common_bytes: [u64; 2],
    pending_at_end: u64,
    last_arrival: Duration,
    max_gap: Duration,
    blackouts: u64,
}

impl Kind {
    /// The send interval of periodic streams.
    fn interval(&self) -> Option<Duration> {
        match *self {
            Kind::Periodic { hz, .. } | Kind::Tick { hz, .. } => {
                Some(Duration::from_secs_f64(1.0 / hz))
            }
            _ => None,
        }
    }

    /// Latency samples a run of `seconds` collects, reserved so they don't count as heap
    /// growth.
    fn samples(&self, seconds: u64) -> (usize, usize) {
        let seconds = seconds as f64;
        match *self {
            Kind::Periodic { hz, .. } => ((hz * seconds) as usize + 2, 0),
            Kind::Tick { hz, sizes } => ((hz * seconds) as usize * sizes.len() + 8, 0),
            Kind::Burst { every, count, .. } => {
                let bursts = (seconds / every.as_secs_f64()) as usize + 2;
                (bursts * count, bursts)
            }
            _ => (0, 0),
        }
    }
}

fn message(id: u16, seq: u64, sent_us: u64, size: usize) -> Vec<u8> {
    let mut message = vec![0u8; size.max(HEADER)];
    message[..2].copy_from_slice(&id.to_le_bytes());
    message[2..6].copy_from_slice(&(seq as u32).to_le_bytes());
    message[6..14].copy_from_slice(&sent_us.to_le_bytes());
    message
}

struct Args {
    seconds: u64,
    drain: u64,
    seed: u64,
    seeds: u64,
    trace: bool,
    scenarios: Option<Vec<String>>,
    profiles: Option<Vec<String>>,
}

fn args() -> Args {
    let mut args = Args {
        seconds: 30,
        drain: 5,
        seed: 1,
        seeds: 1,
        trace: false,
        scenarios: None,
        profiles: None,
    };
    let mut iter = std::env::args().skip(1);
    while let Some(arg) = iter.next() {
        let mut value = || iter.next().expect("value expected");
        match arg.as_str() {
            "--seconds" => args.seconds = value().parse().expect("seconds"),
            "--drain" => args.drain = value().parse().expect("drain seconds"),
            "--seed" => args.seed = value().parse().expect("seed"),
            "--seeds" => args.seeds = value().parse().expect("seeds"),
            "--trace" => args.trace = true,
            "--scenario" => args.scenarios = Some(value().split(',').map(Into::into).collect()),
            "--profile" => args.profiles = Some(value().split(',').map(Into::into).collect()),
            "--bench" => {}
            other => panic!("unknown argument {other}"),
        }
    }
    assert!(
        args.seconds > 0 && args.seeds > 0,
        "seconds and seeds must be positive"
    );
    args
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    sorted[((p * sorted.len() as f64).ceil() as usize).clamp(1, sorted.len()) - 1]
}

/// Per link: mean and max queue delay in ms.
struct Outcome {
    streams: Vec<StreamOutcome>,
    links: [[f64; 2]; 2],
    common_start: f64,
    /// Unreliable messages that expired on either side.
    expired: u64,
    /// Ends that timed out or were closed.
    failures: u64,
    /// Peak heap of connections and simulator in MiB.
    heap: f64,
    /// Wall-clock ms per simulated second, single-threaded.
    cpu: f64,
}

/// One stream, or with more than `MAX_LISTED_FLOWS` flows a stream name over all flows
/// (`pair` is `None`, goodput and rates are means per flow).
struct StreamOutcome {
    name: &'static str,
    pair: Option<usize>,
    reliable: bool,
    /// Delivery %, goodput Mbit/s, latency p50, p95, p99, p99.9 and max in ms.
    metrics: [f64; 7],
    common_rates: [f64; 2],
    pending_at_end: u64,
    pending_after_drain: u64,
    max_gap: f64,
    blackouts: u64,
    /// Burst completion p50, p99 and max in ms, and bursts not completed.
    completion: Option<([f64; 3], u64)>,
}

struct Path {
    link: Link,
    extra_delay: Duration,
}

impl NetworkSimulator for Path {
    fn simulate(&mut self, now: Instant, peer: SocketAddr, packet: &mut [u8]) -> Fate {
        match self.link.simulate(now, peer, packet) {
            Fate::Drop => Fate::Drop,
            Fate::Deliver(at) => Fate::Deliver(at + self.extra_delay),
            Fate::Duplicate(first, second) => {
                Fate::Duplicate(first + self.extra_delay, second + self.extra_delay)
            }
        }
    }
}

fn run(scenario: &Scenario, profile: &Profile, args: &Args, seed: u64) -> Outcome {
    let wall = Instant::now();
    let heap_base = reset_peak();
    let mut pairs = Pairs::new();
    let channels = if scenario.name == "channels" {
        ChannelConfiguration {
            weights_reliable: vec![1; 256],
            weights_unreliable_ordered: vec![1; 256],
            ..ChannelConfiguration::default()
        }
    } else {
        ChannelConfiguration::default()
    };
    let mut links = vec![profile.links(seed)];
    let mut streams: Vec<Stream> = Vec::new();
    for flow in 0..scenario.flows {
        if scenario.independent && flow > 0 {
            links.push(profile.links(seed.wrapping_add(flow as u64 * 0x1_0000)));
        }
        // Flows share the bottleneck unless independent; the crowds' last flow is a download.
        let (up, down) = links.last().unwrap().clone();
        let extra_delay = match scenario.delays {
            [] => Duration::ZERO,
            delays => ms(delays[flow % delays.len()]),
        };
        let pair = pairs.add(
            channels.clone(),
            CongestionConfig::default(),
            Some(Box::new(Path {
                link: up,
                extra_delay,
            })),
            Some(Box::new(Path {
                link: down,
                extra_delay,
            })),
        );
        let specs: Vec<StreamSpec> = if scenario.name == "channels" {
            std::iter::once(Channel::Unreliable)
                .chain((0..=255).map(Channel::UnreliableOrdered))
                .chain((0..=255).map(Channel::Reliable))
                .map(|channel| StreamSpec {
                    name: "lane",
                    from: Side::Server,
                    channel,
                    kind: Kind::Periodic {
                        hz: 10.0,
                        min: 100,
                        max: 100,
                    },
                    offset: Duration::ZERO,
                })
                .collect()
        } else if scenario.name.starts_with("crowd") && flow == scenario.flows - 1 {
            vec![DOWNLOAD]
        } else {
            scenario.streams.to_vec()
        };
        for spec in specs {
            let id = u16::try_from(streams.len()).expect("too many benchmark streams");
            let mut rng = Xoshiro256PlusPlus::seed_from_u64(seed ^ u64::from(id) << 32);
            let phase = Duration::from_secs_f64(rng.r#gen::<f64>() / 64.0);
            let start = scenario.stagger * flow as u32 + phase + spec.offset;
            let (samples, bursts) = spec.kind.samples(args.seconds);
            streams.push(Stream {
                spec,
                pair,
                id,
                next: start,
                start,
                rng,
                sent: 0,
                ping: None,
                latencies: Vec::with_capacity(samples),
                completions: Vec::with_capacity(bursts),
                active_bytes: 0,
                common_bytes: [0; 2],
                pending_at_end: 0,
                last_arrival: start,
                max_gap: Duration::ZERO,
                blackouts: 0,
            });
        }
    }
    let end = Duration::from_secs(args.seconds);
    let observation_end = end + Duration::from_secs(args.drain);
    let common_start = streams
        .iter()
        .map(|stream| stream.start - stream.spec.offset)
        .max()
        .unwrap_or_default();
    let common_middle = common_start + end.saturating_sub(common_start) / 2;
    let epoch = pairs.now() - pairs.elapsed();
    let tick = Duration::from_millis(1);
    let mut trace_at = Duration::ZERO;
    let mut draining = false;
    let mut failures = 0;
    while pairs.elapsed() < observation_end {
        let now = pairs.elapsed();
        if now >= end && !draining {
            draining = true;
            for stream in &mut streams {
                stream.pending_at_end = stream.sent - stream.latencies.len() as u64;
            }
        }
        for stream in &mut streams {
            if draining || stream.next > now {
                continue;
            }
            let now_us = now.as_micros() as u64;
            match stream.spec.kind {
                Kind::Bulk { size, queued } => {
                    let waiting = pairs.stats(stream.pair, stream.spec.from).queued_bytes;
                    let mut waiting = waiting;
                    while waiting < queued {
                        let msg = message(stream.id, stream.sent, now_us, size);
                        pairs.send(stream.pair, stream.spec.from, stream.spec.channel, msg);
                        stream.sent += 1;
                        waiting += size;
                    }
                    stream.next = now + tick;
                }
                Kind::Periodic { hz, min, max } => {
                    let size = stream.rng.gen_range(min..=max);
                    let msg = message(stream.id, stream.sent, now_us, size);
                    pairs.send(stream.pair, stream.spec.from, stream.spec.channel, msg);
                    stream.sent += 1;
                    stream.next += Duration::from_secs_f64(1.0 / hz);
                }
                Kind::Tick { hz, sizes } => {
                    for &(min, max) in sizes {
                        let size = stream.rng.gen_range(min..=max);
                        let msg = message(stream.id, stream.sent, now_us, size);
                        pairs.send(stream.pair, stream.spec.from, stream.spec.channel, msg);
                        stream.sent += 1;
                    }
                    pairs.flush(stream.pair, stream.spec.from);
                    stream.next += Duration::from_secs_f64(1.0 / hz);
                }
                Kind::Burst { every, count, size } => {
                    for _ in 0..count {
                        let msg = message(stream.id, stream.sent, now_us, size);
                        pairs.send(stream.pair, stream.spec.from, stream.spec.channel, msg);
                        stream.sent += 1;
                    }
                    stream.next += every;
                }
                Kind::PingPong { size } => {
                    if stream
                        .ping
                        .is_none_or(|ping| now - ping >= Duration::from_secs(1))
                    {
                        let msg = message(stream.id, stream.sent, now_us, size);
                        pairs.send(stream.pair, stream.spec.from, stream.spec.channel, msg);
                        stream.sent += 1;
                        stream.ping = Some(now);
                    }
                    stream.next = now + Duration::from_millis(1);
                }
            }
        }
        if args.trace && now >= trace_at {
            trace_at += Duration::from_millis(
                std::env::var("TRACE_MS")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(250),
            );
            let mut line = format!("{:6.2}s", now.as_secs_f64());
            let side = match std::env::var("TRACE_SIDE").as_deref() {
                Ok("client") => Side::Client,
                _ => Side::Server,
            };
            for pair in 0..scenario.flows {
                let s = pairs.stats(pair, side);
                line += &format!(
                    " | {:6.2} Mbit/s dlv {:6.2} qd {:5.1} rtt {:5.1} {:?}",
                    s.send_rate as f64 * 8e-6,
                    s.delivery_rate as f64 * 8e-6,
                    s.queue_delay.as_secs_f64() * 1e3,
                    s.rtt.map_or(0.0, |rtt| rtt.as_secs_f64() * 1e3),
                    s.congestion,
                );
            }
            println!("{line}");
        }
        let next = if draining {
            observation_end.min(now + tick)
        } else {
            streams
                .iter()
                .map(|stream| stream.next)
                .min()
                .unwrap_or(end)
                .min(end)
                .max(now + Duration::from_micros(100))
        };
        let until = pairs.now() + (next - now);
        let by_id = &mut streams;
        let mut echoes = Vec::new();
        pairs.run(until, &mut |pair, side, at, delivery| {
            if matches!(delivery, Delivery::TimedOut | Delivery::Closed(_)) {
                failures += 1;
            }
            if let Delivery::Message(message) = delivery {
                let id = u16::from_le_bytes(message[..2].try_into().unwrap()) as usize;
                let stream = &mut by_id[id];
                if matches!(stream.spec.kind, Kind::PingPong { .. }) {
                    if side == Side::Server {
                        echoes.push((pair, stream.spec.channel, message));
                        return;
                    }
                    stream.ping = None;
                    stream.next = (at - epoch).min(stream.next);
                }
                let sent_us = u64::from_le_bytes(message[6..14].try_into().unwrap());
                let at_us = (at - epoch).as_micros() as i64;
                let latency = (at_us - sent_us as i64) as f64 / 1000.0;
                stream.latencies.push(latency);
                if let Kind::Burst { count, .. } = stream.spec.kind {
                    let seq = u32::from_le_bytes(message[2..6].try_into().unwrap()) as usize;
                    if (seq + 1) % count == 0 {
                        stream.completions.push(latency);
                    }
                }
                let elapsed = at - epoch;
                if elapsed <= end {
                    stream.active_bytes += message.len() as u64;
                    let gap = elapsed.saturating_sub(stream.last_arrival);
                    stream.max_gap = stream.max_gap.max(gap);
                    if stream
                        .spec
                        .kind
                        .interval()
                        .is_some_and(|interval| gap > interval + BLACKOUT)
                    {
                        stream.blackouts += 1;
                    }
                    stream.last_arrival = elapsed;
                    if elapsed >= common_start {
                        stream.common_bytes[usize::from(elapsed >= common_middle)] +=
                            message.len() as u64;
                    }
                }
            }
        });
        for (pair, channel, message) in echoes {
            pairs.send(pair, Side::Server, channel, message);
        }
    }
    let expired = (0..scenario.flows)
        .flat_map(|pair| [(pair, Side::Client), (pair, Side::Server)])
        .map(|(pair, side)| pairs.stats(pair, side).expired_messages)
        .sum();
    let harness = streams.capacity() * size_of::<Stream>()
        + streams
            .iter()
            .map(|stream| (stream.latencies.capacity() + stream.completions.capacity()) * 8)
            .sum::<usize>();
    let heap = PEAK
        .load(Ordering::Relaxed)
        .saturating_sub(heap_base + harness) as f64
        / (1 << 20) as f64;
    for stream in &mut streams {
        if !draining {
            stream.pending_at_end = stream.sent - stream.latencies.len() as u64;
        }
        let final_gap = end.saturating_sub(stream.last_arrival);
        stream.max_gap = stream.max_gap.max(final_gap);
        if stream
            .spec
            .kind
            .interval()
            .is_some_and(|interval| final_gap > interval + BLACKOUT)
        {
            stream.blackouts += 1;
        }
    }
    let listed = scenario.flows <= MAX_LISTED_FLOWS;
    let mut groups: Vec<(Option<usize>, &str, Vec<&Stream>)> = Vec::new();
    for stream in &streams {
        let pair = listed.then_some(stream.pair);
        match groups
            .iter_mut()
            .find(|(p, name, _)| *p == pair && *name == stream.spec.name)
        {
            Some((.., members)) => members.push(stream),
            None => groups.push((pair, stream.spec.name, vec![stream])),
        }
    }
    let link_stats: Vec<[LinkStats; 2]> = links
        .iter()
        .map(|(up, down)| [down.stats(), up.stats()])
        .collect();
    let link = |j: usize| {
        [
            link_stats
                .iter()
                .map(|stats| stats[j].mean_queue_delay().as_secs_f64() * 1e3)
                .sum::<f64>()
                / link_stats.len() as f64,
            link_stats
                .iter()
                .map(|stats| stats[j].max_queue_delay.as_secs_f64() * 1e3)
                .fold(0.0, f64::max),
        ]
    };
    let simulated = observation_end.as_secs_f64();
    Outcome {
        streams: groups
            .into_iter()
            .map(|(pair, name, members)| stream_outcome(name, pair, &members, end, common_start))
            .collect(),
        links: [link(0), link(1)],
        common_start: common_start.as_secs_f64(),
        expired,
        failures,
        heap,
        cpu: wall.elapsed().as_secs_f64() * 1e3 / simulated,
    }
}

fn stream_outcome(
    name: &'static str,
    pair: Option<usize>,
    members: &[&Stream],
    end: Duration,
    common_start: Duration,
) -> StreamOutcome {
    let n = members.len() as f64;
    let sorted = |samples: fn(&Stream) -> &Vec<f64>| {
        let mut all: Vec<f64> = members
            .iter()
            .flat_map(|stream| samples(stream))
            .copied()
            .collect();
        all.sort_by(f64::total_cmp);
        all
    };
    let l = sorted(|stream| &stream.latencies);
    let sent: u64 = members.iter().map(|stream| stream.sent).sum();
    let goodput = members
        .iter()
        .map(|stream| {
            stream.active_bytes as f64 * 8e-6 / end.saturating_sub(stream.start).as_secs_f64()
        })
        .sum::<f64>()
        / n;
    let half = end.saturating_sub(common_start).as_secs_f64() / 2.0;
    let completion = match members[0].spec.kind {
        Kind::Burst { count, .. } => {
            let c = sorted(|stream| &stream.completions);
            let bursts = sent / count as u64;
            Some((
                [
                    percentile(&c, 0.5),
                    percentile(&c, 0.99),
                    c.last().copied().unwrap_or(f64::NAN),
                ],
                bursts - c.len() as u64,
            ))
        }
        _ => None,
    };
    StreamOutcome {
        name,
        pair,
        reliable: matches!(members[0].spec.channel, Channel::Reliable(_)),
        metrics: [
            100.0 * l.len() as f64 / sent.max(1) as f64,
            goodput,
            percentile(&l, 0.5),
            percentile(&l, 0.95),
            percentile(&l, 0.99),
            percentile(&l, 0.999),
            l.last().copied().unwrap_or(f64::NAN),
        ],
        common_rates: [0, 1].map(|i| {
            members
                .iter()
                .map(|stream| stream.common_bytes[i] as f64 * 8e-6 / half)
                .sum::<f64>()
                / n
        }),
        pending_at_end: members.iter().map(|stream| stream.pending_at_end).sum(),
        pending_after_drain: sent - l.len() as u64,
        max_gap: members
            .iter()
            .map(|stream| stream.max_gap.as_secs_f64() * 1e3)
            .fold(0.0, f64::max),
        blackouts: members.iter().map(|stream| stream.blackouts).sum(),
        completion,
    }
}

fn report(scenario: &Scenario, profile: &Profile, args: &Args) {
    let outcomes: Vec<Outcome> = (0..args.seeds)
        .map(|i| run(scenario, profile, args, args.seed + i))
        .collect();
    let n = outcomes.len() as f64;
    for (seed, outcome) in outcomes.iter().enumerate() {
        println!(
            "  seed {}: active {} s, drain {} s, common {:.3}..{} s (first/second half)",
            args.seed + seed as u64,
            args.seconds,
            args.drain,
            outcome.common_start,
            args.seconds
        );
        for stream in &outcome.streams {
            println!(
                "    {} {:<10} active {:.3} Mbit/s, common {:.3}/{:.3}, p99 {:.1} p99.9 {:.1} max {:.1} gap {:.1} ms, {} blackouts, {} {} -> {}",
                pair_label(stream.pair),
                stream.name,
                stream.metrics[1],
                stream.common_rates[0],
                stream.common_rates[1],
                stream.metrics[4],
                stream.metrics[5],
                stream.metrics[6],
                stream.max_gap,
                stream.blackouts,
                if stream.reliable {
                    "pending"
                } else {
                    "unobserved"
                },
                stream.pending_at_end,
                stream.pending_after_drain
            );
            if let Some(([p50, p99, max], incomplete)) = stream.completion {
                println!(
                    "      bursts completed p50 {p50:.1} p99 {p99:.1} max {max:.1} ms, {incomplete} incomplete"
                );
            }
        }
        println!(
            "    expired {}, failures {}, peak heap {:.2} MiB, {:.2} ms CPU per simulated s",
            outcome.expired, outcome.failures, outcome.heap, outcome.cpu
        );
        if matches!(scenario.name, "fair" | "fair-rtt") {
            let fairness = |half: usize| {
                let rates: Vec<_> = outcome
                    .streams
                    .iter()
                    .map(|s| s.common_rates[half])
                    .collect();
                rates.iter().sum::<f64>().powi(2)
                    / (rates.len() as f64 * rates.iter().map(|x| x * x).sum::<f64>())
            };
            println!(
                "    common Jain fairness {:.3} -> {:.3}",
                fairness(0),
                fairness(1)
            );
        }
    }
    for (i, stream) in outcomes[0].streams.iter().enumerate() {
        let (name, pair) = (stream.name, pair_label(stream.pair));
        let mean = |k: usize| {
            outcomes
                .iter()
                .map(|o| o.streams[i].metrics[k])
                .sum::<f64>()
                / n
        };
        let worst = |k: usize| {
            outcomes
                .iter()
                .map(|o| o.streams[i].metrics[k])
                .fold(f64::NAN, f64::max)
        };
        println!(
            "  mean {pair:<2} {name:<10} {:>6.1}% {:>7.2} Mbit/s  p50 {:>7.1}  p95 {:>7.1}  p99 {:>7.1}; worst-seed p99 {:>7.1} p99.9 {:>7.1} max {:>7.1} ms, gap {:>6.1} ms, {} blackouts",
            mean(0),
            mean(1),
            mean(2),
            mean(3),
            mean(4),
            worst(4),
            worst(5),
            worst(6),
            outcomes
                .iter()
                .map(|o| o.streams[i].max_gap)
                .fold(0.0, f64::max),
            outcomes.iter().map(|o| o.streams[i].blackouts).sum::<u64>(),
        );
        if stream.completion.is_some() {
            let completion = |k: usize| {
                outcomes
                    .iter()
                    .filter_map(|o| o.streams[i].completion)
                    .map(|(c, _)| c[k])
                    .fold(f64::NAN, f64::max)
            };
            println!(
                "       {:<10} worst-seed burst completion p50 {:>7.1} p99 {:>7.1} max {:>7.1} ms, {} incomplete",
                "",
                completion(0),
                completion(1),
                completion(2),
                outcomes
                    .iter()
                    .filter_map(|o| o.streams[i].completion)
                    .map(|(_, incomplete)| incomplete)
                    .sum::<u64>(),
            );
        }
    }
    for (j, name) in ["down", "up"].iter().enumerate() {
        let mean = |k: usize| outcomes.iter().map(|o| o.links[j][k]).sum::<f64>() / n;
        println!(
            "  {name:<4} link including drain: queue mean {:6.1} worst-seed max {:6.1} ms",
            mean(0),
            outcomes.iter().map(|o| o.links[j][1]).fold(0.0, f64::max)
        );
    }
    println!(
        "  mean expired {:.0}, failures {}, worst-seed peak heap {:.2} MiB, mean {:.2} ms CPU per simulated s",
        outcomes.iter().map(|o| o.expired as f64).sum::<f64>() / n,
        outcomes.iter().map(|o| o.failures).sum::<u64>(),
        outcomes.iter().map(|o| o.heap).fold(0.0, f64::max),
        outcomes.iter().map(|o| o.cpu).sum::<f64>() / n,
    );
}

fn pair_label(pair: Option<usize>) -> String {
    pair.map_or_else(|| "*".into(), |pair| pair.to_string())
}

fn main() {
    let args = args();
    for scenario in scenarios() {
        if args
            .scenarios
            .as_ref()
            .is_some_and(|names| !names.iter().any(|n| n == scenario.name))
        {
            continue;
        }
        for (name, profile) in profiles() {
            if args
                .profiles
                .as_ref()
                .is_some_and(|names| !names.iter().any(|n| n == name))
            {
                continue;
            }
            println!("━━ {} ({}) on {name}", scenario.name, scenario.about);
            let start = std::time::Instant::now();
            report(&scenario, &profile, &args);
            println!("  ({:.1} s)", start.elapsed().as_secs_f64());
        }
    }
}
