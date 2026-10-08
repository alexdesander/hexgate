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

use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

use hexgate::{
    bench::{Delivery, Pairs, Side},
    sim::{
        Bottleneck, Fate, Jitter, JitterDistribution, Link, LinkConfig, LinkStats,
        NetworkSimulator, Profile,
    },
    Channel, ChannelConfiguration, CongestionConfig,
};
use rand::{Rng, SeedableRng};
use rand_xoshiro::Xoshiro256PlusPlus;

const HEADER: usize = 14;
const KIB: usize = 1024;

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
}

struct Scenario {
    name: &'static str,
    about: &'static str,
    /// Connections sharing the bottleneck, started this far apart.
    flows: usize,
    stagger: Duration,
    streams: &'static [StreamSpec],
}

const SNAPSHOTS: StreamSpec = StreamSpec {
    name: "snapshots",
    from: Side::Server,
    channel: Channel::UnreliableOrdered(0),
    kind: Kind::Periodic {
        hz: 64.0,
        min: 300,
        max: 1100,
    },
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
};
const UPLOAD: StreamSpec = StreamSpec {
    name: "upload",
    from: Side::Client,
    channel: Channel::Reliable(0),
    kind: Kind::Bulk {
        size: 64 * KIB,
        queued: 1024 * KIB,
    },
};
const PINGS: [StreamSpec; 2] = [
    StreamSpec {
        name: "ping rel",
        from: Side::Client,
        channel: Channel::Reliable(0),
        kind: Kind::PingPong { size: 64 },
    },
    StreamSpec {
        name: "ping unrel",
        from: Side::Client,
        channel: Channel::Unreliable,
        kind: Kind::PingPong { size: 64 },
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
};
const DOWNLOAD: StreamSpec = StreamSpec {
    name: "download",
    from: Side::Server,
    channel: Channel::Reliable(0),
    kind: Kind::Bulk {
        size: 64 * KIB,
        queued: 1024 * KIB,
    },
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

fn scenarios() -> Vec<Scenario> {
    vec![
        Scenario {
            name: "bulk",
            about: "one reliable download",
            flows: 1,
            stagger: Duration::ZERO,
            streams: &[DOWNLOAD],
        },
        Scenario {
            name: "game",
            about: "64 Hz snapshots down, inputs up",
            flows: 1,
            stagger: Duration::ZERO,
            streams: &[SNAPSHOTS, INPUTS],
        },
        Scenario {
            name: "mixed",
            about: "game traffic plus a download on the same connection",
            flows: 1,
            stagger: Duration::ZERO,
            streams: &[SNAPSHOTS, INPUTS, DOWNLOAD],
        },
        Scenario {
            name: "bidir",
            about: "a download and an upload at once",
            flows: 1,
            stagger: Duration::ZERO,
            streams: &[DOWNLOAD, UPLOAD],
        },
        Scenario {
            name: "pingpong",
            about: "reliable and unreliable round trips at once",
            flows: 1,
            stagger: Duration::ZERO,
            streams: &PINGS,
        },
        Scenario {
            name: "ticks",
            about: "30 Hz ticks of 4 messages with flush(), plus inputs",
            flows: 1,
            stagger: Duration::ZERO,
            streams: &[TICKS, INPUTS],
        },
        Scenario {
            name: "idle",
            about: "100 x 200 B reliable at once every 1.5 s",
            flows: 1,
            stagger: Duration::ZERO,
            streams: &[IDLE_BURSTS],
        },
        Scenario {
            name: "fair",
            about: "3 downloads sharing the bottleneck, started 5 s apart",
            flows: 3,
            stagger: Duration::from_secs(5),
            streams: &[DOWNLOAD],
        },
        Scenario {
            name: "crowd",
            about: "game traffic of 3 clients plus one download sharing the bottleneck",
            flows: 4,
            stagger: Duration::ZERO,
            streams: &[SNAPSHOTS, INPUTS],
        },
        Scenario {
            name: "fair-rtt",
            about: "3 downloads with 0/40/100 ms added RTT sharing the bottleneck",
            flows: 3,
            stagger: Duration::from_secs(5),
            streams: &[DOWNLOAD],
        },
        Scenario {
            name: "scale",
            about: "32 clients sending snapshots and inputs through a shared bottleneck",
            flows: 32,
            stagger: Duration::ZERO,
            streams: &[SNAPSHOTS, INPUTS],
        },
        Scenario {
            name: "channels",
            about: "513 channels, each sending one 100-byte message at 10 Hz",
            flows: 1,
            stagger: Duration::ZERO,
            streams: &[],
        },
        Scenario {
            name: "moba",
            about: "30 Hz updates and reliable events every 250 ms",
            flows: 1,
            stagger: Duration::ZERO,
            streams: &MOBA,
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
    active_bytes: u64,
    common_bytes: [u64; 2],
    pending_at_end: u64,
    last_arrival: Duration,
    max_gap: Duration,
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

/// Per stream: name, pair, delivery, goodput, p50, p95, p99, max; per link: mean and max
/// queue delay.
struct Outcome {
    streams: Vec<StreamOutcome>,
    links: [[f64; 2]; 2],
    common_start: f64,
}

struct StreamOutcome {
    name: &'static str,
    pair: usize,
    reliable: bool,
    metrics: [f64; 6],
    common_rates: [f64; 2],
    pending_at_end: u64,
    pending_after_drain: u64,
    max_gap: f64,
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
    let (shared_up, shared_down) = profile.links(seed);
    let mut streams: Vec<Stream> = Vec::new();
    for flow in 0..scenario.flows {
        // Flows share the bottleneck; the crowd's last flow is a download.
        let (up, down) = (shared_up.clone(), shared_down.clone());
        let extra_delay = if scenario.name == "fair-rtt" {
            ms([0, 20, 50][flow])
        } else {
            Duration::ZERO
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
                })
                .collect()
        } else if scenario.name == "crowd" && flow == scenario.flows - 1 {
            vec![DOWNLOAD]
        } else {
            scenario.streams.to_vec()
        };
        for spec in specs {
            let id = u16::try_from(streams.len()).expect("too many benchmark streams");
            let mut rng = Xoshiro256PlusPlus::seed_from_u64(seed ^ u64::from(id) << 32);
            let phase = Duration::from_secs_f64(rng.gen::<f64>() / 64.0);
            let start = scenario.stagger * flow as u32 + phase;
            streams.push(Stream {
                spec,
                pair,
                id,
                next: start,
                start,
                rng,
                sent: 0,
                ping: None,
                latencies: Vec::new(),
                active_bytes: 0,
                common_bytes: [0; 2],
                pending_at_end: 0,
                last_arrival: start,
                max_gap: Duration::ZERO,
            });
        }
    }
    let end = Duration::from_secs(args.seconds);
    let observation_end = end + Duration::from_secs(args.drain);
    let common_start = streams
        .iter()
        .map(|stream| stream.start)
        .max()
        .unwrap_or_default();
    let common_middle = common_start + end.saturating_sub(common_start) / 2;
    let epoch = pairs.now() - pairs.elapsed();
    let tick = Duration::from_millis(1);
    let mut trace_at = Duration::ZERO;
    let mut draining = false;
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
                stream
                    .latencies
                    .push((at_us - sent_us as i64) as f64 / 1000.0);
                let elapsed = at - epoch;
                if elapsed <= end {
                    stream.active_bytes += message.len() as u64;
                    stream.max_gap = stream
                        .max_gap
                        .max(elapsed.saturating_sub(stream.last_arrival));
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
    let link = |stats: LinkStats| {
        [
            stats.mean_queue_delay().as_secs_f64() * 1e3,
            stats.max_queue_delay.as_secs_f64() * 1e3,
        ]
    };
    Outcome {
        streams: streams
            .iter_mut()
            .map(|stream| {
                stream.latencies.sort_by(f64::total_cmp);
                let l = &stream.latencies;
                if !draining {
                    stream.pending_at_end = stream.sent - stream.latencies.len() as u64;
                }
                StreamOutcome {
                    name: stream.spec.name,
                    pair: stream.pair,
                    reliable: matches!(stream.spec.channel, Channel::Reliable(_)),
                    metrics: [
                        100.0 * l.len() as f64 / stream.sent.max(1) as f64,
                        stream.active_bytes as f64 * 8e-6
                            / end.saturating_sub(stream.start).as_secs_f64(),
                        percentile(l, 0.5),
                        percentile(l, 0.95),
                        percentile(l, 0.99),
                        l.last().copied().unwrap_or(f64::NAN),
                    ],
                    common_rates: stream.common_bytes.map(|bytes| {
                        bytes as f64 * 8e-6 / (end.saturating_sub(common_start).as_secs_f64() / 2.0)
                    }),
                    pending_at_end: stream.pending_at_end,
                    pending_after_drain: stream.sent - l.len() as u64,
                    max_gap: stream
                        .max_gap
                        .max(end.saturating_sub(stream.last_arrival))
                        .as_secs_f64()
                        * 1e3,
                }
            })
            .collect(),
        links: [link(shared_down.stats()), link(shared_up.stats())],
        common_start: common_start.as_secs_f64(),
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
            println!("    {} {:<10} active {:.3} Mbit/s, common {:.3}/{:.3}, p99 {:.1} max {:.1} gap {:.1} ms, {} {} -> {}",
                stream.pair, stream.name, stream.metrics[1], stream.common_rates[0], stream.common_rates[1],
                stream.metrics[4], stream.metrics[5], stream.max_gap,
                if stream.reliable { "pending" } else { "unobserved" },
                stream.pending_at_end, stream.pending_after_drain);
        }
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
        let (name, pair) = (stream.name, stream.pair);
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
            "  mean {pair:<2} {name:<10} {:>6.1}% {:>7.2} Mbit/s  p50 {:>7.1}  p95 {:>7.1}  p99 {:>7.1}; worst-seed p99 {:>7.1} max {:>7.1} ms",
            mean(0),
            mean(1),
            mean(2),
            mean(3),
            mean(4),
            worst(4),
            worst(5),
        );
    }
    for (j, name) in ["down", "up"].iter().enumerate() {
        let mean = |k: usize| outcomes.iter().map(|o| o.links[j][k]).sum::<f64>() / n;
        println!(
            "  {name:<4} link including drain: queue mean {:6.1} worst-seed max {:6.1} ms",
            mean(0),
            outcomes.iter().map(|o| o.links[j][1]).fold(0.0, f64::max)
        );
    }
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
