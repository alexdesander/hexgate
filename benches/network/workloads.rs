// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The connection profiles and the traffic each run sends.

use std::time::Duration;

use hexgate::{sim::Profile, Channel, ChannelConfiguration};
use rand::Rng;
use rand_xoshiro::Xoshiro256PlusPlus;
use serde::Serialize;

pub const KIB: usize = 1024;
pub const MIB: usize = 1024 * KIB;
/// Reserved for the end-of-run marker, so it doesn't wait behind bulk data.
pub const CONTROL: Channel = Channel::Reliable(2);

pub fn channel_config() -> ChannelConfiguration {
    ChannelConfiguration {
        weight_unreliable: 10,
        weights_unreliable_ordered: vec![10; 2],
        weights_reliable: vec![10; 3],
        ..ChannelConfiguration::default()
    }
}

pub fn profiles() -> Vec<(&'static str, Profile)> {
    vec![
        ("perfect", Profile::perfect()),
        ("good", Profile::good()),
        ("average", Profile::average()),
        ("bad", Profile::bad()),
        ("terrible", Profile::terrible()),
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Dir {
    /// Client to server.
    Up,
    /// Server to client.
    Down,
}

/// Message sizes in bytes (at least the 13-byte header).
#[derive(Debug, Clone, Copy)]
pub enum Size {
    Fixed(usize),
    Uniform(usize, usize),
    LogUniform(usize, usize),
    Cycle(&'static [usize]),
}

impl Size {
    pub fn sample(self, seq: u32, rng: &mut Xoshiro256PlusPlus) -> usize {
        match self {
            Size::Fixed(size) => size,
            Size::Uniform(min, max) => rng.gen_range(min..=max),
            Size::LogUniform(min, max) => {
                let (min, max) = ((min as f64).ln(), (max as f64).ln());
                rng.gen_range(min..=max).exp().round() as usize
            }
            Size::Cycle(sizes) => sizes[seq as usize % sizes.len()],
        }
    }
}

/// When a stream sends.
#[derive(Debug, Clone, Copy)]
pub enum Pattern {
    /// A tick rate.
    Periodic { hz: f64, size: Size },
    /// Exponential gaps (a Poisson process).
    Random { mean_gap: Duration, size: Size },
    /// As much as the connection takes, at most `max_queued` bytes waiting in hexgate.
    Bulk { size: usize, max_queued: usize },
    /// `count` messages at once, every `every`.
    Bursts {
        every: Duration,
        count: usize,
        size: usize,
    },
    /// Unreliable at `factor` times the link rate (hexgate's maximum rate for unlimited links).
    Overload { factor: f64, size: usize },
    /// One message in flight, echoed by the server: round-trip times.
    PingPong { size: usize },
}

impl Pattern {
    /// The send interval of periodic streams.
    pub fn interval(&self) -> Option<Duration> {
        match self {
            Pattern::Periodic { hz, .. } => Some(Duration::from_secs_f64(1.0 / hz)),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Stream {
    pub name: &'static str,
    pub dir: Dir,
    pub channel: Channel,
    pub pattern: Pattern,
}

#[derive(Debug, Clone)]
pub struct Workload {
    pub name: &'static str,
    pub category: &'static str,
    pub about: &'static str,
    pub streams: Vec<Stream>,
    /// The stream in the summary.
    pub key: &'static str,
}

const fn ms(ms: u64) -> Duration {
    Duration::from_millis(ms)
}

fn stream(name: &'static str, dir: Dir, channel: Channel, pattern: Pattern) -> Stream {
    Stream {
        name,
        dir,
        channel,
        pattern,
    }
}

fn periodic(hz: f64, size: Size) -> Pattern {
    Pattern::Periodic { hz, size }
}

/// Sizes around packet and fragment boundaries. One packet carries up to 1178 (unreliable),
/// 1177 (ordered) or 1172 (reliable) bytes; a fragment 1173, 1172 or 1172.
const FRAGMENT_EDGES: &[usize] = &[
    13, 1171, 1172, 1173, 1177, 1178, 1179, 2343, 2344, 2345, 2346, 2347, 3515, 3516, 3517, 3518,
    3519, 3520,
];

pub fn workloads() -> Vec<Workload> {
    use Channel::{Reliable, Unreliable, UnreliableOrdered};
    use Dir::{Down, Up};
    let bulk = Pattern::Bulk {
        size: 64 * KIB,
        max_queued: MIB,
    };
    let fps = || {
        vec![
            stream(
                "inputs",
                Up,
                UnreliableOrdered(0),
                periodic(64.0, Size::Uniform(48, 80)),
            ),
            stream(
                "snapshots",
                Down,
                UnreliableOrdered(0),
                periodic(64.0, Size::Uniform(300, 1100)),
            ),
        ]
    };
    let voice = |dir| {
        stream(
            "voice",
            dir,
            Unreliable,
            periodic(50.0, Size::Uniform(80, 120)),
        )
    };
    vec![
        Workload {
            name: "bulk",
            category: "continuous big data",
            about: "down: reliable 64 KiB messages, 1 MiB kept queued",
            streams: vec![stream("download", Down, Reliable(0), bulk)],
            key: "download",
        },
        Workload {
            name: "bulk_bidir",
            category: "continuous big data",
            about: "both ways at once: reliable 64 KiB messages, 1 MiB kept queued",
            streams: vec![
                stream("download", Down, Reliable(0), bulk),
                stream("upload", Up, Reliable(0), bulk),
            ],
            key: "download",
        },
        Workload {
            name: "bursts",
            category: "small bursts of big data",
            about: "down: 4 x 64 KiB reliable every second (level chunks)",
            streams: vec![stream(
                "chunks",
                Down,
                Reliable(0),
                Pattern::Bursts {
                    every: Duration::from_secs(1),
                    count: 4,
                    size: 64 * KIB,
                },
            )],
            key: "chunks",
        },
        Workload {
            name: "steady",
            category: "constant small data",
            about: "both ways: 60 Hz 64 B unreliable, 10 Hz 32 B reliable",
            streams: vec![
                stream("state", Down, Unreliable, periodic(60.0, Size::Fixed(64))),
                stream("state", Up, Unreliable, periodic(60.0, Size::Fixed(64))),
                stream("events", Down, Reliable(0), periodic(10.0, Size::Fixed(32))),
                stream("events", Up, Reliable(0), periodic(10.0, Size::Fixed(32))),
            ],
            key: "state",
        },
        Workload {
            name: "random",
            category: "completely random",
            about: "both ways, every channel: exponential gaps, log-uniform sizes up to 64 KiB",
            streams: [Down, Up]
                .into_iter()
                .flat_map(|dir| {
                    [
                        stream(
                            "unreliable",
                            dir,
                            Unreliable,
                            Pattern::Random {
                                mean_gap: ms(30),
                                size: Size::LogUniform(13, 16 * KIB),
                            },
                        ),
                        stream(
                            "ordered",
                            dir,
                            UnreliableOrdered(0),
                            Pattern::Random {
                                mean_gap: ms(30),
                                size: Size::LogUniform(13, 4 * KIB),
                            },
                        ),
                        stream(
                            "reliable",
                            dir,
                            Reliable(0),
                            Pattern::Random {
                                mean_gap: ms(100),
                                size: Size::LogUniform(13, 64 * KIB),
                            },
                        ),
                    ]
                })
                .collect(),
            key: "reliable",
        },
        Workload {
            name: "fps",
            category: "game",
            about: "shooter: 64 Hz inputs up, 64 Hz snapshots down, reliable events",
            streams: [
                fps(),
                vec![
                    stream(
                        "events",
                        Up,
                        Reliable(0),
                        periodic(2.0, Size::Uniform(50, 150)),
                    ),
                    stream(
                        "events",
                        Down,
                        Reliable(0),
                        periodic(4.0, Size::Uniform(50, 200)),
                    ),
                ],
            ]
            .concat(),
            key: "snapshots",
        },
        Workload {
            name: "mmo",
            category: "game",
            about: "10 Hz reliable state and 20 Hz positions down, commands up, 32 KiB assets",
            streams: vec![
                stream(
                    "state",
                    Down,
                    Reliable(0),
                    periodic(10.0, Size::Uniform(200, 3000)),
                ),
                stream(
                    "positions",
                    Down,
                    Unreliable,
                    periodic(20.0, Size::Uniform(100, 400)),
                ),
                stream(
                    "commands",
                    Up,
                    Reliable(0),
                    periodic(10.0, Size::Uniform(30, 100)),
                ),
                stream(
                    "assets",
                    Down,
                    Reliable(1),
                    Pattern::Bursts {
                        every: Duration::from_secs(5),
                        count: 1,
                        size: 32 * KIB,
                    },
                ),
            ],
            key: "state",
        },
        Workload {
            name: "lockstep",
            category: "game",
            about: "RTS lockstep: 10 Hz reliable command frames both ways",
            streams: vec![
                stream(
                    "frames",
                    Down,
                    Reliable(0),
                    periodic(10.0, Size::Uniform(40, 200)),
                ),
                stream(
                    "frames",
                    Up,
                    Reliable(0),
                    periodic(10.0, Size::Uniform(40, 200)),
                ),
            ],
            key: "frames",
        },
        Workload {
            name: "voice",
            category: "game",
            about: "voice chat: 50 Hz 80-120 B unreliable both ways (20 ms Opus frames)",
            streams: vec![voice(Down), voice(Up)],
            key: "voice",
        },
        Workload {
            name: "mixed",
            category: "game",
            about: "fps + voice + a reliable bulk download on another channel",
            streams: [
                fps(),
                vec![
                    voice(Down),
                    voice(Up),
                    stream("download", Down, Reliable(1), bulk),
                ],
            ]
            .concat(),
            key: "snapshots",
        },
        Workload {
            name: "tiny_flood",
            category: "weird",
            about: "down: 13 B reliable messages as fast as accepted (64 KiB queued)",
            streams: vec![stream(
                "flood",
                Down,
                Reliable(0),
                Pattern::Bulk {
                    size: 13,
                    max_queued: 64 * KIB,
                },
            )],
            key: "flood",
        },
        Workload {
            name: "fragment_edges",
            category: "weird",
            about: "down, every channel: 20 Hz sizes around packet and fragment boundaries",
            streams: [
                ("unreliable", Unreliable),
                ("ordered", UnreliableOrdered(1)),
                ("reliable", Reliable(1)),
            ]
            .into_iter()
            .map(|(name, channel)| {
                stream(
                    name,
                    Down,
                    channel,
                    periodic(20.0, Size::Cycle(FRAGMENT_EDGES)),
                )
            })
            .collect(),
            key: "reliable",
        },
        Workload {
            name: "max_message",
            category: "weird",
            about: "down: 1 MiB reliable messages (the default maximum), 2 MiB queued",
            streams: vec![stream(
                "huge",
                Down,
                Reliable(0),
                Pattern::Bulk {
                    size: MIB,
                    max_queued: 2 * MIB,
                },
            )],
            key: "huge",
        },
        Workload {
            name: "idle_burst",
            category: "weird",
            about: "down: 100 x 200 B reliable at once after 1.5 s of silence",
            streams: vec![stream(
                "burst",
                Down,
                Reliable(0),
                Pattern::Bursts {
                    every: ms(1500),
                    count: 100,
                    size: 200,
                },
            )],
            key: "burst",
        },
        Workload {
            name: "overload",
            category: "weird",
            about: "down: unreliable 1100 B at 3x the link rate",
            streams: vec![stream(
                "flood",
                Down,
                Unreliable,
                Pattern::Overload {
                    factor: 3.0,
                    size: 1100,
                },
            )],
            key: "flood",
        },
        Workload {
            name: "ping_pong",
            category: "weird",
            about: "one 64 B message in flight, echoed: round trips (reliable and unreliable)",
            streams: vec![
                stream("reliable", Up, Reliable(0), Pattern::PingPong { size: 64 }),
                stream("unreliable", Up, Unreliable, Pattern::PingPong { size: 64 }),
            ],
            key: "reliable",
        },
    ]
}
