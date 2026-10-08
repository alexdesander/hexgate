// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::time::Duration;

use super::{
    Bottleneck, CrossTraffic, Duplicate, Episodes, Interval, Jitter, JitterDistribution, Link,
    LinkConfig, Loss, Reorder, Simulator, Spikes,
};

const fn ms(ms: u64) -> Duration {
    Duration::from_millis(ms)
}

/// Bytes per second of `mbit` megabits per second.
fn mbit(mbit: f64) -> u64 {
    (mbit * 125_000.0) as u64
}

/// The conditions of a connection: `up` from client to server, `down` from server to client.
///
/// The presets are typical connections, from measurements of home Wi-Fi, cellular and
/// satellite links (bursty loss, long-tailed jitter, bufferbloat, Starlink's 15 s
/// reconfigurations). Fields can be changed for anything in between.
///
/// Hexgate is tuned for `perfect` to `average`. `bad` and `terrible` are stress tests:
/// connections have to survive them, not perform well on them.
#[derive(Debug, Clone, Default)]
pub struct Profile {
    /// Client to server.
    pub up: LinkConfig,
    /// Server to client.
    pub down: LinkConfig,
}

impl Profile {
    /// No loss, no delay, no rate limit.
    pub fn perfect() -> Self {
        Self::default()
    }

    /// Wired fiber in the same region: 20 ms RTT, 1 ms jitter, 0.1 % loss, 100/20 Mbit/s.
    pub fn good() -> Self {
        let link = |rate| LinkConfig {
            delay: ms(10),
            jitter: Some(Jitter {
                distribution: JitterDistribution::Normal,
                mean: Duration::from_micros(800),
                correlation: ms(5),
            }),
            loss: Some(Loss::random(0.001)),
            bottleneck: Some(Bottleneck::new(mbit(rate), ms(50))),
            ..LinkConfig::default()
        };
        Self {
            up: link(20.0),
            down: link(100.0),
        }
    }

    /// Cable or DSL with home Wi-Fi, across a country: 60 ms RTT, 3 ms long-tailed jitter,
    /// 0.5 % loss in pairs, 25/5 Mbit/s, 40 ms spikes about every 10 s.
    pub fn average() -> Self {
        let link = |rate| LinkConfig {
            delay: ms(30),
            jitter: Some(Jitter {
                distribution: JitterDistribution::ParetoNormal,
                mean: ms(3),
                correlation: ms(10),
            }),
            loss: Some(Loss::bursty(0.005, 2.0)),
            bottleneck: Some(Bottleneck::new(mbit(rate), ms(100))),
            spikes: Some(Spikes {
                episodes: Episodes {
                    interval: Interval::Random(Duration::from_secs(10)),
                    duration: ms(50),
                },
                extra: ms(40),
            }),
            slot: Some(ms(1)),
            ..LinkConfig::default()
        };
        Self {
            up: link(5.0),
            down: link(25.0),
        }
    }

    /// Congested Wi-Fi or 4G: 120 ms RTT, 10 ms jitter, 2 % loss in bursts, 5/1 Mbit/s with
    /// bufferbloat and other traffic, spikes, stalls, some reordering and duplicates.
    pub fn bad() -> Self {
        let link = |rate| {
            let mut bottleneck = Bottleneck::new(mbit(rate), ms(300));
            bottleneck.cross_traffic = Some(CrossTraffic {
                rate: mbit(rate * 0.3),
                active: Some(Episodes {
                    interval: Interval::Random(Duration::from_secs(8)),
                    duration: Duration::from_secs(4),
                }),
            });
            LinkConfig {
                delay: ms(60),
                jitter: Some(Jitter {
                    distribution: JitterDistribution::ParetoNormal,
                    mean: ms(10),
                    correlation: ms(20),
                }),
                loss: Some(Loss::bursty(0.02, 3.0)),
                bottleneck: Some(bottleneck),
                spikes: Some(Spikes {
                    episodes: Episodes {
                        interval: Interval::Random(Duration::from_secs(5)),
                        duration: ms(200),
                    },
                    extra: ms(120),
                }),
                stalls: Some(Episodes {
                    interval: Interval::Random(Duration::from_secs(20)),
                    duration: ms(150),
                }),
                reorder: Some(Reorder {
                    probability: 0.005,
                    delay: ms(20),
                }),
                duplicate: Some(Duplicate {
                    probability: 0.001,
                    max_delay: ms(10),
                }),
                slot: Some(ms(2)),
                ..LinkConfig::default()
            }
        };
        Self {
            up: link(1.0),
            down: link(5.0),
        }
    }

    /// An overloaded cellular edge or a satellite link: 300 ms RTT, 25 ms Pareto jitter, 6 %
    /// loss in long bursts, 1.5/0.4 Mbit/s that keeps changing, 1 s of bufferbloat, heavy
    /// other traffic, spikes every 15 s, 1 s outages, reordering and duplicates.
    pub fn terrible() -> Self {
        let link = |rate: f64| {
            let steps = [
                (2000, 1.0),
                (1000, 0.4),
                (3000, 1.5),
                (1000, 0.6),
                (2000, 0.8),
            ];
            let mut bottleneck = Bottleneck::new(mbit(rate), Duration::from_secs(1));
            bottleneck.rates = steps
                .iter()
                .map(|&(duration, factor)| (ms(duration), mbit(rate * factor)))
                .collect();
            bottleneck.cross_traffic = Some(CrossTraffic {
                rate: mbit(rate * 0.5),
                active: Some(Episodes {
                    interval: Interval::Random(Duration::from_secs(6)),
                    duration: Duration::from_secs(3),
                }),
            });
            LinkConfig {
                delay: ms(150),
                jitter: Some(Jitter {
                    distribution: JitterDistribution::Pareto,
                    mean: ms(25),
                    correlation: ms(50),
                }),
                loss: Some(Loss::bursty(0.06, 5.0)),
                bottleneck: Some(bottleneck),
                spikes: Some(Spikes {
                    episodes: Episodes {
                        interval: Interval::Periodic(Duration::from_secs(15)),
                        duration: ms(300),
                    },
                    extra: ms(150),
                }),
                outages: Some(Episodes {
                    interval: Interval::Random(Duration::from_secs(30)),
                    duration: Duration::from_secs(1),
                }),
                reorder: Some(Reorder {
                    probability: 0.02,
                    delay: ms(50),
                }),
                duplicate: Some(Duplicate {
                    probability: 0.01,
                    max_delay: ms(30),
                }),
                slot: Some(ms(5)),
                ..LinkConfig::default()
            }
        };
        Self {
            up: link(0.4),
            down: link(1.5),
        }
    }

    /// The round-trip time without queueing, jitter and spikes.
    pub fn base_rtt(&self) -> Duration {
        self.up.delay + self.down.delay
    }

    /// Simulates both directions at the client, from `seed`: `up` for sent and `down` for
    /// received packets. Use `Client::set_simulator` or the `simulator` option.
    pub fn client(&self, seed: u64) -> Simulator {
        let (up, down) = self.links(seed);
        Simulator::new(up, down)
    }

    /// Simulates both directions at the server (all clients share the links), from `seed`:
    /// `down` for sent and `up` for received packets.
    pub fn server(&self, seed: u64) -> Simulator {
        let (up, down) = self.links(seed);
        Simulator::new(down, up)
    }

    /// The `up` and `down` links, from `seed`.
    pub fn links(&self, seed: u64) -> (Link, Link) {
        (
            Link::new(self.up.clone(), seed),
            Link::new(self.down.clone(), seed.wrapping_add(0x9e37_79b9_7f4a_7c15)),
        )
    }
}
