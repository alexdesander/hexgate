#![cfg(feature = "bench")]

use hexgate::sim::{Fate, NetworkSimulator};
use hexgate::{
    Channel, ChannelConfiguration, CongestionConfig, SendOptions,
    bench::{Delivery, Pairs, Side},
    sim::{Bottleneck, Link, LinkConfig},
};
use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

#[test]
fn game_ticks_do_not_build_a_standing_queue() {
    for (hz, size, capacity) in [
        (64, 700, 48_000),
        (60, 1250, 80_000),
        (30, 700, 24_000),
        (128, 700, 96_000),
        (60, 1250, 100_000),
    ] {
        for (buffer_ms, variable_sizes) in [(30, false), (500, false), (30, true), (500, true)] {
            let mut pairs = Pairs::new();
            let link = LinkConfig {
                delay: Duration::from_millis(20),
                bottleneck: Some(Bottleneck::new(capacity, Duration::from_millis(buffer_ms))),
                ..LinkConfig::default()
            };
            let link = Link::new(link, 1);
            pairs.add(
                ChannelConfiguration::default(),
                CongestionConfig::default(),
                Some(Box::new(link.clone())),
                Some(Box::new(Link::new(
                    LinkConfig {
                        delay: Duration::from_millis(20),
                        ..LinkConfig::default()
                    },
                    2,
                ))),
            );
            let epoch = pairs.now();
            let mut latencies = Vec::new();
            for tick in 0..hz * 120 {
                let actual_size = if variable_sizes {
                    size * [4, 5, 6][tick as usize % 3] / 5
                } else {
                    size
                };
                let mut message = vec![0; actual_size];
                message[..8].copy_from_slice(&(pairs.elapsed().as_micros() as u64).to_le_bytes());
                if variable_sizes {
                    pairs.send_with(
                        0,
                        Side::Client,
                        Channel::Unreliable,
                        message,
                        SendOptions {
                            deadline: Some(pairs.now() + Duration::from_millis(100)),
                            ..SendOptions::default()
                        },
                    );
                } else {
                    pairs.send(0, Side::Client, Channel::Unreliable, message);
                }
                pairs.run(
                    epoch + Duration::from_secs_f64((tick + 1) as f64 / hz as f64),
                    &mut |_, _, at, d| {
                        if let Delivery::Message(m) = d {
                            if at.duration_since(epoch) > Duration::from_secs(100) {
                                let sent = u64::from_le_bytes(m[..8].try_into().unwrap());
                                latencies.push(at.duration_since(epoch).as_micros() as u64 - sent);
                            }
                        } else {
                            panic!("{d:?}");
                        }
                    },
                );
            }
            latencies.sort_unstable();
            assert!(
                latencies.len() > hz as usize * 10,
                "no progress: {hz}/{size}/{buffer_ms}: count={} stats={:?}",
                latencies.len(),
                pairs.stats(0, Side::Client)
            );
            let p95 = latencies[latencies.len() * 95 / 100];
            eprintln!(
                "{hz}/{size}/{capacity}/{buffer_ms} variable={variable_sizes}: p95={p95}us count={} max_queue={:?}",
                latencies.len(),
                link.stats().max_queue_delay
            );
            assert!(
                p95 < 160_000,
                "{hz}/{size}/{capacity}/{buffer_ms} variable={variable_sizes}: p95={p95}us stats={:?}",
                pairs.stats(0, Side::Client)
            );
        }
    }
}

#[test]
fn reliable_sentinel_progresses_during_capacity_drop_and_realtime_traffic() {
    let mut pairs = Pairs::new();
    let bottleneck = Bottleneck {
        rates: vec![
            (Duration::from_secs(3), 1_000_000),
            (Duration::from_secs(30), 100_000),
        ],
        buffer: 50_000,
        overhead: 28,
        cross_traffic: None,
    };
    pairs.add(
        ChannelConfiguration {
            weights_reliable: vec![1, 1],
            ..ChannelConfiguration::default()
        },
        CongestionConfig::default(),
        Some(Box::new(Link::new(
            LinkConfig {
                delay: Duration::from_millis(20),
                bottleneck: Some(bottleneck),
                ..LinkConfig::default()
            },
            3,
        ))),
        Some(Box::new(Link::new(
            LinkConfig {
                delay: Duration::from_millis(20),
                ..LinkConfig::default()
            },
            4,
        ))),
    );
    let epoch = pairs.now();
    for _ in 0..8 {
        pairs.send(0, Side::Client, Channel::Reliable(0), vec![3; 1 << 20]);
    }
    let mut sentinel = None;
    for ms in 0u64..20_000 {
        if ms % 17 == 0 {
            pairs.send(0, Side::Client, Channel::Unreliable, vec![1; 800]);
        }
        if ms == 7000 {
            pairs.send(0, Side::Client, Channel::Reliable(1), vec![42]);
        }
        pairs.run(epoch + Duration::from_millis(ms + 1), &mut |_, _, at, d| {
            if let Delivery::Message(m) = d {
                if m == [42] {
                    sentinel = Some(at);
                }
            } else {
                panic!("{d:?}");
            }
        });
    }
    assert!(
        sentinel.is_some_and(|at| at < epoch + Duration::from_secs(9)),
        "{sentinel:?}"
    );
}

struct DelayedLink {
    link: Link,
    extra: Duration,
}

impl NetworkSimulator for DelayedLink {
    fn simulate(&mut self, now: Instant, peer: SocketAddr, packet: &mut [u8]) -> Fate {
        match self.link.simulate(now, peer, packet) {
            Fate::Drop => Fate::Drop,
            Fate::Deliver(at) => Fate::Deliver(at + self.extra),
            Fate::Duplicate(a, b) => Fate::Duplicate(a + self.extra, b + self.extra),
        }
    }
}

fn clean_link(rate: u64, seed: u64) -> Link {
    Link::new(
        LinkConfig {
            delay: Duration::from_millis(20),
            bottleneck: Some(Bottleneck::new(rate, Duration::from_millis(200))),
            ..LinkConfig::default()
        },
        seed,
    )
}

#[test]
fn mixed_gameplay_keeps_latency_low_while_bulk_progresses() {
    let mut pairs = Pairs::new();
    pairs.add(
        ChannelConfiguration::default(),
        CongestionConfig::default(),
        Some(Box::new(clean_link(1_250_000, 1))),
        Some(Box::new(clean_link(1_250_000, 2))),
    );
    let epoch = pairs.now();
    let mut latencies = Vec::new();
    let mut bulk_bytes = 0;
    for ms in 0u64..20_000 {
        if pairs.stats(0, Side::Server).queued_bytes < 512 * 1024 {
            pairs.send(0, Side::Server, Channel::Reliable(0), vec![0; 64 * 1024]);
        }
        if ms % 16 == 0 {
            let mut message = vec![1; 700];
            message[..8].copy_from_slice(&ms.to_le_bytes());
            pairs.send(0, Side::Server, Channel::Unreliable, message);
        }
        pairs.run(
            epoch + Duration::from_millis(ms + 1),
            &mut |_, _, at, delivery| match delivery {
                Delivery::Message(message) if message.len() == 700 => {
                    let sent = u64::from_le_bytes(message[..8].try_into().unwrap());
                    latencies.push(at.duration_since(epoch).as_millis() as u64 - sent);
                }
                Delivery::Message(message) => bulk_bytes += message.len(),
                other => panic!("unexpected connection event: {other:?}"),
            },
        );
    }
    latencies.sort_unstable();
    assert!(latencies.len() > 1200);
    assert!(latencies[latencies.len() * 99 / 100] < 70, "{latencies:?}");
    assert!(bulk_bytes > 15_000_000, "bulk stalled: {bulk_bytes}");
}

#[test]
fn shared_bottleneck_converges_with_different_rtts_and_congested_feedback() {
    for reverse_rate in [1_250_000, 12_500] {
        let mut pairs = Pairs::new();
        let up = clean_link(reverse_rate, 1);
        let down = clean_link(1_250_000, 2);
        for extra in [0, 20, 50] {
            pairs.add(
                ChannelConfiguration::default(),
                CongestionConfig::default(),
                Some(Box::new(DelayedLink {
                    link: up.clone(),
                    extra: Duration::from_millis(extra),
                })),
                Some(Box::new(DelayedLink {
                    link: down.clone(),
                    extra: Duration::from_millis(extra),
                })),
            );
        }
        let epoch = pairs.now();
        let mut bytes = [0u64; 3];
        for ms in 0..30_000 {
            for pair in 0..3 {
                if ms >= pair as u64 * 5000
                    && pairs.stats(pair, Side::Server).queued_bytes < 512 * 1024
                {
                    pairs.send(pair, Side::Server, Channel::Reliable(0), vec![0; 16 * 1024]);
                }
            }
            pairs.run(
                epoch + Duration::from_millis(ms + 1),
                &mut |pair, _, at, delivery| match delivery {
                    Delivery::Message(message) if at >= epoch + Duration::from_secs(20) => {
                        bytes[pair] += message.len() as u64
                    }
                    Delivery::Message(_) => {}
                    other => panic!("unexpected connection event: {other:?}"),
                },
            );
        }
        let sum = bytes.iter().sum::<u64>() as f64;
        let fairness = sum * sum
            / (3.0
                * bytes
                    .iter()
                    .map(|&bytes| (bytes as f64).powi(2))
                    .sum::<f64>());
        assert!(bytes.iter().all(|&bytes| bytes > 200_000), "{bytes:?}");
        assert!(
            fairness > 0.9,
            "reverse={reverse_rate}: Jain={fairness}, bytes={bytes:?}"
        );
    }
}
