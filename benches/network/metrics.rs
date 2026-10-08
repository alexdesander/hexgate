// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Turns a run's send and arrival times into the reported numbers.

use std::time::Duration;

use hexgate::{
    Channel, Stats,
    sim::{LinkStats, Profile},
};
use serde::Serialize;

use crate::{
    run::{Arrival, RawRun, StreamRecord},
    workloads::{Dir, Pattern, Stream, Workload},
};

/// An arrival gap this much longer than the send interval is a stall (Pudica's 100 ms for
/// realtime streams).
const STALL_MS: f64 = 100.0;

#[derive(Serialize)]
pub struct RunResult {
    pub workload: &'static str,
    pub profile: &'static str,
    pub connected: bool,
    pub connect_ms: Option<f64>,
    /// The connect error, or why the connection ended during the run.
    pub error: Option<String>,
    pub duration_s: f64,
    pub streams: Vec<StreamResult>,
    pub link_up: LinkSummary,
    pub link_down: LinkSummary,
    /// Delivered message bytes per datagram byte sent (both directions, all packets).
    pub wire_efficiency: Option<f64>,
    /// hexgate's statistics at the end of the send phase.
    pub client_stats: Option<StatsSummary>,
    pub server_stats: Option<StatsSummary>,
}

#[derive(Serialize)]
pub struct StreamResult {
    pub name: &'static str,
    pub dir: Dir,
    pub channel: String,
    pub key: bool,
    pub round_trip: bool,
    pub sent: u64,
    pub backpressured: u64,
    pub delivered: u64,
    /// Delivered / sent, 0..1.
    pub delivery: f64,
    pub sent_bytes: u64,
    pub delivered_bytes: u64,
    pub offered_mbit: f64,
    /// Message bytes that arrived during the send phase, per second.
    pub goodput_mbit: f64,
    /// From `send()` to `Received` (round trips for ping streams).
    pub latency_ms: Option<Percentiles>,
    /// Latency minus the profile's base delay (one way or round trip): what queueing,
    /// jitter, retransmission and hexgate add.
    pub added_ms: Option<Added>,
    /// RFC 3550 interarrival jitter.
    pub jitter_ms: Option<f64>,
    /// Longest gap between arrivals during the send phase (periodic streams).
    pub max_gap_ms: Option<f64>,
    /// Arrival gaps over the send interval + 100 ms, per minute (periodic streams).
    pub stalls_per_min: Option<f64>,
    pub bursts: Option<Bursts>,
    pub duplicates: u64,
    pub reordered: u64,
    pub corrupt: u64,
    /// Broken guarantees: duplicates, corruption, reordering on ordered channels.
    pub violations: Vec<String>,
}

#[derive(Serialize, Clone, Copy)]
pub struct Percentiles {
    pub min: f64,
    pub p50: f64,
    pub p90: f64,
    pub p99: f64,
    pub p999: f64,
    pub max: f64,
    pub mean: f64,
}

#[derive(Serialize)]
pub struct Added {
    pub p50: f64,
    pub p99: f64,
}

#[derive(Serialize)]
pub struct Bursts {
    pub sent: u64,
    pub complete: u64,
    /// From sending a burst until its last message arrived.
    pub completion_ms: Option<Percentiles>,
}

#[derive(Serialize)]
pub struct LinkSummary {
    pub packets: u64,
    pub bytes: u64,
    pub lost: u64,
    pub lost_outage: u64,
    pub lost_queue: u64,
    pub corrupted: u64,
    pub reordered: u64,
    pub duplicated: u64,
    /// All drops / packets, 0..1.
    pub drop_rate: f64,
    pub mean_queue_ms: f64,
    pub max_queue_ms: f64,
}

#[derive(Serialize)]
pub struct StatsSummary {
    pub rtt_ms: Option<f64>,
    pub min_rtt_ms: Option<f64>,
    pub rtt_var_ms: f64,
    pub queue_delay_ms: f64,
    pub packet_loss: f32,
    pub send_rate_mbit: f64,
    pub delivery_rate_mbit: f64,
    pub congestion: Option<String>,
    pub queued_bytes: usize,
    pub expired_messages: u64,
}

fn ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

pub fn channel_name(channel: Channel) -> String {
    match channel {
        Channel::Unreliable => "unrel".into(),
        Channel::UnreliableOrdered(id) => format!("ord{id}"),
        Channel::Reliable(id) => format!("rel{id}"),
        Channel::ReliableUnordered(id) => format!("unord{id}"),
    }
}

/// Nearest-rank percentiles of sorted values.
fn percentiles(sorted: &[f64]) -> Option<Percentiles> {
    let at =
        |p: f64| sorted[((p * sorted.len() as f64).ceil() as usize).clamp(1, sorted.len()) - 1];
    (!sorted.is_empty()).then(|| Percentiles {
        min: sorted[0],
        p50: at(0.5),
        p90: at(0.9),
        p99: at(0.99),
        p999: at(0.999),
        max: sorted[sorted.len() - 1],
        mean: sorted.iter().sum::<f64>() / sorted.len() as f64,
    })
}

fn sorted(mut values: Vec<f64>) -> Vec<f64> {
    values.sort_by(f64::total_cmp);
    values
}

pub fn evaluate(
    workload: &Workload,
    profile_name: &'static str,
    profile: &Profile,
    raw: RawRun,
) -> RunResult {
    let duration_s = raw.end_us.saturating_sub(raw.start_us) as f64 / 1e6;
    let streams: Vec<StreamResult> = workload
        .streams
        .iter()
        .zip(&raw.streams)
        .map(|(spec, record)| stream(spec, workload.key, profile, record, &raw, duration_s))
        .collect();
    let datagram_bytes = raw.up.bytes + raw.down.bytes;
    let delivered: u64 = streams.iter().map(|stream| stream.delivered_bytes).sum();
    RunResult {
        workload: workload.name,
        profile: profile_name,
        connected: raw.connect.is_ok(),
        connect_ms: raw.connect.as_ref().ok().copied().map(ms),
        error: raw.connect.err().or(raw.ended),
        duration_s,
        streams,
        link_up: link(&raw.up),
        link_down: link(&raw.down),
        wire_efficiency: (datagram_bytes > 0).then(|| delivered as f64 / datagram_bytes as f64),
        client_stats: raw.client_stats.map(stats),
        server_stats: raw.server_stats.map(stats),
    }
}

fn stream(
    spec: &Stream,
    key: &str,
    profile: &Profile,
    record: &StreamRecord,
    raw: &RawRun,
    duration_s: f64,
) -> StreamResult {
    let round_trip = matches!(spec.pattern, Pattern::PingPong { .. });
    let mut seen = Vec::<bool>::new();
    let mut unique: Vec<Arrival> = Vec::with_capacity(record.arrivals.len());
    let (mut duplicates, mut reordered, mut highest) = (0, 0, None);
    for &arrival in &record.arrivals {
        let seq = arrival.seq as usize;
        if seen.len() <= seq {
            seen.resize(seq + 1, false);
        }
        if std::mem::replace(&mut seen[seq], true) {
            duplicates += 1;
            continue;
        }
        if highest.is_some_and(|highest| arrival.seq < highest) {
            reordered += 1;
        }
        highest = highest.max(Some(arrival.seq));
        unique.push(arrival);
    }

    let delivered_bytes: u64 = unique.iter().map(|arrival| u64::from(arrival.len)).sum();
    let in_phase = |arrival: &&Arrival| (raw.start_us..=raw.end_us).contains(&arrival.recv_us);
    let phase_bytes: u64 = unique
        .iter()
        .filter(in_phase)
        .map(|arrival| u64::from(arrival.len))
        .sum();
    let latencies = sorted(
        unique
            .iter()
            .map(|arrival| arrival.recv_us.saturating_sub(arrival.sent_us) as f64 / 1000.0)
            .collect(),
    );
    let latency = percentiles(&latencies);
    let base = ms(match (round_trip, spec.dir) {
        (true, _) => profile.base_rtt(),
        (false, Dir::Up) => profile.up.delay,
        (false, Dir::Down) => profile.down.delay,
    });

    let jitter = (unique.len() > 1).then(|| {
        unique.windows(2).fold(0.0, |jitter, pair| {
            let transit = |arrival: &Arrival| arrival.recv_us as f64 - arrival.sent_us as f64;
            let d = (transit(&pair[1]) - transit(&pair[0])).abs() / 1000.0;
            jitter + (d - jitter) / 16.0
        })
    });

    let interval_ms = spec.pattern.interval().map(ms);
    let gaps: Option<Vec<f64>> = interval_ms.map(|_| {
        let times: Vec<u64> = std::iter::once(raw.start_us)
            .chain(
                unique
                    .iter()
                    .filter(in_phase)
                    .map(|arrival| arrival.recv_us),
            )
            .chain(std::iter::once(raw.end_us))
            .collect();
        times
            .windows(2)
            .map(|pair| pair[1].saturating_sub(pair[0]) as f64 / 1000.0)
            .collect()
    });
    let max_gap = gaps
        .as_ref()
        .map(|gaps| gaps.iter().copied().fold(0.0, f64::max));
    let stalls = gaps.as_ref().zip(interval_ms).map(|(gaps, interval)| {
        let stalls = gaps
            .iter()
            .filter(|&&gap| gap > interval + STALL_MS)
            .count();
        stalls as f64 / (duration_s / 60.0)
    });

    let bursts = match spec.pattern {
        Pattern::Bursts { count, .. } => Some(bursts(&unique, record.sent, count)),
        _ => None,
    };

    let ordered = !matches!(spec.channel, Channel::Unreliable);
    let mut violations = Vec::new();
    if duplicates > 0 {
        violations.push(format!("{duplicates} duplicates"));
    }
    if record.corrupt > 0 {
        violations.push(format!("{} corrupt messages", record.corrupt));
    }
    if ordered && reordered > 0 {
        violations.push(format!("{reordered} out of order"));
    }

    StreamResult {
        name: spec.name,
        dir: spec.dir,
        channel: channel_name(spec.channel),
        key: spec.name == key,
        round_trip,
        sent: record.sent,
        backpressured: record.backpressured,
        delivered: unique.len() as u64,
        delivery: if record.sent == 0 {
            0.0
        } else {
            unique.len() as f64 / record.sent as f64
        },
        sent_bytes: record.sent_bytes,
        delivered_bytes,
        offered_mbit: record.sent_bytes as f64 * 8.0 / 1e6 / duration_s,
        goodput_mbit: phase_bytes as f64 * 8.0 / 1e6 / duration_s,
        added_ms: latency.map(|latency| Added {
            p50: latency.p50 - base,
            p99: latency.p99 - base,
        }),
        latency_ms: latency,
        jitter_ms: jitter,
        max_gap_ms: max_gap,
        stalls_per_min: stalls,
        bursts,
        duplicates,
        reordered,
        corrupt: record.corrupt,
        violations,
    }
}

/// Completion times of bursts of `count` messages (sequence numbers `k·count..(k+1)·count`).
fn bursts(unique: &[Arrival], sent: u64, count: usize) -> Bursts {
    let bursts = sent.div_ceil(count as u64) as usize;
    // Earliest send, latest arrival, arrivals.
    let mut groups = vec![(u64::MAX, 0, 0); bursts];
    for arrival in unique {
        if let Some(group) = groups.get_mut(arrival.seq as usize / count) {
            group.0 = group.0.min(arrival.sent_us);
            group.1 = group.1.max(arrival.recv_us);
            group.2 += 1;
        }
    }
    let times = sorted(
        groups
            .iter()
            .filter(|group| group.2 == count)
            .map(|group| (group.1 - group.0) as f64 / 1000.0)
            .collect(),
    );
    Bursts {
        sent: bursts as u64,
        complete: times.len() as u64,
        completion_ms: percentiles(&times),
    }
}

fn link(stats: &LinkStats) -> LinkSummary {
    let dropped = stats.lost + stats.lost_outage + stats.lost_queue;
    LinkSummary {
        packets: stats.packets,
        bytes: stats.bytes,
        lost: stats.lost,
        lost_outage: stats.lost_outage,
        lost_queue: stats.lost_queue,
        corrupted: stats.corrupted,
        reordered: stats.reordered,
        duplicated: stats.duplicated,
        drop_rate: if stats.packets == 0 {
            0.0
        } else {
            dropped as f64 / stats.packets as f64
        },
        mean_queue_ms: ms(stats.mean_queue_delay()),
        max_queue_ms: ms(stats.max_queue_delay),
    }
}

fn stats(stats: Stats) -> StatsSummary {
    StatsSummary {
        rtt_ms: stats.rtt.map(ms),
        min_rtt_ms: stats.min_rtt.map(ms),
        rtt_var_ms: ms(stats.rtt_var),
        queue_delay_ms: ms(stats.queue_delay),
        packet_loss: stats.packet_loss,
        send_rate_mbit: stats.send_rate as f64 * 8.0 / 1e6,
        delivery_rate_mbit: stats.delivery_rate as f64 * 8.0 / 1e6,
        congestion: stats.congestion.map(|congestion| format!("{congestion:?}")),
        queued_bytes: stats.queued_bytes,
        expired_messages: stats.expired_messages,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn periodic_gaps_include_both_observation_boundaries() {
        use super::*;
        use crate::workloads::Size;
        let spec = Stream {
            name: "ticks",
            dir: Dir::Up,
            channel: Channel::Unreliable,
            pattern: Pattern::Periodic {
                hz: 64.0,
                size: Size::Fixed(100),
            },
        };
        let raw = RawRun {
            connect: Ok(Duration::ZERO),
            ended: None,
            start_us: 1_000_000,
            end_us: 11_000_000,
            streams: Vec::new(),
            client_stats: None,
            server_stats: None,
            up: LinkStats::default(),
            down: LinkStats::default(),
        };
        for (times, expected_gap, expected_stalls) in [
            (vec![], 10_000.0, 6.0),
            (vec![1_010_000], 9990.0, 6.0),
            (vec![10_990_000], 9990.0, 6.0),
            (vec![6_000_000], 5000.0, 12.0),
            (vec![11_100_000], 10_000.0, 6.0),
        ] {
            let record = StreamRecord {
                sent: 640,
                backpressured: 0,
                sent_bytes: 64_000,
                corrupt: 0,
                arrivals: times
                    .into_iter()
                    .enumerate()
                    .map(|(seq, recv_us)| Arrival {
                        seq: seq as u32,
                        sent_us: raw.start_us,
                        recv_us,
                        len: 100,
                    })
                    .collect(),
            };
            let result = stream(&spec, spec.name, &Profile::perfect(), &record, &raw, 10.0);
            assert_eq!(result.max_gap_ms, Some(expected_gap));
            assert_eq!(result.stalls_per_min, Some(expected_stalls));
        }
    }
}
