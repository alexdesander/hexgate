// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use rand_xoshiro::Xoshiro256PlusPlus;

use super::link::{Episodes, FAR_FUTURE, Schedule};

/// Size of a cross-traffic packet.
const CROSS_PACKET: usize = 1500;
/// Cross traffic further back than this is skipped when the link was idle.
const CROSS_HORIZON: Duration = Duration::from_secs(1);

/// The slowest part of a path: packets are sent one after another at `rates`, and wait in a
/// drop-tail buffer while the link is busy. A buffer much larger than the rate needs is
/// bufferbloat.
#[derive(Debug, Clone, PartialEq)]
pub struct Bottleneck {
    /// Bytes per second as `(duration, rate)` steps that repeat (e.g. a cellular link's
    /// changing capacity). A single step is a constant rate.
    pub rates: Vec<(Duration, u64)>,
    /// Bytes the buffer holds; a packet that doesn't fit is dropped.
    pub buffer: usize,
    /// Bytes added to every packet: 28 for IPv4 and UDP headers, 48 for IPv6.
    pub overhead: usize,
    /// Other traffic sharing the link.
    pub cross_traffic: Option<CrossTraffic>,
}

impl Bottleneck {
    /// A constant `rate` in bytes per second with a buffer for `buffer` of traffic at that rate,
    /// and IPv4 overhead.
    pub fn new(rate: u64, buffer: Duration) -> Self {
        Self {
            rates: vec![(Duration::from_secs(1), rate)],
            buffer: (rate as f64 * buffer.as_secs_f64()) as usize,
            overhead: 28,
            cross_traffic: None,
        }
    }
}

/// Inelastic traffic of other apps in the bottleneck (a download, a video call), sent as
/// 1500-byte packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrossTraffic {
    /// Bytes per second while active.
    pub rate: u64,
    /// When it is active, always if `None`.
    pub active: Option<Episodes>,
}

/// A FIFO bottleneck. Departures are computed on arrival: the rate schedule and stalls are
/// known in advance and nothing behind a packet delays it.
pub(super) struct Queue {
    rates: Vec<(Duration, u64)>,
    cycle: Duration,
    epoch: Instant,
    buffer: usize,
    /// When the link has sent everything queued.
    free_at: Instant,
    /// Departure and size of the queued packets.
    queued: VecDeque<(Instant, usize)>,
    backlog: usize,
    cross: Option<Cross>,
}

struct Cross {
    interval: Duration,
    active: Option<Schedule>,
    next: Instant,
}

impl Queue {
    pub fn new(config: &Bottleneck, now: Instant, rng: &mut Xoshiro256PlusPlus) -> Self {
        let rates = if config.rates.is_empty() {
            vec![(Duration::from_secs(1), u64::MAX)]
        } else {
            config.rates.clone()
        };
        let cross = config
            .cross_traffic
            .filter(|cross| cross.rate > 0)
            .map(|cross| Cross {
                interval: Duration::from_secs_f64(CROSS_PACKET as f64 / cross.rate as f64),
                active: cross
                    .active
                    .map(|episodes| Schedule::new(episodes, now, rng)),
                next: now,
            });
        Self {
            cycle: rates.iter().map(|(duration, _)| *duration).sum(),
            rates,
            epoch: now,
            buffer: config.buffer,
            free_at: now,
            queued: VecDeque::new(),
            backlog: 0,
            cross,
        }
    }

    /// The departure of a packet of `size` bytes arriving at `now`, `None` if the buffer is
    /// full.
    pub fn enqueue(
        &mut self,
        now: Instant,
        size: usize,
        mut stalls: Option<&mut Schedule>,
        rng: &mut Xoshiro256PlusPlus,
    ) -> Option<Instant> {
        self.cross_traffic(now, stalls.as_deref_mut(), rng);
        self.push(now, size, stalls, rng)
    }

    fn push(
        &mut self,
        at: Instant,
        size: usize,
        stalls: Option<&mut Schedule>,
        rng: &mut Xoshiro256PlusPlus,
    ) -> Option<Instant> {
        while let Some(&(departure, size)) = self.queued.front() {
            if departure > at {
                break;
            }
            self.backlog -= size;
            self.queued.pop_front();
        }
        // The packet being sent doesn't occupy the buffer.
        let waiting = self.backlog - self.queued.front().map_or(0, |&(_, size)| size);
        if !self.queued.is_empty() && waiting.saturating_add(size) > self.buffer {
            return None;
        }
        let departure = self.serve(at.max(self.free_at), size, stalls, rng);
        self.free_at = departure;
        self.queued.push_back((departure, size));
        self.backlog += size;
        Some(departure)
    }

    /// Adds the cross traffic that arrived until `now`.
    fn cross_traffic(
        &mut self,
        now: Instant,
        mut stalls: Option<&mut Schedule>,
        rng: &mut Xoshiro256PlusPlus,
    ) {
        let Some(mut cross) = self.cross.take() else {
            return;
        };
        cross.next = cross
            .next
            .max(now.checked_sub(CROSS_HORIZON).unwrap_or(now));
        while cross.next <= now {
            if let Some(active) = &mut cross.active {
                let episode = active.at(cross.next, rng);
                if !episode.contains(&cross.next) {
                    cross.next = episode.start;
                    continue;
                }
            }
            self.push(cross.next, CROSS_PACKET, stalls.as_deref_mut(), rng);
            cross.next += cross.interval;
        }
        self.cross = Some(cross);
    }

    /// When `size` bytes starting at `start` are sent, through rate steps and stalls.
    fn serve(
        &self,
        start: Instant,
        size: usize,
        mut stalls: Option<&mut Schedule>,
        rng: &mut Xoshiro256PlusPlus,
    ) -> Instant {
        let mut t = start;
        let mut left = size as f64;
        loop {
            let mut segment_end = t + FAR_FUTURE;
            if let Some(stalls) = stalls.as_deref_mut() {
                let stall = stalls.at(t, rng);
                if stall.contains(&t) {
                    t = stall.end;
                    continue;
                }
                segment_end = stall.start;
            }
            let (rate, step_end) = self.rate_at(t);
            segment_end = segment_end.min(step_end);
            let rate = rate.max(1) as f64;
            let needed = Duration::from_secs_f64((left / rate).min(FAR_FUTURE.as_secs_f64()));
            if t + needed <= segment_end {
                return t + needed;
            }
            left -= rate * (segment_end - t).as_secs_f64();
            t = segment_end;
        }
    }

    /// The rate at `t` and when it changes.
    fn rate_at(&self, t: Instant) -> (u64, Instant) {
        if self.rates.len() == 1 || self.cycle.is_zero() {
            return (self.rates[0].1, t + FAR_FUTURE);
        }
        let cycle = self.cycle.as_nanos();
        let mut offset = (t - self.epoch).as_nanos() % cycle;
        for &(duration, rate) in &self.rates {
            let duration = duration.as_nanos();
            if offset < duration {
                return (rate, t + Duration::from_nanos((duration - offset) as u64));
            }
            offset -= duration;
        }
        unreachable!("the offset is within the cycle")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn buffer_excludes_the_packet_currently_being_serialized() {
        let now = Instant::now();
        let config = Bottleneck {
            buffer: 1028,
            ..Bottleneck::new(102_800, Duration::ZERO)
        };
        let mut rng = Xoshiro256PlusPlus::seed_from_u64(1);
        let mut queue = Queue::new(&config, now, &mut rng);
        assert_eq!(
            queue.enqueue(now, 1028, None, &mut rng),
            Some(now + Duration::from_millis(10))
        );
        assert_eq!(
            queue.enqueue(now, 1028, None, &mut rng),
            Some(now + Duration::from_millis(20))
        );
        assert_eq!(queue.enqueue(now, 1, None, &mut rng), None);
        assert_eq!(
            queue.enqueue(now + Duration::from_millis(5), 1, None, &mut rng),
            None
        );
        assert_eq!(
            queue.enqueue(now + Duration::from_millis(10), 1028, None, &mut rng),
            Some(now + Duration::from_millis(30))
        );
        assert_eq!(
            queue.enqueue(now + Duration::from_millis(10), 1, None, &mut rng),
            None
        );
    }

    #[test]
    fn zero_buffer_admits_only_when_the_link_is_idle() {
        let now = Instant::now();
        let config = Bottleneck::new(100_000, Duration::ZERO);
        let mut rng = Xoshiro256PlusPlus::seed_from_u64(1);
        let mut queue = Queue::new(&config, now, &mut rng);
        assert_eq!(
            queue.enqueue(now, 1000, None, &mut rng),
            Some(now + Duration::from_millis(10))
        );
        assert_eq!(queue.enqueue(now, 1, None, &mut rng), None);
        assert_eq!(
            queue.enqueue(now + Duration::from_millis(10), 1000, None, &mut rng),
            Some(now + Duration::from_millis(20))
        );
    }
}
