// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{
    net::SocketAddr,
    ops::Range,
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use rand::{Rng, SeedableRng};
use rand_distr::{Distribution, Exp1, Pareto, StandardNormal};
use rand_xoshiro::Xoshiro256PlusPlus;

use super::{
    Fate, NetworkSimulator,
    bottleneck::{Bottleneck, Queue},
};

/// Shape parameter of the Pareto (Lomax) jitter, finite mean and variance.
const PARETO_SHAPE: f64 = 3.0;
/// Further than any simulated time, used for "never".
pub(super) const FAR_FUTURE: Duration = Duration::from_secs(365 * 24 * 3600);
/// Episodes start at least this far apart.
const MIN_INTERVAL: Duration = Duration::from_millis(1);

/// The conditions of one direction of a network path. `LinkConfig::default()` is a perfect
/// link: no loss, no delay, unlimited rate.
///
/// A packet goes through the stages in this order: outages, loss, corruption, the bottleneck
/// queue (and stalls), propagation delay with jitter and spikes, reordering, slotting,
/// duplication. Packets keep their order unless `reorder` is set.
#[derive(Debug, Clone, Default)]
pub struct LinkConfig {
    /// One-way propagation delay, the minimum delay of every packet.
    pub delay: Duration,
    /// Random extra delay per packet.
    pub jitter: Option<Jitter>,
    /// Random loss.
    pub loss: Option<Loss>,
    /// Probability that a packet has one bit flipped.
    pub corrupt: f64,
    /// A rate-limited link with a buffer, which queues and drops packets.
    pub bottleneck: Option<Bottleneck>,
    /// Episodes of extra delay (Wi-Fi interference, satellite reconfigurations).
    pub spikes: Option<Spikes>,
    /// Episodes in which the link holds packets back and then releases them at once (Wi-Fi
    /// retransmissions, cellular handovers).
    pub stalls: Option<Episodes>,
    /// Episodes in which every packet is lost.
    pub outages: Option<Episodes>,
    /// Packets that overtake others.
    pub reorder: Option<Reorder>,
    /// Packets that arrive twice.
    pub duplicate: Option<Duplicate>,
    /// Deliveries are rounded up to multiples of this, like the frame aggregation of Wi-Fi, LTE
    /// and DOCSIS (netem's `slot`).
    pub slot: Option<Duration>,
}

/// Random extra delay on top of [`LinkConfig::delay`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Jitter {
    /// The shape of the distribution.
    pub distribution: JitterDistribution,
    /// The mean extra delay.
    pub mean: Duration,
    /// Retain the previous jitter with probability `exp(-elapsed / correlation)`, otherwise
    /// draw from the configured distribution, preserving its variance at every packet rate
    /// Zero draws independently; the default ordering still holds back overtaking packets
    pub correlation: Duration,
}

/// Distributions of [`Jitter`], all non-negative with the configured mean.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JitterDistribution {
    /// Uniform between 0 and twice the mean.
    Uniform,
    /// Half-normal: the absolute value of a normal distribution.
    Normal,
    /// Exponential, like GameNetworkingSockets' fake jitter.
    Exponential,
    /// Pareto (Lomax with shape 3), a long tail of rare large delays.
    Pareto,
    /// A quarter normal and three quarters Pareto, like netem's `paretonormal`.
    ParetoNormal,
}

/// Gilbert-Elliott loss (netem's `gemodel`): the link alternates between a good and a bad
/// state, each with its own loss probability. Transitions happen per packet.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Loss {
    /// Probability to change from the good to the bad state.
    pub p: f64,
    /// Probability to change from the bad to the good state.
    pub r: f64,
    /// Loss probability in the bad state (netem's `1-h`).
    pub bad: f64,
    /// Loss probability in the good state (netem's `1-k`).
    pub good: f64,
}

impl Loss {
    /// Each packet is lost with probability `rate`, independently.
    pub fn random(rate: f64) -> Self {
        Self {
            p: 0.0,
            r: 1.0,
            bad: 1.0,
            good: rate,
        }
    }

    /// A fraction `rate` of the packets is lost, in bursts of `mean_burst` packets on average.
    pub fn bursty(rate: f64, mean_burst: f64) -> Self {
        let r = 1.0 / mean_burst.max(1.0);
        Self {
            p: rate * r / (1.0 - rate),
            r,
            bad: 1.0,
            good: 0.0,
        }
    }
}

/// When episodes (spikes, stalls, outages) happen and how long they last.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Episodes {
    /// Time between the starts of two episodes.
    pub interval: Interval,
    /// How long each episode lasts.
    pub duration: Duration,
}

/// Time between episodes, see [`Episodes`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Interval {
    /// Exactly this period, starting at a random phase (e.g. Starlink's 15 s reconfigurations).
    Periodic(Duration),
    /// Exponentially distributed with this mean (a Poisson process).
    Random(Duration),
}

/// Extra delay during episodes, see [`LinkConfig::spikes`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Spikes {
    /// When spikes happen.
    pub episodes: Episodes,
    /// The extra delay of packets sent during a spike.
    pub extra: Duration,
}

/// Packets that overtake others, see [`LinkConfig::reorder`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Reorder {
    /// Probability that a packet takes another route.
    pub probability: f64,
    /// Its extra delay; the packets sent within this time overtake it.
    pub delay: Duration,
}

/// Packets that arrive twice, see [`LinkConfig::duplicate`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Duplicate {
    /// Probability that a packet is duplicated.
    pub probability: f64,
    /// The copy arrives up to this much after the original.
    pub max_delay: Duration,
}

/// What a [`Link`] did with its packets.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LinkStats {
    /// Packets handed to the link.
    pub packets: u64,
    /// Their bytes (UDP payload).
    pub bytes: u64,
    /// Packets lost to [`LinkConfig::loss`].
    pub lost: u64,
    /// Packets lost to [`LinkConfig::outages`].
    pub lost_outage: u64,
    /// Packets dropped by the full bottleneck buffer.
    pub lost_queue: u64,
    /// Packets with a flipped bit.
    pub corrupted: u64,
    /// Packets that overtook others.
    pub reordered: u64,
    /// Packets that arrived twice.
    pub duplicated: u64,
    /// Total time the delivered packets waited in the bottleneck or a stall.
    pub queue_delay: Duration,
    /// The longest of those waits.
    pub max_queue_delay: Duration,
}

impl LinkStats {
    /// Packets that were not lost or dropped (without duplicates).
    pub fn delivered(&self) -> u64 {
        self.packets - self.lost - self.lost_outage - self.lost_queue
    }

    /// Average wait of the delivered packets in the bottleneck or a stall.
    pub fn mean_queue_delay(&self) -> Duration {
        match self.delivered() {
            0 => Duration::ZERO,
            delivered => self.queue_delay.div_f64(delivered as f64),
        }
    }
}

/// One direction of a simulated network path, a [`NetworkSimulator`] for [`LinkConfig`].
///
/// Clones share the link: sockets with clones of one link share its bottleneck (like players
/// behind one router), and a clone kept by the app reads [`Link::stats`]. All random decisions
/// come from `seed`, so a run with the same seed and timing sees the same decisions.
#[derive(Clone)]
pub struct Link(Arc<Mutex<LinkState>>);

impl Link {
    /// A new link, its schedules (rate steps, episodes) start now.
    pub fn new(config: LinkConfig, seed: u64) -> Self {
        let now = Instant::now();
        let mut rng = Xoshiro256PlusPlus::seed_from_u64(seed);
        let mut schedule = |episodes: Option<Episodes>| {
            episodes.map(|episodes| Schedule::new(episodes, now, &mut rng))
        };
        let spikes = schedule(config.spikes.map(|spikes| spikes.episodes));
        let stalls = schedule(config.stalls);
        let outages = schedule(config.outages);
        let queue = config
            .bottleneck
            .as_ref()
            .map(|bottleneck| Queue::new(bottleneck, now, &mut rng));
        Self(Arc::new(Mutex::new(LinkState {
            config,
            rng,
            epoch: now,
            last_now: now,
            bad_state: false,
            jitter: None,
            queue,
            spikes,
            stalls,
            outages,
            last_delivery: now,
            stats: LinkStats::default(),
        })))
    }

    /// What the link did so far.
    pub fn stats(&self) -> LinkStats {
        self.state().stats
    }

    fn state(&self) -> std::sync::MutexGuard<'_, LinkState> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl std::fmt::Debug for Link {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.state();
        f.debug_struct("Link")
            .field("config", &state.config)
            .field("stats", &state.stats)
            .finish()
    }
}

impl NetworkSimulator for Link {
    fn simulate(&mut self, now: Instant, _: SocketAddr, packet: &mut [u8]) -> Fate {
        self.state().simulate(now, packet)
    }
}

struct LinkState {
    config: LinkConfig,
    rng: Xoshiro256PlusPlus,
    epoch: Instant,
    /// Shared links get `now` from several threads, it never goes back.
    last_now: Instant,
    bad_state: bool,
    /// The previous jitter in seconds and when it was drawn, for the correlation.
    jitter: Option<(f64, Instant)>,
    queue: Option<Queue>,
    spikes: Option<Schedule>,
    stalls: Option<Schedule>,
    outages: Option<Schedule>,
    last_delivery: Instant,
    stats: LinkStats,
}

impl LinkState {
    fn simulate(&mut self, now: Instant, packet: &mut [u8]) -> Fate {
        let now = now.max(self.last_now);
        self.last_now = now;
        let size = packet.len()
            + self
                .config
                .bottleneck
                .as_ref()
                .map_or(0, |bottleneck| bottleneck.overhead);
        self.stats.packets += 1;
        self.stats.bytes += packet.len() as u64;

        if let Some(outages) = &mut self.outages {
            if outages.at(now, &mut self.rng).contains(&now) {
                self.stats.lost_outage += 1;
                return Fate::Drop;
            }
        }
        if self.lose() {
            self.stats.lost += 1;
            return Fate::Drop;
        }
        if !packet.is_empty() && self.rng.r#gen::<f64>() < self.config.corrupt {
            let bit = self.rng.gen_range(0..packet.len() * 8);
            packet[bit / 8] ^= 1 << (bit % 8);
            self.stats.corrupted += 1;
        }

        let departure = match &mut self.queue {
            Some(queue) => match queue.enqueue(now, size, self.stalls.as_mut(), &mut self.rng) {
                Some(departure) => departure,
                None => {
                    self.stats.lost_queue += 1;
                    return Fate::Drop;
                }
            },
            None => self.stalls.as_mut().map_or(now, |stalls| {
                let stall = stalls.at(now, &mut self.rng);
                if stall.contains(&now) { stall.end } else { now }
            }),
        };
        let waited = departure - now;
        self.stats.queue_delay += waited;
        self.stats.max_queue_delay = self.stats.max_queue_delay.max(waited);

        let mut delivery = departure + self.config.delay + self.jitter(departure);
        if let (Some(spikes), Some(config)) = (&mut self.spikes, self.config.spikes) {
            if spikes.at(departure, &mut self.rng).contains(&departure) {
                delivery += config.extra;
            }
        }
        let reordered = self
            .config
            .reorder
            .filter(|reorder| self.rng.r#gen::<f64>() < reorder.probability);
        if let Some(reorder) = reordered {
            delivery += reorder.delay;
            self.stats.reordered += 1;
        }
        if let Some(slot) = self.config.slot.filter(|slot| !slot.is_zero()) {
            let since = (delivery - self.epoch).as_nanos();
            let slot = slot.as_nanos();
            let rounded = since.div_ceil(slot) * slot;
            delivery += Duration::from_nanos((rounded - since) as u64);
        }
        if reordered.is_none() {
            delivery = delivery.max(self.last_delivery);
            self.last_delivery = delivery;
        }

        match self.config.duplicate {
            Some(duplicate) if self.rng.r#gen::<f64>() < duplicate.probability => {
                self.stats.duplicated += 1;
                let delay = duplicate.max_delay.mul_f64(self.rng.r#gen());
                Fate::Duplicate(delivery, delivery + delay)
            }
            _ => Fate::Deliver(delivery),
        }
    }

    fn lose(&mut self) -> bool {
        let Some(loss) = self.config.loss else {
            return false;
        };
        let change = if self.bad_state { loss.r } else { loss.p };
        if self.rng.r#gen::<f64>() < change {
            self.bad_state = !self.bad_state;
        }
        let rate = if self.bad_state { loss.bad } else { loss.good };
        self.rng.r#gen::<f64>() < rate
    }

    fn jitter(&mut self, now: Instant) -> Duration {
        let Some(jitter) = self.config.jitter else {
            return Duration::ZERO;
        };
        let mean = jitter.mean.as_secs_f64();
        let rng = &mut self.rng;
        let mut normal = || {
            let sample: f64 = StandardNormal.sample(rng);
            sample.abs() * mean * (std::f64::consts::PI / 2.0).sqrt()
        };
        let pareto = |rng: &mut Xoshiro256PlusPlus| {
            let scale = mean * (PARETO_SHAPE - 1.0);
            Pareto::new(scale.max(f64::MIN_POSITIVE), PARETO_SHAPE)
                .map_or(0.0, |pareto| pareto.sample(rng) - scale)
        };
        let sample = match jitter.distribution {
            JitterDistribution::Uniform => self.rng.r#gen::<f64>() * 2.0 * mean,
            JitterDistribution::Normal => normal(),
            JitterDistribution::Exponential => {
                let sample: f64 = Exp1.sample(&mut self.rng);
                sample * mean
            }
            JitterDistribution::Pareto => pareto(&mut self.rng),
            JitterDistribution::ParetoNormal => {
                let normal = normal();
                0.25 * normal + 0.75 * pareto(&mut self.rng)
            }
        };
        let (previous, at) = self.jitter.unwrap_or((sample, now));
        let elapsed = now.saturating_duration_since(at).as_secs_f64();
        let weight = match jitter.correlation.as_secs_f64() {
            0.0 => 0.0,
            correlation => (-elapsed / correlation).exp(),
        };
        let value = if self.rng.r#gen::<f64>() < weight {
            previous
        } else {
            sample
        };
        self.jitter = Some((value, now));
        Duration::from_secs_f64(value.clamp(0.0, FAR_FUTURE.as_secs_f64()))
    }
}

/// The episodes of an [`Episodes`] config, generated lazily for increasing times.
pub(super) struct Schedule {
    config: Episodes,
    current: Range<Instant>,
}

impl Schedule {
    pub fn new(config: Episodes, start: Instant, rng: &mut Xoshiro256PlusPlus) -> Self {
        let first = match config.interval {
            Interval::Periodic(period) => period.mul_f64(rng.r#gen()),
            Interval::Random(mean) => exponential(mean, rng),
        };
        let start = start + first;
        Self {
            config,
            current: start..start + config.duration,
        }
    }

    /// The episode that is active at `t`, or the next one. `t` must not decrease much.
    pub fn at(&mut self, t: Instant, rng: &mut Xoshiro256PlusPlus) -> Range<Instant> {
        while self.current.end <= t {
            let gap = match self.config.interval {
                Interval::Periodic(period) => period,
                Interval::Random(mean) => exponential(mean, rng),
            };
            let start = (self.current.start + gap).max(self.current.end);
            let start = start.max(self.current.start + MIN_INTERVAL);
            self.current = start..start + self.config.duration;
        }
        self.current.clone()
    }
}

fn exponential(mean: Duration, rng: &mut Xoshiro256PlusPlus) -> Duration {
    let sample: f64 = Exp1.sample(rng);
    mean.mul_f64(sample).min(FAR_FUTURE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jitter_preserves_moments_at_different_packet_rates() {
        let mean = 0.01;
        for (distribution, variance) in [
            (JitterDistribution::Uniform, mean * mean / 3.0),
            (
                JitterDistribution::Normal,
                mean * mean * (std::f64::consts::PI / 2.0 - 1.0),
            ),
            (JitterDistribution::Exponential, mean * mean),
        ] {
            for cadence_us in [100, 1000, 20_000] {
                let (mut sum, mut squares, mut covariance, mut count) = (0.0, 0.0, 0.0, 0);
                let lag = 20_000 / cadence_us;
                for seed in 1..=4 {
                    let link = Link::new(
                        LinkConfig {
                            jitter: Some(Jitter {
                                distribution,
                                mean: Duration::from_secs_f64(mean),
                                correlation: Duration::from_millis(20),
                            }),
                            ..LinkConfig::default()
                        },
                        seed,
                    );
                    let mut state = link.state();
                    let epoch = state.epoch;
                    let mut samples = Vec::new();
                    for i in 0..100_000 {
                        let value = state
                            .jitter(epoch + Duration::from_micros(i * cadence_us))
                            .as_secs_f64();
                        sum += value;
                        squares += (value - mean).powi(2);
                        if i >= lag {
                            covariance += (value - mean) * (samples[(i - lag) as usize] - mean);
                            count += 1;
                        }
                        samples.push(value);
                    }
                }
                let observed_mean = sum / 400_000.0;
                let observed_variance = squares / 400_000.0;
                let correlation = covariance / f64::from(count) / observed_variance;
                assert!(
                    (observed_mean / mean - 1.0).abs() < 0.1,
                    "{distribution:?}, {cadence_us} us: mean {observed_mean}"
                );
                assert!(
                    (observed_variance.sqrt() / variance.sqrt() - 1.0).abs() < 0.12,
                    "{distribution:?}, {cadence_us} us: variance {observed_variance}"
                );
                assert!(
                    (correlation - (-1.0_f64).exp()).abs() < 0.08,
                    "{distribution:?}, {cadence_us} us: correlation {correlation}"
                );
            }
        }
    }
}
