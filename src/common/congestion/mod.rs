// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! HLC, the hexgate latency-first controller (see `CONGESTION_CONTROL.md`), after Pudica
//! (NSDI'24): a rate-based controller that sends data in paced bursts and measures from each
//! burst how busy the bottleneck is, increases multiplicatively while it is lightly used,
//! converges to fair shares with AI-MD near full use, and drains any queue it causes within a
//! few bursts.
//!
//! Utilization is measured without absolute delays, which path jitter makes useless: a burst's
//! receive spread gives the rate the bottleneck had left for us (`U = our rate / that`), and
//! the trend of the bursts' one-way delays gives the overload of the bottleneck by everyone
//! (a queue growing by `x` seconds per second means a load of `1 + x`).

use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use burst::{Bursts, Sample};
use filter::Windowed;
use pacer::{Pacer, Rates};

use crate::common::{
    error::ConfigError,
    transport::{ack::MAX_ACK_DELAY, recovery::Rtt},
};

mod burst;
mod filter;
mod pacer;

const MTU: f64 = 1200.0;
/// Utilization below which the rate increases multiplicatively (Pudica α), also the share of
/// the delivery rate kept while draining.
const ALPHA: f64 = 0.85;
/// The utilization the rate moves to after an increase or a drain.
const TARGET: f64 = (ALPHA + 1.0) / 2.0;
const GAMMA_MI: f64 = 0.3;
/// At most doubles per round.
const MAX_STEP: f64 = 1.0;
const U_FLOOR: f64 = 0.05;
/// A sample above this is an outlier (a delay spike stretching one burst).
const U_MAX: f64 = 4.0;
/// A sample from the pacing rate alone, without a delivery rate, says at most this.
const PACED_MAX: f64 = 0.8;
/// Multiplicative part of AI-MD per round.
const GAMMA_MD: f64 = 0.05;
/// The additive part grows from 1 packet per round to this, and restarts on overuse and every
/// `AI_RESET`.
const AI_MAX_PACKETS: f64 = 32.0;
const AI_RESET: Duration = Duration::from_secs(5);
/// An overused burst shrinks the next one by this share (temporary fallback).
const ZETA: f64 = 0.15;
/// This many overused bursts in a row start draining, or two above `SEVERE`.
const OVERUSE_BURSTS: u32 = 3;
const SEVERE: f64 = 1.5;
/// App-limited traffic drains only when overuse lasts this long: elastic traffic that caused
/// it drains first.
const APP_PATIENCE: Duration = Duration::from_millis(300);
/// A self-induced queue is drained within this time, sending at least this share of the
/// bottleneck's rate meanwhile.
const T_DRAIN: f64 = 0.2;
const DRAIN_FLOOR: f64 = 0.25;
const MAX_DRAIN: Duration = Duration::from_secs(1);
/// Utilization samples are smoothed over this window.
const T_WD: Duration = Duration::from_millis(200);
/// The delay trend is fitted over this many bursts within this window.
const TREND_POINTS: usize = 20;
const TREND_WINDOW: Duration = Duration::from_secs(1);
const TREND_MIN_SPAN: f64 = 0.03;
/// Queue growth (in seconds per second, the bottleneck's excess load) that counts as overuse:
/// at least this, and twice the standard error of the fitted slope (jitter makes it noisy).
const GROWTH_OVERUSE: f64 = 0.03;
/// Pacing gain over the expected bottleneck rate (Pudica γp), and its maximum.
const GAMMA_P: f64 = 1.25;
const RHO_MAX: f64 = 4.0;
/// Minimum one-way delay and RTT window.
const BASE_WINDOW: Duration = Duration::from_secs(10);
/// Increases stop at this multiple of the highest rate actually sent (GCC).
const DEMAND_HEADROOM: f64 = 1.5;
/// Loss in a round with an increase above this undoes it and caps the rate (BBRv3).
const LOSS_PROBE: f64 = 0.02;
/// Smoothed loss above this lowers the rate proportionally (GCC).
const LOSS_HIGH: f64 = 0.10;
const BETA: f64 = 0.7;
const LOSS_CAP_HOLD: Duration = Duration::from_secs(2);
/// Micro-burst period of backlogged data: room for a few packets per burst.
const BURST_PACKETS: f64 = 3.0;
const MIN_PERIOD: Duration = Duration::from_millis(5);
const MAX_PERIOD: Duration = Duration::from_millis(100);
/// Tick intervals above this are idle periods, not ticks.
const MAX_TICK: Duration = Duration::from_millis(250);
/// After the queue ran empty, the token bucket holds at least this much time at the rate:
/// what the app queues after being idle leaves at once (paced).
const BUCKET: f64 = 0.04;
/// Realtime data may use this share of the delivery rate even while a drain holds the rest
/// of the connection back.
const REALTIME_SHARE: f64 = 0.5;
/// In flight at most this many times the data the path holds at the current rate.
const IN_FLIGHT_GAIN: f64 = 1.25;

/// The congestion controller's limits, in bytes per second. `min_rate == max_rate` sends at a
/// fixed rate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CongestionConfig {
    /// The rate never goes below this because of delay (16 KB/s by default), only heavy loss
    /// lowers it further. Set it to what the game needs at least.
    pub min_rate: u32,
    /// The rate before any feedback (256 KB/s by default).
    pub initial_rate: u32,
    /// The rate never exceeds this (12.5 MB/s by default).
    pub max_rate: u32,
    /// The queueing delay the game accepts when other traffic keeps the bottleneck's queue
    /// full (50 ms by default). Above it, the connection reports `Congestion::CrossTraffic`.
    pub max_queue_delay: Duration,
}

impl Default for CongestionConfig {
    fn default() -> Self {
        Self {
            min_rate: 16_000,
            initial_rate: 256_000,
            max_rate: 12_500_000,
            max_queue_delay: Duration::from_millis(50),
        }
    }
}

impl CongestionConfig {
    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        if 0 < self.min_rate
            && self.min_rate <= self.initial_rate
            && self.initial_rate <= self.max_rate
        {
            Ok(())
        } else {
            Err(ConfigError::InvalidRate)
        }
    }
}

/// Why a connection's rate is limited, see [`crate::Stats::congestion`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Congestion {
    /// The connection itself filled the bottleneck; the rate was lowered to drain it.
    SelfInduced,
    /// Other traffic keeps the bottleneck's queue above `max_queue_delay`.
    CrossTraffic,
    /// Heavy packet loss.
    Loss,
}

/// What the controller keeps per sent packet. The default belongs to no burst (packets the
/// controller doesn't track, like CLOSE).
#[derive(Debug, Clone, Copy)]
pub struct SentInfo {
    burst: u64,
    first: bool,
}

impl Default for SentInfo {
    fn default() -> Self {
        Self {
            burst: u64::MAX,
            first: false,
        }
    }
}

impl SentInfo {
    /// The first packet of its burst.
    pub fn is_first(&self) -> bool {
        self.first
    }
}

/// Whether a packet may be sent.
pub enum SendPermit {
    Now,
    /// Only realtime (unreliable) data, the rest at the given time.
    Realtime(Instant),
    At(Instant),
    /// Too much in flight, an acknowledgement opens the window.
    Blocked,
}

/// Receive-side bytes over a span (µs on the receiver's clock).
#[derive(Debug, Clone, Copy)]
struct Received {
    first: i64,
    last: i64,
    bytes: u64,
    packets: u32,
}

impl Received {
    fn add(&mut self, other: Received) {
        self.first = self.first.min(other.first);
        self.last = self.last.max(other.last);
        self.bytes += other.bytes;
        self.packets += other.packets;
    }

    /// Bytes per second, without the first packet (it starts the span).
    fn rate(&self) -> Option<f64> {
        let span = (self.last - self.first) as f64 / 1e6;
        (self.packets > 1 && span > 0.0).then(|| {
            self.bytes as f64 * f64::from(self.packets - 1) / f64::from(self.packets) / span
        })
    }
}

struct Resolved {
    at: Instant,
    utilization: f64,
    rate: f64,
    packets: u32,
}

/// A least-squares line through the one-way delays of recent bursts.
#[derive(Default)]
struct Trend {
    points: VecDeque<(f64, f64)>,
}

impl Trend {
    fn push(&mut self, x: f64, y: f64) {
        self.points.push_back((x, y));
        while self.points.len() > TREND_POINTS
            || self
                .points
                .front()
                .is_some_and(|&(first, _)| x - first > TREND_WINDOW.as_secs_f64())
        {
            self.points.pop_front();
        }
    }

    /// Seconds of one-way delay gained per second, if the gain is significant.
    fn growth(&self) -> Option<f64> {
        let n = self.points.len() as f64;
        let (first, last) = (self.points.front()?.0, self.points.back()?.0);
        if n < 6.0 || last - first < TREND_MIN_SPAN {
            return None;
        }
        let (mx, my) = self
            .points
            .iter()
            .fold((0.0, 0.0), |(x, y), p| (x + p.0 / n, y + p.1 / n));
        let (sxy, sxx) = self.points.iter().fold((0.0, 0.0), |(sxy, sxx), p| {
            (sxy + (p.0 - mx) * (p.1 - my), sxx + (p.0 - mx) * (p.0 - mx))
        });
        if sxx <= 0.0 {
            return None;
        }
        let slope = sxy / sxx;
        let residuals: f64 = self
            .points
            .iter()
            .map(|p| (p.1 - my - slope * (p.0 - mx)).powi(2))
            .sum();
        let error = (residuals / (n - 2.0) / sxx).sqrt();
        // A queue that grows keeps growing; a delay step (a spike) rises in one half only.
        let half = self.points.len() / 2;
        let rising = |points: &mut dyn Iterator<Item = &(f64, f64)>| {
            let points: Vec<_> = points.collect();
            let mid = points.len() / 2;
            let mean = |p: &[&(f64, f64)]| p.iter().map(|p| p.1).sum::<f64>() / p.len() as f64;
            mean(&points[mid..]) > mean(&points[..mid])
        };
        let consistent = rising(&mut self.points.iter().take(half))
            && rising(&mut self.points.iter().skip(half));
        (consistent && slope > GROWTH_OVERUSE.max(2.0 * error)).then_some(slope)
    }

    fn clear(&mut self) {
        self.points.clear();
    }
}

struct Drain {
    since: Instant,
    /// The delivery rate the drain is based on.
    rate: f64,
}

pub(crate) struct Controller {
    min_rate: f64,
    max_rate: f64,
    initial_rate: f64,
    max_queue_delay: Duration,
    epoch: Instant,

    rate: f64,
    drain: Option<Drain>,
    /// The rate before a severe overuse sample cut it, restored unless the next one confirms.
    provisional: Option<f64>,
    over_streak: u32,
    over_since: Option<Instant>,
    /// What the receiver got since the current overuse began.
    onset: Option<Received>,
    tau: u32,
    tau_reset: Instant,
    /// BBRv3-like cap after an increase that caused loss: rate and until when.
    loss_cap: Option<(f64, Instant)>,

    pacer: Pacer,
    bursts: Bursts,
    samples: VecDeque<Resolved>,
    /// Receive spans of recently resolved bursts.
    recent: VecDeque<(Instant, Received)>,
    trend: Trend,
    /// Significant queue growth of the bottleneck.
    growth: Option<f64>,
    base_owd: Windowed<i64>,
    min_rtt: Windowed<Duration>,
    sent_peak: Windowed<f64>,
    /// Estimated tick interval (L̂) in seconds, from app-limited bursts.
    tick: Option<f64>,
    /// Start of the last burst that followed an empty queue.
    last_app_burst: Option<Instant>,
    previous_burst_app_limited: bool,

    round_end_pn: u64,
    round_acked: u32,
    round_lost: u32,
    round_increased_from: Option<f64>,
    hold_increase: bool,
    loss: f64,

    queue_delay: f64,
    utilization: f64,
    congestion: Option<Congestion>,
}

impl Controller {
    pub fn new(config: CongestionConfig, now: Instant) -> Self {
        let rate = f64::from(config.initial_rate);
        let mut controller = Self {
            min_rate: f64::from(config.min_rate),
            max_rate: f64::from(config.max_rate),
            initial_rate: rate,
            max_queue_delay: config.max_queue_delay,
            epoch: now,
            rate,
            drain: None,
            provisional: None,
            over_streak: 0,
            over_since: None,
            onset: None,
            tau: 0,
            tau_reset: now,
            loss_cap: None,
            pacer: Pacer::new(now, 0.0),
            bursts: Bursts::default(),
            samples: VecDeque::new(),
            recent: VecDeque::new(),
            trend: Trend::default(),
            growth: None,
            base_owd: Windowed::min(),
            min_rtt: Windowed::min(),
            sent_peak: Windowed::max(),
            tick: None,
            last_app_burst: None,
            previous_burst_app_limited: true,
            round_end_pn: 0,
            round_acked: 0,
            round_lost: 0,
            round_increased_from: None,
            hold_increase: false,
            loss: 0.0,
            queue_delay: 0.0,
            utilization: 0.0,
            congestion: None,
        };
        controller.pacer = Pacer::new(now, controller.rates().cap);
        controller
    }

    fn fixed(&self) -> bool {
        self.min_rate >= self.max_rate
    }

    fn micros(&self, at: Instant) -> i64 {
        at.saturating_duration_since(self.epoch).as_micros() as i64
    }

    /// The micro-burst period of backlogged data.
    fn period(&self) -> Duration {
        Duration::from_secs_f64(BURST_PACKETS * MTU / self.rate).clamp(MIN_PERIOD, MAX_PERIOD)
    }

    fn rho(&self) -> f64 {
        (GAMMA_P / self.utilization.min(1.0)).clamp(GAMMA_P, RHO_MAX)
    }

    fn rates(&self) -> Rates {
        let period = self.period().as_secs_f64();
        Rates {
            rate: self.rate,
            pacing_rate: self.rate * self.rho(),
            cap: self.rate
                * period
                    .max(self.tick.unwrap_or(0.0))
                    .max(if self.previous_burst_app_limited {
                        BUCKET
                    } else {
                        0.0
                    }),
            burst: (self.rate * period).max(MTU),
            realtime_rate: self
                .rate
                .max(REALTIME_SHARE * self.recent_rate().unwrap_or(0.0)),
            draining: self.drain.is_some(),
        }
    }

    pub fn rate(&self) -> f64 {
        self.rate
    }

    /// The estimated tick interval of the app's sends.
    pub fn tick(&self) -> Option<Duration> {
        self.tick.map(Duration::from_secs_f64)
    }

    /// Whether a packet may be sent now. Ack-only packets and probes don't ask.
    pub fn permit(&mut self, now: Instant, in_flight: usize, rtt: &Rtt) -> SendPermit {
        // A path's worth of data plus some queue: when the path slows down, sending follows
        // the acknowledgements within a round trip instead of filling the queue until the
        // controller notices.
        let path = match self.min_rtt.get() {
            Some(base) => base + rtt.var * 2,
            None => rtt.smoothed(),
        };
        let horizon = (path + MAX_ACK_DELAY).as_secs_f64()
            + self.tick.unwrap_or(0.0).max(self.period().as_secs_f64());
        let max_in_flight = (IN_FLIGHT_GAIN * self.rate * horizon).max(4.0 * MTU);
        if in_flight as f64 >= max_in_flight {
            return SendPermit::Blocked;
        }
        let rates = self.rates();
        match self.pacer.delay(now, rates) {
            None => SendPermit::Now,
            Some(at) if self.pacer.realtime(now, rates) => SendPermit::Realtime(at),
            Some(at) => SendPermit::At(at),
        }
    }

    /// Whether a packet of `size` bytes ends the current micro-burst (the bucket runs dry).
    pub fn ends_burst(&mut self, now: Instant, size: usize) -> bool {
        let rates = self.rates();
        self.pacer.would_run_dry(now, size, rates)
    }

    /// `end`: the last packet of its burst; `app_limited`: and the queue is empty;
    /// `realtime`: sent past the pacer, between micro-bursts.
    pub fn on_sent(
        &mut self,
        now: Instant,
        size: usize,
        (end, app_limited, realtime): (bool, bool, bool),
    ) -> SentInfo {
        let rates = self.rates();
        let gap = Duration::from_secs_f64(size as f64 / rates.pacing_rate);
        let (burst, first) = self
            .bursts
            .on_sent(now, size, (end, app_limited, realtime), gap);
        if first && !realtime && self.previous_burst_app_limited {
            if let Some(last) = self.last_app_burst {
                let interval = now.saturating_duration_since(last);
                // Much shorter intervals are a tick's messages that left apart.
                let split = self
                    .tick
                    .is_some_and(|tick| interval.as_secs_f64() < tick / 4.0);
                if interval <= MAX_TICK && !split {
                    let interval = interval.as_secs_f64();
                    self.tick = Some(
                        self.tick
                            .map_or(interval, |tick| tick + (interval - tick) / 8.0),
                    );
                }
            }
            self.last_app_burst = Some(now);
        }
        if end && !realtime {
            self.previous_burst_app_limited = app_limited;
        }
        self.pacer.on_sent(now, size, rates, realtime);
        SentInfo { burst, first }
    }

    pub fn on_timestamp(
        &mut self,
        (pn, info): (u64, SentInfo),
        sent: Instant,
        size: usize,
        recv_us: u64,
        now: Instant,
    ) {
        let owd = recv_us as i64 - self.micros(sent);
        let base = self.base_owd.update(now, owd, BASE_WINDOW);
        let queue = (owd - base) as f64 / 1e6;
        self.queue_delay += (queue - self.queue_delay) / 16.0;
        self.bursts
            .on_timestamp(info.burst, pn, info.first, (recv_us as i64, owd), size);
    }

    pub fn on_acked(&mut self, info: SentInfo, pn: u64) {
        self.bursts.on_done(info.burst, false);
        self.round_acked += 1;
        if pn >= self.round_end_pn {
            self.round_end_pn = u64::MAX;
        }
    }

    pub fn on_lost(&mut self, info: SentInfo) {
        self.bursts.on_done(info.burst, true);
        self.round_lost += 1;
    }

    pub fn on_rtt(&mut self, now: Instant, sample: Duration) {
        self.min_rtt.update(now, sample, BASE_WINDOW);
    }

    /// After an ACK frame: resolves bursts and runs the control rounds. `next_pn`: the next
    /// packet number to be sent.
    pub fn on_ack_end(&mut self, now: Instant, next_pn: u64, in_flight: usize, rtt: &Rtt) {
        if self.fixed() {
            return;
        }
        while let Some(sample) = self.bursts.resolve() {
            self.on_sample(now, sample, in_flight, rtt);
        }
        if self.round_end_pn == u64::MAX {
            self.on_round(now, rtt);
            self.round_end_pn = next_pn;
        }
        self.check_stall(now, rtt);
    }

    fn base_rtt(&self) -> Duration {
        self.min_rtt.get().unwrap_or(Duration::ZERO)
    }

    /// Pudica's "next delay": a burst without feedback for much longer than expected is
    /// treated as overuse before its acknowledgement arrives.
    pub fn check_stall(&mut self, now: Instant, rtt: &Rtt) {
        if self.fixed() {
            return;
        }
        let Some((start, seq)) = self.bursts.stall_candidate() else {
            return;
        };
        let period = self.tick.map_or(self.period(), Duration::from_secs_f64);
        let limit =
            self.base_rtt() + period + MAX_ACK_DELAY + Duration::from_millis(10).max(rtt.var * 4);
        if now.saturating_duration_since(start) > limit {
            self.bursts.mark_stalled(seq);
            self.fallback();
        }
    }

    /// The temporary fallback: the next period sends `ZETA` less.
    fn fallback(&mut self) {
        let period = self.tick.unwrap_or(self.period().as_secs_f64());
        self.pacer.shrink(ZETA * self.rate * period);
    }

    /// What the receiver got recently, in bytes per second: our share of the bottleneck.
    fn recent_rate(&self) -> Option<f64> {
        let mut recent = self.recent.iter().map(|(_, received)| *received);
        let mut total = recent.next()?;
        recent.for_each(|received| total.add(received));
        total.rate()
    }

    fn on_sample(&mut self, now: Instant, sample: Sample, in_flight: usize, rtt: &Rtt) {
        let received = sample.recv.map(|(first, last, bytes, packets)| Received {
            first,
            last,
            bytes,
            packets,
        });
        if let Some(received) = received {
            self.recent.push_back((now, received));
        }
        while self
            .recent
            .front()
            .is_some_and(|(at, ..)| now.saturating_duration_since(*at) > T_WD)
        {
            self.recent.pop_front();
        }
        if let Some(owd) = sample.first_owd {
            let x = sample
                .start
                .saturating_duration_since(self.epoch)
                .as_secs_f64();
            self.trend.push(x, owd);
            self.growth = self.trend.growth();
        }
        if sample.interleaved {
            return;
        }
        // An app-limited burst sent soon after another is part of the same tick.
        let period = match self.tick {
            Some(tick) if sample.app_limited => sample.period.as_secs_f64().max(tick / 2.0),
            _ => sample.period.as_secs_f64(),
        };
        let rate = sample.bytes as f64 / period;
        // Without a delivery rate (a single packet), the bottleneck took the burst at least as
        // fast as it was paced, which tells only that it isn't overused.
        let own = Some(sample.delivery_rate.map_or(
            (rate / (self.rate * self.rho())).min(PACED_MAX),
            |delivery| (rate / delivery).min(U_MAX),
        ));
        let utilization = match (own, self.growth) {
            (Some(own), Some(growth)) => Some(own.max(1.0 + growth)),
            (own, growth) => own.or(growth.map(|growth| 1.0 + growth)),
        };
        if let Some(utilization) = utilization {
            self.sent_peak.update(now, rate, BASE_WINDOW);
            self.samples.push_back(Resolved {
                at: now,
                utilization,
                rate,
                packets: sample.packets,
            });
        }
        while self
            .samples
            .front()
            .is_some_and(|s| now.saturating_duration_since(s.at) > T_WD)
        {
            self.samples.pop_front();
        }
        if let Some(smoothed) = self.smoothed() {
            self.utilization = smoothed;
        }

        let Some(utilization) = utilization.filter(|&u| u > 1.0) else {
            if let Some(rate) = self.provisional.take() {
                self.rate = self.rate.max(rate);
            }
            self.over_streak = 0;
            self.over_since = None;
            self.onset = None;
            self.end_drain(now, in_flight, sample.app_limited);
            return;
        };
        self.over_streak += 1;
        let since = *self.over_since.get_or_insert(now);
        self.tau = 0;
        if let Some(received) = received {
            match &mut self.onset {
                Some(onset) => onset.add(received),
                None => self.onset = Some(received),
            }
        }
        let ready = if sample.app_limited {
            self.over_streak >= OVERUSE_BURSTS
                && now.saturating_duration_since(since) >= APP_PATIENCE.max(rtt.smoothed() * 2)
        } else {
            self.over_streak >= OVERUSE_BURSTS || (utilization > SEVERE && self.over_streak >= 2)
        };
        if !ready {
            // A severe overuse (a capacity drop, or a delay spike) cuts the rate to what the
            // bottleneck delivered until the next sample tells which.
            match sample.delivery_rate {
                Some(delivery) if utilization > SEVERE && !sample.app_limited => {
                    self.provisional.get_or_insert(self.rate);
                    self.rate = self.rate.min(ALPHA * delivery).max(self.min_rate);
                }
                _ => self.fallback(),
            }
            return;
        }
        self.provisional = None;
        // Active queue draining (Pudica eq. 11): below what we received since the overuse
        // began (the bottleneck's rate for us), minus the self-induced queue spread over
        // `T_DRAIN`. That rate stays the reference: what we receive later is held back by the
        // drain itself.
        let delivery = match &self.drain {
            Some(drain) => drain.rate,
            None => {
                let Some(delivery) = self
                    .onset
                    .filter(|onset| onset.packets >= 4 && onset.last - onset.first >= 5000)
                    .and_then(|onset| onset.rate())
                    .or_else(|| self.recent_rate())
                else {
                    self.fallback();
                    return;
                };
                self.drain = Some(Drain {
                    since: now,
                    rate: delivery,
                });
                delivery
            }
        };
        let floor = (DRAIN_FLOOR * delivery).max(self.min_rate);
        let target = (ALPHA * delivery - self.queued(in_flight, delivery) / T_DRAIN)
            .max(floor)
            .min(self.max_rate);
        self.rate = self.rate.min(target);
        self.congestion = Some(Congestion::SelfInduced);
    }

    /// Bytes of ours queued at the bottleneck: in flight beyond what the path holds.
    fn queued(&self, in_flight: usize, delivery: f64) -> f64 {
        let path = (self.base_rtt() + MAX_ACK_DELAY).as_secs_f64();
        (in_flight as f64 - delivery * path).max(0.0)
    }

    /// Ends a drain once the queue is gone, back at the target utilization of what the path
    /// delivers (Pudica's one-step recovery).
    fn end_drain(&mut self, now: Instant, in_flight: usize, app_limited: bool) {
        let Some(drain) = &self.drain else {
            return;
        };
        let delivery = drain.rate;
        let drained = self.queued(in_flight, delivery) <= delivery * self.period().as_secs_f64();
        if !drained && now.saturating_duration_since(drain.since) < MAX_DRAIN {
            return;
        }
        let mut rate = TARGET * delivery;
        if app_limited {
            rate = rate.max(DEMAND_HEADROOM * self.recent_send_rate());
        }
        self.rate = rate.clamp(self.min_rate, self.max_rate);
        self.drain = None;
        self.congestion = None;
    }

    fn recent_send_rate(&self) -> f64 {
        self.samples.back().map_or(0.0, |s| s.rate)
    }

    /// Pudica's smoothed utilization (eq. 6, appendix B): larger, more loaded and newer
    /// samples weigh more; each is scaled to the mean rate of the window.
    fn smoothed(&self) -> Option<f64> {
        let count = self.samples.len();
        if count == 0 {
            return None;
        }
        let mean_rate = self.samples.iter().map(|s| s.rate).sum::<f64>() / count as f64;
        let (mut sum, mut weights) = (0.0, 0.0);
        for (k, s) in self.samples.iter().enumerate() {
            let weight = (s.utilization + 1.0).min(2.0)
                * (f64::from(s.packets) + 10.0).min(50.0)
                * (k as f64 + 21.0);
            let scale = (mean_rate / s.rate).clamp(0.5, 2.0);
            sum += weight * s.utilization * scale;
            weights += weight;
        }
        Some(sum / weights)
    }

    fn on_round(&mut self, now: Instant, rtt: &Rtt) {
        let total = self.round_acked + self.round_lost;
        let loss = if total > 0 {
            f64::from(self.round_lost) / f64::from(total)
        } else {
            0.0
        };
        let increased_from = self.round_increased_from.take();
        self.round_acked = 0;
        self.round_lost = 0;
        self.hold_increase = false;
        if total >= 4 {
            // Random loss at the long-term rate is binomial; three standard deviations above
            // its mean is congestion.
            let n = f64::from(total);
            let expected = n * self.loss;
            let deviation = (expected * (1.0 - self.loss)).sqrt();
            let excess = f64::from(self.round_lost) > expected + 3.0 * deviation + 1.0;
            self.on_round_loss(now, loss, increased_from, excess);
            self.loss += (loss - self.loss) / 8.0;
        }
        if now.saturating_duration_since(self.tau_reset) >= AI_RESET {
            self.tau = 0;
            self.tau_reset = now;
        }
        if self.drain.is_some() || self.hold_increase {
            return;
        }
        let Some(utilization) = self.smoothed() else {
            return;
        };
        let before = self.rate;
        if utilization <= ALPHA {
            let xi = (GAMMA_MI * (TARGET - utilization) / utilization.max(U_FLOOR)).min(MAX_STEP);
            self.raise(now, self.rate * (1.0 + xi));
        } else if utilization <= 1.0 {
            self.tau += 1;
            let packets = 2f64.powf(f64::from(self.tau) / 2.0).min(AI_MAX_PACKETS);
            let increase = packets * MTU / rtt.smoothed().as_secs_f64().max(0.001);
            let target = self.rate + increase - GAMMA_MD * self.rate;
            if target > self.rate {
                self.raise(now, target);
            } else {
                self.rate = target.max(self.min_rate);
            }
        }
        if self.rate > before {
            self.round_increased_from = Some(before);
        }
    }

    /// `excess`: the round lost significantly more than the long-term rate predicts.
    fn on_round_loss(
        &mut self,
        now: Instant,
        loss: f64,
        increased_from: Option<f64>,
        excess: bool,
    ) {
        match increased_from {
            Some(before) if loss > LOSS_PROBE && excess => {
                self.rate = before.max(BETA * self.rate);
                self.loss_cap = Some((before, now + LOSS_CAP_HOLD));
                self.hold_increase = true;
            }
            _ if self.loss > LOSS_HIGH => {
                self.rate = (self.rate * (1.0 - 0.5 * self.loss)).max(self.min_rate * 0.5);
                self.congestion = Some(Congestion::Loss);
                self.hold_increase = true;
            }
            _ if loss > LOSS_PROBE && excess => self.hold_increase = true,
            _ => {}
        }
    }

    fn raise(&mut self, now: Instant, target: f64) {
        let demand = (DEMAND_HEADROOM * self.sent_peak.get().unwrap_or(0.0)).max(self.initial_rate);
        let loss_cap = match self.loss_cap {
            Some((cap, until)) if now < until => cap,
            _ => f64::INFINITY,
        };
        let cap = demand.min(loss_cap).min(self.max_rate);
        if target > self.rate {
            self.rate = target.min(cap).max(self.rate);
        }
        if self.congestion == Some(Congestion::Loss) {
            self.congestion = None;
        }
    }

    /// RFC 9002 persistent congestion: everything sent over several PTOs was lost.
    pub fn on_persistent_congestion(&mut self) {
        if self.fixed() {
            return;
        }
        let delivered = self.recent_rate().unwrap_or(self.rate);
        self.rate = (0.5 * delivered).clamp(self.min_rate, self.max_rate);
        self.drain = None;
        self.over_streak = 0;
        self.over_since = None;
        self.onset = None;
        self.samples.clear();
        self.trend.clear();
        self.bursts.clear();
    }

    pub fn min_rtt(&self) -> Option<Duration> {
        self.min_rtt.get()
    }

    pub fn queue_delay(&self) -> Duration {
        Duration::from_secs_f64(self.queue_delay.max(0.0))
    }

    pub fn delivery_rate(&self) -> f64 {
        self.recent_rate().unwrap_or(0.0)
    }

    pub fn utilization(&self) -> f64 {
        self.utilization
    }

    pub fn loss(&self) -> f64 {
        self.loss
    }

    pub fn congestion(&self) -> Option<Congestion> {
        self.congestion.or_else(|| {
            (self.queue_delay() > self.max_queue_delay).then_some(Congestion::CrossTraffic)
        })
    }
}
