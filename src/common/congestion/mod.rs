// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Copa-derived window control with bounded aggregate pacing and application-limited growth
//!
//! Tuned for average or better connections, where most players are. Behavior on bad or
//! terrible connections (heavy jitter, loss, outages) only has to stay robust: no stalls, no
//! collapse. It must not cost anything on good connections.

use crate::common::{error::ConfigError, transport::recovery::Rtt};
use filter::Windowed;
use pacer::Pacer;
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

mod filter;
mod pacer;

const MTU: f64 = 1200.0;
// Copa's delay price, with equal weight on throughput and delay
const DELTA: f64 = 1.0;
const MIN_WINDOW: f64 = 2.0 * MTU;
const RATE_WINDOW: Duration = Duration::from_millis(200);
const MAX_RATE_SAMPLES: usize = 2048;
const LOSS_MAX_AGE: Duration = Duration::from_secs(1);

/// The congestion controller's limits, in bytes per second. `min_rate == max_rate` sends at a
/// fixed rate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CongestionConfig {
    /// The minimum sending rate (16 KB/s by default)
    pub min_rate: u32,
    /// The rate before any feedback (256 KB/s by default).
    pub initial_rate: u32,
    /// The rate never exceeds this (12.5 MB/s by default).
    pub max_rate: u32,
    /// Queue delay warning threshold (50 ms by default)
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
    /// Delay feedback is reducing the sending window
    SelfInduced,
    /// The measured standing queue exceeds `max_queue_delay`
    CrossTraffic,
    /// Heavy packet loss.
    Loss,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SentInfo {
    bytes: u32,
    app_limited: bool,
    first: bool,
}

impl SentInfo {
    pub fn is_first(&self) -> bool {
        self.first
    }
}

pub enum SendPermit {
    Now,
    At(Instant),
    Blocked,
}

pub(crate) struct Controller {
    config: CongestionConfig,
    rate: f64,
    window: f64,
    pacer: Pacer,
    standing_rtt: Windowed<Duration>,
    min_rtt: Windowed<Duration>,
    srtt: Duration,
    queue_delay: f64,
    samples: VecDeque<(Instant, u64, usize)>,
    acked_bytes: usize,
    demand_bytes: usize,
    acked_packets: u32,
    lost_packets: u32,
    loss_since: Instant,
    loss: f64,
    loss_until: Instant,
    velocity: f64,
    direction: i8,
    direction_rounds: u32,
    direction_at: Instant,
    round_window: f64,
    slow_start: bool,
    last_app_send: Option<Instant>,
    tick: Option<f64>,
    previous_end: bool,
}

impl Controller {
    pub fn new(config: CongestionConfig, now: Instant) -> Self {
        let rate = f64::from(config.initial_rate);
        let window = 10.0 * MTU;
        Self {
            config,
            rate,
            window,
            pacer: Pacer::new(now),
            standing_rtt: Windowed::min(),
            min_rtt: Windowed::min(),
            srtt: Duration::from_millis(100),
            queue_delay: 0.0,
            samples: VecDeque::new(),
            acked_bytes: 0,
            demand_bytes: 0,
            acked_packets: 0,
            lost_packets: 0,
            loss_since: now,
            loss: 0.0,
            loss_until: now,
            velocity: 1.0,
            direction: 0,
            direction_rounds: 0,
            direction_at: now,
            round_window: window,
            slow_start: true,
            last_app_send: None,
            tick: None,
            previous_end: true,
        }
    }

    fn fixed(&self) -> bool {
        self.config.min_rate == self.config.max_rate
    }

    pub fn rate(&self) -> f64 {
        self.rate
    }

    pub fn tick(&self) -> Option<Duration> {
        self.tick.map(Duration::from_secs_f64)
    }

    pub fn permit(&mut self, now: Instant, in_flight: usize) -> SendPermit {
        self.maintain(now);
        if !self.fixed() && in_flight as f64 >= self.window {
            return SendPermit::Blocked;
        }
        match self.pacer.delay(now, self.pacing_rate()) {
            None => SendPermit::Now,
            Some(at) => SendPermit::At(at),
        }
    }

    pub fn ends_burst(&mut self, now: Instant, size: usize) -> bool {
        self.pacer.ends_burst(now, size, self.pacing_rate())
    }

    pub fn on_sent(&mut self, now: Instant, size: usize, end: bool, app_limited: bool) -> SentInfo {
        let first = self.previous_end;
        self.previous_end = end;
        if first {
            if let Some(last) = self.last_app_send {
                let interval = now.saturating_duration_since(last).as_secs_f64();
                if (0.001..=0.25).contains(&interval) {
                    self.tick = Some(
                        self.tick
                            .map_or(interval, |tick| tick + (interval - tick) / 8.0),
                    );
                }
            }
            self.last_app_send = app_limited.then_some(now);
        }
        self.pacer.on_sent(now, size, self.pacing_rate());
        SentInfo {
            bytes: size as u32,
            app_limited,
            first,
        }
    }

    pub fn on_timestamp(&mut self, now: Instant, size: usize, recv_us: u64) {
        self.samples.push_back((now, recv_us, size));
        if self.samples.len() > MAX_RATE_SAMPLES {
            self.samples.pop_front();
        }
    }

    pub fn on_acked(&mut self, info: SentInfo) {
        if self.fixed() {
            return;
        }
        self.acked_bytes += info.bytes as usize;
        self.demand_bytes += if info.app_limited {
            0
        } else {
            info.bytes as usize
        };
        self.acked_packets += 1;
    }

    pub fn on_lost(&mut self, _: SentInfo) {
        if !self.fixed() {
            self.lost_packets += 1;
        }
    }

    pub fn on_rtt(&mut self, now: Instant, sample: Duration) {
        let base = self.min_rtt.update(now, sample, Duration::from_secs(10));
        let standing =
            self.standing_rtt
                .update(now, sample, (self.srtt / 2).max(Duration::from_millis(1)));
        self.queue_delay = standing.saturating_sub(base).as_secs_f64();
    }

    fn pacing_rate(&self) -> f64 {
        if self.fixed() || self.loss > 0.02 {
            self.rate
        } else {
            (2.0 * self.rate).min(f64::from(self.config.max_rate))
        }
    }

    pub fn on_ack_end(&mut self, now: Instant, rtt: &Rtt) {
        self.maintain(now);
        if self.fixed() {
            return;
        }
        self.srtt = rtt.smoothed().max(Duration::from_millis(1));
        let total = self.acked_packets + self.lost_packets;
        if total >= 4
            || (total > 0 && now.saturating_duration_since(self.loss_since) >= LOSS_MAX_AGE)
        {
            let observed = f64::from(self.lost_packets) / f64::from(total);
            let excess = self.lost_packets >= 2 && observed > (2.0 * self.loss).max(0.02);
            self.loss += (observed - self.loss) / 8.0;
            if now >= self.loss_until && (excess || observed > 0.1) {
                self.window = (0.7 * self.window).max(MIN_WINDOW);
                self.loss_until = now + self.srtt;
                self.slow_start = false;
                self.velocity = 1.0;
            }
            self.acked_packets = 0;
            self.lost_packets = 0;
            self.loss_since = now;
        }
        let standing = self
            .standing_rtt
            .get()
            .unwrap_or(self.srtt)
            .as_secs_f64()
            .max(0.001);
        let current = self.window / standing;
        let target = MTU / (DELTA * self.queue_delay.max(0.000001));
        let direction = if target > current { 1 } else { -1 };
        if now.saturating_duration_since(self.direction_at) >= self.srtt {
            let observed_direction = if self.window > self.round_window {
                1
            } else if self.window < self.round_window {
                -1
            } else {
                0
            };
            if observed_direction != 0 && observed_direction == self.direction {
                self.direction_rounds = self.direction_rounds.saturating_add(1);
                if self.direction_rounds >= 3 {
                    self.velocity *= 2.0;
                }
            } else {
                self.direction = observed_direction;
                self.direction_rounds = 0;
                self.velocity = 1.0;
            }
            self.direction_at = now;
            self.round_window = self.window;
        }
        if direction != self.direction && self.velocity > 1.0 {
            self.direction = direction;
            self.velocity = 1.0;
            self.direction_rounds = 0;
        }
        self.velocity = self.velocity.min(self.window * DELTA / MTU).max(1.0);
        let acked = std::mem::take(&mut self.acked_bytes) as f64;
        let demand = std::mem::take(&mut self.demand_bytes) as f64;
        if demand == 0.0 {
            self.velocity = 1.0;
            self.direction_rounds = 0;
        }
        if direction < 0 {
            self.slow_start = false;
            self.window -=
                (acked * self.velocity * MTU / (DELTA * self.window)).min(self.window * 0.25);
        } else if now >= self.loss_until && demand > 0.0 {
            let increase = if self.slow_start {
                demand
            } else {
                demand * self.velocity * MTU / (DELTA * self.window)
            };
            self.window += increase.min(self.window * 0.25);
        }
        self.window = self.window.clamp(
            MIN_WINDOW.max(f64::from(self.config.min_rate) * self.srtt.as_secs_f64()),
            MIN_WINDOW.max(f64::from(self.config.max_rate) * self.srtt.as_secs_f64()),
        );
        self.rate = (self.window / standing).clamp(
            f64::from(self.config.min_rate),
            f64::from(self.config.max_rate),
        );
    }

    pub fn maintain(&mut self, now: Instant) {
        while self
            .samples
            .front()
            .is_some_and(|&(at, _, _)| now.saturating_duration_since(at) > RATE_WINDOW)
        {
            self.samples.pop_front();
        }
    }

    pub fn on_persistent_congestion(&mut self) {
        if !self.fixed() {
            self.window = MIN_WINDOW;
            self.rate = f64::from(self.config.min_rate);
            self.slow_start = false;
            self.velocity = 1.0;
        }
    }

    pub fn min_rtt(&self) -> Option<Duration> {
        self.min_rtt.get()
    }
    pub fn queue_delay(&self) -> Duration {
        Duration::from_secs_f64(self.queue_delay)
    }
    pub fn delivery_rate(&self) -> f64 {
        let Some(first) = self.samples.iter().min_by_key(|sample| sample.1) else {
            return 0.0;
        };
        let last = self
            .samples
            .iter()
            .map(|sample| sample.1)
            .max()
            .unwrap_or(first.1);
        if last <= first.1 {
            return 0.0;
        }
        let bytes: usize = self.samples.iter().map(|sample| sample.2).sum();
        (bytes - first.2) as f64 * 1e6 / (last - first.1) as f64
    }
    pub fn loss(&self) -> f64 {
        self.loss
    }
    pub fn congestion(&self) -> Option<Congestion> {
        if self.loss > 0.1 {
            Some(Congestion::Loss)
        } else if self.queue_delay() > self.config.max_queue_delay {
            Some(Congestion::CrossTraffic)
        } else if self.direction < 0 {
            Some(Congestion::SelfInduced)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests;
