// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use crate::common::error::ConfigError;

// TODO: IMPLEMENT A BETTER CONGESTION CONTROL ALGORITHM (this is a super scuffed homebrew solution)
// I HAVE MY EYES ON BBRv3 BUT THATS A LOT OF WORK AND MAYBE NOT EVEN WORTH IT.
// => How does Valve do it? Or RakNet?

const LATENCIES_CONSIDERED: usize = 12;
const SPEED_UP_INTERVAL: Duration = Duration::from_millis(500);
const SPEED_UP_AFTER_SLOWDOWN_INTERVAL: Duration = Duration::from_secs(5);
const RESET_RELIABLE_COUNT_INTERVAL: Duration = Duration::from_secs(2);
const BATCHES_PER_SECOND: u32 = 30;
const BATCHES_DOWNTIME: Duration = Duration::from_millis(1000 / BATCHES_PER_SECOND as u64);
/// RTT assumed before the first sample (RFC 9002).
const INITIAL_RTT: Duration = Duration::from_millis(333);
const TIMER_GRANULARITY: Duration = Duration::from_millis(1);

/// Bandwidth is in kibibytes per second (1024 bytes per second), with
/// `0 < min_bandwidth <= start_bandwidth <= max_bandwidth`.
/// You should manually tune this to your game's needs.
#[derive(Debug, Clone, Copy)]
pub struct CongestionConfiguration {
    /// Send rate of a new connection (600 KiB/s by default).
    pub start_bandwidth: u32,
    /// The send rate never exceeds this (10000 KiB/s by default).
    pub max_bandwidth: u32,
    /// Congestion never lowers the send rate below this (100 KiB/s by default).
    pub min_bandwidth: u32,
}

impl CongestionConfiguration {
    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        if 0 < self.min_bandwidth
            && self.min_bandwidth <= self.start_bandwidth
            && self.start_bandwidth <= self.max_bandwidth
        {
            Ok(())
        } else {
            Err(ConfigError::InvalidBandwidth)
        }
    }
}

impl Default for CongestionConfiguration {
    fn default() -> Self {
        Self {
            start_bandwidth: 600,
            max_bandwidth: 10000,
            min_bandwidth: 100,
        }
    }
}

pub(crate) struct CongestionController {
    /// Bytes per second.
    bandwidth: u64,
    max_bandwidth: u64,
    min_bandwidth: u64,
    /// Send token bucket in bytes, refilled at `bandwidth` up to one batch. Negative after a
    /// packet larger than the remaining tokens was sent.
    tokens: f64,
    last_refill: Instant,
    latencies: VecDeque<Duration>,
    last_speedup: Instant,
    last_slowdown: Option<Instant>,
    sent_reliable: u32,
    resent_reliable: u32,
    last_reset_reliable_count: Instant,
    srtt: Option<Duration>,
    rttvar: Duration,
}

impl CongestionController {
    pub fn new(config: CongestionConfiguration) -> Self {
        let bandwidth = u64::from(config.start_bandwidth) * 1024;
        Self {
            bandwidth,
            max_bandwidth: u64::from(config.max_bandwidth) * 1024,
            min_bandwidth: u64::from(config.min_bandwidth) * 1024,
            tokens: bandwidth as f64 / BATCHES_PER_SECOND as f64,
            last_refill: Instant::now(),
            latencies: VecDeque::new(),
            last_speedup: Instant::now(),
            last_slowdown: Some(Instant::now()),
            sent_reliable: 0,
            resent_reliable: 0,
            last_reset_reliable_count: Instant::now(),
            srtt: None,
            rttvar: INITIAL_RTT / 2,
        }
    }

    /// Refills the token bucket and returns whether a packet may be sent now.
    pub fn can_send(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last_refill);
        self.last_refill = now;
        let max_tokens = self.bandwidth as f64 / BATCHES_PER_SECOND as f64;
        self.tokens = (self.tokens + self.bandwidth as f64 * elapsed.as_secs_f64()).min(max_tokens);
        self.tokens > 0.0
    }

    pub fn consume(&mut self, size: usize) {
        self.tokens -= size as f64;
    }

    /// Time until `can_send` allows the next packet.
    pub fn time_until_send(&self) -> Duration {
        Duration::from_secs_f64((-self.tokens).max(0.0) / self.bandwidth as f64)
    }

    pub fn downtime_between_batches(&self) -> Duration {
        BATCHES_DOWNTIME
    }

    /// Retransmission timeout (RFC 6298) plus the time the peer may delay its acks.
    pub fn rto(&self) -> Duration {
        let srtt = self.srtt.unwrap_or(INITIAL_RTT);
        srtt + (self.rttvar * 4).max(TIMER_GRANULARITY) + self.ack_delay()
    }

    /// Feeds an RTT sample (latency probe or ack) into the RFC 6298 estimator.
    pub fn update_rtt(&mut self, rtt: Duration) {
        match self.srtt {
            None => {
                self.srtt = Some(rtt);
                self.rttvar = rtt / 2;
            }
            Some(srtt) => {
                self.rttvar = (self.rttvar * 3 + srtt.abs_diff(rtt)) / 4;
                self.srtt = Some((srtt * 7 + rtt) / 8);
            }
        }
    }

    pub fn update_latency(&mut self, latency: Duration) {
        self.update_rtt(latency);
        if self.latencies.is_empty() {
            self.latencies.push_back(latency);
            return;
        }
        let avg = self.avg_latency();
        let deviation = self.jitter();
        self.latencies.push_back(latency);
        if self.latencies.len() > LATENCIES_CONSIDERED {
            self.latencies.pop_front();
        }
        // Normal jitter (4 mean deviations, like RFC 6298's RTO) is not congestion.
        let threshold = avg + (avg / 10).max(Duration::from_millis(5)).max(deviation * 4);
        if latency > threshold {
            self.slow_down();
        } else {
            self.speed_up();
        }
    }

    pub fn register_sent_reliable(&mut self) {
        self.sent_reliable += 1;
        if self.last_reset_reliable_count.elapsed() > RESET_RELIABLE_COUNT_INTERVAL {
            self.reset_reliable_count();
        }
    }

    pub fn register_resent_reliable(&mut self) {
        self.resent_reliable += 1;
        if self.last_reset_reliable_count.elapsed() > RESET_RELIABLE_COUNT_INTERVAL {
            self.reset_reliable_count();
        }
    }

    pub fn avg_latency(&self) -> Duration {
        if self.latencies.is_empty() {
            return Duration::from_millis(50);
        }
        self.latencies.iter().sum::<Duration>() / self.latencies.len() as u32
    }

    /// Average probe RTT, `None` before the first sample.
    pub fn rtt(&self) -> Option<Duration> {
        (!self.latencies.is_empty()).then(|| self.avg_latency())
    }

    /// Mean deviation of the probe RTTs.
    pub fn jitter(&self) -> Duration {
        let Some(avg) = self.rtt() else {
            return Duration::ZERO;
        };
        self.latencies
            .iter()
            .map(|sample| sample.abs_diff(avg))
            .sum::<Duration>()
            / self.latencies.len() as u32
    }

    pub fn send_rate(&self) -> u64 {
        self.bandwidth
    }

    pub fn ack_delay(&self) -> Duration {
        (self.avg_latency() / 2).max(Duration::from_millis(5))
    }

    fn reset_reliable_count(&mut self) {
        if self.resent_reliable * 50 > self.sent_reliable {
            self.slow_down();
        } else {
            self.speed_up();
        }
        self.sent_reliable = 0;
        self.resent_reliable = 0;
        self.last_reset_reliable_count = Instant::now();
    }

    fn slow_down(&mut self) {
        self.last_slowdown = Some(Instant::now());
        self.bandwidth = (self.bandwidth * 8 / 10).max(self.min_bandwidth);
    }

    fn speed_up(&mut self) {
        if let Some(last_slowdown) = self.last_slowdown {
            if last_slowdown.elapsed() < SPEED_UP_AFTER_SLOWDOWN_INTERVAL {
                return;
            }
        }
        if self.last_speedup.elapsed() < SPEED_UP_INTERVAL {
            return;
        }
        self.last_speedup = Instant::now();
        self.bandwidth = (self.bandwidth * 11 / 10).min(self.max_bandwidth);
    }
}
