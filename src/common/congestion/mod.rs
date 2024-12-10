// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

// TODO: IMPLEMENT A BETTER CONGESTION CONTROL ALGORITHM (this is a super scuffed homebrew solution)
// I HAVE MY EYES ON BBRv3 BUT THATS A LOT OF WORK AND MAYBE NOT EVEN WORTH IT.
// => How does Valve do it? Or RakNet?

const LATENCIES_CONSIDERED: usize = 12;
const SPEED_UP_INTERVAL: Duration = Duration::from_millis(500);
const SPEED_UP_AFTER_SLOWDOWN_INTERVAL: Duration = Duration::from_secs(5);
const RESET_RELIABLE_COUNT_INTERVAL: Duration = Duration::from_secs(2);
const BATCHES_PER_SECOND: u32 = 30;
const BATCHES_DOWNTIME: Duration = Duration::from_millis(1000 / BATCHES_PER_SECOND as u64);

/// Bandwidth is in kibibytes per second (1024 bytes per second).
/// You should manually tune this to your game's needs.
#[derive(Debug, Clone, Copy)]
pub struct CongestionConfiguration {
    pub start_bandwidth: u32,
    pub max_bandwidth: u32,
    pub min_bandwidth: u32,
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
    // Bandwidth in kbps
    bandwidth: u32,
    max_bandwidth: u32,
    min_bandwidth: u32,
    batch_size: u32,
    latencies: VecDeque<Duration>,
    last_speedup: Instant,
    last_slowdown: Option<Instant>,
    sent_reliable: u32,
    resent_reliable: u32,
    last_reset_reliable_count: Instant,
    max_in_flight: usize,
}

impl CongestionController {
    pub fn new(config: CongestionConfiguration) -> Self {
        Self {
            bandwidth: config.start_bandwidth,
            max_bandwidth: config.max_bandwidth,
            min_bandwidth: config.min_bandwidth,
            batch_size: config.start_bandwidth / BATCHES_PER_SECOND,
            latencies: VecDeque::new(),
            last_speedup: Instant::now(),
            last_slowdown: Some(Instant::now()),
            sent_reliable: 0,
            resent_reliable: 0,
            last_reset_reliable_count: Instant::now(),
            max_in_flight: 32,
        }
    }

    pub fn max_in_flight(&self) -> usize {
        self.max_in_flight
    }

    pub fn allowed_to_send_this_batch(&self) -> u32 {
        self.batch_size * 1024
    }

    pub fn downtime_between_batches(&self) -> Duration {
        BATCHES_DOWNTIME
    }

    pub fn resend_cooldown(&self) -> Duration {
        (self.avg_latency() * 4) / 3 + Duration::from_millis(20)
    }

    pub fn update_latency(&mut self, latency: Duration) {
        if self.latencies.is_empty() {
            self.latencies.push_back(latency);
            return;
        }
        let sum = self.latencies.iter().sum::<Duration>();
        let avg = sum / self.latencies.len() as u32;
        self.latencies.push_back(latency);
        if self.latencies.len() > LATENCIES_CONSIDERED {
            self.latencies.pop_front();
        }
        let threshhold = ((avg * 11) / 10).max(avg + Duration::from_millis(5));
        if latency > threshhold {
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
        self.bandwidth = (self.bandwidth * 8) / 10;
        self.bandwidth = self.bandwidth.max(self.min_bandwidth);
        self.batch_size = self.bandwidth / BATCHES_PER_SECOND;
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
        self.bandwidth = (self.bandwidth * 11) / 10;
        self.bandwidth = self.bandwidth.min(self.max_bandwidth);
        self.batch_size = self.bandwidth / BATCHES_PER_SECOND;
    }
}
