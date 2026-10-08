// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::time::{Duration, Instant};

const MTU: f64 = 1200.0;

pub struct Pacer {
    tokens: f64,
    last: Instant,
}

impl Pacer {
    pub fn new(now: Instant) -> Self {
        Self {
            tokens: MTU,
            last: now,
        }
    }

    fn refill(&mut self, now: Instant, rate: f64) {
        self.tokens = (self.tokens + now.saturating_duration_since(self.last).as_secs_f64() * rate)
            .min(MTU.max(rate * 0.001));
        self.last = now;
    }

    pub fn delay(&mut self, now: Instant, rate: f64) -> Option<Instant> {
        self.refill(now, rate);
        (self.tokens <= 0.0).then(|| now + Duration::from_secs_f64((1.0 - self.tokens) / rate))
    }

    pub fn on_sent(&mut self, now: Instant, size: usize, rate: f64) {
        self.refill(now, rate);
        self.tokens -= size as f64;
    }

    pub fn ends_burst(&mut self, now: Instant, size: usize, rate: f64) -> bool {
        self.refill(now, rate);
        self.tokens <= size as f64
    }
}
