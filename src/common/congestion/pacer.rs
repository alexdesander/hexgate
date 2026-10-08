// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::time::{Duration, Instant};

/// Packets within this much of the pacing schedule leave back to back (the poll timer has
/// millisecond resolution).
const QUANTUM: Duration = Duration::from_millis(1);
/// The realtime bucket holds this much time at its rate, plus two packets.
const REALTIME_WINDOW: f64 = 0.02;
const REALTIME_BURST: f64 = 2400.0;
/// Realtime packets past the pacer put the main bucket at most this much time into debt.
const MAX_DEBT: f64 = 0.1;
/// Between two micro-bursts, realtime packets may go past the pacer for at most this share of
/// a micro-burst, so the other channels still get their turn when realtime data alone exceeds
/// the rate.
const BYPASS_SHARE: f64 = 0.5;

/// A token bucket refilled at the rate R, holding at most one period of tokens. Once it runs
/// dry with data still queued, it waits for a whole micro-burst of tokens, so backlogged data
/// leaves as periodic bursts the utilization estimator can measure. Within a burst, packets
/// leave at the pacing rate ρR.
///
/// Realtime data doesn't wait for micro-bursts or the pacing schedule: it has its own bucket,
/// which also lets it through while a drain holds the rest of the connection back.
pub struct Pacer {
    tokens: f64,
    realtime_tokens: f64,
    /// Bytes sent past the pacer since the last regular packet.
    bypassed: f64,
    last_refill: Instant,
    /// Earliest time for the next packet at the pacing rate.
    next_send: Instant,
    /// Ran dry: wait for `burst` tokens.
    refilling: bool,
}

/// What the pacer needs to know about the controller.
#[derive(Debug, Clone, Copy)]
pub struct Rates {
    /// R, bytes per second.
    pub rate: f64,
    /// ρR.
    pub pacing_rate: f64,
    /// Most tokens the bucket holds.
    pub cap: f64,
    /// Tokens a micro-burst of backlogged data starts with.
    pub burst: f64,
    /// The refill rate of the realtime bucket.
    pub realtime_rate: f64,
    /// A drain holds back everything but realtime data.
    pub draining: bool,
}

impl Pacer {
    pub fn new(now: Instant, initial_tokens: f64) -> Self {
        Self {
            tokens: initial_tokens,
            realtime_tokens: REALTIME_BURST,
            bypassed: 0.0,
            last_refill: now,
            next_send: now,
            refilling: false,
        }
    }

    fn refill(&mut self, now: Instant, rates: Rates) {
        let elapsed = now
            .saturating_duration_since(self.last_refill)
            .as_secs_f64();
        self.last_refill = now;
        self.tokens = (self.tokens + rates.rate * elapsed).min(rates.cap);
        self.realtime_tokens = (self.realtime_tokens + rates.realtime_rate * elapsed)
            .min(rates.realtime_rate * REALTIME_WINDOW + REALTIME_BURST);
    }

    /// `None` if a packet may be sent now, otherwise when it may.
    pub fn delay(&mut self, now: Instant, rates: Rates) -> Option<Instant> {
        self.refill(now, rates);
        let needed = if self.refilling {
            rates.burst.min(rates.cap)
        } else {
            f64::MIN_POSITIVE
        };
        if self.tokens < needed {
            let wait = (needed - self.tokens).max(1.0) / rates.rate;
            return Some(now + Duration::from_secs_f64(wait));
        }
        self.refilling = false;
        (self.next_send > now).then_some(self.next_send)
    }

    /// Whether realtime data may go now although `delay` says no.
    pub fn realtime(&mut self, now: Instant, rates: Rates) -> bool {
        self.refill(now, rates);
        self.realtime_tokens > 0.0 && (rates.draining || self.bypassed < BYPASS_SHARE * rates.burst)
    }

    /// Accounts a sent packet, returns whether the bucket ran dry (the burst ends).
    /// `realtime`: sent past the pacer.
    pub fn on_sent(&mut self, now: Instant, size: usize, rates: Rates, realtime: bool) -> bool {
        self.tokens -= size as f64;
        if realtime {
            self.bypassed += size as f64;
            self.realtime_tokens -= size as f64;
            self.tokens = self.tokens.max(-rates.rate * MAX_DEBT);
        } else {
            self.bypassed = 0.0;
            let gap = Duration::from_secs_f64(size as f64 / rates.pacing_rate);
            let slack = QUANTUM.max(gap * 2);
            self.next_send = self.next_send.max(now.checked_sub(slack).unwrap_or(now)) + gap;
        }
        self.refilling |= self.tokens <= 0.0;
        self.refilling
    }

    /// Whether the bucket would run dry after `size` more bytes.
    pub fn would_run_dry(&mut self, now: Instant, size: usize, rates: Rates) -> bool {
        self.refill(now, rates);
        self.tokens - size as f64 <= 0.0
    }

    /// Takes tokens away (temporary fallback); the next burst is smaller.
    pub fn shrink(&mut self, bytes: f64) {
        self.tokens -= bytes;
    }
}
