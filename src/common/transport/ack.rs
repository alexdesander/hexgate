// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{
    ops::RangeInclusive,
    time::{Duration, Instant},
};

use super::frame;
use crate::common::codec::Writer;

/// Packets this far below the largest received one are rejected as replays.
const WINDOW: u64 = 1024;
const WORDS: usize = (WINDOW / 64) as usize;
/// The receiver acknowledges ack-eliciting packets within this time (known to both sides).
pub const MAX_ACK_DELAY: Duration = Duration::from_millis(10);
/// ... or once this many are unacknowledged.
const ACK_ELICITING_THRESHOLD: u32 = 16;
/// Ranges and receive timestamps per ACK frame.
pub const MAX_ACK_RANGES: usize = 32;
pub const MAX_TIMESTAMPS: usize = 64;

/// The packet numbers received within `WINDOW` of the largest: the replay window and the
/// source of ACK ranges.
#[derive(Default)]
pub struct Received {
    largest: Option<u64>,
    /// Bit `i` of the window: `largest - i` was received.
    bits: [u64; WORDS],
}

impl Received {
    pub fn largest(&self) -> Option<u64> {
        self.largest
    }

    /// Whether `pn` is new: neither seen nor too old.
    pub fn is_new(&self, pn: u64) -> bool {
        match self.largest {
            None => true,
            Some(largest) if pn > largest => true,
            Some(largest) => largest - pn < WINDOW && !self.bit(largest - pn),
        }
    }

    /// Records a new `pn` (see `is_new`).
    pub fn insert(&mut self, pn: u64) {
        match self.largest {
            Some(largest) if pn <= largest => {
                let offset = largest - pn;
                self.bits[offset as usize / 64] |= 1 << (offset % 64);
            }
            largest => {
                self.shift(largest.map_or(WINDOW, |largest| pn - largest));
                self.bits[0] |= 1;
                self.largest = Some(pn);
            }
        }
    }

    fn bit(&self, offset: u64) -> bool {
        self.bits[offset as usize / 64] & (1 << (offset % 64)) != 0
    }

    /// Moves every bit `by` offsets further from the largest.
    fn shift(&mut self, by: u64) {
        if by >= WINDOW {
            self.bits = [0; WORDS];
            return;
        }
        let (words, bits) = ((by / 64) as usize, (by % 64) as u32);
        for i in (0..WORDS).rev() {
            let low = i.checked_sub(words).map_or(0, |j| self.bits[j]);
            let lower = i.checked_sub(words + 1).map_or(0, |j| self.bits[j]);
            self.bits[i] = if bits == 0 {
                low
            } else {
                (low << bits) | (lower >> (64 - bits))
            };
        }
    }

    /// The first offset `>= from` whose bit equals `set`, `WINDOW` if there is none.
    fn next(&self, from: u64, set: bool) -> u64 {
        let mut offset = from;
        while offset < WINDOW {
            let word = self.bits[offset as usize / 64];
            let word = if set { word } else { !word } >> (offset % 64);
            if word != 0 {
                return (offset + u64::from(word.trailing_zeros())).min(WINDOW);
            }
            offset = (offset / 64 + 1) * 64;
        }
        WINDOW
    }

    /// Received ranges, newest first.
    pub fn ranges(&self) -> impl Iterator<Item = RangeInclusive<u64>> + '_ {
        let largest = self.largest.unwrap_or(0);
        let mut offset = if self.largest.is_some() { 0 } else { WINDOW };
        std::iter::from_fn(move || {
            if offset >= WINDOW || offset > largest {
                return None;
            }
            let end = self.next(offset, false).min(largest + 1);
            let range = largest - (end - 1)..=largest - offset;
            offset = self.next(end, true);
            Some(range)
        })
    }
}

/// What the receiver still has to acknowledge, and when.
#[derive(Default)]
pub struct AckState {
    pub received: Received,
    largest_received_at: Option<Instant>,
    /// Packets received since the last ACK frame: number and receive time (µs since the
    /// connection's epoch).
    timestamps: Vec<(u64, u64)>,
    unacked_eliciting: u32,
    /// Something was received since the last ACK frame.
    pending: bool,
    deadline: Option<Instant>,
}

impl AckState {
    pub fn on_packet(
        &mut self,
        now: Instant,
        recv_us: u64,
        pn: u64,
        eliciting: bool,
        ack_now: bool,
    ) {
        let in_order = self
            .received
            .largest()
            .is_none_or(|largest| pn == largest + 1);
        if self.received.largest().is_none_or(|largest| pn > largest) {
            self.largest_received_at = Some(now);
        }
        self.received.insert(pn);
        if self.timestamps.len() == MAX_TIMESTAMPS {
            self.timestamps.remove(0);
        }
        self.timestamps.push((pn, recv_us));
        self.pending = true;
        if !eliciting {
            return;
        }
        self.unacked_eliciting += 1;
        let deadline = if ack_now || !in_order || self.unacked_eliciting >= ACK_ELICITING_THRESHOLD
        {
            now
        } else {
            now + MAX_ACK_DELAY
        };
        self.deadline = Some(self.deadline.map_or(deadline, |at| at.min(deadline)));
    }

    /// When an ACK frame must be sent.
    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    /// Whether an ACK frame would carry news, so it is worth piggybacking.
    pub fn pending(&self) -> bool {
        self.pending
    }

    /// Writes an ACK frame if it fits, returns whether it did.
    pub fn write(&mut self, now: Instant, w: &mut Writer) -> bool {
        let (Some(largest), Some(received_at)) =
            (self.received.largest(), self.largest_received_at)
        else {
            return false;
        };
        let delay = now.saturating_duration_since(received_at).as_micros() as u64;
        let mut ranges = [(0, 0); MAX_ACK_RANGES];
        let mut count = 0;
        for (slot, range) in ranges.iter_mut().zip(self.received.ranges()) {
            *slot = (*range.start(), *range.end());
            count += 1;
        }
        debug_assert_eq!(ranges[0].1, largest);
        self.timestamps
            .sort_unstable_by_key(|&(pn, _)| std::cmp::Reverse(pn));
        if !frame::write_ack(w, delay, &ranges[..count], &self.timestamps) {
            return false;
        }
        self.timestamps.clear();
        self.unacked_eliciting = 0;
        self.pending = false;
        self.deadline = None;
        true
    }
}
