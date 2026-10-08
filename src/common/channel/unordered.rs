// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The receiving side of a reliable unordered channel: each message is assembled on its own
//! and delivered once complete. Messages lie in the sender's stream offsets (see
//! `MESSAGE_COST`) and only start below the credit limit, so the ones held here are disjoint
//! and take at most `WINDOW` plus one message of bytes.

use std::collections::{BTreeMap, VecDeque};

use super::{
    ranges::RangeSet,
    reliable::{Credit, MESSAGE_COST},
};
use crate::common::{error::ProtocolViolation, events::DeliveryBudget, transport::frame::Fragment};

struct Assembly {
    buf: Vec<u8>,
    /// One bit per received byte, empty once complete.
    coverage: Vec<u64>,
    missing: usize,
}

impl Assembly {
    fn new(total: usize, offset: usize, data: &[u8]) -> Self {
        if data.len() == total {
            return Self {
                buf: data.to_vec(),
                coverage: Vec::new(),
                missing: 0,
            };
        }
        let mut assembly = Self {
            buf: vec![0; total],
            coverage: vec![0; total.div_ceil(64)],
            missing: total,
        };
        assembly.fill(offset, data);
        assembly
    }

    /// Copies `data` to `offset`, returns whether this completed the message.
    fn fill(&mut self, offset: usize, data: &[u8]) -> bool {
        if self.missing == 0 {
            return false;
        }
        let end = offset + data.len();
        self.buf[offset..end].copy_from_slice(data);
        let mut at = offset;
        while at < end {
            let bits = (64 - at % 64).min(end - at);
            let mask = (u64::MAX >> (64 - bits)) << (at % 64);
            let word = &mut self.coverage[at / 64];
            self.missing -= (mask & !*word).count_ones() as usize;
            *word |= mask;
            at += bits;
        }
        if self.missing == 0 {
            self.coverage = Vec::new();
        }
        self.missing == 0
    }
}

pub struct UnorderedRecv {
    max_size: usize,
    /// Every message below was delivered or skipped by a reset.
    delivered: u64,
    /// Delivered messages above `delivered`.
    done: RangeSet,
    /// Messages by stream offset, complete or not.
    assemblies: BTreeMap<u64, Assembly>,
    /// Complete messages in the order they completed.
    ready: VecDeque<u64>,
    pub credit: Credit,
}

impl UnorderedRecv {
    pub fn new(max_size: usize) -> Self {
        Self {
            max_size,
            delivered: 0,
            done: RangeSet::default(),
            assemblies: BTreeMap::new(),
            ready: VecDeque::new(),
            credit: Credit::default(),
        }
    }

    pub fn credit_pending(&self) -> Option<u64> {
        self.credit.pending(self.delivered)
    }

    pub fn has_pending_delivery(&self) -> bool {
        !self.ready.is_empty()
    }

    pub fn receive(
        &mut self,
        start: u64,
        fragment: Option<Fragment>,
        data: &[u8],
    ) -> Result<(), ProtocolViolation> {
        let (offset, total) = fragment.map_or((0, data.len() as u64), |f| (f.offset, f.total));
        let total = usize::try_from(total)
            .ok()
            .filter(|&total| total <= self.max_size)
            .ok_or(ProtocolViolation::MessageTooLarge { max: self.max_size })?;
        let offset = usize::try_from(offset).unwrap_or(usize::MAX);
        offset
            .checked_add(data.len())
            .filter(|&end| end <= total && (fragment.is_none() || !data.is_empty()))
            .ok_or(ProtocolViolation::Malformed)?;
        if start >= self.credit.limit() {
            return Err(ProtocolViolation::Malformed);
        }
        if start < self.delivered || self.done.contains(start..start + 1) {
            return Ok(());
        }
        let complete = match self.assemblies.get_mut(&start) {
            Some(assembly) if assembly.buf.len() != total => {
                return Err(ProtocolViolation::Malformed);
            }
            Some(assembly) => assembly.fill(offset, data),
            None => {
                let end = start + MESSAGE_COST + total as u64;
                let overlaps = self.assemblies.range(..start).next_back().is_some_and(
                    |(&before, assembly)| before + MESSAGE_COST + assembly.buf.len() as u64 > start,
                ) || self.assemblies.range(start..end).next().is_some()
                    || self.done.intersects(start..end);
                if overlaps {
                    return Err(ProtocolViolation::Malformed);
                }
                let assembly = Assembly::new(total, offset, data);
                let complete = assembly.missing == 0;
                self.assemblies.insert(start, assembly);
                complete
            }
        };
        if complete {
            self.ready.push_back(start);
        }
        Ok(())
    }

    pub fn drain(&mut self, budget: &mut DeliveryBudget, out: &mut impl FnMut(Vec<u8>)) {
        while let Some(&start) = self.ready.front() {
            if !budget.take(self.assemblies[&start].buf.len()) {
                break;
            }
            self.ready.pop_front();
            let Some(assembly) = self.assemblies.remove(&start) else {
                continue;
            };
            self.done
                .insert(start..start + MESSAGE_COST + assembly.buf.len() as u64);
            out(assembly.buf);
        }
        self.advance();
    }

    /// Skips the messages below `offset`, the peer abandoned them.
    pub fn reset(&mut self, offset: u64) {
        if offset < self.delivered {
            return;
        }
        self.delivered = offset;
        self.done.remove_below(offset);
        self.assemblies = self.assemblies.split_off(&offset);
        self.ready.retain(|&start| start >= offset);
        self.advance();
        self.credit.reset(offset);
    }

    fn advance(&mut self) {
        if let Some(first) = self
            .done
            .first()
            .filter(|first| first.start <= self.delivered)
        {
            self.delivered = first.end;
            self.done.remove_below(first.end);
        }
    }
}
