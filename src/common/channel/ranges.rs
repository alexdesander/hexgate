// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{collections::BTreeMap, ops::Range};

/// Disjoint, non-adjacent `u64` ranges.
#[derive(Debug, Default, Clone)]
pub struct RangeSet {
    /// Start to end.
    ranges: BTreeMap<u64, u64>,
}

impl RangeSet {
    pub fn first(&self) -> Option<Range<u64>> {
        self.ranges
            .first_key_value()
            .map(|(&start, &end)| start..end)
    }

    pub fn insert(&mut self, range: Range<u64>) {
        if range.is_empty() {
            return;
        }
        let (mut start, mut end) = (range.start, range.end);
        if let Some((&before, &before_end)) = self.ranges.range(..=start).next_back()
            && before_end >= start
        {
            start = before;
            end = end.max(before_end);
        }
        while let Some((&next, &next_end)) = self.ranges.range(start..).next() {
            if next > end {
                break;
            }
            end = end.max(next_end);
            self.ranges.remove(&next);
        }
        self.ranges.insert(start, end);
    }

    pub fn remove(&mut self, range: Range<u64>) {
        if range.is_empty() {
            return;
        }
        if let Some((&before, &before_end)) = self.ranges.range(..range.start).next_back()
            && before_end > range.start
        {
            self.ranges.insert(before, range.start);
            if before_end > range.end {
                self.ranges.insert(range.end, before_end);
                return;
            }
        }
        while let Some((&next, &next_end)) = self.ranges.range(range.start..).next() {
            if next >= range.end {
                break;
            }
            self.ranges.remove(&next);
            if next_end > range.end {
                self.ranges.insert(range.end, next_end);
                break;
            }
        }
    }

    /// Removes everything below `value`.
    pub fn remove_below(&mut self, value: u64) {
        self.remove(0..value);
    }

    pub fn iter(&self) -> impl Iterator<Item = Range<u64>> + '_ {
        self.ranges.iter().map(|(&start, &end)| start..end)
    }
}
