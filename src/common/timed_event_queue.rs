// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{cmp::Reverse, hash::Hash, time::Instant};

use priority_queue::PriorityQueue;

pub struct TimedEventQueue<K: Hash + Eq> {
    events: PriorityQueue<K, Reverse<Instant>>,
}

impl<K: Hash + Eq> TimedEventQueue<K> {
    pub fn new() -> Self {
        Self {
            events: PriorityQueue::new(),
        }
    }

    /// Schedules a key, preserving its earlier deadline if already present
    pub fn push(&mut self, key: K, deadline: Instant) {
        let deadline = self
            .events
            .get(&key)
            .map_or(deadline, |(_, existing)| existing.0.min(deadline));
        self.events.push(key, Reverse(deadline));
    }

    /// Sets a key's deadline, earlier or later than before
    pub fn set(&mut self, key: K, deadline: Instant) {
        self.events.push(key, Reverse(deadline));
    }

    pub fn next(&self) -> Option<Instant> {
        self.events.peek().map(|(_, deadline)| deadline.0)
    }

    pub fn pop(&mut self) -> Option<K> {
        self.events.pop().map(|(key, _)| key)
    }

    pub fn remove(&mut self, key: &K) {
        self.events.remove(key);
    }
}
