// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![allow(unused)]

use std::time::Instant;

use std::hash::Hash;

use priority_queue::PriorityQueue;

pub trait EventData: Eq {}
impl<T> EventData for T where T: Eq {}

#[derive(Debug)]
pub struct TimedEvent<T: EventData> {
    pub deadline: Instant,
    pub event: T,
}

impl<T: EventData> PartialEq for TimedEvent<T> {
    fn eq(&self, other: &Self) -> bool {
        self.deadline == other.deadline && self.event == other.event
    }
}

impl<T: EventData> Eq for TimedEvent<T> {}

impl<T: EventData> PartialOrd for TimedEvent<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(other.deadline.cmp(&self.deadline))
    }
}

impl<T: EventData> Ord for TimedEvent<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other.deadline.cmp(&self.deadline)
    }
}

#[derive(Debug)]
pub struct TimedEventQueue<K: Hash + Eq, T: EventData> {
    events: PriorityQueue<K, TimedEvent<T>>,
}

impl<K: Hash + Eq, T: EventData> TimedEventQueue<K, T> {
    pub fn new() -> Self {
        Self {
            events: PriorityQueue::new(),
        }
    }

    /// Pushes a new event into the queue. If an event with the same key already exists,
    /// this will modify the deadline and event of the existing event. The deadline
    /// will be the minimum of the existing deadline and the new deadline.
    pub fn push(&mut self, key: K, deadline: Instant, event: T) {
        let deadline = self
            .events
            .get(&key)
            .map_or(deadline, |(_, e)| e.deadline.min(deadline));
        self.events.push(key, TimedEvent { deadline, event });
    }

    pub fn deadline(&self, key: &K) -> Option<Instant> {
        self.events.get(key).map(|(_, e)| e.deadline)
    }

    /// Returns the lowest deadline.
    pub fn next(&mut self) -> Option<Instant> {
        self.events.peek().map(|(_, e)| e.deadline)
    }

    /// Pops the event with the lowest deadline.
    pub fn pop(&mut self) -> Option<(K, T)> {
        self.events.pop().map(|(k, e)| (k, e.event))
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }
}
