// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{
    collections::BinaryHeap,
    time::{Duration, Instant},
};

use super::Channel;

pub struct ChannelConfiguration {
    pub weight_unreliable: u16,
    pub weights_unreliable_ordered: Vec<u16>,
    pub weights_reliable: Vec<u16>,
}

#[derive(Debug, PartialEq, Eq)]
struct SchedulerEntry {
    finish_time: Instant,
    channel: Channel,
}

impl Ord for SchedulerEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other.finish_time.cmp(&self.finish_time)
    }
}

impl PartialOrd for SchedulerEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(other.finish_time.cmp(&self.finish_time))
    }
}

pub(crate) struct Scheduler {
    queue: BinaryHeap<SchedulerEntry>,
}

impl Scheduler {
    pub fn new() -> Self {
        Self {
            queue: BinaryHeap::new(),
        }
    }

    pub fn schedule(
        &mut self,
        now: Instant,
        config: &ChannelConfiguration,
        channel: Channel,
        packet_size: usize,
    ) {
        let weight = match channel {
            Channel::Unreliable => config.weight_unreliable,
            Channel::UnreliableOrdered(i) => config.weights_unreliable_ordered[i as usize],
            Channel::Reliable(i) => config.weights_reliable[i as usize],
        };
        let finish_time = now + Duration::from_secs_f32(packet_size as f32 / weight as f32);
        self.queue.push(SchedulerEntry {
            finish_time,
            channel,
        });
    }

    pub fn next(&mut self) -> Option<Channel> {
        self.queue.pop().map(|entry| entry.channel)
    }
}
