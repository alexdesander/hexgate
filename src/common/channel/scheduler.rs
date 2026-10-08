// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::time::Duration;

use crate::common::error::ConfigError;

/// The channels and their send weights. Client and server need the same channel counts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelConfiguration {
    /// Share of the send rate for `Channel::Unreliable` while several channels have data queued.
    pub weight_unreliable: u16,
    /// One weight per `Channel::UnreliableOrdered` channel (at most 256).
    pub weights_unreliable_ordered: Vec<u16>,
    /// One weight per `Channel::Reliable` channel (at most 256).
    pub weights_reliable: Vec<u16>,
    /// Unreliable messages that waited this long for the send rate are dropped instead of
    /// sent late (100 ms by default). A message that started to go out as fragments is finished
    pub unreliable_max_age: Duration,
}

/// One channel of each kind, with equal weights.
impl Default for ChannelConfiguration {
    fn default() -> Self {
        Self {
            weight_unreliable: 1,
            weights_unreliable_ordered: vec![1],
            weights_reliable: vec![1],
            unreliable_max_age: Duration::from_millis(100),
        }
    }
}

impl ChannelConfiguration {
    /// Unreliable ordered and reliable channel counts (at most 256 each once validated).
    pub(crate) fn counts(&self) -> [u16; 2] {
        [
            self.weights_unreliable_ordered.len() as u16,
            self.weights_reliable.len() as u16,
        ]
    }

    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        let channels = self
            .weights_unreliable_ordered
            .len()
            .max(self.weights_reliable.len());
        if channels > 256 {
            return Err(ConfigError::TooManyChannels(channels));
        }
        let mut weights = std::iter::once(&self.weight_unreliable)
            .chain(&self.weights_unreliable_ordered)
            .chain(&self.weights_reliable);
        if weights.any(|&weight| weight == 0) {
            return Err(ConfigError::ZeroChannelWeight);
        }
        Ok(())
    }
}

/// Weighted service accounting in bytes actually written
pub(crate) struct Scheduler {
    weights: Vec<u16>,
    tags: Vec<Option<u64>>,
    virtual_time: u64,
    priorities: Vec<i8>,
    priority_bytes: usize,
}

impl Scheduler {
    pub fn new(config: &ChannelConfiguration) -> Self {
        let weights: Vec<u16> = std::iter::once(config.weight_unreliable)
            .chain(config.weights_unreliable_ordered.iter().copied())
            .chain(config.weights_reliable.iter().copied())
            .collect();
        Self {
            tags: vec![None; weights.len()],
            priorities: vec![0; weights.len()],
            priority_bytes: 0,
            weights,
            virtual_time: 0,
        }
    }

    pub fn slots(&self) -> usize {
        self.weights.len()
    }

    pub fn tag(&mut self, slot: usize) -> u64 {
        *self.tags[slot].get_or_insert(self.virtual_time)
    }

    pub fn set_priority(&mut self, slot: usize, priority: i8) {
        self.priorities[slot] = priority;
    }

    pub fn priority(&self, slot: usize) -> i8 {
        if self.priority_bytes >= 16 << 10 {
            0
        } else {
            self.priorities[slot]
        }
    }

    /// The slot has nothing to send right now.
    pub fn clear(&mut self, slot: usize) {
        self.tags[slot] = None;
    }

    pub fn served(&mut self, slot: usize, bytes: usize) {
        if self.priority_bytes >= 16 << 10 {
            self.priority_bytes = 0;
        } else {
            self.priority_bytes += bytes;
        }
        let start = self.tags[slot].unwrap_or(self.virtual_time);
        self.virtual_time = self.virtual_time.max(start);
        self.tags[slot] = Some(start + ((bytes as u64) << 16) / u64::from(self.weights[slot]));
    }

    /// No slot is backlogged, so the virtual time can restart (keeps it from overflowing).
    pub fn reset(&mut self) {
        self.virtual_time = 0;
        self.priority_bytes = 0;
    }
}
