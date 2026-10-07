// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::common::error::ConfigError;

pub struct ChannelConfiguration {
    pub weight_unreliable: u16,
    pub weights_unreliable_ordered: Vec<u16>,
    pub weights_reliable: Vec<u16>,
}

impl ChannelConfiguration {
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

/// Self-clocked fair queueing over channel slots (0: unreliable, then unreliable ordered, then
/// reliable). The head packet of a sendable slot gets the finish tag `virtual_time + size / weight`
/// once; the smallest tag is sent next and advances the virtual time.
pub(crate) struct Scheduler {
    weights: Vec<u16>,
    tags: Vec<Option<u64>>,
    virtual_time: u64,
}

impl Scheduler {
    pub fn new(config: &ChannelConfiguration) -> Self {
        let weights: Vec<u16> = std::iter::once(config.weight_unreliable)
            .chain(config.weights_unreliable_ordered.iter().copied())
            .chain(config.weights_reliable.iter().copied())
            .collect();
        Self {
            tags: vec![None; weights.len()],
            weights,
            virtual_time: 0,
        }
    }

    pub fn slots(&self) -> usize {
        self.weights.len()
    }

    pub fn tag(&mut self, slot: usize, size: usize) -> u64 {
        let finish = self.virtual_time + ((size as u64) << 16) / self.weights[slot] as u64;
        *self.tags[slot].get_or_insert(finish)
    }

    /// The slot has nothing to send right now.
    pub fn clear(&mut self, slot: usize) {
        self.tags[slot] = None;
    }

    pub fn served(&mut self, slot: usize) {
        if let Some(tag) = self.tags[slot].take() {
            self.virtual_time = tag;
        }
    }

    /// No slot is backlogged, so the virtual time can restart (keeps it from overflowing).
    pub fn reset(&mut self) {
        self.virtual_time = 0;
    }
}
