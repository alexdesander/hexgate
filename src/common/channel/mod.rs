// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{
    rc::Rc,
    time::{Duration, Instant},
};

use reliable::ReliableChannel;
pub use scheduler::ChannelConfiguration;
use scheduler::Scheduler;
use unreliable::UnreliableChannel;
use unreliable_ordered::UnreliableOrderedChannel;

use super::{
    congestion::CongestionController,
    crypto::Crypto,
    error::{ProtocolViolation, SendError, TooLarge},
    packets::{
        acks::Acks, reliable_payload::ReliablePayload, unreliable_payload::UnreliablePayload,
    },
};

mod fragments;
mod reliable;
pub(crate) mod scheduler;
mod unreliable;
mod unreliable_ordered;

// TODO: Implement a scheduler and use it here to make the weights actually do something.

/// Sent to the peer when a message id counter is used up.
pub(crate) const IDS_EXHAUSTED: &[u8] = b"Message ids exhausted";

pub(crate) enum Pop {
    /// A packet of this size was written (`peek`: can be sent now).
    Packet(usize),
    /// Nothing can be sent before then (reliable retransmissions).
    Wait(Duration),
    /// Nothing is queued.
    Idle,
    /// A message id counter is used up, sending more would reuse AEAD nonces.
    Exhausted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Channel {
    Unreliable,
    UnreliableOrdered(u8),
    Reliable(u8),
}

/// What `send` validates before a message is handed to the network thread.
#[derive(Clone, Copy)]
pub(crate) struct SendLimits {
    max_msg_size: usize,
    unreliable_ordered_channels: usize,
    reliable_channels: usize,
}

impl SendLimits {
    pub fn new(config: &ChannelConfiguration, max_msg_size: usize) -> Self {
        Self {
            max_msg_size,
            unreliable_ordered_channels: config.weights_unreliable_ordered.len(),
            reliable_channels: config.weights_reliable.len(),
        }
    }

    pub fn check(&self, channel: Channel, size: usize) -> Result<(), SendError> {
        let configured = match channel {
            Channel::Unreliable => true,
            Channel::UnreliableOrdered(id) => (id as usize) < self.unreliable_ordered_channels,
            Channel::Reliable(id) => (id as usize) < self.reliable_channels,
        };
        if !configured {
            return Err(SendError::UnknownChannel(channel));
        }
        TooLarge::check(size, self.max_msg_size).map_err(SendError::MessageTooLarge)
    }
}

pub(crate) struct Channels {
    max_recv_msg_size: usize,
    scheduler: Scheduler,
    unreliable: UnreliableChannel,
    unreliable_ordered: Vec<UnreliableOrderedChannel>,
    reliable: Vec<ReliableChannel>,
}

impl Channels {
    pub fn new(config: &ChannelConfiguration, max_recv_msg_size: usize) -> Self {
        Self {
            max_recv_msg_size,
            scheduler: Scheduler::new(config),
            unreliable: UnreliableChannel::new(max_recv_msg_size),
            unreliable_ordered: (0..config.weights_unreliable_ordered.len())
                .map(|i| UnreliableOrderedChannel::new(i.try_into().unwrap(), max_recv_msg_size))
                .collect(),
            reliable: (0..config.weights_reliable.len())
                .map(|i| ReliableChannel::new(i.try_into().unwrap(), max_recv_msg_size))
                .collect(),
        }
    }

    pub fn push(&mut self, channel: Channel, message: Rc<Vec<u8>>) {
        match channel {
            Channel::Unreliable => self.unreliable.push(message),
            Channel::UnreliableOrdered(channel_id) => {
                self.unreliable_ordered[channel_id as usize].push(message)
            }
            Channel::Reliable(channel_id) => self.reliable[channel_id as usize].push(message),
        }
    }

    /// Encrypts the next packet into `buf`.
    pub fn pop(
        &mut self,
        congestion: &mut CongestionController,
        crypto: &Crypto,
        buf: &mut [u8],
    ) -> Pop {
        let now = Instant::now();
        let mut next: Option<(u64, usize)> = None;
        let mut wait: Option<Duration> = None;
        for slot in 0..self.scheduler.slots() {
            match self.peek(slot, now) {
                Pop::Packet(size) => {
                    let tag = self.scheduler.tag(slot, size);
                    if next.is_none_or(|(best, _)| tag < best) {
                        next = Some((tag, slot));
                    }
                }
                other => {
                    self.scheduler.clear(slot);
                    if let Pop::Wait(slot_wait) = other {
                        wait = Some(wait.map_or(slot_wait, |wait| wait.min(slot_wait)));
                    }
                }
            }
        }
        let Some((_, slot)) = next else {
            self.scheduler.reset();
            return wait.map_or(Pop::Idle, Pop::Wait);
        };
        self.scheduler.served(slot);
        let ordered = self.unreliable_ordered.len();
        let size = match slot {
            0 => self.unreliable.pop(crypto, buf),
            slot if slot <= ordered => self.unreliable_ordered[slot - 1].pop(crypto, buf),
            slot => Some(self.reliable[slot - 1 - ordered].pop(now, congestion, crypto, buf)),
        };
        size.map_or(Pop::Exhausted, Pop::Packet)
    }

    fn peek(&mut self, slot: usize, now: Instant) -> Pop {
        let ordered = self.unreliable_ordered.len();
        let size = match slot {
            0 => self.unreliable.peek_size(),
            slot if slot <= ordered => self.unreliable_ordered[slot - 1].peek_size(),
            slot => return self.reliable[slot - 1 - ordered].peek(now),
        };
        if size > 0 {
            Pop::Packet(size)
        } else {
            Pop::Idle
        }
    }

    pub fn queued_bytes(&self) -> usize {
        self.unreliable.queued_bytes()
            + self
                .unreliable_ordered
                .iter()
                .map(UnreliableOrderedChannel::queued_bytes)
                .sum::<usize>()
            + self
                .reliable
                .iter()
                .map(ReliableChannel::queued_bytes)
                .sum::<usize>()
    }

    pub fn handle_unreliable(
        &mut self,
        packet: UnreliablePayload,
    ) -> Result<Option<Vec<u8>>, ProtocolViolation> {
        match packet {
            UnreliablePayload::Standalone { payload, .. }
            | UnreliablePayload::OrderedStandalone { payload, .. }
                if payload.len() > self.max_recv_msg_size =>
            {
                Err(ProtocolViolation::MessageTooLarge {
                    max: self.max_recv_msg_size,
                })
            }
            UnreliablePayload::Standalone { .. } | UnreliablePayload::Fragmented { .. } => {
                self.unreliable.handle(packet)
            }
            UnreliablePayload::OrderedStandalone { channel_id, .. }
            | UnreliablePayload::OrderedFragmented { channel_id, .. } => {
                if channel_id as usize >= self.unreliable_ordered.len() {
                    return Ok(None);
                }
                self.unreliable_ordered[channel_id as usize].handle(packet)
            }
        }
    }

    pub fn handle_reliable(
        &mut self,
        packet: ReliablePayload,
    ) -> Result<Vec<Vec<u8>>, ProtocolViolation> {
        if packet.channel_id() as usize >= self.reliable.len() {
            return Ok(Vec::new());
        }
        self.reliable[packet.channel_id() as usize].handle(packet.to_owned())
    }

    pub fn acks(&mut self, channel: Channel) -> Acks {
        match channel {
            Channel::Reliable(channel_id) => self.reliable[channel_id as usize].acks(),
            _ => unreachable!(),
        }
    }

    pub fn handle_acks(&mut self, acks: Acks, congestion: &mut CongestionController) {
        let Some(channel) = self.reliable.get_mut(acks.channel_id as usize) else {
            return;
        };
        if let Some(rtt) = channel.handle_acks(acks) {
            congestion.update_rtt(rtt);
        }
    }
}
