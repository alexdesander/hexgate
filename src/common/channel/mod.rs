// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{
    rc::Rc,
    time::{Duration, Instant},
};

use either::Either;
use reliable::ReliableChannel;
use scheduler::{ChannelConfiguration, Scheduler};
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
pub mod scheduler;
mod unreliable;
mod unreliable_ordered;

// TODO: Implement a scheduler and use it here to make the weights actually do something.

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
    pub fn new(
        congestion: &CongestionController,
        config: &ChannelConfiguration,
        max_recv_msg_size: usize,
    ) -> Self {
        Self {
            max_recv_msg_size,
            scheduler: Scheduler::new(),
            unreliable: UnreliableChannel::new(max_recv_msg_size),
            unreliable_ordered: (0..config.weights_unreliable_ordered.len())
                .map(|i| UnreliableOrderedChannel::new(i.try_into().unwrap(), max_recv_msg_size))
                .collect(),
            reliable: (0..config.weights_reliable.len())
                .map(|i| {
                    ReliableChannel::new(
                        i.try_into().unwrap(),
                        congestion.max_in_flight(),
                        max_recv_msg_size,
                    )
                })
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

    pub fn pop(
        &mut self,
        config: &ChannelConfiguration,
        congestion: &mut CongestionController,
        crypto: &Crypto,
        buf: &mut [u8],
    ) -> Either<usize, Option<Duration>> {
        // This is initialized here to minimize drift in the scheduler.
        let now = Instant::now();

        // Schedule unreliable packets
        let size = self.unreliable.peek_size();
        if size > 0 {
            self.scheduler
                .schedule(now, &config, Channel::Unreliable, size);
        }

        // Schedule unreliable ordered packets
        for (i, channel) in self.unreliable_ordered.iter().enumerate() {
            let size = channel.peek_size();
            if size > 0 {
                self.scheduler
                    .schedule(now, &config, Channel::UnreliableOrdered(i as u8), size);
            }
        }

        // Schedule reliable packets
        for (i, channel) in self.reliable.iter_mut().enumerate() {
            let size = channel.peek_size();
            if size > 0 {
                self.scheduler
                    .schedule(now, &config, Channel::Reliable(i as u8), size);
            }
        }

        // Pop the next packet
        if let Some(channel) = self.scheduler.next() {
            match channel {
                Channel::Unreliable => {
                    let size = self.unreliable.pop(crypto, buf);
                    if size > 0 {
                        return Either::Left(size);
                    }
                }
                Channel::UnreliableOrdered(channel_id) => {
                    let size = self.unreliable_ordered[channel_id as usize].pop(crypto, buf);
                    if size > 0 {
                        return Either::Left(size);
                    }
                }
                Channel::Reliable(channel_id) => {
                    match self.reliable[channel_id as usize].pop(congestion, crypto, buf) {
                        Either::Left(size) => {
                            assert!(size > 0);
                            return Either::Left(size);
                        }
                        Either::Right(Some(cooldown)) => {
                            return Either::Right(Some(cooldown));
                        }
                        _ => {}
                    }
                }
            }
        }
        Either::Right(None)
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
