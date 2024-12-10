// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{rc::Rc, time::Duration};

use either::Either;
use reliable::ReliableChannel;
use scheduler::ChannelConfiguration;
use unreliable::UnreliableChannel;
use unreliable_ordered::UnreliableOrderedChannel;

use super::{
    congestion::CongestionController,
    crypto::Crypto,
    packets::{
        acks::Acks, reliable_payload::ReliablePayload, unreliable_payload::UnreliablePayload,
    },
};

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

pub(crate) struct Channels {
    unreliable: UnreliableChannel,
    unreliable_ordered: Vec<UnreliableOrderedChannel>,
    reliable: Vec<ReliableChannel>,
}

impl Channels {
    pub fn new(congestion: &CongestionController, config: &ChannelConfiguration) -> Self {
        Self {
            unreliable: UnreliableChannel::new(),
            unreliable_ordered: (0..config.weights_unreliable_ordered.len())
                .map(|i| UnreliableOrderedChannel::new(i.try_into().unwrap()))
                .collect(),
            reliable: (0..config.weights_reliable.len())
                .map(|i| {
                    ReliableChannel::new(
                        i.try_into().unwrap(),
                        congestion.resend_cooldown(),
                        congestion.max_in_flight(),
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
        congestion: &mut CongestionController,
        crypto: &Crypto,
        buf: &mut [u8],
    ) -> Either<usize, Option<Duration>> {
        // TODO: Implement a scheduler and use it here to make the weights actually do something.
        let size = self.unreliable.pop(crypto, buf);
        if size > 0 {
            return Either::Left(size);
        }

        for channel in &mut self.unreliable_ordered {
            let size = channel.pop(crypto, buf);
            if size > 0 {
                return Either::Left(size);
            }
        }

        let mut lowest_resend_cooldown = None;
        for channel in &mut self.reliable {
            match channel.pop(congestion, crypto, buf) {
                Either::Left(size) => {
                    assert!(size > 0);
                    return Either::Left(size);
                }
                Either::Right(Some(cooldown)) => {
                    if let Some(old) = lowest_resend_cooldown {
                        if cooldown < old {
                            lowest_resend_cooldown = Some(cooldown);
                        }
                    } else {
                        lowest_resend_cooldown = Some(cooldown);
                    }
                }
                _ => continue,
            }
        }
        either::Right(lowest_resend_cooldown)
    }

    pub fn handle_unreliable(&mut self, packet: UnreliablePayload) -> Option<Vec<u8>> {
        match packet {
            UnreliablePayload::Standalone { .. } | UnreliablePayload::Fragmented { .. } => {
                self.unreliable.handle(packet)
            }
            UnreliablePayload::OrderedStandalone { channel_id, .. }
            | UnreliablePayload::OrderedFragmented { channel_id, .. } => {
                if channel_id as usize >= self.unreliable_ordered.len() {
                    return None;
                }
                self.unreliable_ordered[channel_id as usize].handle(packet)
            }
        }
    }

    pub fn handle_reliable(&mut self, packet: ReliablePayload) -> Vec<Vec<u8>> {
        if packet.channel_id() as usize >= self.reliable.len() {
            return Vec::new();
        }
        self.reliable[packet.channel_id() as usize].handle(packet.to_owned())
    }

    pub fn acks(&mut self, channel: Channel) -> Acks {
        match channel {
            Channel::Reliable(channel_id) => self.reliable[channel_id as usize].acks(),
            _ => unreachable!(),
        }
    }

    pub fn handle_acks(&mut self, acks: Acks) {
        if acks.channel_id as usize >= self.reliable.len() {
            return;
        }
        self.reliable[acks.channel_id as usize].handle_acks(acks);
    }
}