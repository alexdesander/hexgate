// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{rc::Rc, time::Instant};

use reliable::{RecvStream, SendStream};
pub use scheduler::ChannelConfiguration;
use scheduler::Scheduler;
use unreliable::{AssemblyBudget, UnreliableRecv, UnreliableSend, Write};

use super::{
    codec::Writer,
    error::{ProtocolViolation, SendError, TooLarge},
    transport::frame::Fragment,
};

mod ranges;
mod reliable;
pub(crate) mod scheduler;
mod unreliable;

/// Fragment assemblies of a connection may hold this many times `max_recv_msg_size`.
const ASSEMBLY_BUDGET: usize = 4;

/// Where a message is sent, which decides its delivery guarantees. Each channel has its own
/// queue, so a full reliable channel doesn't delay the others.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Channel {
    /// Messages may get lost or arrive out of order, never twice. A message larger than one
    /// packet (about 1.1 KiB) is lost when any of its fragments is. Messages that waited
    /// longer than `unreliable_max_age` to be sent are dropped.
    Unreliable,
    /// Like `Unreliable`, but a message older than the newest one received on this channel is
    /// dropped (sequenced).
    UnreliableOrdered(u8),
    /// Messages arrive exactly once and in the order they were sent on this channel.
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

/// Reliable stream bytes a packet carried.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct StreamRange {
    pub channel: u8,
    pub start: u64,
    pub len: u32,
}

impl StreamRange {
    fn range(&self) -> std::ops::Range<u64> {
        self.start..self.start + u64::from(self.len)
    }
}

/// The reliable frames of one packet.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct StreamFrames {
    ranges: [StreamRange; 4],
    len: u8,
}

impl StreamFrames {
    fn is_full(&self) -> bool {
        self.len as usize == self.ranges.len()
    }

    fn push(&mut self, range: StreamRange) {
        self.ranges[self.len as usize] = range;
        self.len += 1;
    }

    pub fn iter(&self) -> impl Iterator<Item = StreamRange> + '_ {
        self.ranges[..self.len as usize].iter().copied()
    }
}

pub(crate) struct Channels {
    max_recv_msg_size: usize,
    scheduler: Scheduler,
    /// `Channel::Unreliable` first, then the ordered ones.
    unreliable: Vec<(UnreliableSend, UnreliableRecv)>,
    reliable: Vec<(SendStream, RecvStream)>,
    budget: AssemblyBudget,
    /// Slots whose next frame didn't fit into the packet being written.
    no_room: Vec<bool>,
}

impl Channels {
    pub fn new(config: &ChannelConfiguration, max_recv_msg_size: usize) -> Self {
        let max_age = config.unreliable_max_age;
        let unreliable = std::iter::once((
            UnreliableSend::new(None, max_age),
            UnreliableRecv::new(false),
        ))
        .chain((0..config.weights_unreliable_ordered.len()).map(|id| {
            (
                UnreliableSend::new(Some(id as u8), max_age),
                UnreliableRecv::new(true),
            )
        }))
        .collect();
        let reliable = (0..config.weights_reliable.len())
            .map(|_| (SendStream::default(), RecvStream::new(max_recv_msg_size)))
            .collect();
        let scheduler = Scheduler::new(config);
        Self {
            max_recv_msg_size,
            no_room: vec![false; scheduler.slots()],
            scheduler,
            unreliable,
            reliable,
            budget: AssemblyBudget {
                left: max_recv_msg_size.saturating_mul(ASSEMBLY_BUDGET),
            },
        }
    }

    pub fn push(&mut self, channel: Channel, message: Rc<Vec<u8>>, now: Instant) {
        match channel {
            Channel::Unreliable => self.unreliable[0].0.push(message, now),
            Channel::UnreliableOrdered(id) => self.unreliable[id as usize + 1].0.push(message, now),
            Channel::Reliable(id) => self.reliable[id as usize].0.push(message),
        }
    }

    /// Size of the next frame of `slot` in an empty packet of `capacity`, 0 if it has none.
    fn next_size(&mut self, slot: usize, now: Instant, capacity: usize) -> usize {
        match self.unreliable.get_mut(slot) {
            Some((send, _)) => match send.ready(now) {
                true => send.next_size(capacity),
                false => 0,
            },
            None => {
                (self.reliable[slot - self.unreliable.len()].0.sendable() as usize).min(capacity)
            }
        }
    }

    /// Whether a channel has something to send. Drops expired unreliable messages.
    pub fn has_data(&mut self, now: Instant) -> bool {
        (0..self.scheduler.slots()).any(|slot| self.next_size(slot, now, 1) > 0)
    }

    /// Whether an unreliable channel has something to send.
    pub fn has_realtime(&mut self, now: Instant) -> bool {
        (0..self.unreliable.len()).any(|slot| self.next_size(slot, now, 1) > 0)
    }

    /// Fills the packet with frames in fair-queueing order, only from the unreliable channels
    /// if `realtime_only`. `capacity` is the room of an empty packet. Returns whether anything
    /// was written.
    pub fn write(
        &mut self,
        now: Instant,
        w: &mut Writer,
        (capacity, realtime_only): (usize, bool),
        frames: &mut StreamFrames,
    ) -> bool {
        let unreliable = self.unreliable.len();
        let slots = if realtime_only {
            unreliable
        } else {
            self.scheduler.slots()
        };
        self.no_room.fill(false);
        let mut wrote = false;
        loop {
            let mut best: Option<(u64, usize)> = None;
            let mut backlogged = false;
            for slot in 0..slots {
                let size = self.next_size(slot, now, capacity);
                if size == 0 {
                    self.scheduler.clear(slot);
                    continue;
                }
                backlogged = true;
                if self.no_room[slot] || (slot >= unreliable && frames.is_full()) {
                    continue;
                }
                let tag = self.scheduler.tag(slot, size);
                if best.is_none_or(|(best, _)| tag < best) {
                    best = Some((tag, slot));
                }
            }
            if !backlogged {
                self.scheduler.reset();
            }
            let Some((_, slot)) = best else {
                return wrote;
            };
            let written = match self.unreliable.get_mut(slot) {
                Some((send, _)) => matches!(send.write(w, capacity), Write::Wrote),
                None => {
                    let channel = (slot - unreliable) as u8;
                    let range = self.reliable[channel as usize].0.write(channel, w);
                    if let Some(range) = &range {
                        frames.push(StreamRange {
                            channel,
                            start: range.start,
                            len: (range.end - range.start) as u32,
                        });
                    }
                    range.is_some()
                }
            };
            if written {
                self.scheduler.served(slot);
                wrote = true;
            } else {
                self.no_room[slot] = true;
            }
        }
    }

    pub fn on_acked(&mut self, frames: &StreamFrames) {
        for range in frames.iter() {
            self.reliable[range.channel as usize]
                .0
                .on_acked(range.range());
        }
    }

    pub fn on_lost(&mut self, frames: &StreamFrames) {
        for range in frames.iter() {
            self.reliable[range.channel as usize]
                .0
                .on_lost(range.range());
        }
    }

    /// Handles an UNRELIABLE frame, returns a complete message.
    pub fn on_unreliable(
        &mut self,
        channel: Option<u8>,
        msg_id: u64,
        fragment: Option<Fragment>,
        data: &[u8],
    ) -> Result<Option<Vec<u8>>, ProtocolViolation> {
        let slot = channel.map_or(0, |id| id as usize + 1);
        let Some((_, recv)) = self.unreliable.get_mut(slot) else {
            return Ok(None);
        };
        recv.on_frame(
            msg_id,
            fragment,
            data,
            self.max_recv_msg_size,
            &mut self.budget,
        )
    }

    /// Handles a RELIABLE frame, complete messages go to `out`.
    pub fn on_reliable(
        &mut self,
        channel: u8,
        offset: u64,
        data: &[u8],
        out: &mut impl FnMut(Vec<u8>),
    ) -> Result<(), ProtocolViolation> {
        match self.reliable.get_mut(channel as usize) {
            Some((_, recv)) => recv.on_frame(offset, data, out),
            None => Ok(()),
        }
    }

    /// Bytes waiting to be sent, plus reliable bytes waiting for an acknowledgement.
    pub fn queued_bytes(&self) -> usize {
        self.unreliable
            .iter()
            .map(|(send, _)| send.queued_bytes())
            .sum::<usize>()
            + self
                .reliable
                .iter()
                .map(|(send, _)| send.queued_bytes() as usize)
                .sum::<usize>()
    }

    /// Unreliable messages dropped because they waited too long.
    pub fn expired(&self) -> u64 {
        self.unreliable.iter().map(|(send, _)| send.expired).sum()
    }
}
