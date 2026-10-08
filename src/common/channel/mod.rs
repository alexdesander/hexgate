// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#[cfg(test)]
use std::rc::Rc;
use std::{sync::Arc, time::Instant};

use reliable::{RecvStream, SendStream};
pub use scheduler::ChannelConfiguration;
use scheduler::Scheduler;
use unreliable::{AssemblyBudget, UnreliableRecv, UnreliableSend, Write};

use super::{
    codec::Writer,
    error::{ProtocolViolation, SendError, TooLarge},
    events::DeliveryBudget,
    send::{Message, Reservation, SendOutcome},
    stats::ChannelStats,
    transport::frame::Fragment,
};

mod ranges;
mod reliable;
pub(crate) mod scheduler;
mod unreliable;

pub(crate) type SendResult = (u64, SendOutcome, Option<Arc<Reservation>>);

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
    credits: [(u8, u64); 4],
    credits_len: usize,
    resets: [(u8, u64); 4],
    resets_len: usize,
    receipts: [(u16, u64); 4],
    receipts_len: usize,
}

impl StreamFrames {
    pub fn is_empty(&self) -> bool {
        self.len == 0 && self.credits_len == 0 && self.resets_len == 0 && self.receipts_len == 0
    }

    fn is_full(&self) -> bool {
        self.len as usize == self.ranges.len()
    }

    pub fn push(&mut self, range: StreamRange) {
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
    drain_next: usize,
}

impl Channels {
    pub fn exhausted(&self) -> bool {
        self.reliable.iter().any(|(send, _)| send.exhausted())
    }

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
            drain_next: 0,
            no_room: vec![false; scheduler.slots()],
            scheduler,
            unreliable,
            reliable,
            budget: AssemblyBudget {
                left: max_recv_msg_size.saturating_mul(ASSEMBLY_BUDGET),
            },
        }
    }

    #[cfg(test)]
    pub fn push(&mut self, channel: Channel, message: Rc<Vec<u8>>, now: Instant) {
        self.push_message(channel, Message::untracked(message, now));
    }

    pub fn push_message(&mut self, channel: Channel, message: Message) {
        match channel {
            Channel::Unreliable => self.unreliable[0].0.push_message(message),
            Channel::UnreliableOrdered(id) => {
                self.unreliable[id as usize + 1].0.push_message(message)
            }
            Channel::Reliable(id) => self.reliable[id as usize].0.push_message(message),
        }
    }

    pub fn reset_channel(&mut self, channel: u8) {
        self.reliable[channel as usize].0.reset();
    }

    fn slot(&self, channel: Channel) -> Option<usize> {
        match channel {
            Channel::Unreliable => Some(0),
            Channel::UnreliableOrdered(id) => {
                (id as usize + 1 < self.unreliable.len()).then_some(id as usize + 1)
            }
            Channel::Reliable(id) => {
                ((id as usize) < self.reliable.len()).then_some(self.unreliable.len() + id as usize)
            }
        }
    }

    pub fn set_priority(&mut self, channel: Channel, priority: i8) {
        if let Some(slot) = self.slot(channel) {
            self.scheduler.set_priority(slot, priority);
        }
    }

    pub fn stats(&self, channel: Channel, now: Instant, rate: f64) -> Option<ChannelStats> {
        self.slot(channel)?;
        let (unsent_bytes, unacked_bytes, oldest) = match channel {
            Channel::Unreliable => {
                let send = &self.unreliable[0].0;
                (send.unsent_bytes(), 0, send.oldest())
            }
            Channel::UnreliableOrdered(id) => {
                let send = &self.unreliable[id as usize + 1].0;
                (send.unsent_bytes(), 0, send.oldest())
            }
            Channel::Reliable(id) => {
                let send = &self.reliable[id as usize].0;
                (send.unsent_bytes(), send.unacked_bytes(), send.oldest())
            }
        };
        Some(ChannelStats {
            unsent_bytes,
            unacked_bytes,
            oldest_queued: oldest.map(|at| now.saturating_duration_since(at)),
            send_delay: (rate > 0.0)
                .then(|| std::time::Duration::from_secs_f64(unsent_bytes as f64 / rate)),
        })
    }

    pub fn take_results(&mut self, out: &mut Vec<SendResult>) {
        for (send, _) in &mut self.unreliable {
            send.take_results(out);
        }
        for (send, _) in &mut self.reliable {
            send.take_results(out);
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
        self.reliable
            .iter()
            .any(|(_, recv)| recv.credit_pending().is_some())
            || self
                .reliable
                .iter()
                .any(|(send, _)| send.reset_pending().is_some())
            || (0..self.scheduler.slots()).any(|slot| self.next_size(slot, now, 1) > 0)
    }

    /// Fills the packet with frames in fair-queueing order. `capacity` is the room of an empty
    /// packet. Returns whether anything was written.
    pub fn write(
        &mut self,
        now: Instant,
        w: &mut Writer,
        capacity: usize,
        frames: &mut StreamFrames,
    ) -> bool {
        let unreliable = self.unreliable.len();
        let slots = self.scheduler.slots();
        self.no_room.fill(false);
        let mut wrote = false;
        for (channel, (send, _)) in self.reliable.iter_mut().enumerate() {
            if frames.resets_len == frames.resets.len() {
                break;
            }
            if let Some(offset) = send.reset_pending() {
                if super::transport::frame::write_reset(w, channel as u8, offset) {
                    send.reset_sent();
                    frames.resets[frames.resets_len] = (channel as u8, offset);
                    frames.resets_len += 1;
                    wrote = true;
                }
            }
        }
        for (channel, (_, recv)) in self.reliable.iter_mut().enumerate() {
            if frames.credits_len == frames.credits.len() {
                break;
            }
            if let Some(limit) = recv.credit_pending() {
                if super::transport::frame::write_credit(w, channel as u8, limit) {
                    recv.credit_sent(limit);
                    frames.credits[frames.credits_len] = (channel as u8, limit);
                    frames.credits_len += 1;
                    wrote = true;
                }
            }
        }
        loop {
            let mut best: Option<(i16, u64, usize)> = None;
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
                if slot < unreliable
                    && frames.receipts_len == frames.receipts.len()
                    && self.unreliable[slot].0.receipt().is_some()
                {
                    continue;
                }
                let tag = self.scheduler.tag(slot);
                let candidate = (-i16::from(self.scheduler.priority(slot)), tag, slot);
                if best.is_none_or(|best| candidate < best) {
                    best = Some(candidate);
                }
            }
            if !backlogged {
                self.scheduler.reset();
            }
            let Some((_, _, slot)) = best else {
                return wrote;
            };
            let before = w.len();
            let written = match self.unreliable.get_mut(slot) {
                Some((send, _)) => {
                    let receipt = send.receipt();
                    let written = matches!(send.write(w, capacity), Write::Wrote);
                    if written {
                        if let Some(id) = receipt {
                            frames.receipts[frames.receipts_len] = (slot as u16, id);
                            frames.receipts_len += 1;
                        }
                    }
                    written
                }
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
                self.scheduler.served(slot, w.len() - before);
                wrote = true;
            } else {
                self.no_room[slot] = true;
            }
        }
    }

    pub fn on_acked(&mut self, frames: &StreamFrames) {
        for &(channel, offset) in &frames.resets[..frames.resets_len] {
            self.reliable[channel as usize].0.reset_acked(offset);
        }
        for &(slot, id) in &frames.receipts[..frames.receipts_len] {
            self.unreliable[slot as usize].0.on_acked(id);
        }
        for &(channel, limit) in &frames.credits[..frames.credits_len] {
            self.reliable[channel as usize].1.credit_acked(limit);
        }
        for range in frames.iter() {
            self.reliable[range.channel as usize]
                .0
                .on_acked(range.range());
        }
    }

    pub fn on_lost(&mut self, frames: &StreamFrames) {
        for &(channel, offset) in &frames.resets[..frames.resets_len] {
            self.reliable[channel as usize].0.reset_lost(offset);
        }
        for &(slot, id) in &frames.receipts[..frames.receipts_len] {
            self.unreliable[slot as usize].0.on_lost(id);
        }
        for &(channel, _) in &frames.credits[..frames.credits_len] {
            self.reliable[channel as usize].1.credit_lost();
        }
        for range in frames.iter() {
            self.reliable[range.channel as usize]
                .0
                .on_lost(range.range());
        }
    }

    /// Handles an UNRELIABLE frame, returns a complete message.
    pub fn on_unreliable(
        &mut self,
        now: Instant,
        channel: Option<u8>,
        msg_id: u64,
        fragment: Option<Fragment>,
        data: &[u8],
    ) -> Result<Option<Vec<u8>>, ProtocolViolation> {
        let slot = channel.map_or(0, |id| id as usize + 1);
        if slot >= self.unreliable.len() {
            return Ok(None);
        }
        self.maintain(now);
        if let Some(fragment) = fragment {
            if fragment.total <= self.max_recv_msg_size as u64 {
                let needed = self.unreliable[slot]
                    .1
                    .needs(msg_id, fragment.total as usize);
                while needed > self.budget.left {
                    let largest = self
                        .unreliable
                        .iter()
                        .enumerate()
                        .filter_map(|(i, (_, recv))| {
                            recv.oldest()
                                .map(|created| (recv.allocated(), std::cmp::Reverse(created), i))
                        })
                        .max();
                    let Some((_, _, channel)) = largest else {
                        break;
                    };
                    self.unreliable[channel].1.reclaim(&mut self.budget);
                }
            }
        }
        let recv = &mut self.unreliable[slot].1;
        recv.on_frame(
            msg_id,
            fragment,
            data,
            self.max_recv_msg_size,
            &mut self.budget,
            now,
        )
    }

    pub fn maintain(&mut self, now: Instant) {
        for (send, recv) in &mut self.unreliable {
            send.ready(now);
            recv.expire(now, &mut self.budget);
        }
    }

    pub fn deadline(&self) -> Option<Instant> {
        self.unreliable
            .iter()
            .flat_map(|(send, recv)| [send.deadline(), recv.deadline()])
            .flatten()
            .min()
    }

    pub fn has_pending_delivery(&self) -> bool {
        self.reliable
            .iter()
            .any(|(_, recv)| recv.has_pending_delivery())
    }

    pub fn on_credit(&mut self, channel: u8, limit: u64) -> Result<(), ProtocolViolation> {
        let Some((send, _)) = self.reliable.get_mut(channel as usize) else {
            return Err(ProtocolViolation::Malformed);
        };
        if limit > super::transport::packet::MAX_PACKET_NUMBER {
            return Err(ProtocolViolation::Malformed);
        }
        send.grant(limit);
        Ok(())
    }

    pub fn on_reset(&mut self, channel: u8, offset: u64) -> Result<(), ProtocolViolation> {
        let Some((_, recv)) = self.reliable.get_mut(channel as usize) else {
            return Err(ProtocolViolation::Malformed);
        };
        if offset > super::transport::packet::MAX_PACKET_NUMBER - reliable::WINDOW {
            return Err(ProtocolViolation::Malformed);
        }
        recv.reset(offset);
        Ok(())
    }

    pub fn on_reliable(
        &mut self,
        channel: u8,
        offset: u64,
        data: &[u8],
    ) -> Result<(), ProtocolViolation> {
        match self.reliable.get_mut(channel as usize) {
            Some((_, recv)) => recv.receive(offset, data),
            None => Err(ProtocolViolation::Malformed),
        }
    }

    pub fn drain_received(
        &mut self,
        budget: &mut DeliveryBudget,
        out: &mut impl FnMut(Channel, Vec<u8>),
    ) -> Result<(), ProtocolViolation> {
        let count = self.reliable.len();
        for _ in 0..count {
            let channel = self.drain_next;
            self.drain_next = (channel + 1) % count;
            self.reliable[channel]
                .1
                .drain(budget, &mut |m| out(Channel::Reliable(channel as u8), m))?;
            if budget.messages == 0 || budget.work == 0 {
                break;
            }
        }
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{
        codec::Reader,
        transport::frame::{self, Frame},
    };

    #[test]
    fn mixed_sizes_receive_equal_byte_service() {
        let now = Instant::now();
        let mut channels = Channels::new(&ChannelConfiguration::default(), 1 << 20);
        channels.push(Channel::Reliable(0), Rc::new(vec![1; 1 << 20]), now);
        let mut unreliable = 0;
        let mut reliable = 0;
        for _ in 0..1000 {
            for _ in 0..12 {
                channels.push(Channel::Unreliable, Rc::new(vec![2; 100]), now);
            }
            let mut buf = [0; 1180];
            let mut w = Writer::new(&mut buf);
            let mut frames = StreamFrames::default();
            assert!(channels.write(now, &mut w, 1180, &mut frames));
            let len = w.len();
            let mut r = Reader::new(&buf[..len]);
            while let Some(frame) = frame::parse(&mut r).unwrap() {
                match frame {
                    Frame::Unreliable { data, .. } => unreliable += data.len(),
                    Frame::Reliable { data, .. } => reliable += data.len(),
                    _ => unreachable!(),
                }
            }
            channels.on_acked(&frames);
        }
        let ratio = unreliable as f64 / reliable as f64;
        assert!((0.9..1.1).contains(&ratio), "{unreliable}:{reliable}");
    }

    #[test]
    fn empty_unreliable_is_sendable() {
        let now = Instant::now();
        let mut channels = Channels::new(&ChannelConfiguration::default(), 1024);
        channels.push(Channel::Unreliable, Rc::new(vec![]), now);
        channels.push(Channel::Unreliable, Rc::new(vec![1]), now);
        assert!(channels.has_data(now));
        let mut buf = [0; 1180];
        let mut w = Writer::new(&mut buf);
        channels.write(now, &mut w, 1180, &mut StreamFrames::default());
        let len = w.len();
        let mut r = Reader::new(&buf[..len]);
        assert!(matches!(
            frame::parse(&mut r).unwrap(),
            Some(Frame::Unreliable { data: [], .. })
        ));
        assert!(matches!(
            frame::parse(&mut r).unwrap(),
            Some(Frame::Unreliable { data: [1], .. })
        ));
    }

    #[test]
    fn abandoned_assemblies_expire_and_other_channels_reclaim_budget() {
        let now = Instant::now();
        let mut channels = Channels::new(&ChannelConfiguration::default(), 1024);
        for msg_id in 0..4 {
            channels
                .on_unreliable(
                    now,
                    None,
                    msg_id,
                    Some(Fragment {
                        offset: 0,
                        total: 1024,
                    }),
                    &[1],
                )
                .unwrap();
        }
        assert!(channels
            .on_unreliable(
                now,
                Some(0),
                0,
                Some(Fragment {
                    offset: 0,
                    total: 1024
                }),
                &[2; 512]
            )
            .unwrap()
            .is_none());
        let message = channels
            .on_unreliable(
                now,
                Some(0),
                0,
                Some(Fragment {
                    offset: 512,
                    total: 1024,
                }),
                &[2; 512],
            )
            .unwrap()
            .unwrap();
        assert_eq!(message, vec![2; 1024]);
        assert!(channels.deadline().is_some());
        channels.maintain(now + std::time::Duration::from_secs(2));
        assert!(channels.deadline().is_none());
        assert_eq!(channels.budget.left, 4096);
    }

    #[test]
    fn urgent_reliable_service_preserves_bulk_progress() {
        let now = Instant::now();
        let config = ChannelConfiguration {
            weights_reliable: vec![1, 1],
            ..ChannelConfiguration::default()
        };
        let mut channels = Channels::new(&config, 1 << 20);
        for channel in 0..2 {
            channels.push(
                Channel::Reliable(channel),
                Rc::new(vec![channel; 1 << 20]),
                now,
            );
        }
        channels.set_priority(Channel::Reliable(1), 10);
        let mut bytes = [0usize; 2];
        for packet in 0..100 {
            let mut buf = [0; 1180];
            let mut w = Writer::new(&mut buf);
            let mut frames = StreamFrames::default();
            channels.write(now, &mut w, 1180, &mut frames);
            let len = w.len();
            let mut r = Reader::new(&buf[..len]);
            while let Some(frame) = frame::parse(&mut r).unwrap() {
                if let Frame::Reliable { channel, data, .. } = frame {
                    if packet == 0 {
                        assert_eq!(channel, 1);
                    }
                    bytes[channel as usize] += data.len();
                }
            }
            channels.on_acked(&frames);
        }
        assert!(bytes[0] > 4000, "bulk starved: {bytes:?}");
        assert!(bytes[1] > bytes[0] * 8, "priority ignored: {bytes:?}");
    }
}
