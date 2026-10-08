// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A reliable channel is a byte stream of varint-length-prefixed messages, sent in RELIABLE
//! frames addressed by stream offset (like QUIC STREAM frames) and acknowledged per packet.
//! A reliable unordered channel lays its messages out in the same offset space, each taking
//! `MESSAGE_COST` plus its length, and sends each in UNORDERED frames of its own.

#[cfg(test)]
use std::rc::Rc;
use std::{
    collections::{BTreeMap, VecDeque},
    ops::Range,
    time::Instant,
};

use super::{SendResult, ranges::RangeSet};
use crate::common::{
    codec::{Writer, write_varint},
    error::ProtocolViolation,
    events::DeliveryBudget,
    send::{Message, SendOutcome},
    transport::frame::{self, Fragment},
};

/// Stream bytes beyond the receiver's delivered position that may be in flight, the same on
/// both sides: the sender never sends past its acknowledged prefix plus this, so the receiver
/// buffers at most this much out of order.
pub const WINDOW: u64 = 1 << 20;
/// Out-of-order gaps a receiver tracks per channel. A sender within `WINDOW` creates at most
/// one per lost packet (about 900).
const MAX_SEGMENTS: usize = 4096;
/// A reliable frame is only started with at least this many data bytes (or the rest).
const MIN_FRAME_DATA: u64 = 32;
/// Stream offsets an unordered message takes besides its bytes: its first frame covers them.
/// Keeps empty messages apart and bounds the messages a receiver holds to `WINDOW / 64`.
pub const MESSAGE_COST: u64 = 64;

struct Queued {
    start: u64,
    header: [u8; 10],
    header_len: u8,
    message: Message,
}

impl Queued {
    fn end(&self) -> u64 {
        self.start + u64::from(self.header_len) + self.message.len() as u64
    }

    /// Copies the bytes at stream offsets `range` (within this message) into `out`.
    fn copy(&self, range: Range<u64>, out: &mut [u8]) {
        let header_len = u64::from(self.header_len);
        let (from, to) = (range.start - self.start, range.end - self.start);
        let mut at = 0;
        if from < header_len {
            let header = &self.header[from as usize..to.min(header_len) as usize];
            out[..header.len()].copy_from_slice(header);
            at = header.len();
        }
        if to > header_len {
            let body = &self.message
                [from.max(header_len) as usize - header_len as usize..(to - header_len) as usize];
            out[at..at + body.len()].copy_from_slice(body);
        }
    }
}

#[derive(Default)]
pub struct SendStream {
    unordered: bool,
    messages: VecDeque<Queued>,
    end: u64,
    /// Everything below was sent at least once.
    sent: u64,
    credit: u64,
    /// Everything below was acknowledged.
    acked_until: u64,
    /// Acknowledged ranges above `acked_until`.
    acked: RangeSet,
    /// Ranges to send again.
    lost: RangeSet,
    reset: Option<(u64, bool)>,
    results: Vec<SendResult>,
    exhausted: bool,
}

impl SendStream {
    pub fn new(unordered: bool) -> Self {
        Self {
            unordered,
            ..Self::default()
        }
    }

    #[cfg(test)]
    pub fn push(&mut self, message: Rc<Vec<u8>>) {
        self.push_message(Message::untracked(message, Instant::now()));
    }

    pub fn push_message(&mut self, message: Message) {
        let mut header = [0; 10];
        let header_len = match self.unordered {
            true => MESSAGE_COST as u8,
            false => write_varint(&mut header, message.len() as u64) as u8,
        };
        let next = self
            .end
            .checked_add(u64::from(header_len))
            .and_then(|next| next.checked_add(message.len() as u64))
            .filter(|&next| next <= crate::common::transport::packet::MAX_PACKET_NUMBER - WINDOW);
        let Some(next) = next else {
            self.exhausted = true;
            if let Some(receipt) = message.options.receipt {
                self.results
                    .push((receipt, SendOutcome::Dropped, message.reservation.clone()));
            }
            return;
        };
        let queued = Queued {
            start: self.end,
            header,
            header_len,
            message,
        };
        self.end = next;
        self.messages.push_back(queued);
    }

    pub fn exhausted(&self) -> bool {
        self.exhausted
    }

    /// Bytes not acknowledged yet, sent or not.
    pub fn queued_bytes(&self) -> u64 {
        self.bytes(self.acked_until..self.end)
    }

    /// The bytes in a stream range, without the `MESSAGE_COST` of unordered messages starting
    /// in it.
    fn bytes(&self, range: Range<u64>) -> u64 {
        let len = range.end - range.start;
        if !self.unordered {
            return len;
        }
        let starts = self
            .messages
            .partition_point(|queued| queued.start < range.end)
            - self
                .messages
                .partition_point(|queued| queued.start < range.start);
        len.saturating_sub(starts as u64 * MESSAGE_COST)
    }

    /// Unordered messages only need to start within the credit, so ones larger than `WINDOW`
    /// can complete.
    fn new_data(&self) -> Range<u64> {
        if self.reset.is_some() {
            return self.sent..self.sent;
        }
        let mut limit = self.credit.max(WINDOW);
        if self.unordered
            && let Some(queued) = self
                .messages
                .get(
                    self.messages
                        .partition_point(|queued| queued.end() <= limit),
                )
                .filter(|queued| queued.start < limit)
        {
            limit = queued.end();
        }
        self.sent..self.end.min(limit)
    }

    pub fn reset(&mut self) {
        for queued in self.messages.drain(..) {
            if let Some(receipt) = queued.message.options.receipt {
                self.results.push((
                    receipt,
                    SendOutcome::Dropped,
                    queued.message.reservation.clone(),
                ));
            }
        }
        self.sent = self.end;
        self.acked_until = self.end;
        self.acked = RangeSet::default();
        self.lost = RangeSet::default();
        self.reset = Some((self.end, false));
    }

    pub fn reset_pending(&self) -> Option<u64> {
        self.reset
            .filter(|(_, sent)| !sent)
            .map(|(offset, _)| offset)
    }

    pub fn reset_sent(&mut self) {
        if let Some((_, sent)) = &mut self.reset {
            *sent = true;
        }
    }

    pub fn reset_acked(&mut self, offset: u64) {
        if self.reset.is_some_and(|(latest, _)| offset == latest) {
            self.reset = None;
            self.grant(offset.saturating_add(WINDOW));
        }
    }

    pub fn reset_lost(&mut self, offset: u64) {
        if let Some((latest, sent)) = &mut self.reset
            && *latest == offset
        {
            *sent = false;
        }
    }

    pub fn take_results(&mut self, out: &mut Vec<SendResult>) {
        out.append(&mut self.results);
    }

    pub fn unsent_bytes(&self) -> usize {
        self.bytes(self.sent..self.end) as usize
    }

    pub fn unacked_bytes(&self) -> usize {
        let acked: u64 = self.acked.iter().map(|range| self.bytes(range)).sum();
        self.bytes(self.acked_until..self.sent)
            .saturating_sub(acked) as usize
    }

    pub fn oldest(&self) -> Option<Instant> {
        self.messages.front().map(|queued| queued.message.submitted)
    }

    pub fn grant(&mut self, limit: u64) {
        self.credit = self.credit.max(limit);
    }

    /// Bytes ready to be sent: lost ones and new ones within the window.
    pub fn sendable(&self) -> u64 {
        self.lost.first().map_or(0, |range| range.end - range.start)
            + self.new_data().end.saturating_sub(self.sent)
    }

    /// Writes one frame of lost or new data into `w`, returns its stream range. `capacity` is
    /// the room of an empty packet.
    pub fn write(&mut self, channel: u8, w: &mut Writer, capacity: usize) -> Option<Range<u64>> {
        let lost = self.lost.first();
        let next = lost.clone().unwrap_or_else(|| self.new_data());
        if next.is_empty() {
            return None;
        }
        if self.unordered {
            return self.write_unordered(channel, w, capacity, next, lost.is_some());
        }
        let available = next.end - next.start;
        let header = frame::reliable_header(next.start);
        let len = frame::fit(header, available as usize, w.remaining()) as u64;
        if len == 0 || (len < MIN_FRAME_DATA && len < available) {
            return None;
        }
        let range = next.start..next.start + len;
        if lost.is_some() {
            self.lost.remove(range.clone());
        } else {
            self.sent = range.end;
        }
        frame::write_reliable_header(w, channel, range.start, len as usize);
        let out = w.space(len as usize);
        let first = self
            .messages
            .partition_point(|queued| queued.end() <= range.start);
        let mut at = range.start;
        for queued in self.messages.range(first..) {
            if at >= range.end {
                break;
            }
            let to = queued.end().min(range.end);
            queued.copy(at..to, &mut out[(at - range.start) as usize..]);
            at = to;
        }
        Some(range)
    }

    /// Writes the message at `next.start` or a fragment of it. Frame ranges start at a message
    /// or after at least one of its bytes, and so does `next`. Messages that fit into an empty
    /// packet of `capacity` are never fragmented.
    fn write_unordered(
        &mut self,
        channel: u8,
        w: &mut Writer,
        capacity: usize,
        next: Range<u64>,
        lost: bool,
    ) -> Option<Range<u64>> {
        let queued = &self.messages[self
            .messages
            .partition_point(|queued| queued.end() <= next.start)];
        let data_start = queued.start + MESSAGE_COST;
        let from = next.start.saturating_sub(data_start);
        let available = next.end.min(queued.end()).saturating_sub(data_start + from) as usize;
        let total = queued.message.len();
        let mut fragment = Some(Fragment {
            offset: from,
            total: total as u64,
        });
        if from == 0 && available == total {
            let header = frame::unordered_header(queued.start, None);
            if w.remaining() >= header && frame::fit(header, total, w.remaining()) == total {
                fragment = None;
            } else if frame::fit(header, total, capacity) == total {
                return None;
            }
        }
        let header = frame::unordered_header(queued.start, fragment);
        let take = match fragment {
            None => total,
            Some(_) => frame::fit(header, available, w.remaining()),
        };
        if fragment.is_some() && (take == 0 || (take < available && take < MIN_FRAME_DATA as usize))
        {
            return None;
        }
        let from = from as usize;
        let data = &queued.message[from..from + take];
        frame::write_unordered(w, channel, queued.start, fragment, data);
        let range = next.start..data_start + (from + take) as u64;
        if lost {
            self.lost.remove(range.clone());
        } else {
            self.sent = range.end;
        }
        Some(range)
    }

    pub fn on_acked(&mut self, range: Range<u64>) {
        self.lost.remove(range.clone());
        self.acked.insert(range.clone());
        if let Some(first) = self
            .acked
            .first()
            .filter(|first| first.start <= self.acked_until)
        {
            self.acked_until = self.acked_until.max(first.end);
            self.acked.remove_below(self.acked_until);
            self.lost.remove_below(self.acked_until);
            while self
                .messages
                .front()
                .is_some_and(|queued| queued.end() <= self.acked_until)
            {
                let queued = self.messages.pop_front().unwrap();
                if let Some(receipt) = queued.message.options.receipt {
                    self.results.push((
                        receipt,
                        SendOutcome::Acked,
                        queued.message.reservation.clone(),
                    ));
                }
            }
        }
        if self.unordered {
            self.unordered_receipts(range);
        }
    }

    /// Reports unordered messages in `range` that are acknowledged before the ones ahead.
    fn unordered_receipts(&mut self, range: Range<u64>) {
        let first = self
            .messages
            .partition_point(|queued| queued.end() <= range.start);
        for queued in self.messages.range_mut(first..) {
            if queued.start >= range.end {
                break;
            }
            if self
                .acked
                .contains(queued.start.max(self.acked_until)..queued.end())
                && let Some(receipt) = queued.message.options.receipt.take()
            {
                self.results.push((
                    receipt,
                    SendOutcome::Acked,
                    queued.message.reservation.clone(),
                ));
            }
        }
    }

    pub fn on_lost(&mut self, range: Range<u64>) {
        if range.end <= self.acked_until {
            return;
        }
        let range = range.start.max(self.acked_until)..range.end;
        self.lost.insert(range.clone());
        for acked in self.acked.iter() {
            if acked.start >= range.end {
                break;
            }
            self.lost.remove(acked);
        }
    }
}

/// Splits a byte stream into length-prefixed messages.
struct Assembler {
    max_size: usize,
    /// The length prefix read so far: value and bytes.
    prefix: (u64, u32),
    /// The message being read and its length.
    body: Option<(Vec<u8>, usize)>,
}

impl Assembler {
    fn feed(
        &mut self,
        mut data: &[u8],
        budget: &mut DeliveryBudget,
        out: &mut impl FnMut(Vec<u8>),
    ) -> Result<usize, ProtocolViolation> {
        let original = data.len();
        loop {
            if let Some((body, len)) = &mut self.body {
                if body.len() == *len {
                    if !budget.take(*len) {
                        break;
                    }
                    out(self.body.take().unwrap().0);
                    continue;
                }
                let take = (*len - body.len()).min(data.len()).min(budget.work);
                if take == 0 || budget.messages == 0 {
                    break;
                }
                body.extend_from_slice(&data[..take]);
                data = &data[take..];
                budget.work -= take;
                continue;
            }
            if data.is_empty() || budget.messages == 0 || budget.work == 0 {
                break;
            }
            let byte = data[0];
            data = &data[1..];
            budget.work -= 1;
            let (value, bytes) = &mut self.prefix;
            if *bytes == 9 {
                return Err(ProtocolViolation::Malformed);
            }
            *value |= u64::from(byte & 0x7f) << (7 * *bytes);
            *bytes += 1;
            if byte & 0x80 != 0 {
                continue;
            }
            let len = usize::try_from(*value)
                .ok()
                .filter(|&len| len <= self.max_size)
                .ok_or(ProtocolViolation::MessageTooLarge { max: self.max_size })?;
            self.prefix = (0, 0);
            self.body = Some((Vec::with_capacity(len.min(1 << 16)), len));
        }
        Ok(original - data.len())
    }
}

/// Receive credit: the sender may use stream offsets below the limit, `delivered + WINDOW`.
pub struct Credit {
    /// The highest limit sent.
    sent: u64,
    acked: u64,
    pending: bool,
}

impl Default for Credit {
    fn default() -> Self {
        Self {
            sent: WINDOW,
            acked: WINDOW,
            pending: false,
        }
    }
}

impl Credit {
    /// The highest limit sent: the peer must stay below it.
    pub fn limit(&self) -> u64 {
        self.sent
    }

    pub fn pending(&self, delivered: u64) -> Option<u64> {
        (self.pending || delivered + WINDOW > self.sent).then_some(delivered + WINDOW)
    }

    pub fn sent(&mut self, limit: u64) {
        self.sent = self.sent.max(limit);
        self.pending = false;
    }

    pub fn acked(&mut self, limit: u64) {
        self.acked = self.acked.max(limit);
        if self.acked >= self.sent {
            self.pending = false;
        }
    }

    pub fn lost(&mut self) {
        self.pending = self.acked < self.sent;
    }

    /// The peer skipped to `offset`.
    pub fn reset(&mut self, offset: u64) {
        self.sent = self.sent.max(offset.saturating_add(WINDOW));
        self.pending = true;
    }
}

pub struct RecvStream {
    delivered: u64,
    pub credit: Credit,
    /// Data beyond `delivered`, merged where adjacent.
    pending: BTreeMap<u64, VecDeque<u8>>,
    assembler: Assembler,
}

impl RecvStream {
    pub fn reset(&mut self, offset: u64) {
        if offset < self.delivered {
            return;
        }
        self.delivered = offset;
        self.pending
            .retain(|&start, data| start + data.len() as u64 > offset);
        self.assembler.prefix = (0, 0);
        self.assembler.body = None;
        self.credit.reset(offset);
    }

    pub fn credit_pending(&self) -> Option<u64> {
        self.credit.pending(self.delivered)
    }

    pub fn has_pending_delivery(&self) -> bool {
        self.assembler
            .body
            .as_ref()
            .is_some_and(|(body, len)| body.len() == *len)
            || self
                .pending
                .first_key_value()
                .is_some_and(|(&offset, _)| offset <= self.delivered)
    }

    pub fn new(max_recv_msg_size: usize) -> Self {
        Self {
            delivered: 0,
            credit: Credit::default(),
            pending: BTreeMap::new(),
            assembler: Assembler {
                max_size: max_recv_msg_size,
                prefix: (0, 0),
                body: None,
            },
        }
    }

    pub fn receive(&mut self, offset: u64, data: &[u8]) -> Result<(), ProtocolViolation> {
        let end = offset
            .checked_add(data.len() as u64)
            .filter(|&end| end <= self.credit.limit())
            .ok_or(ProtocolViolation::Malformed)?;
        if end <= self.delivered {
            return Ok(());
        }
        let skip = self.delivered.saturating_sub(offset) as usize;
        self.buffer(offset.max(self.delivered), &data[skip..])
    }

    pub fn drain(
        &mut self,
        budget: &mut DeliveryBudget,
        out: &mut impl FnMut(Vec<u8>),
    ) -> Result<(), ProtocolViolation> {
        self.assembler.feed(&[], budget, out)?;
        while budget.messages > 0 && budget.work > 0 {
            let Some(entry) = self.pending.first_entry() else {
                break;
            };
            let start = *entry.key();
            if start > self.delivered {
                break;
            }
            let mut segment = entry.remove();
            let skip = (self.delivered - start) as usize;
            segment.drain(..skip);
            let consumed = self.assembler.feed(segment.as_slices().0, budget, out)?;
            self.delivered += consumed as u64;
            segment.drain(..consumed);
            if !segment.is_empty() {
                self.pending.insert(self.delivered, segment);
                if consumed == 0 {
                    break;
                }
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub fn on_frame(
        &mut self,
        offset: u64,
        data: &[u8],
        out: &mut impl FnMut(Vec<u8>),
    ) -> Result<(), ProtocolViolation> {
        self.receive(offset, data)?;
        self.drain(&mut DeliveryBudget::unlimited(), out)?;
        self.credit.sent(self.delivered + WINDOW);
        Ok(())
    }

    fn buffer(&mut self, mut offset: u64, mut data: &[u8]) -> Result<(), ProtocolViolation> {
        let end = offset + data.len() as u64;
        if let Some((&start, segment)) = self.pending.range(..=offset).next_back() {
            let segment_end = start + segment.len() as u64;
            if segment_end >= end {
                return Ok(());
            }
            if segment_end > offset {
                data = &data[(segment_end - offset) as usize..];
                offset = segment_end;
            }
        }
        while !data.is_empty() {
            let next = self
                .pending
                .range(offset..offset + data.len() as u64)
                .next()
                .map(|(&start, segment)| (start, start + segment.len() as u64));
            let Some((start, segment_end)) = next else {
                return self.insert(offset, data);
            };
            if start > offset {
                self.insert(offset, &data[..(start - offset) as usize])?;
            }
            if segment_end >= end {
                return Ok(());
            }
            data = &data[(segment_end - offset) as usize..];
            offset = segment_end;
        }
        Ok(())
    }

    /// Inserts data that overlaps no segment, merging it with adjacent ones.
    fn insert(&mut self, offset: u64, data: &[u8]) -> Result<(), ProtocolViolation> {
        let end = offset + data.len() as u64;
        let following = self.pending.remove(&end);
        if let Some((&start, segment)) = self.pending.range_mut(..offset).next_back()
            && start + segment.len() as u64 == offset
        {
            // Reuse the larger buffer when merging reordered fragments
            match following {
                Some(mut following) if following.len() > segment.len() => {
                    for &byte in data.iter().rev() {
                        following.push_front(byte);
                    }
                    for byte in std::mem::take(segment).into_iter().rev() {
                        following.push_front(byte);
                    }
                    *segment = following;
                }
                following => {
                    segment.extend(data.iter().copied());
                    if let Some(mut following) = following {
                        segment.append(&mut following);
                    }
                }
            }
            return Ok(());
        }
        if following.is_none() && self.pending.len() >= MAX_SEGMENTS {
            return Err(ProtocolViolation::Malformed);
        }
        let mut segment = following.unwrap_or_default();
        for &byte in data.iter().rev() {
            segment.push_front(byte);
        }
        self.pending.insert(offset, segment);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(i: usize) -> Rc<Vec<u8>> {
        Rc::new((0..i * 37 % 3000).map(|j| (i + j) as u8).collect())
    }

    /// Sends `count` messages through frames of `room` bytes, delivering them in the order
    /// `order` picks, and losing every `lose`-th frame once.
    fn transfer(count: usize, room: usize, lose: usize, reverse: bool) {
        let mut send = SendStream::default();
        let mut recv = RecvStream::new(1 << 20);
        for i in 0..count {
            send.push(message(i));
        }
        let mut received = Vec::new();
        let mut frames = Vec::new();
        let mut sent = 0;
        while send.queued_bytes() > 0 {
            while send.sendable() > 0 {
                let mut buf = vec![0u8; room];
                let mut w = Writer::new(&mut buf);
                let range = send.write(0, &mut w, 1200).unwrap();
                let len = w.len();
                buf.truncate(len);
                sent += 1;
                if lose > 0 && sent % lose == 0 {
                    send.on_lost(range);
                } else {
                    frames.push((range, buf));
                }
            }
            if reverse {
                frames.reverse();
            }
            for (range, buf) in frames.drain(..) {
                let mut r = crate::common::codec::Reader::new(&buf);
                let Some(frame::Frame::Reliable { offset, data, .. }) =
                    frame::parse(&mut r).unwrap()
                else {
                    panic!("not a reliable frame");
                };
                assert_eq!(offset, range.start);
                recv.on_frame(offset, data, &mut |m| received.push(m))
                    .unwrap();
                send.on_acked(range);
            }
        }
        assert_eq!(received.len(), count);
        for (i, m) in received.iter().enumerate() {
            assert_eq!(*m, *message(i));
        }
    }

    #[test]
    fn in_order() {
        transfer(200, 1200, 0, false);
    }

    #[test]
    fn reordered_and_lost() {
        transfer(200, 700, 3, true);
        transfer(200, 50, 7, true);
    }

    #[test]
    fn gap_delivery_respects_message_and_work_budgets() {
        let mut recv = RecvStream::new(1 << 20);
        recv.receive(1, &vec![0; WINDOW as usize - 1]).unwrap();
        recv.receive(0, &[0]).unwrap();
        let mut delivered = 0;
        let mut budget = DeliveryBudget {
            room: usize::MAX,
            messages: 17,
            bytes: 0,
            work: 1024,
        };
        recv.drain(&mut budget, &mut |message| {
            assert!(message.is_empty());
            delivered += 1;
        })
        .unwrap();
        assert_eq!(delivered, 17);
        assert!(recv.has_pending_delivery());
        assert!(recv.delivered <= 18);
        let mut budget = DeliveryBudget {
            room: usize::MAX,
            messages: 100,
            bytes: 0,
            work: 7,
        };
        recv.drain(&mut budget, &mut |_| delivered += 1).unwrap();
        assert_eq!(delivered, 24);
        assert_eq!(budget.work, 0);
    }

    #[test]
    fn credit_stops_at_application_capacity_and_resumes() {
        let mut send = SendStream::default();
        send.push(Rc::new(vec![1; WINDOW as usize]));
        let mut recv = RecvStream::new(WINDOW as usize);
        while send.sendable() > 0 {
            let mut buf = [0; 1200];
            let mut w = Writer::new(&mut buf);
            let range = send.write(0, &mut w, 1200).unwrap();
            let len = w.len();
            let Some(frame::Frame::Reliable { offset, data, .. }) =
                frame::parse(&mut crate::common::codec::Reader::new(&buf[..len])).unwrap()
            else {
                panic!();
            };
            recv.receive(offset, data).unwrap();
            send.on_acked(range);
        }
        assert_eq!(send.sent, WINDOW);
        assert!(send.queued_bytes() > 0);
        let mut budget = DeliveryBudget {
            room: usize::MAX,
            messages: 0,
            bytes: 0,
            work: 1 << 20,
        };
        recv.drain(&mut budget, &mut |_| panic!("application is full"))
            .unwrap();
        assert!(recv.credit_pending().is_none());
        recv.drain(&mut DeliveryBudget::unlimited(), &mut |_| {
            panic!("tail not received")
        })
        .unwrap();
        let limit = recv.credit_pending().unwrap();
        recv.credit.sent(limit);
        send.grant(limit);
        assert!(send.sendable() > 0);
        recv.credit.lost();
        assert_eq!(recv.credit_pending(), Some(limit));
        recv.receive(WINDOW, &[1; 3]).unwrap();
    }

    #[test]
    fn late_original_ack_cancels_queued_and_sent_retransmissions() {
        let mut send = SendStream::default();
        send.push(Rc::new(vec![1; 100]));
        let mut buf = [0; 1200];
        let original = send.write(0, &mut Writer::new(&mut buf), 1200).unwrap();
        send.on_lost(original.clone());
        let resent = send.write(0, &mut Writer::new(&mut buf), 1200).unwrap();
        send.on_acked(original);
        send.on_lost(resent);
        assert_eq!(send.queued_bytes(), 0);
        assert_eq!(send.sendable(), 0);
    }

    #[test]
    fn reset_retransmits_and_isolates_new_messages_from_delayed_packets() {
        let mut send = SendStream::default();
        let mut recv = RecvStream::new(1 << 20);
        send.push(Rc::new(vec![1; 2000]));
        let mut old = [0; 1200];
        let mut w = Writer::new(&mut old);
        let old_range = send.write(0, &mut w, 1200).unwrap();
        let old_len = w.len();
        let Some(frame::Frame::Reliable { offset, data, .. }) =
            frame::parse(&mut crate::common::codec::Reader::new(&old[..old_len])).unwrap()
        else {
            panic!()
        };
        recv.on_frame(offset, data, &mut |_| panic!("incomplete"))
            .unwrap();
        send.reset();
        let skip = send.reset_pending().unwrap();
        send.push(Rc::new(vec![9]));
        send.reset_sent();
        assert_eq!(send.sendable(), 0);
        send.reset_lost(skip);
        assert_eq!(send.reset_pending(), Some(skip));
        recv.reset(skip);
        send.reset_sent();
        send.reset_acked(skip);
        send.on_acked(old_range.clone());
        send.on_lost(old_range);
        assert_eq!(send.sendable(), 2);
        let mut buf = [0; 1200];
        let mut w = Writer::new(&mut buf);
        let range = send.write(0, &mut w, 1200).unwrap();
        let len = w.len();
        let Some(frame::Frame::Reliable { offset, data, .. }) =
            frame::parse(&mut crate::common::codec::Reader::new(&buf[..len])).unwrap()
        else {
            panic!()
        };
        let mut messages = Vec::new();
        recv.on_frame(offset, data, &mut |message| messages.push(message))
            .unwrap();
        recv.reset(skip);
        let Some(frame::Frame::Reliable { offset, data, .. }) =
            frame::parse(&mut crate::common::codec::Reader::new(&old[..old_len])).unwrap()
        else {
            panic!()
        };
        recv.on_frame(offset, data, &mut |_| panic!("obsolete"))
            .unwrap();
        send.on_acked(range);
        assert_eq!(messages, [vec![9]]);
        assert_eq!(send.queued_bytes(), 0);
    }

    #[test]
    fn stream_offsets_stop_before_the_protocol_boundary() {
        let mut send = SendStream {
            end: crate::common::transport::packet::MAX_PACKET_NUMBER - WINDOW,
            ..SendStream::default()
        };
        send.push(Rc::new(vec![]));
        assert!(send.exhausted());
        assert!(send.messages.is_empty());
    }

    #[test]
    fn reversed_small_fragments_and_wrapped_segments_preserve_payloads() {
        let mut recv = RecvStream::new(1 << 20);
        let mut data = [0; 10];
        let len = write_varint(&mut data, 65_536);
        let mut bytes = data[..len].to_vec();
        bytes.extend((0..65_536).map(|i| i as u8));
        for offset in (0..bytes.len()).rev() {
            recv.receive(offset as u64, &bytes[offset..offset + 1])
                .unwrap();
        }
        let mut messages = Vec::new();
        while recv.has_pending_delivery() {
            let mut budget = DeliveryBudget {
                room: usize::MAX,
                messages: 1,
                bytes: 1 << 20,
                work: 997,
            };
            recv.drain(&mut budget, &mut |message| messages.push(message))
                .unwrap();
        }
        assert_eq!(messages, [bytes[len..].to_vec()]);
    }
}
