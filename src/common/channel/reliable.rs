// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! A reliable channel is a byte stream of varint-length-prefixed messages, sent in RELIABLE
//! frames addressed by stream offset (like QUIC STREAM frames) and acknowledged per packet.

use std::{
    collections::{BTreeMap, VecDeque},
    ops::Range,
    rc::Rc,
};

use super::ranges::RangeSet;
use crate::common::{
    codec::{write_varint, Writer},
    error::ProtocolViolation,
    transport::frame,
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

struct Queued {
    start: u64,
    header: [u8; 10],
    header_len: u8,
    message: Rc<Vec<u8>>,
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
    messages: VecDeque<Queued>,
    end: u64,
    /// Everything below was sent at least once.
    sent: u64,
    /// Everything below was acknowledged.
    acked_until: u64,
    /// Acknowledged ranges above `acked_until`.
    acked: RangeSet,
    /// Ranges to send again.
    lost: RangeSet,
}

impl SendStream {
    pub fn push(&mut self, message: Rc<Vec<u8>>) {
        let mut header = [0; 10];
        let header_len = write_varint(&mut header, message.len() as u64) as u8;
        let queued = Queued {
            start: self.end,
            header,
            header_len,
            message,
        };
        self.end = queued.end();
        self.messages.push_back(queued);
    }

    /// Bytes not acknowledged yet, sent or not.
    pub fn queued_bytes(&self) -> u64 {
        self.end - self.acked_until
    }

    fn new_data(&self) -> Range<u64> {
        self.sent..self.end.min(self.acked_until + WINDOW)
    }

    /// Bytes ready to be sent: lost ones and new ones within the window.
    pub fn sendable(&self) -> u64 {
        self.lost.first().map_or(0, |range| range.end - range.start)
            + self.new_data().end.saturating_sub(self.sent)
    }

    /// Writes one frame of lost or new data into `w`, returns its stream range.
    pub fn write(&mut self, channel: u8, w: &mut Writer) -> Option<Range<u64>> {
        let lost = self.lost.first();
        let next = lost.clone().unwrap_or_else(|| self.new_data());
        if next.is_empty() {
            return None;
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

    pub fn on_acked(&mut self, range: Range<u64>) {
        self.lost.remove(range.clone());
        self.acked.insert(range);
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
                self.messages.pop_front();
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
        out: &mut impl FnMut(Vec<u8>),
    ) -> Result<(), ProtocolViolation> {
        while !data.is_empty() {
            if let Some((body, len)) = &mut self.body {
                let take = (*len - body.len()).min(data.len());
                body.extend_from_slice(&data[..take]);
                data = &data[take..];
                if body.len() == *len {
                    out(self.body.take().unwrap().0);
                }
                continue;
            }
            let byte = data[0];
            data = &data[1..];
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
            if len == 0 {
                out(Vec::new());
            } else {
                self.body = Some((Vec::with_capacity(len.min(1 << 16)), len));
            }
        }
        Ok(())
    }
}

pub struct RecvStream {
    delivered: u64,
    /// Data beyond `delivered`, merged where adjacent.
    pending: BTreeMap<u64, Vec<u8>>,
    assembler: Assembler,
}

impl RecvStream {
    pub fn new(max_recv_msg_size: usize) -> Self {
        Self {
            delivered: 0,
            pending: BTreeMap::new(),
            assembler: Assembler {
                max_size: max_recv_msg_size,
                prefix: (0, 0),
                body: None,
            },
        }
    }

    /// Handles a frame's data at `offset`, complete messages go to `out`.
    pub fn on_frame(
        &mut self,
        offset: u64,
        data: &[u8],
        out: &mut impl FnMut(Vec<u8>),
    ) -> Result<(), ProtocolViolation> {
        let end = offset
            .checked_add(data.len() as u64)
            .filter(|&end| end <= self.delivered + WINDOW)
            .ok_or(ProtocolViolation::Malformed)?;
        if end <= self.delivered {
            return Ok(());
        }
        let (offset, data) = if offset < self.delivered {
            (self.delivered, &data[(self.delivered - offset) as usize..])
        } else {
            (offset, data)
        };
        if offset > self.delivered {
            return self.buffer(offset, data);
        }
        self.assembler.feed(data, out)?;
        self.delivered = end;
        while let Some(entry) = self.pending.first_entry() {
            let start = *entry.key();
            if start > self.delivered {
                break;
            }
            let segment = entry.remove();
            let segment_end = start + segment.len() as u64;
            if segment_end > self.delivered {
                self.assembler
                    .feed(&segment[(self.delivered - start) as usize..], out)?;
                self.delivered = segment_end;
            }
        }
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
        if let Some((&start, segment)) = self.pending.range_mut(..offset).next_back() {
            if start + segment.len() as u64 == offset {
                segment.extend_from_slice(data);
                segment.extend_from_slice(following.as_deref().unwrap_or_default());
                return Ok(());
            }
        }
        if following.is_none() && self.pending.len() >= MAX_SEGMENTS {
            return Err(ProtocolViolation::Malformed);
        }
        let mut segment = data.to_vec();
        segment.extend_from_slice(following.as_deref().unwrap_or_default());
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
                let range = send.write(0, &mut w).unwrap();
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
}
