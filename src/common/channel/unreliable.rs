// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Unreliable channels: `Channel::Unreliable` (`channel: None`) and the ordered ones. Each
//! packet arrives at most once (the transport's replay window), so unordered messages need no
//! id unless they are fragmented.

use std::{
    collections::VecDeque,
    rc::Rc,
    time::{Duration, Instant},
};

use crate::common::{
    codec::Writer,
    error::ProtocolViolation,
    transport::frame::{self, Fragment},
};

/// Incomplete fragmented messages kept per channel; a newer one evicts the oldest.
const MAX_ASSEMBLIES: usize = 4;
/// Fragments of one message that may arrive out of order.
const MAX_FRAGMENT_RANGES: usize = 64;
/// A fragment is only started with at least this many bytes of room.
const MIN_FRAGMENT: usize = 64;

struct Queued {
    message: Rc<Vec<u8>>,
    queued_at: Instant,
    msg_id: u64,
    /// Bytes already sent as fragments.
    sent: usize,
}

pub enum Write {
    Wrote,
    /// The next message doesn't fit into the rest of this packet.
    NoRoom,
    Idle,
}

pub struct UnreliableSend {
    channel: Option<u8>,
    queue: VecDeque<Queued>,
    next_id: u64,
    max_age: Duration,
    queued_bytes: usize,
    /// Messages dropped because they waited longer than `max_age`.
    pub expired: u64,
}

impl UnreliableSend {
    pub fn new(channel: Option<u8>, max_age: Duration) -> Self {
        Self {
            channel,
            queue: VecDeque::new(),
            next_id: 0,
            max_age,
            queued_bytes: 0,
            expired: 0,
        }
    }

    pub fn push(&mut self, message: Rc<Vec<u8>>, now: Instant) {
        self.queued_bytes += message.len();
        self.queue.push_back(Queued {
            message,
            queued_at: now,
            msg_id: self.next_id,
            sent: 0,
        });
        self.next_id += 1;
    }

    pub fn queued_bytes(&self) -> usize {
        self.queued_bytes
    }

    /// Drops messages that waited too long to be started, except the newest one (the latest
    /// state is worth sending late). Returns whether one is left.
    pub fn ready(&mut self, now: Instant) -> bool {
        while let Some(queued) = self.queue.front() {
            if queued.sent > 0
                || self.queue.len() == 1
                || now.saturating_duration_since(queued.queued_at) <= self.max_age
            {
                return true;
            }
            self.queued_bytes -= queued.message.len();
            self.queue.pop_front();
            self.expired += 1;
        }
        false
    }

    /// Bytes the next frame would carry into an empty packet of `capacity`.
    pub fn next_size(&self, capacity: usize) -> usize {
        self.queue.front().map_or(0, |queued| {
            (queued.message.len() - queued.sent).min(capacity)
        })
    }

    /// Writes the next message, or as much of it as fits as a fragment. Messages that fit into
    /// an empty packet of `capacity` are never fragmented.
    pub fn write(&mut self, w: &mut Writer, capacity: usize) -> Write {
        let Some(queued) = self.queue.front_mut() else {
            return Write::Idle;
        };
        let len = queued.message.len();
        if queued.sent == 0 {
            let header = frame::unreliable_header(self.channel, queued.msg_id, None);
            if frame::fit(header, len, w.remaining()) == len {
                frame::write_unreliable(w, self.channel, queued.msg_id, None, &queued.message);
                self.pop();
                return Write::Wrote;
            }
            if frame::fit(header, len, capacity) == len {
                return Write::NoRoom;
            }
        }
        let fragment = Some(Fragment {
            offset: queued.sent as u64,
            total: len as u64,
        });
        let header = frame::unreliable_header(self.channel, queued.msg_id, fragment);
        let left = len - queued.sent;
        let take = frame::fit(header, left, w.remaining());
        if take == 0 || (take < left && take < MIN_FRAGMENT) {
            return Write::NoRoom;
        }
        let data = &queued.message[queued.sent..queued.sent + take];
        frame::write_unreliable(w, self.channel, queued.msg_id, fragment, data);
        queued.sent += take;
        if queued.sent == len {
            self.pop();
        }
        Write::Wrote
    }

    fn pop(&mut self) {
        if let Some(queued) = self.queue.pop_front() {
            self.queued_bytes -= queued.message.len();
        }
    }
}

struct Assembly {
    msg_id: u64,
    total: usize,
    received: usize,
    buf: Vec<u8>,
    /// Received byte ranges, to reject overlapping fragments.
    ranges: Vec<(usize, usize)>,
}

pub struct UnreliableRecv {
    ordered: bool,
    /// Ordered channels deliver only newer messages than this.
    last_delivered: Option<u64>,
    assemblies: Vec<Assembly>,
}

/// Bytes the fragment assemblies of a connection may hold together.
pub struct AssemblyBudget {
    pub left: usize,
}

impl UnreliableRecv {
    pub fn new(ordered: bool) -> Self {
        Self {
            ordered,
            last_delivered: None,
            assemblies: Vec::new(),
        }
    }

    fn deliverable(&self, msg_id: u64) -> bool {
        !self.ordered || self.last_delivered.is_none_or(|last| msg_id > last)
    }

    fn delivered(&mut self, msg_id: u64, budget: &mut AssemblyBudget) {
        if self.ordered {
            self.last_delivered = Some(msg_id);
            self.assemblies.retain(|assembly| {
                let keep = assembly.msg_id > msg_id;
                if !keep {
                    budget.left += assembly.buf.capacity();
                }
                keep
            });
        }
    }

    pub fn on_frame(
        &mut self,
        msg_id: u64,
        fragment: Option<Fragment>,
        data: &[u8],
        max_size: usize,
        budget: &mut AssemblyBudget,
    ) -> Result<Option<Vec<u8>>, ProtocolViolation> {
        let too_large = ProtocolViolation::MessageTooLarge { max: max_size };
        if !self.deliverable(msg_id) {
            return Ok(None);
        }
        let Some(fragment) = fragment else {
            if data.len() > max_size {
                return Err(too_large);
            }
            self.delivered(msg_id, budget);
            return Ok(Some(data.to_vec()));
        };
        let total = usize::try_from(fragment.total)
            .ok()
            .filter(|&total| total <= max_size)
            .ok_or(too_large)?;
        let start = usize::try_from(fragment.offset).unwrap_or(usize::MAX);
        let end = start
            .checked_add(data.len())
            .filter(|&end| end <= total && !data.is_empty())
            .ok_or(ProtocolViolation::Malformed)?;
        let index = match self.assemblies.iter().position(|a| a.msg_id == msg_id) {
            Some(index) => index,
            None => {
                if self.assemblies.len() == MAX_ASSEMBLIES {
                    let oldest = (0..self.assemblies.len())
                        .min_by_key(|&i| self.assemblies[i].msg_id)
                        .unwrap();
                    if self.assemblies[oldest].msg_id > msg_id {
                        return Ok(None);
                    }
                    budget.left += self.assemblies.swap_remove(oldest).buf.capacity();
                }
                self.assemblies.push(Assembly {
                    msg_id,
                    total,
                    received: 0,
                    buf: Vec::new(),
                    ranges: Vec::new(),
                });
                self.assemblies.len() - 1
            }
        };
        let assembly = &mut self.assemblies[index];
        if assembly.total != total {
            return Err(ProtocolViolation::Malformed);
        }
        if assembly.ranges.len() == MAX_FRAGMENT_RANGES
            || assembly.ranges.iter().any(|&(s, e)| start < e && s < end)
        {
            return Ok(None);
        }
        if end > assembly.buf.len() {
            let grow = end.max(assembly.buf.capacity()) - assembly.buf.capacity();
            if grow > budget.left {
                budget.left += self.assemblies.swap_remove(index).buf.capacity();
                return Ok(None);
            }
            let before = assembly.buf.capacity();
            assembly.buf.reserve_exact(end - assembly.buf.len());
            budget.left -= assembly.buf.capacity() - before;
            assembly.buf.resize(end, 0);
        }
        assembly.buf[start..end].copy_from_slice(data);
        assembly.ranges.push((start, end));
        assembly.received += data.len();
        if assembly.received < total {
            return Ok(None);
        }
        let assembly = self.assemblies.swap_remove(index);
        budget.left += assembly.buf.capacity();
        self.delivered(msg_id, budget);
        Ok(Some(assembly.buf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{codec::Reader, transport::frame::Frame};

    fn frames(send: &mut UnreliableSend, room: usize) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            let mut buf = vec![0u8; room];
            let mut w = Writer::new(&mut buf);
            while let Write::Wrote = send.write(&mut w, room) {}
            let len = w.len();
            if len == 0 {
                return out;
            }
            buf.truncate(len);
            out.push(buf);
        }
    }

    fn receive(
        recv: &mut UnreliableRecv,
        packet: &[u8],
        budget: &mut AssemblyBudget,
    ) -> Vec<Vec<u8>> {
        let mut r = Reader::new(packet);
        let mut messages = Vec::new();
        while let Some(frame) = frame::parse(&mut r).unwrap() {
            let Frame::Unreliable {
                msg_id,
                fragment,
                data,
                ..
            } = frame
            else {
                panic!("unexpected frame");
            };
            messages.extend(
                recv.on_frame(msg_id, fragment, data, 1 << 20, budget)
                    .unwrap(),
            );
        }
        messages
    }

    #[test]
    fn coalesces_and_fragments() {
        let now = Instant::now();
        let mut send = UnreliableSend::new(Some(2), Duration::from_millis(100));
        let messages: Vec<Vec<u8>> = [10, 20, 1100, 5000, 30]
            .iter()
            .map(|&len| (0..len).map(|i| i as u8).collect())
            .collect();
        for message in &messages {
            send.push(Rc::new(message.clone()), now);
        }
        let packets = frames(&mut send, 1150);
        assert!(packets.len() <= 7, "{}", packets.len());
        let mut recv = UnreliableRecv::new(true);
        let mut budget = AssemblyBudget { left: 1 << 20 };
        let received: Vec<_> = packets
            .iter()
            .flat_map(|packet| receive(&mut recv, packet, &mut budget))
            .collect();
        assert!(received == messages, "every message arrives whole");
        assert_eq!(budget.left, 1 << 20);
    }

    #[test]
    fn ordered_drops_older_and_reassembles_out_of_order() {
        let now = Instant::now();
        let mut send = UnreliableSend::new(Some(0), Duration::from_millis(100));
        let big: Vec<u8> = (0..3000).map(|i| (i * 7) as u8).collect();
        send.push(Rc::new(big.clone()), now);
        let mut packets = frames(&mut send, 1200);
        send.push(Rc::new(vec![1; 10]), now);
        let small = frames(&mut send, 1200);
        let mut recv = UnreliableRecv::new(true);
        let mut budget = AssemblyBudget { left: 1 << 20 };
        packets.reverse();
        let mut received = Vec::new();
        for packet in &packets {
            received.extend(receive(&mut recv, packet, &mut budget));
        }
        assert!(received == [big], "the big message arrives whole");
        received.extend(receive(&mut recv, &small[0], &mut budget));
        assert_eq!(received.len(), 2);
        assert!(receive(&mut recv, &packets[0], &mut budget).is_empty());
        assert_eq!(budget.left, 1 << 20);
    }

    #[test]
    fn expires_stale_messages() {
        let now = Instant::now();
        let mut send = UnreliableSend::new(None, Duration::from_millis(100));
        send.push(Rc::new(vec![0; 10]), now);
        send.push(Rc::new(vec![0; 10]), now + Duration::from_millis(50));
        send.push(Rc::new(vec![0; 10]), now + Duration::from_millis(60));
        assert!(send.ready(now + Duration::from_millis(120)));
        assert_eq!(send.expired, 1);
        assert!(send.ready(now + Duration::from_millis(500)));
        assert_eq!(send.expired, 2);
        assert_eq!(send.queued_bytes(), 10);
    }
}
