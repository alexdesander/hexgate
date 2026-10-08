// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Unreliable channels: `Channel::Unreliable` (`channel: None`) and the ordered ones. Each
//! packet arrives at most once (the transport's replay window), so unordered messages need no
//! id unless they are fragmented.

#[cfg(test)]
use std::rc::Rc;
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};

use super::SendResult;
use crate::common::{
    codec::Writer,
    error::ProtocolViolation,
    send::{Message, Reservation, SendOutcome},
    transport::frame::{self, Fragment},
};

/// Incomplete fragmented messages kept per channel; a newer one evicts the oldest.
const MAX_ASSEMBLIES: usize = 4;
/// A fragment is only started with at least this many bytes of room.
const MIN_FRAGMENT: usize = 64;
const ASSEMBLY_IDLE: Duration = Duration::from_secs(2);
const ASSEMBLY_LIFETIME: Duration = Duration::from_secs(30);

struct Queued {
    message: Message,
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

struct Receipt {
    cookie: u64,
    remaining: usize,
    complete: bool,
    reservation: Option<Arc<Reservation>>,
}

pub struct UnreliableSend {
    channel: Option<u8>,
    queue: VecDeque<Queued>,
    next_id: u64,
    max_age: Duration,
    queued_bytes: usize,
    /// Messages dropped because they waited longer than `max_age`.
    pub expired: u64,
    receipts: HashMap<u64, Receipt>,
    results: Vec<SendResult>,
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
            receipts: HashMap::new(),
            results: Vec::new(),
        }
    }

    #[cfg(test)]
    pub fn push(&mut self, message: Rc<Vec<u8>>, now: Instant) {
        self.push_message(Message::untracked(message, now));
    }

    pub fn push_message(&mut self, message: Message) {
        if message.options.replace {
            let obsolete: Vec<_> = self
                .queue
                .iter()
                .filter(|queued| queued.sent == 0)
                .map(|queued| queued.msg_id)
                .collect();
            for id in obsolete {
                self.drop_message(id);
            }
        }
        if let Some(cookie) = message.options.receipt {
            self.receipts.insert(
                self.next_id,
                Receipt {
                    cookie,
                    remaining: 0,
                    complete: false,
                    reservation: message.reservation.clone(),
                },
            );
        }
        self.queued_bytes += message.len();
        self.queue.push_back(Queued {
            message,
            msg_id: self.next_id,
            sent: 0,
        });
        self.next_id += 1;
    }

    pub fn queued_bytes(&self) -> usize {
        self.queued_bytes
    }

    pub fn unsent_bytes(&self) -> usize {
        self.queue
            .iter()
            .map(|queued| queued.message.len() - queued.sent)
            .sum()
    }

    pub fn oldest(&self) -> Option<Instant> {
        self.queue.front().map(|queued| queued.message.submitted)
    }

    pub fn deadline(&self) -> Option<Instant> {
        let queued = self.queue.front()?;
        let age = (queued.sent == 0)
            .then(|| queued.message.submitted.checked_add(self.max_age))
            .flatten();
        age.into_iter().chain(queued.message.options.deadline).min()
    }

    pub fn receipt(&self) -> Option<u64> {
        self.queue
            .front()
            .filter(|queued| queued.message.options.receipt.is_some())
            .map(|queued| queued.msg_id)
    }

    pub fn on_acked(&mut self, id: u64) {
        if let Some(receipt) = self.receipts.get_mut(&id) {
            receipt.remaining = receipt.remaining.saturating_sub(1);
            if receipt.remaining == 0 && receipt.complete {
                let receipt = self.receipts.remove(&id).unwrap();
                self.results
                    .push((receipt.cookie, SendOutcome::Acked, receipt.reservation));
            }
        }
    }

    pub fn on_lost(&mut self, id: u64) {
        self.drop_message(id);
    }

    pub fn take_results(&mut self, out: &mut Vec<SendResult>) {
        out.append(&mut self.results);
    }

    fn drop_message(&mut self, id: u64) {
        if let Some(receipt) = self.receipts.remove(&id) {
            self.results
                .push((receipt.cookie, SendOutcome::Dropped, receipt.reservation));
        }
        self.queue.retain(|queued| {
            if queued.msg_id == id {
                self.queued_bytes -= queued.message.len();
                false
            } else {
                true
            }
        });
    }

    fn written(&mut self, id: u64, complete: bool) {
        if let Some(receipt) = self.receipts.get_mut(&id) {
            receipt.remaining += 1;
            receipt.complete = complete;
        }
    }

    /// Drops messages that expired before starting, and any past an explicit deadline
    pub fn ready(&mut self, now: Instant) -> bool {
        while let Some(queued) = self.queue.front() {
            let deadline = queued
                .message
                .options
                .deadline
                .is_some_and(|deadline| now >= deadline);
            if !deadline
                && (queued.sent > 0
                    || now.saturating_duration_since(queued.message.submitted) < self.max_age)
            {
                return true;
            }
            let id = queued.msg_id;
            self.drop_message(id);
            self.expired += 1;
        }
        false
    }

    /// Bytes the next frame would carry into an empty packet of `capacity`.
    pub fn next_size(&self, capacity: usize) -> usize {
        self.queue.front().map_or(0, |queued| {
            (queued.message.len() - queued.sent).max(1).min(capacity)
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
            if w.remaining() > header && frame::fit(header, len, w.remaining()) == len {
                frame::write_unreliable(w, self.channel, queued.msg_id, None, &queued.message);
                let id = queued.msg_id;
                self.written(id, true);
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
        let complete = queued.sent == len;
        let id = queued.msg_id;
        self.written(id, complete);
        if complete {
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
    coverage: Vec<u64>,
    created: Instant,
    updated: Instant,
}

impl Assembly {
    fn allocated(&self) -> usize {
        self.total + self.coverage.len() * 8
    }

    fn deadline(&self) -> Instant {
        (self.created + ASSEMBLY_LIFETIME).min(self.updated + ASSEMBLY_IDLE)
    }
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

    pub fn expire(&mut self, now: Instant, budget: &mut AssemblyBudget) {
        self.assemblies.retain(|assembly| {
            let keep = now < assembly.deadline();
            if !keep {
                budget.left += assembly.allocated();
            }
            keep
        });
    }

    pub fn deadline(&self) -> Option<Instant> {
        self.assemblies.iter().map(Assembly::deadline).min()
    }

    pub fn oldest(&self) -> Option<Instant> {
        self.assemblies
            .iter()
            .map(|assembly| assembly.created)
            .min()
    }

    pub fn allocated(&self) -> usize {
        self.assemblies.iter().map(Assembly::allocated).sum()
    }

    pub fn reclaim(&mut self, budget: &mut AssemblyBudget) {
        if let Some(index) = (0..self.assemblies.len()).min_by_key(|&i| self.assemblies[i].created)
        {
            budget.left += self.assemblies.swap_remove(index).allocated();
        }
    }

    pub fn needs(&self, msg_id: u64, total: usize) -> usize {
        if !self.deliverable(msg_id) || self.assemblies.iter().any(|a| a.msg_id == msg_id) {
            0
        } else {
            total.saturating_add(total.div_ceil(64).saturating_mul(8))
        }
    }

    fn delivered(&mut self, msg_id: u64, budget: &mut AssemblyBudget) {
        if self.ordered {
            self.last_delivered = Some(msg_id);
            self.assemblies.retain(|assembly| {
                let keep = assembly.msg_id > msg_id;
                if !keep {
                    budget.left += assembly.allocated();
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
        now: Instant,
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
                    budget.left += self.assemblies.swap_remove(oldest).allocated();
                }
                let needed = total
                    .checked_add(total.div_ceil(64).saturating_mul(8))
                    .ok_or(ProtocolViolation::Malformed)?;
                if needed > budget.left {
                    return Ok(None);
                }
                budget.left -= needed;
                self.assemblies.push(Assembly {
                    msg_id,
                    total,
                    received: 0,
                    buf: vec![0; total],
                    coverage: vec![0; total.div_ceil(64)],
                    created: now,
                    updated: now,
                });
                self.assemblies.len() - 1
            }
        };
        let assembly = &mut self.assemblies[index];
        if assembly.total != total {
            return Err(ProtocolViolation::Malformed);
        }
        assembly.updated = now;
        for (offset, byte) in (start..end).zip(data) {
            let bit = 1 << (offset % 64);
            let word = &mut assembly.coverage[offset / 64];
            if *word & bit == 0 {
                *word |= bit;
                assembly.received += 1;
                assembly.buf[offset] = *byte;
            } else if assembly.buf[offset] != *byte {
                return Err(ProtocolViolation::Malformed);
            }
        }
        if assembly.received < total {
            return Ok(None);
        }
        let assembly = self.assemblies.swap_remove(index);
        budget.left += assembly.allocated();
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
                recv.on_frame(msg_id, fragment, data, 1 << 20, budget, Instant::now())
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
        assert!(!send.ready(now + Duration::from_millis(500)));
        assert_eq!(send.expired, 3);
        assert_eq!(send.queued_bytes(), 0);
    }

    #[test]
    fn maximum_messages_complete_with_reordering_and_duplicate_fragments() {
        for ordered in [false, true] {
            let now = Instant::now();
            let mut send = UnreliableSend::new(ordered.then_some(0), Duration::from_millis(100));
            let message: Vec<_> = (0..1 << 20).map(|i| (i * 13) as u8).collect();
            send.push(Rc::new(message.clone()), now);
            let packets = frames(&mut send, 1200);
            let mut recv = UnreliableRecv::new(ordered);
            let mut budget = AssemblyBudget { left: 4 << 20 };
            let mut received = Vec::new();
            for packet in packets.iter().rev() {
                received.extend(receive(&mut recv, packet, &mut budget));
                if received.is_empty() {
                    assert!(receive(&mut recv, packet, &mut budget).is_empty());
                }
            }
            assert_eq!(received, [message]);
            assert_eq!(budget.left, 4 << 20);
        }
    }

    #[test]
    fn active_assemblies_survive_idle_limit_but_not_absolute_lifetime() {
        let now = Instant::now();
        let mut recv = UnreliableRecv::new(false);
        let mut budget = AssemblyBudget { left: 4096 };
        for offset in 0..5 {
            let at = now + Duration::from_secs(offset);
            recv.expire(at, &mut budget);
            let message = recv
                .on_frame(
                    0,
                    Some(Fragment { offset, total: 5 }),
                    &[7],
                    1024,
                    &mut budget,
                    at,
                )
                .unwrap();
            if offset == 4 {
                assert_eq!(message, Some(vec![7; 5]));
            } else {
                assert!(message.is_none());
            }
        }
        for second in 0..30 {
            let at = now + Duration::from_secs(second);
            recv.expire(at, &mut budget);
            recv.on_frame(
                1,
                Some(Fragment {
                    offset: 0,
                    total: 100,
                }),
                &[1],
                1024,
                &mut budget,
                at,
            )
            .unwrap();
        }
        recv.expire(now + Duration::from_secs(30), &mut budget);
        assert!(recv.assemblies.is_empty());
        assert_eq!(budget.left, 4096);
    }
}
