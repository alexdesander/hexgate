// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{
    collections::{BTreeMap, BinaryHeap},
    rc::Rc,
    time::{Duration, Instant},
};

use assembler::MessageAssembler;
use bitvec::{array::BitArray, order::Lsb0};
use disassembler::MessageDisassembler;
use either::Either;

use crate::common::{
    congestion::CongestionController,
    crypto::Crypto,
    error::ProtocolViolation,
    packets::{
        acks::{Acks, ACK_BITFIELD_SIZE},
        reliable_payload::ReliablePayloadOwned,
    },
};

mod assembler;
mod disassembler;

/// Retransmissions wait `rto * 2^n` for the n-th retransmission, up to this exponent.
const MAX_BACKOFF_EXPONENT: u32 = 2;
/// A packet is lost once a packet this many ids later, sent after it, is acked (RFC 9002).
const PACKET_THRESHOLD: u64 = 3;

struct InFlight {
    /// Last transmission and its retransmission deadline, `None` until first sent.
    sent: Option<(Instant, Instant)>,
    transmissions: u32,
    packet: ReliablePayloadOwned,
}

impl InFlight {
    fn resend_at(&self) -> Option<Instant> {
        self.sent.map(|(_, resend_at)| resend_at)
    }
}

impl PartialEq for InFlight {
    fn eq(&self, other: &Self) -> bool {
        self.packet.packet_id() == other.packet.packet_id()
    }
}

impl Eq for InFlight {}

impl PartialOrd for InFlight {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Unsent packets first, then by retransmission deadline (`BinaryHeap` is a max-heap).
impl Ord for InFlight {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other
            .resend_at()
            .cmp(&self.resend_at())
            .then_with(|| other.packet.packet_id().cmp(&self.packet.packet_id()))
    }
}

#[derive(Debug)]
struct AckData {
    pub lowest_unreceived: u64,
    pub bitfield: BitArray<[u8; ACK_BITFIELD_SIZE], Lsb0>,
}

impl AckData {
    pub fn ack(&mut self, mut id: u64) {
        if id < self.lowest_unreceived || id > self.lowest_unreceived + 8 * 16 {
            return;
        }
        if id == self.lowest_unreceived {
            while id == self.lowest_unreceived {
                self.lowest_unreceived += 1;
                if *self.bitfield.first().unwrap() {
                    id += 1;
                }
                self.bitfield.shift_left(1);
            }
        } else {
            self.bitfield
                .set((id - self.lowest_unreceived - 1) as usize, true);
        }
    }

    pub fn is_acked(&self, id: u64) -> bool {
        if id < self.lowest_unreceived {
            return true;
        }
        if id > self.lowest_unreceived + 8 * 16 {
            return false;
        }
        if id == self.lowest_unreceived {
            return false;
        }
        *self
            .bitfield
            .get((id - self.lowest_unreceived - 1) as usize)
            .unwrap()
    }
}

pub struct ReliableChannel {
    channel_id: u8,
    assembler: MessageAssembler,
    disassembler: MessageDisassembler,

    next: u64,
    max_in_flight: usize,
    in_flights: BinaryHeap<InFlight>,
    lowest_unreceived_remote: u64,
    /// Id and last send time of the highest acked packet.
    largest_acked: Option<(u64, Instant)>,

    received: BTreeMap<u64, Vec<u8>>,
    acks_next: u64,
    ack_data: AckData,
    has_acks_to_send: bool,
    next_to_assemble: u64,
}

impl ReliableChannel {
    pub fn new(channel_id: u8, max_in_flight: usize, max_recv_msg_size: usize) -> Self {
        Self {
            channel_id,
            assembler: MessageAssembler::new(max_recv_msg_size),
            disassembler: MessageDisassembler::new(),

            next: 0,
            max_in_flight,
            in_flights: BinaryHeap::new(),
            lowest_unreceived_remote: 0,
            largest_acked: None,

            received: BTreeMap::new(),
            acks_next: 0,
            ack_data: AckData {
                lowest_unreceived: 0,
                bitfield: BitArray::ZERO,
            },
            has_acks_to_send: false,
            next_to_assemble: 0,
        }
    }

    pub fn push(&mut self, message: Rc<Vec<u8>>) {
        self.disassembler.push(message);
    }

    pub fn peek_size(&mut self) -> usize {
        self.gather_in_flights();
        if let Some(in_flight) = self.in_flights.peek() {
            in_flight.packet.serialized_size()
        } else {
            0
        }
    }

    pub fn pop(
        &mut self,
        congestion: &mut CongestionController,
        crypto: &Crypto,
        buf: &mut [u8],
    ) -> Either<usize, Option<Duration>> {
        self.gather_in_flights();
        self.next_to_send(congestion, crypto, buf)
    }

    fn gather_in_flights(&mut self) {
        for _ in self.in_flights.len()..self.max_in_flight {
            if self.next
                >= self
                    .lowest_unreceived_remote
                    .saturating_add(self.max_in_flight as u64)
            {
                break;
            }
            let Some(payload) = self
                .disassembler
                .pop(ReliablePayloadOwned::max_payload_size(None, self.next))
            else {
                break;
            };
            let packet = ReliablePayloadOwned::NoAcks {
                channel_id: self.channel_id,
                packet_id: self.next,
                payload,
            };
            self.next += 1;
            self.in_flights.push(InFlight {
                sent: None,
                transmissions: 0,
                packet,
            });
        }
    }

    fn next_to_send(
        &mut self,
        congestion: &mut CongestionController,
        crypto: &Crypto,
        buf: &mut [u8],
    ) -> Either<usize, Option<Duration>> {
        // Return resend wait time if there are no packets to send
        if self.in_flights.is_empty() {
            return Either::Right(None);
        }
        let now = Instant::now();
        let in_flight = self.in_flights.peek().unwrap();
        if let Some(resend_at) = in_flight.resend_at() {
            if resend_at > now {
                return Either::Right(Some(resend_at - now));
            }
        }

        // A packet is ready to be sent, return its size
        let mut packet = self.in_flights.pop().unwrap();

        if packet.transmissions > 0 {
            congestion.register_resent_reliable();
        } else {
            congestion.register_sent_reliable();
        }

        let backoff = 1 << packet.transmissions.min(MAX_BACKOFF_EXPONENT);
        packet.transmissions += 1;
        packet.sent = Some((now, now + congestion.rto() * backoff));
        let size = packet.packet.serialize(crypto, buf);
        self.in_flights.push(packet);
        Either::Left(size)
    }

    pub fn handle(
        &mut self,
        packet: ReliablePayloadOwned,
    ) -> Result<Vec<Vec<u8>>, ProtocolViolation> {
        let pid = packet.packet_id();
        if self.ack_data.is_acked(pid) {
            return Ok(Vec::new());
        }
        if pid > self.ack_data.lowest_unreceived + self.max_in_flight as u64 {
            return Ok(Vec::new());
        }
        self.ack_data.ack(pid);
        self.has_acks_to_send = true;

        self.received.insert(pid, packet.take_payload());
        let mut messages = Vec::new();
        while let Some(payload) = self.received.remove(&self.next_to_assemble) {
            let mut new_messages = self.assembler.assemble_packet(payload)?;
            messages.append(&mut new_messages);
            self.next_to_assemble += 1;
        }
        Ok(messages)
    }

    pub fn acks(&mut self) -> Acks {
        self.acks_next += 1;
        Acks {
            channel_id: self.channel_id,
            packet_id: self.acks_next - 1,
            lowest_unreceived: self.ack_data.lowest_unreceived,
            ack_bitfield: self.ack_data.bitfield.into_inner(),
        }
    }

    /// Returns an RTT sample from the newest acked packet that was sent once (Karn's algorithm).
    /// Unacked packets that were overtaken by `PACKET_THRESHOLD` acked ones are resent now.
    pub fn handle_acks(&mut self, acks: Acks) -> Option<Duration> {
        let ack_data = AckData {
            lowest_unreceived: acks.lowest_unreceived,
            bitfield: BitArray::new(acks.ack_bitfield),
        };
        self.lowest_unreceived_remote = self
            .lowest_unreceived_remote
            .max(ack_data.lowest_unreceived);
        let mut in_flights = std::mem::take(&mut self.in_flights).into_vec();
        let mut newest_sample = None;
        in_flights.retain(|in_flight| {
            let id = in_flight.packet.packet_id();
            if !ack_data.is_acked(id) {
                return true;
            }
            if let Some((sent, _)) = in_flight.sent {
                if in_flight.transmissions == 1 {
                    newest_sample = newest_sample.max(Some(sent));
                }
                if self.largest_acked.is_none_or(|(largest, _)| id > largest) {
                    self.largest_acked = Some((id, sent));
                }
            }
            false
        });
        if let Some((largest, largest_sent)) = self.largest_acked {
            let now = Instant::now();
            for in_flight in &mut in_flights {
                if let Some((sent, resend_at)) = &mut in_flight.sent {
                    if in_flight.packet.packet_id() + PACKET_THRESHOLD <= largest
                        && *sent < largest_sent
                    {
                        *resend_at = (*resend_at).min(now);
                    }
                }
            }
        }
        self.in_flights = in_flights.into();
        newest_sample.map(|sent| sent.elapsed())
    }

    pub fn _has_acks_to_send(&self) -> bool {
        self.has_acks_to_send
    }

    pub fn _reset_acks_to_send(&mut self) {
        self.has_acks_to_send = false;
    }
}
