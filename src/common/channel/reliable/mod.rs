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
    packets::{acks::Acks, reliable_payload::ReliablePayloadOwned},
};

mod assembler;
mod disassembler;

struct InFlight {
    sent: Option<Instant>,
    packet: ReliablePayloadOwned,
}

impl PartialEq for InFlight {
    fn eq(&self, other: &Self) -> bool {
        self.packet.packet_id() == other.packet.packet_id()
    }
}

impl Eq for InFlight {}

impl PartialOrd for InFlight {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        match other.sent.cmp(&self.sent) {
            std::cmp::Ordering::Equal => {
                Some(other.packet.packet_id().cmp(&self.packet.packet_id()))
            }
            x => Some(x),
        }
    }
}

impl Ord for InFlight {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match other.sent.cmp(&self.sent) {
            std::cmp::Ordering::Equal => other.packet.packet_id().cmp(&self.packet.packet_id()),
            x => x,
        }
    }
}

#[derive(Debug)]
struct AckData {
    pub lowest_unreceived: u64,
    pub bitfield: BitArray<[u8; 16], Lsb0>,
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
    resend_cooldown: Duration,

    received: BTreeMap<u64, Vec<u8>>,
    acks_next: u64,
    ack_data: AckData,
    has_acks_to_send: bool,
    next_to_assemble: u64,
}

impl ReliableChannel {
    pub fn new(channel_id: u8, resend_cooldown: Duration, max_in_flight: usize) -> Self {
        Self {
            channel_id,
            assembler: MessageAssembler::new(),
            disassembler: MessageDisassembler::new(),

            next: 0,
            max_in_flight,
            in_flights: BinaryHeap::new(),
            resend_cooldown,
            lowest_unreceived_remote: 0,

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
            self.in_flights.push(InFlight { sent: None, packet });
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
        let in_flight = self.in_flights.peek().unwrap();
        if let Some(sent) = in_flight.sent {
            let elapsed = sent.elapsed();
            if elapsed < self.resend_cooldown {
                return Either::Right(Some(self.resend_cooldown.saturating_sub(elapsed)));
            }
        }

        // A packet is ready to be sent, return its size
        let mut packet = self.in_flights.pop().unwrap();

        if packet.sent.is_some() {
            congestion.register_resent_reliable();
        } else {
            congestion.register_sent_reliable();
        }

        packet.sent = Some(Instant::now());
        let size = packet.packet.serialize(crypto, buf);
        self.in_flights.push(packet);
        Either::Left(size)
    }

    pub fn handle(&mut self, packet: ReliablePayloadOwned) -> Vec<Vec<u8>> {
        let pid = packet.packet_id();
        if self.ack_data.is_acked(pid) {
            return Vec::new();
        }
        if pid > self.ack_data.lowest_unreceived + self.max_in_flight as u64 {
            return Vec::new();
        }
        self.ack_data.ack(pid);
        self.has_acks_to_send = true;

        self.received.insert(pid, packet.take_payload());
        let mut messages = Vec::new();
        while let Some(payload) = self.received.remove(&self.next_to_assemble) {
            let mut new_messages = self.assembler.assemble_packet(payload);
            messages.append(&mut new_messages);
            self.next_to_assemble += 1;
        }
        messages
    }

    pub fn acks(&mut self) -> Acks {
        self.acks_next += 1;
        Acks {
            channel_id: self.channel_id,
            packet_id: self.acks_next - 1,
            lowest_unreceived: self.ack_data.lowest_unreceived,
            ack_bitfield: self.ack_data.bitfield.as_raw_slice(),
        }
    }

    pub fn handle_acks(&mut self, acks: Acks) {
        let mut bitfield = [0u8; 16];
        bitfield.copy_from_slice(acks.ack_bitfield);
        let ack_data = AckData {
            lowest_unreceived: acks.lowest_unreceived,
            bitfield: BitArray::new(bitfield),
        };
        self.lowest_unreceived_remote = self
            .lowest_unreceived_remote
            .max(ack_data.lowest_unreceived);
        self.in_flights
            .retain(|in_flight| !ack_data.is_acked(in_flight.packet.packet_id()));
    }

    pub fn _has_acks_to_send(&self) -> bool {
        self.has_acks_to_send
    }

    pub fn _reset_acks_to_send(&mut self) {
        self.has_acks_to_send = false;
    }
}
