// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{collections::VecDeque, rc::Rc};

use ahash::HashSet;

use crate::common::{
    crypto::Crypto,
    packets::unreliable_payload::{
        UnreliablePayload, UNRELIABLE_ORDERED_FRAGMENTED_PAYLOAD_MAX_PAYLOAD_SIZE,
        UNRELIABLE_ORDERED_STANDALONE_PAYLOAD_MAX_PAYLOAD_SIZE,
    },
};

struct ToSend {
    sent: usize,
    payload: Rc<Vec<u8>>,
}

pub struct UnreliableOrderedChannel {
    channel_id: u8,
    lowest_acceptable_message_id: u32,
    // TODO: Use a more efficient data structure
    fragments_in_assembly: HashSet<u32>,
    needed_fragments: u32,
    assembly: Vec<u8>,

    to_send: VecDeque<ToSend>,
    next_message_id: u32,
    next_fragment_id: u32,
}

impl UnreliableOrderedChannel {
    pub fn new(channel_id: u8) -> Self {
        Self {
            channel_id,
            lowest_acceptable_message_id: 0,
            fragments_in_assembly: HashSet::default(),
            needed_fragments: u32::MAX,
            assembly: Vec::new(),

            to_send: VecDeque::new(),
            next_message_id: 0,
            next_fragment_id: 0,
        }
    }

    pub fn push(&mut self, message: Rc<Vec<u8>>) {
        self.to_send.push_back(ToSend {
            sent: 0,
            payload: message,
        });
    }

    pub fn pop(&mut self, crypto: &Crypto, buf: &mut [u8]) -> usize {
        let Some(to_send) = self.to_send.front_mut() else {
            return 0;
        };
        let len = to_send.payload.len();
        if len <= UNRELIABLE_ORDERED_STANDALONE_PAYLOAD_MAX_PAYLOAD_SIZE {
            // Standalone
            self.next_fragment_id = 0;
            let to_send = self.to_send.pop_front().unwrap();
            let message_id = self.next_message_id;
            self.next_message_id += 1;
            let packet = UnreliablePayload::OrderedStandalone {
                channel_id: self.channel_id,
                message_id,
                payload: &to_send.payload,
            };
            packet.serialize(crypto, buf)
        } else {
            // Fragmented
            let payload_size =
                (len - to_send.sent).min(UNRELIABLE_ORDERED_FRAGMENTED_PAYLOAD_MAX_PAYLOAD_SIZE);
            to_send.sent += payload_size;
            let message_id = self.next_message_id;
            let fragment_id = self.next_fragment_id;
            self.next_fragment_id += 1;
            let is_last = to_send.sent == len;
            let packet = UnreliablePayload::OrderedFragmented {
                channel_id: self.channel_id,
                message_id,
                fragment_id,
                is_last,
                payload: &to_send.payload[to_send.sent - payload_size..to_send.sent],
            };
            let size = packet.serialize(crypto, buf);
            if is_last {
                self.next_message_id += 1;
                self.next_fragment_id = 0;
                self.to_send.pop_front();
            }
            size
        }
    }

    pub fn handle(&mut self, packet: UnreliablePayload) -> Option<Vec<u8>> {
        match packet {
            UnreliablePayload::OrderedStandalone {
                channel_id,
                message_id,
                payload,
            } => {
                assert!(channel_id == self.channel_id);
                if message_id < self.lowest_acceptable_message_id {
                    return None;
                }
                self.lowest_acceptable_message_id = message_id + 1;

                self.fragments_in_assembly.clear();
                self.needed_fragments = u32::MAX;
                self.assembly.clear();
                Some(payload.to_vec())
            }
            UnreliablePayload::OrderedFragmented {
                channel_id,
                message_id,
                fragment_id,
                is_last,
                payload,
            } => {
                assert!(channel_id == self.channel_id);
                if message_id < self.lowest_acceptable_message_id {
                    return None;
                }
                self.lowest_acceptable_message_id = message_id;
                if self.fragments_in_assembly.contains(&fragment_id) {
                    return None;
                }
                self.fragments_in_assembly.insert(fragment_id);
                let offset =
                    fragment_id as usize * UNRELIABLE_ORDERED_FRAGMENTED_PAYLOAD_MAX_PAYLOAD_SIZE;
                if offset + payload.len() > self.assembly.len() {
                    self.assembly.resize(offset + payload.len(), 0);
                }
                self.assembly[offset..offset + payload.len()].copy_from_slice(payload);
                if is_last {
                    self.needed_fragments = fragment_id + 1;
                }
                if self.needed_fragments as usize == self.fragments_in_assembly.len() {
                    self.lowest_acceptable_message_id = message_id + 1;
                    self.fragments_in_assembly.clear();
                    self.needed_fragments = u32::MAX;
                    let message = std::mem::take(&mut self.assembly);
                    Some(message)
                } else {
                    None
                }
            }
            _ => unreachable!(),
        }
    }
}
