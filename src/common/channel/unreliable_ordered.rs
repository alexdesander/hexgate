// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{collections::VecDeque, rc::Rc};

use super::fragments::FragmentAssembler;
use crate::common::{
    crypto::Crypto,
    error::ProtocolViolation,
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
    assembler: FragmentAssembler,

    to_send: VecDeque<ToSend>,
    next_message_id: u32,
    next_fragment_id: u32,
}

impl UnreliableOrderedChannel {
    pub fn new(channel_id: u8, max_recv_msg_size: usize) -> Self {
        Self {
            channel_id,
            lowest_acceptable_message_id: 0,
            assembler: FragmentAssembler::new(
                UNRELIABLE_ORDERED_FRAGMENTED_PAYLOAD_MAX_PAYLOAD_SIZE,
                max_recv_msg_size,
            ),

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

    pub fn peek_size(&self) -> usize {
        let Some(to_send) = self.to_send.front() else {
            return 0;
        };
        let len = to_send.payload.len();
        if len <= UNRELIABLE_ORDERED_STANDALONE_PAYLOAD_MAX_PAYLOAD_SIZE {
            UnreliablePayload::OrderedStandalone {
                channel_id: self.channel_id,
                message_id: self.next_message_id,
                payload: &to_send.payload,
            }
            .serialized_size()
        } else {
            let payload_size =
                (len - to_send.sent).min(UNRELIABLE_ORDERED_FRAGMENTED_PAYLOAD_MAX_PAYLOAD_SIZE);
            let is_last = to_send.sent + payload_size == len;
            UnreliablePayload::OrderedFragmented {
                channel_id: self.channel_id,
                message_id: self.next_message_id,
                fragment_id: self.next_fragment_id,
                is_last,
                payload: &to_send.payload[to_send.sent..to_send.sent + payload_size],
            }
            .serialized_size()
        }
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

    pub fn handle(
        &mut self,
        packet: UnreliablePayload,
    ) -> Result<Option<Vec<u8>>, ProtocolViolation> {
        match packet {
            UnreliablePayload::OrderedStandalone {
                channel_id,
                message_id,
                payload,
            } => {
                assert!(channel_id == self.channel_id);
                if message_id < self.lowest_acceptable_message_id {
                    return Ok(None);
                }
                self.lowest_acceptable_message_id = message_id.saturating_add(1);
                Ok(Some(payload.to_vec()))
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
                    return Ok(None);
                }
                self.lowest_acceptable_message_id = message_id;
                let message = self
                    .assembler
                    .handle(message_id, fragment_id, is_last, payload)?;
                if message.is_some() {
                    self.lowest_acceptable_message_id = message_id.saturating_add(1);
                }
                Ok(message)
            }
            _ => unreachable!(),
        }
    }
}
