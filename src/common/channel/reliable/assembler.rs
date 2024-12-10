// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use integer_encoding::VarInt;

pub struct MessageAssembler {
    needed: usize,
    message_buffer: Vec<u8>,
}

impl MessageAssembler {
    pub fn new() -> Self {
        Self {
            needed: 0,
            message_buffer: Vec::new(),
        }
    }

    pub fn assemble_packet(&mut self, payload: Vec<u8>) -> Vec<Vec<u8>> {
        let mut messages = Vec::new();
        let mut cursor = 0;
        while cursor < payload.len() {
            if self.needed == 0 {
                let Some((need, varint_size)) = u32::decode_var(&payload[cursor..]) else {
                    break;
                };
                self.needed = need as usize;
                cursor += varint_size;
                if cursor >= payload.len() {
                    break;
                }
            }
            let to_consume = self.needed.min(payload.len() - cursor);
            self.message_buffer
                .extend_from_slice(&payload[cursor..cursor + to_consume]);
            self.needed -= to_consume;
            cursor += to_consume;
            if self.needed == 0 && !self.message_buffer.is_empty() {
                messages.push(std::mem::take(&mut self.message_buffer));
            }
        }
        messages
    }
}
