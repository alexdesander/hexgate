// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use integer_encoding::VarInt;
use std::{collections::VecDeque, rc::Rc};

pub struct MessageDisassembler {
    messages: VecDeque<(Rc<Vec<u8>>, usize, bool)>,
}

impl MessageDisassembler {
    pub fn new() -> Self {
        Self {
            messages: VecDeque::new(),
        }
    }

    pub fn push(&mut self, message: Rc<Vec<u8>>) {
        if message.is_empty() {
            return;
        }
        self.messages.push_back((message, 0, false));
    }

    pub fn pop(&mut self, mut max_size: usize) -> Option<Vec<u8>> {
        let mut payload = Vec::with_capacity(max_size);
        while let Some((message, offset, wrote_size)) = self.messages.front_mut() {
            // If we haven't written the size yet, do it now.
            if !*wrote_size {
                let mut encoded = [0u8; 5];
                let size_len = message.len().encode_var(&mut encoded);
                if max_size < size_len {
                    break;
                }
                payload.extend_from_slice(&encoded[..size_len]);
                max_size -= size_len;
                *wrote_size = true;
            }

            let remaining_msg = message.len() - *offset;
            if max_size == 0 {
                break;
            } else if max_size > remaining_msg {
                // We can write the whole message
                payload.extend_from_slice(&message[*offset..]);
                max_size -= remaining_msg;
                self.messages.pop_front();
            } else if max_size < remaining_msg {
                // Only part of the message fits
                payload.extend_from_slice(&message[*offset..*offset + max_size]);
                *offset += max_size;
                break;
            } else {
                // Exact fit
                payload.extend_from_slice(&message[*offset..]);
                self.messages.pop_front();
                break;
            }
        }
        if payload.is_empty() {
            None
        } else {
            Some(payload)
        }
    }
}
