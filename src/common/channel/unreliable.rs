// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{collections::VecDeque, rc::Rc};

use super::fragments::FragmentAssembler;
use crate::common::{
    crypto::Crypto,
    error::ProtocolViolation,
    packets::unreliable_payload::{
        UnreliablePayload, UNRELIABLE_FRAGMENTED_PAYLOAD_MAX_PAYLOAD_SIZE,
        UNRELIABLE_STANDALONE_PAYLOAD_MAX_PAYLOAD_SIZE,
    },
};

struct ToSend {
    sent: usize,
    payload: Rc<Vec<u8>>,
}

/// Accepts every message id once, within 64 ids of the highest one (drops duplicates and replays).
struct ReplayWindow {
    highest: u32,
    /// Bit `n` is set when `highest - n` was received.
    seen: u64,
}

impl ReplayWindow {
    fn new() -> Self {
        // Id 0 is never sent.
        Self {
            highest: 0,
            seen: 1,
        }
    }

    fn accept(&mut self, id: u32) -> bool {
        if id > self.highest {
            self.seen = self.seen.checked_shl(id - self.highest).unwrap_or(0) | 1;
            self.highest = id;
            return true;
        }
        let bit = 1u64.checked_shl(self.highest - id).unwrap_or(0);
        let fresh = bit != 0 && self.seen & bit == 0;
        self.seen |= bit;
        fresh
    }
}

pub struct UnreliableChannel {
    // Standalone
    standalone_received: ReplayWindow,
    standalone_next: u32,

    // Fragmented
    fragmented_next: u32,
    fragmented_fragment_next: u32,
    assembler: FragmentAssembler,

    to_send: VecDeque<ToSend>,
}

impl UnreliableChannel {
    pub fn new(max_recv_msg_size: usize) -> Self {
        Self {
            standalone_received: ReplayWindow::new(),
            standalone_next: 1,

            fragmented_next: 1,
            fragmented_fragment_next: 0,
            assembler: FragmentAssembler::new(
                UNRELIABLE_FRAGMENTED_PAYLOAD_MAX_PAYLOAD_SIZE,
                max_recv_msg_size,
            ),

            to_send: VecDeque::new(),
        }
    }

    pub fn push(&mut self, message: Rc<Vec<u8>>) {
        self.to_send.push_back(ToSend {
            sent: 0,
            payload: message,
        });
    }

    pub fn queued_bytes(&self) -> usize {
        self.to_send
            .iter()
            .map(|to_send| to_send.payload.len() - to_send.sent)
            .sum()
    }

    pub fn peek_size(&self) -> usize {
        let Some(to_send) = self.to_send.front() else {
            return 0;
        };
        let len = to_send.payload.len();
        if len <= UNRELIABLE_STANDALONE_PAYLOAD_MAX_PAYLOAD_SIZE {
            // Standalone
            UnreliablePayload::Standalone {
                message_id: self.standalone_next,
                payload: &to_send.payload,
            }
            .serialized_size()
        } else {
            // Fragmented
            let payload_size =
                (len - to_send.sent).min(UNRELIABLE_FRAGMENTED_PAYLOAD_MAX_PAYLOAD_SIZE);
            let is_last = to_send.sent + payload_size == len;
            UnreliablePayload::Fragmented {
                message_id: self.fragmented_next,
                fragment_id: self.fragmented_fragment_next,
                is_last,
                payload: &to_send.payload[to_send.sent..to_send.sent + payload_size],
            }
            .serialized_size()
        }
    }

    /// `None` once the message ids are used up: the next one would wrap and reuse nonces.
    pub fn pop(&mut self, crypto: &Crypto, buf: &mut [u8]) -> Option<usize> {
        let Some(to_send) = self.to_send.front_mut() else {
            return Some(0);
        };
        let len = to_send.payload.len();
        if len <= UNRELIABLE_STANDALONE_PAYLOAD_MAX_PAYLOAD_SIZE {
            // Standalone
            if self.standalone_next == u32::MAX {
                return None;
            }
            let to_send = self.to_send.pop_front().unwrap();
            let message_id = self.standalone_next;
            self.standalone_next += 1;
            let packet = UnreliablePayload::Standalone {
                message_id,
                payload: &to_send.payload,
            };
            Some(packet.serialize(crypto, buf))
        } else {
            // Fragmented
            if self.fragmented_next == u32::MAX {
                return None;
            }
            let payload_size =
                (len - to_send.sent).min(UNRELIABLE_FRAGMENTED_PAYLOAD_MAX_PAYLOAD_SIZE);
            to_send.sent += payload_size;
            let message_id = self.fragmented_next;
            let fragment_id = self.fragmented_fragment_next;
            self.fragmented_fragment_next += 1;
            let is_last = to_send.sent == len;
            let packet = UnreliablePayload::Fragmented {
                message_id,
                fragment_id,
                is_last,
                payload: &to_send.payload[to_send.sent - payload_size..to_send.sent],
            };
            let size = packet.serialize(crypto, buf);
            if is_last {
                self.fragmented_next += 1;
                self.fragmented_fragment_next = 0;
                self.to_send.pop_front();
            }
            Some(size)
        }
    }

    pub fn handle(
        &mut self,
        packet: UnreliablePayload,
    ) -> Result<Option<Vec<u8>>, ProtocolViolation> {
        match packet {
            UnreliablePayload::Standalone {
                message_id,
                payload,
            } => Ok(self
                .standalone_received
                .accept(message_id)
                .then(|| payload.to_vec())),
            UnreliablePayload::Fragmented {
                message_id,
                fragment_id,
                is_last,
                payload,
            } => {
                // TODO: FIX Fragmented being ordered because we don't have multiple assemblies.
                self.assembler
                    .handle(message_id, fragment_id, is_last, payload)
            }
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use rand::Rng;
    use x25519_dalek::{PublicKey, ReusableSecret};

    use crate::common::{
        crypto::Crypto,
        packets::unreliable_payload::{
            UnreliablePayload, UNRELIABLE_STANDALONE_PAYLOAD_MAX_PAYLOAD_SIZE,
        },
        Cipher,
    };

    use super::UnreliableChannel;

    #[test]
    fn test_unreliable_standalone() {
        let mut rng = rand::thread_rng();
        let s1 = ReusableSecret::random_from_rng(&mut rng);
        let s2 = ReusableSecret::random_from_rng(&mut rng);
        let shared_secret_0 = s1.diffie_hellman(&PublicKey::from(&s2));
        let shared_secret_1 = s2.diffie_hellman(&PublicKey::from(&s1));
        let crypto_server = Crypto::new(shared_secret_0, [44u8; 32], true, Cipher::AES256GCM);
        let crypto_client = Crypto::new(shared_secret_1, [44u8; 32], false, Cipher::AES256GCM);

        let mut channel_server = UnreliableChannel::new(usize::MAX);
        let mut channel_client = UnreliableChannel::new(usize::MAX);

        let num_messages = 4444;
        for _ in 0..num_messages {
            let msg_len = rng.gen_range(0..UNRELIABLE_STANDALONE_PAYLOAD_MAX_PAYLOAD_SIZE + 1);
            let msg = Rc::new(vec![(msg_len % 256) as u8; msg_len]);
            channel_client.push(msg);
        }

        let mut buf = [0; 1200];
        for _ in 0..num_messages {
            let size = channel_client.pop(&crypto_client, &mut buf).unwrap();
            let packet = UnreliablePayload::deserialize(&crypto_server, &mut buf[..size]).unwrap();
            let message = channel_server.handle(packet).unwrap().unwrap();
            if !message.is_empty() {
                assert_eq!(message.len() % 256, message[0] as usize);
            }
        }
    }

    #[test]
    fn test_unreliable_fragmented() {
        let mut rng = rand::thread_rng();
        let s1 = ReusableSecret::random_from_rng(&mut rng);
        let s2 = ReusableSecret::random_from_rng(&mut rng);
        let shared_secret_0 = s1.diffie_hellman(&PublicKey::from(&s2));
        let shared_secret_1 = s2.diffie_hellman(&PublicKey::from(&s1));
        let crypto_server = Crypto::new(shared_secret_0, [44u8; 32], true, Cipher::AES256GCM);
        let crypto_client = Crypto::new(shared_secret_1, [44u8; 32], false, Cipher::AES256GCM);

        let mut channel_server = UnreliableChannel::new(usize::MAX);
        let mut channel_client = UnreliableChannel::new(usize::MAX);

        let num_messages = 4444;
        for _ in 0..num_messages {
            let msg_len = rng.gen_range(
                UNRELIABLE_STANDALONE_PAYLOAD_MAX_PAYLOAD_SIZE + 1
                    ..UNRELIABLE_STANDALONE_PAYLOAD_MAX_PAYLOAD_SIZE * 50 + 1,
            );
            let msg = Rc::new(vec![(msg_len % 256) as u8; msg_len]);
            channel_client.push(msg);
        }

        let mut buf = [0; 1200];
        loop {
            let size = channel_client.pop(&crypto_client, &mut buf).unwrap();
            if size == 0 {
                break;
            }
            let packet = UnreliablePayload::deserialize(&crypto_server, &mut buf[..size]).unwrap();
            let message = channel_server.handle(packet).unwrap();
            if let Some(message) = message {
                assert_eq!(message.len() % 256, message[0] as usize);
                if channel_client.to_send.is_empty() {
                    break;
                }
            }
        }
    }
}
