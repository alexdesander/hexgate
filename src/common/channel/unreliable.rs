// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{collections::VecDeque, rc::Rc, u32};

use ahash::HashSet;

use crate::common::{
    crypto::Crypto,
    packets::unreliable_payload::{
        UnreliablePayload, UNRELIABLE_FRAGMENTED_PAYLOAD_MAX_PAYLOAD_SIZE,
        UNRELIABLE_STANDALONE_PAYLOAD_MAX_PAYLOAD_SIZE,
    },
};

struct ToSend {
    sent: usize,
    payload: Rc<Vec<u8>>,
}

pub struct UnreliableChannel {
    // Standalone
    standalone_highest_received: u32,
    standalone_next: u32,

    // Fragmented
    fragmented_highest_received: u32,
    fragmented_next: u32,
    fragmented_fragment_next: u32,

    // TODO: Use a more efficient data structure
    fragments_in_assembly: HashSet<u32>,
    needed_fragments: u32,
    assembly: Vec<u8>,

    to_send: VecDeque<ToSend>,
}

impl UnreliableChannel {
    pub fn new() -> Self {
        Self {
            standalone_highest_received: 0,
            standalone_next: 1,

            fragmented_highest_received: 0,
            fragmented_next: 1,
            fragmented_fragment_next: 0,

            fragments_in_assembly: HashSet::default(),
            needed_fragments: u32::MAX,
            assembly: Vec::new(),

            to_send: VecDeque::new(),
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

    pub fn pop(&mut self, crypto: &Crypto, buf: &mut [u8]) -> usize {
        let Some(to_send) = self.to_send.front_mut() else {
            return 0;
        };
        let len = to_send.payload.len();
        if len <= UNRELIABLE_STANDALONE_PAYLOAD_MAX_PAYLOAD_SIZE {
            // Standalone
            let to_send = self.to_send.pop_front().unwrap();
            let message_id = self.standalone_next;
            self.standalone_next += 1;
            let packet = UnreliablePayload::Standalone {
                message_id,
                payload: &to_send.payload,
            };
            packet.serialize(crypto, buf)
        } else {
            // Fragmented
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
            size
        }
    }

    pub fn handle(&mut self, packet: UnreliablePayload) -> Option<Vec<u8>> {
        match packet {
            UnreliablePayload::Standalone {
                message_id,
                payload,
            } => {
                if message_id < self.standalone_highest_received.saturating_sub(64) {
                    return None;
                }
                self.standalone_highest_received = self.standalone_highest_received.max(message_id);
                Some(payload.to_vec())
            }
            UnreliablePayload::Fragmented {
                message_id,
                fragment_id,
                is_last,
                payload,
            } => {
                // TODO: FIX Fragmented being ordered because we don't have multiple assemblies.
                if message_id < self.fragmented_highest_received {
                    return None;
                }
                self.fragmented_highest_received = self.fragmented_highest_received.max(message_id);
                if self.fragments_in_assembly.contains(&fragment_id) {
                    return None;
                }
                self.fragments_in_assembly.insert(fragment_id);
                let offset = fragment_id as usize * UNRELIABLE_FRAGMENTED_PAYLOAD_MAX_PAYLOAD_SIZE;
                if offset + payload.len() > self.assembly.len() {
                    self.assembly.resize(offset + payload.len(), 0);
                }
                self.assembly[offset..offset + payload.len()].copy_from_slice(payload);
                if is_last {
                    self.needed_fragments = fragment_id + 1;
                }
                if self.needed_fragments as usize == self.fragments_in_assembly.len() {
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

        let mut channel_server = UnreliableChannel::new();
        let mut channel_client = UnreliableChannel::new();

        let num_messages = 4444;
        for _ in 0..num_messages {
            let msg_len = rng.gen_range(0..UNRELIABLE_STANDALONE_PAYLOAD_MAX_PAYLOAD_SIZE + 1);
            let msg = Rc::new(vec![(msg_len % 256) as u8; msg_len]);
            channel_client.push(msg);
        }

        let mut buf = [0; 1200];
        for _ in 0..num_messages {
            let size = channel_client.pop(&crypto_client, &mut buf);
            let packet = UnreliablePayload::deserialize(&crypto_server, &mut buf[..size]).unwrap();
            let message = channel_server.handle(packet).unwrap();
            if message.len() > 0 {
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

        let mut channel_server = UnreliableChannel::new();
        let mut channel_client = UnreliableChannel::new();

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
            let size = channel_client.pop(&crypto_client, &mut buf);
            if size == 0 {
                break;
            }
            let packet = UnreliablePayload::deserialize(&crypto_server, &mut buf[..size]).unwrap();
            let message = channel_server.handle(packet);
            if let Some(message) = message {
                assert_eq!(message.len() % 256, message[0] as usize);
                if channel_client.to_send.is_empty() {
                    break;
                }
            }
        }
    }
}
