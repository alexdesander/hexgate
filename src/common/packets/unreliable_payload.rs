// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use integer_encoding::VarInt;

use crate::common::{crypto::Crypto, packets::PacketIdentifier};

use super::{ERROR_INVALID_BUFFER_SIZE, ERROR_MALFORMED_PACKET};

pub const UNRELIABLE_STANDALONE_PAYLOAD_MAX_PAYLOAD_SIZE: usize = 1178;
pub const UNRELIABLE_FRAGMENTED_PAYLOAD_MAX_PAYLOAD_SIZE: usize = 1173;
pub const UNRELIABLE_ORDERED_STANDALONE_PAYLOAD_MAX_PAYLOAD_SIZE: usize = 1177;
pub const UNRELIABLE_ORDERED_FRAGMENTED_PAYLOAD_MAX_PAYLOAD_SIZE: usize = 1172;

pub enum UnreliablePayload<'a> {
    Standalone {
        message_id: u32,
        payload: &'a [u8],
    },
    Fragmented {
        message_id: u32,
        fragment_id: u32,
        is_last: bool,
        payload: &'a [u8],
    },
    OrderedStandalone {
        channel_id: u8,
        message_id: u32,
        payload: &'a [u8],
    },
    OrderedFragmented {
        channel_id: u8,
        message_id: u32,
        fragment_id: u32,
        is_last: bool,
        payload: &'a [u8],
    },
}

impl<'a> UnreliablePayload<'a> {
    pub fn serialized_size(&self) -> usize {
        match self {
            UnreliablePayload::Standalone {
                payload,
                message_id,
            } => {
                let mut tmp = [0u8; 5];
                message_id.encode_var(&mut tmp) + 1 + payload.len() + 16
            }
            UnreliablePayload::Fragmented {
                payload,
                message_id,
                fragment_id,
                ..
            } => {
                let mut tmp = [0u8; 5];
                message_id.encode_var(&mut tmp)
                    + fragment_id.encode_var(&mut tmp)
                    + 1
                    + payload.len()
                    + 16
            }
            UnreliablePayload::OrderedStandalone {
                payload,
                message_id,
                ..
            } => {
                let mut tmp = [0u8; 5];
                message_id.encode_var(&mut tmp) + 2 + payload.len() + 16
            }
            UnreliablePayload::OrderedFragmented {
                payload,
                message_id,
                fragment_id,
                ..
            } => {
                let mut tmp = [0u8; 5];
                message_id.encode_var(&mut tmp)
                    + fragment_id.encode_var(&mut tmp)
                    + 2
                    + payload.len()
                    + 16
            }
        }
    }

    pub fn serialize(&self, crypto: &Crypto, buf: &mut [u8]) -> usize {
        match self {
            UnreliablePayload::Standalone {
                message_id,
                payload,
            } => {
                assert!(payload.len() <= UNRELIABLE_STANDALONE_PAYLOAD_MAX_PAYLOAD_SIZE);
                buf[0] = PacketIdentifier::UnreliableStandalonePayload as u8;
                let message_id_size = message_id.encode_var(&mut buf[1..]);
                let offset = 1 + message_id_size;
                buf[offset..offset + payload.len()].copy_from_slice(payload);
                let mut nonce = [0u8; 12];
                nonce[0] = buf[0];
                nonce[1..1 + message_id_size].copy_from_slice(&buf[1..1 + message_id_size]);
                let tag = crypto.encrypt(&nonce, &[], &mut buf[offset..offset + payload.len()]);
                buf[offset + payload.len()..offset + payload.len() + 16].copy_from_slice(&tag);
                offset + payload.len() + 16
            }
            UnreliablePayload::Fragmented {
                message_id,
                fragment_id,
                is_last,
                payload,
            } => {
                assert!(payload.len() <= UNRELIABLE_FRAGMENTED_PAYLOAD_MAX_PAYLOAD_SIZE);
                if *is_last {
                    buf[0] = PacketIdentifier::UnreliableFragmentedPayloadLast as u8;
                } else {
                    buf[0] = PacketIdentifier::UnreliableFragmentedPayload as u8;
                }
                let message_id_size = message_id.encode_var(&mut buf[1..]);
                let fragment_id_size = fragment_id.encode_var(&mut buf[1 + message_id_size..]);
                let offset = 1 + message_id_size + fragment_id_size;
                buf[offset..offset + payload.len()].copy_from_slice(payload);
                let mut nonce = [0u8; 12];
                nonce[0] = buf[0];
                nonce[1..1 + message_id_size].copy_from_slice(&buf[1..1 + message_id_size]);
                nonce[12 - fragment_id_size..12].copy_from_slice(
                    &buf[1 + message_id_size..1 + message_id_size + fragment_id_size],
                );
                let tag = crypto.encrypt(&nonce, &[], &mut buf[offset..offset + payload.len()]);
                buf[offset + payload.len()..offset + payload.len() + 16].copy_from_slice(&tag);
                offset + payload.len() + 16
            }
            UnreliablePayload::OrderedStandalone {
                channel_id,
                message_id,
                payload,
            } => {
                assert!(payload.len() <= UNRELIABLE_ORDERED_STANDALONE_PAYLOAD_MAX_PAYLOAD_SIZE);
                buf[0] = PacketIdentifier::UnreliableOrderedStandalonePayload as u8;
                buf[1] = *channel_id;
                let message_id_size = message_id.encode_var(&mut buf[2..]);
                let offset = 2 + message_id_size;
                buf[offset..offset + payload.len()].copy_from_slice(payload);
                let mut nonce = [0u8; 12];
                nonce[0] = buf[0];
                nonce[1] = buf[1];
                nonce[2..2 + message_id_size].copy_from_slice(&buf[2..2 + message_id_size]);
                let tag = crypto.encrypt(&nonce, &[], &mut buf[offset..offset + payload.len()]);
                buf[offset + payload.len()..offset + payload.len() + 16].copy_from_slice(&tag);
                offset + payload.len() + 16
            }
            UnreliablePayload::OrderedFragmented {
                channel_id,
                message_id,
                fragment_id,
                is_last,
                payload,
            } => {
                assert!(payload.len() <= UNRELIABLE_ORDERED_FRAGMENTED_PAYLOAD_MAX_PAYLOAD_SIZE);
                if *is_last {
                    buf[0] = PacketIdentifier::UnreliableOrderedFragmentedPayloadLast as u8;
                } else {
                    buf[0] = PacketIdentifier::UnreliableOrderedFragmentedPayload as u8;
                }
                buf[1] = *channel_id;
                let message_id_size = message_id.encode_var(&mut buf[2..]);
                let fragment_id_size = fragment_id.encode_var(&mut buf[2 + message_id_size..]);
                let offset = 2 + message_id_size + fragment_id_size;
                buf[offset..offset + payload.len()].copy_from_slice(payload);
                let mut nonce = [0u8; 12];
                nonce[0] = buf[0];
                nonce[1] = buf[1];
                nonce[2..2 + message_id_size].copy_from_slice(&buf[2..2 + message_id_size]);
                nonce[12 - fragment_id_size..12].copy_from_slice(
                    &buf[2 + message_id_size..2 + message_id_size + fragment_id_size],
                );
                let tag = crypto.encrypt(&nonce, &[], &mut buf[offset..offset + payload.len()]);
                buf[offset + payload.len()..offset + payload.len() + 16].copy_from_slice(&tag);
                offset + payload.len() + 16
            }
        }
    }

    pub fn deserialize(crypto: &Crypto, buf: &'a mut [u8]) -> Result<Self, &'static str> {
        match PacketIdentifier::try_from(buf[0])? {
            PacketIdentifier::UnreliableStandalonePayload => {
                if buf.len() < 18 {
                    return Err(ERROR_INVALID_BUFFER_SIZE);
                }
                let Some((message_id, message_id_size)) = u32::decode_var(&buf[1..]) else {
                    return Err(ERROR_MALFORMED_PACKET);
                };
                let mut nonce = [0u8; 12];
                nonce[0] = buf[0];
                nonce[1..1 + message_id_size].copy_from_slice(&buf[1..1 + message_id_size]);
                let len = buf.len();
                let tag: [u8; 16] = buf[len - 16..len].try_into().unwrap();
                if crypto
                    .decrypt(&nonce, &[], &mut buf[1 + message_id_size..len - 16], &tag)
                    .is_err()
                {
                    return Err(ERROR_MALFORMED_PACKET);
                }
                Ok(UnreliablePayload::Standalone {
                    message_id,
                    payload: &buf[1 + message_id_size..len - 16],
                })
            }
            PacketIdentifier::UnreliableFragmentedPayload
            | PacketIdentifier::UnreliableFragmentedPayloadLast => {
                if buf.len() < 19 {
                    return Err(ERROR_INVALID_BUFFER_SIZE);
                }
                let Some((message_id, message_id_size)) = u32::decode_var(&buf[1..]) else {
                    return Err(ERROR_MALFORMED_PACKET);
                };
                let Some((fragment_id, fragment_id_size)) =
                    u32::decode_var(&buf[1 + message_id_size..])
                else {
                    return Err(ERROR_MALFORMED_PACKET);
                };
                let mut nonce = [0u8; 12];
                nonce[0] = buf[0];
                nonce[1..1 + message_id_size].copy_from_slice(&buf[1..1 + message_id_size]);
                nonce[12 - fragment_id_size..12].copy_from_slice(
                    &buf[1 + message_id_size..1 + message_id_size + fragment_id_size],
                );
                let len = buf.len();
                let tag: [u8; 16] = buf[len - 16..len].try_into().unwrap();
                if crypto
                    .decrypt(
                        &nonce,
                        &[],
                        &mut buf[1 + message_id_size + fragment_id_size..len - 16],
                        &tag,
                    )
                    .is_err()
                {
                    return Err(ERROR_MALFORMED_PACKET);
                }
                Ok(UnreliablePayload::Fragmented {
                    message_id,
                    fragment_id,
                    is_last: buf[0] == PacketIdentifier::UnreliableFragmentedPayloadLast as u8,
                    payload: &buf[1 + message_id_size + fragment_id_size..len - 16],
                })
            }
            PacketIdentifier::UnreliableOrderedStandalonePayload => {
                if buf.len() < 19 {
                    return Err(ERROR_INVALID_BUFFER_SIZE);
                }
                let channel_id = buf[1];
                let Some((message_id, message_id_size)) = u32::decode_var(&buf[2..]) else {
                    return Err(ERROR_MALFORMED_PACKET);
                };
                let mut nonce = [0u8; 12];
                nonce[0] = buf[0];
                nonce[1] = buf[1];
                nonce[2..2 + message_id_size].copy_from_slice(&buf[2..2 + message_id_size]);
                let len = buf.len();
                let tag: [u8; 16] = buf[len - 16..len].try_into().unwrap();
                if crypto
                    .decrypt(&nonce, &[], &mut buf[2 + message_id_size..len - 16], &tag)
                    .is_err()
                {
                    return Err(ERROR_MALFORMED_PACKET);
                }
                Ok(UnreliablePayload::OrderedStandalone {
                    channel_id,
                    message_id,
                    payload: &buf[2 + message_id_size..len - 16],
                })
            }
            PacketIdentifier::UnreliableOrderedFragmentedPayload
            | PacketIdentifier::UnreliableOrderedFragmentedPayloadLast => {
                if buf.len() < 20 {
                    return Err(ERROR_INVALID_BUFFER_SIZE);
                }
                let channel_id = buf[1];
                let Some((message_id, message_id_size)) = u32::decode_var(&buf[2..]) else {
                    return Err(ERROR_MALFORMED_PACKET);
                };
                let Some((fragment_id, fragment_id_size)) =
                    u32::decode_var(&buf[2 + message_id_size..])
                else {
                    return Err(ERROR_MALFORMED_PACKET);
                };
                let mut nonce = [0u8; 12];
                nonce[0] = buf[0];
                nonce[1] = buf[1];
                nonce[2..2 + message_id_size].copy_from_slice(&buf[2..2 + message_id_size]);
                nonce[12 - fragment_id_size..12].copy_from_slice(
                    &buf[2 + message_id_size..2 + message_id_size + fragment_id_size],
                );
                let len = buf.len();
                let tag: [u8; 16] = buf[len - 16..len].try_into().unwrap();
                if crypto
                    .decrypt(
                        &nonce,
                        &[],
                        &mut buf[2 + message_id_size + fragment_id_size..len - 16],
                        &tag,
                    )
                    .is_err()
                {
                    return Err(ERROR_MALFORMED_PACKET);
                }
                Ok(UnreliablePayload::OrderedFragmented {
                    channel_id,
                    message_id,
                    fragment_id,
                    is_last: buf[0]
                        == PacketIdentifier::UnreliableOrderedFragmentedPayloadLast as u8,
                    payload: &buf[2 + message_id_size + fragment_id_size..len - 16],
                })
            }
            _ => unreachable!(),
        }
    }
}
#[cfg(test)]
mod tests {
    use std::u32;

    use rand::Rng;
    use x25519_dalek::{PublicKey, ReusableSecret};

    use crate::common::Cipher;

    use super::*;

    #[test]
    fn test_unreliable_standalone_payload() {
        let mut rng = rand::thread_rng();
        let s1 = ReusableSecret::random_from_rng(&mut rng);
        let s2 = ReusableSecret::random_from_rng(&mut rng);
        let shared_secret_0 = s1.diffie_hellman(&PublicKey::from(&s2));
        let shared_secret_1 = s2.diffie_hellman(&PublicKey::from(&s1));
        let crypto_server = Crypto::new(shared_secret_0, [44u8; 32], true, Cipher::AES256GCM);
        let crypto_client = Crypto::new(shared_secret_1, [44u8; 32], false, Cipher::AES256GCM);

        let mut buf = [0u8; 1200];
        let mut payload = [0u8; UNRELIABLE_STANDALONE_PAYLOAD_MAX_PAYLOAD_SIZE];
        for message_id in (0..4444).chain(u32::MAX - 100..u32::MAX) {
            let payload_size = rng.gen_range(0..UNRELIABLE_STANDALONE_PAYLOAD_MAX_PAYLOAD_SIZE);
            rng.fill(&mut payload[..payload_size]);
            let packet = UnreliablePayload::Standalone {
                message_id,
                payload: &payload[..payload_size],
            };
            let size = packet.serialize(&crypto_client, &mut buf);

            let packet = UnreliablePayload::deserialize(&crypto_server, &mut buf[..size]).unwrap();
            match packet {
                UnreliablePayload::Standalone {
                    message_id: message_id2,
                    payload: payload2,
                } => {
                    assert_eq!(message_id, message_id2);
                    assert_eq!(&payload[..payload_size], payload2);
                }
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn test_unreliable_fragmented_payload() {
        let mut rng = rand::thread_rng();
        let s1 = ReusableSecret::random_from_rng(&mut rng);
        let s2 = ReusableSecret::random_from_rng(&mut rng);
        let shared_secret_0 = s1.diffie_hellman(&PublicKey::from(&s2));
        let shared_secret_1 = s2.diffie_hellman(&PublicKey::from(&s1));
        let crypto_server = Crypto::new(shared_secret_0, [44u8; 32], true, Cipher::AES256GCM);
        let crypto_client = Crypto::new(shared_secret_1, [44u8; 32], false, Cipher::AES256GCM);

        let mut buf = [0u8; 1200];
        let mut payload = [0u8; UNRELIABLE_FRAGMENTED_PAYLOAD_MAX_PAYLOAD_SIZE];
        for message_id in (0..4444).chain(u32::MAX - 100..u32::MAX) {
            let last_fragment_id = rng.gen_range(1..50);
            for fragment_id in 0..last_fragment_id {
                let payload_size = rng.gen_range(0..UNRELIABLE_FRAGMENTED_PAYLOAD_MAX_PAYLOAD_SIZE);
                rng.fill(&mut payload[..payload_size]);
                let is_last = fragment_id == last_fragment_id;
                let packet = UnreliablePayload::Fragmented {
                    message_id,
                    fragment_id,
                    is_last,
                    payload: &payload[..payload_size],
                };
                let size = packet.serialize(&crypto_client, &mut buf);

                let packet =
                    UnreliablePayload::deserialize(&crypto_server, &mut buf[..size]).unwrap();
                match packet {
                    UnreliablePayload::Fragmented {
                        message_id: message_id2,
                        fragment_id: fragment_id2,
                        is_last: is_last2,
                        payload: payload2,
                    } => {
                        assert_eq!(message_id, message_id2);
                        assert_eq!(fragment_id, fragment_id2);
                        assert_eq!(is_last, is_last2);
                        assert_eq!(&payload[..payload_size], payload2);
                    }
                    _ => unreachable!(),
                }
            }
        }
    }

    #[test]
    fn test_unreliable_ordered_standalone_payload() {
        let mut rng = rand::thread_rng();
        let s1 = ReusableSecret::random_from_rng(&mut rng);
        let s2 = ReusableSecret::random_from_rng(&mut rng);
        let shared_secret_0 = s1.diffie_hellman(&PublicKey::from(&s2));
        let shared_secret_1 = s2.diffie_hellman(&PublicKey::from(&s1));
        let crypto_server = Crypto::new(shared_secret_0, [44u8; 32], true, Cipher::AES256GCM);
        let crypto_client = Crypto::new(shared_secret_1, [44u8; 32], false, Cipher::AES256GCM);

        let mut buf = [0u8; 1200];
        let mut payload = [0u8; UNRELIABLE_ORDERED_STANDALONE_PAYLOAD_MAX_PAYLOAD_SIZE];
        for message_id in (0..4444).chain(u32::MAX - 100..u32::MAX) {
            let payload_size =
                rng.gen_range(0..UNRELIABLE_ORDERED_STANDALONE_PAYLOAD_MAX_PAYLOAD_SIZE);
            rng.fill(&mut payload[..payload_size]);
            let channel_id = rng.gen::<u8>();
            let packet = UnreliablePayload::OrderedStandalone {
                channel_id,
                message_id,
                payload: &payload[..payload_size],
            };
            let size = packet.serialize(&crypto_client, &mut buf);

            let packet = UnreliablePayload::deserialize(&crypto_server, &mut buf[..size]).unwrap();
            match packet {
                UnreliablePayload::OrderedStandalone {
                    channel_id: channel_id2,
                    message_id: message_id2,
                    payload: payload2,
                } => {
                    assert_eq!(channel_id, channel_id2);
                    assert_eq!(message_id, message_id2);
                    assert_eq!(&payload[..payload_size], payload2);
                }
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn test_unreliable_ordered_fragmented_payload() {
        let mut rng = rand::thread_rng();
        let s1 = ReusableSecret::random_from_rng(&mut rng);
        let s2 = ReusableSecret::random_from_rng(&mut rng);
        let shared_secret_0 = s1.diffie_hellman(&PublicKey::from(&s2));
        let shared_secret_1 = s2.diffie_hellman(&PublicKey::from(&s1));
        let crypto_server = Crypto::new(shared_secret_0, [44u8; 32], true, Cipher::AES256GCM);
        let crypto_client = Crypto::new(shared_secret_1, [44u8; 32], false, Cipher::AES256GCM);

        let mut buf = [0u8; 1200];
        let mut payload = [0u8; UNRELIABLE_ORDERED_FRAGMENTED_PAYLOAD_MAX_PAYLOAD_SIZE];
        for message_id in (0..4444).chain(u32::MAX - 100..u32::MAX) {
            let last_fragment_id = rng.gen_range(1..50);
            for fragment_id in 0..last_fragment_id {
                let payload_size =
                    rng.gen_range(0..UNRELIABLE_ORDERED_FRAGMENTED_PAYLOAD_MAX_PAYLOAD_SIZE);
                rng.fill(&mut payload[..payload_size]);
                let is_last = fragment_id == last_fragment_id - 1;
                let channel_id = rng.gen::<u8>();
                let packet = UnreliablePayload::OrderedFragmented {
                    channel_id,
                    message_id,
                    fragment_id,
                    is_last,
                    payload: &payload[..payload_size],
                };
                let size = packet.serialize(&crypto_client, &mut buf);

                let packet =
                    UnreliablePayload::deserialize(&crypto_server, &mut buf[..size]).unwrap();
                match packet {
                    UnreliablePayload::OrderedFragmented {
                        channel_id: channel_id2,
                        message_id: message_id2,
                        fragment_id: fragment_id2,
                        is_last: is_last2,
                        payload: payload2,
                    } => {
                        assert_eq!(channel_id, channel_id2);
                        assert_eq!(message_id, message_id2);
                        assert_eq!(fragment_id, fragment_id2);
                        assert_eq!(is_last, is_last2);
                        assert_eq!(&payload[..payload_size], payload2);
                    }
                    _ => unreachable!(),
                }
            }
        }
    }
}
