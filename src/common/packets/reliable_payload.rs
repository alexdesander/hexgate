// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![allow(unused)]

use integer_encoding::VarInt;

use crate::common::{crypto::Crypto, packets::ERROR_INVALID_BUFFER_SIZE};

use super::{
    PacketIdentifier, ERROR_INVALID_PACKET_IDENTIFIER, ERROR_INVALID_TAG, ERROR_MALFORMED_PACKET,
};

#[derive(Debug)]
pub enum ReliablePayload<'a> {
    NoAcks {
        channel_id: u8,
        packet_id: u64,
        payload: &'a [u8],
    },
}

impl<'a> ReliablePayload<'a> {
    pub fn max_payload_size(ack_size: Option<usize>, packet_id: u64) -> usize {
        let mut encoded_packet_id = [0u8; 9];
        if let Some(ack_size) = ack_size {
            todo!()
        } else {
            1200 - 18 - packet_id.encode_var(&mut encoded_packet_id)
        }
    }

    pub fn channel_id(&self) -> u8 {
        match self {
            ReliablePayload::NoAcks { channel_id, .. } => *channel_id,
        }
    }

    pub fn packet_id(&self) -> u64 {
        match self {
            ReliablePayload::NoAcks { packet_id, .. } => *packet_id,
        }
    }

    pub fn payload(&self) -> &'a [u8] {
        match self {
            ReliablePayload::NoAcks { payload, .. } => payload,
        }
    }

    pub fn to_owned(&self) -> ReliablePayloadOwned {
        match self {
            ReliablePayload::NoAcks {
                channel_id,
                packet_id,
                payload,
            } => ReliablePayloadOwned::NoAcks {
                channel_id: *channel_id,
                packet_id: *packet_id,
                payload: payload.to_vec(),
            },
        }
    }

    pub fn serialized_size(&self) -> usize {
        match self {
            ReliablePayload::NoAcks {
                payload, packet_id, ..
            } => {
                let mut tmp = [0u8; 9];
                2 + packet_id.encode_var(&mut tmp) + payload.len() + 16
            }
        }
    }

    pub fn serialize(&self, crypto: &Crypto, buf: &mut [u8]) -> usize {
        match self {
            ReliablePayload::NoAcks {
                channel_id,
                packet_id,
                payload,
            } => {
                buf[0] = PacketIdentifier::ReliablePayloadNoAcks as u8;
                buf[1] = *channel_id;
                let packet_id_size = packet_id.encode_var(&mut buf[2..]);
                let offset = 2 + packet_id_size;
                buf[offset..offset + payload.len()].copy_from_slice(payload);
                let mut nonce = [0u8; 12];
                nonce[0] = buf[0];
                nonce[1] = buf[1];
                nonce[2..2 + packet_id_size].copy_from_slice(&buf[2..2 + packet_id_size]);
                let tag = crypto.encrypt(&nonce, &[], &mut buf[offset..offset + payload.len()]);
                buf[offset + payload.len()..offset + payload.len() + 16].copy_from_slice(&tag);
                offset + payload.len() + 16
            }
        }
    }

    pub fn deserialize(crypto: &Crypto, buf: &'a mut [u8]) -> Result<Self, &'static str> {
        if buf.len() < 19 {
            return Err(ERROR_INVALID_BUFFER_SIZE);
        }
        if buf[0] == PacketIdentifier::ReliablePayloadNoAcks as u8 {
            let channel_id = buf[1];
            let Some((packet_id, packet_id_size)) = u64::decode_var(&buf[2..]) else {
                return Err(ERROR_MALFORMED_PACKET);
            };
            let len = buf.len();
            if 18 + packet_id_size > len {
                return Err(ERROR_INVALID_BUFFER_SIZE);
            }
            let mut nonce = [0u8; 12];
            nonce[0] = buf[0];
            nonce[1] = buf[1];
            nonce[2..2 + packet_id_size].copy_from_slice(&buf[2..2 + packet_id_size]);
            let tag: [u8; 16] = buf[len - 16..len].try_into().unwrap();
            if crypto
                .decrypt(&nonce, &[], &mut buf[2 + packet_id_size..len - 16], &tag)
                .is_err()
            {
                return Err(ERROR_INVALID_TAG);
            }
            return Ok(ReliablePayload::NoAcks {
                channel_id,
                packet_id,
                payload: &buf[2 + packet_id_size..len - 16],
            });
        }
        Err(ERROR_INVALID_PACKET_IDENTIFIER)
    }
}

// OWNED ------------------------------------------------------------------
#[derive(Debug)]
pub enum ReliablePayloadOwned {
    NoAcks {
        channel_id: u8,
        packet_id: u64,
        payload: Vec<u8>,
    },
}

impl ReliablePayloadOwned {
    pub fn max_payload_size(ack_size: Option<usize>, packet_id: u64) -> usize {
        let mut encoded_packet_id = [0u8; 9];
        if let Some(_ack_size) = ack_size {
            todo!()
        } else {
            1200 - 18 - packet_id.encode_var(&mut encoded_packet_id)
        }
    }

    pub fn channel_id(&self) -> u8 {
        match self {
            ReliablePayloadOwned::NoAcks { channel_id, .. } => *channel_id,
        }
    }

    pub fn packet_id(&self) -> u64 {
        match self {
            ReliablePayloadOwned::NoAcks { packet_id, .. } => *packet_id,
        }
    }

    pub fn payload(&self) -> &[u8] {
        match self {
            ReliablePayloadOwned::NoAcks { payload, .. } => &payload,
        }
    }

    pub fn take_payload(self) -> Vec<u8> {
        match self {
            ReliablePayloadOwned::NoAcks { payload, .. } => payload,
        }
    }

    pub fn serialized_size(&self) -> usize {
        match self {
            ReliablePayloadOwned::NoAcks {
                payload, packet_id, ..
            } => {
                let mut tmp = [0u8; 9];
                2 + packet_id.encode_var(&mut tmp) + payload.len() + 16
            }
        }
    }

    pub fn serialize(&self, crypto: &Crypto, buf: &mut [u8]) -> usize {
        match self {
            ReliablePayloadOwned::NoAcks {
                channel_id,
                packet_id,
                payload,
            } => {
                buf[0] = PacketIdentifier::ReliablePayloadNoAcks as u8;
                buf[1] = *channel_id;
                let packet_id_size = packet_id.encode_var(&mut buf[2..]);
                let offset = 2 + packet_id_size;
                buf[offset..offset + payload.len()].copy_from_slice(payload);
                let mut nonce = [0u8; 12];
                nonce[0] = buf[0];
                nonce[1] = buf[1];
                nonce[2..2 + packet_id_size].copy_from_slice(&buf[2..2 + packet_id_size]);
                let tag = crypto.encrypt(&nonce, &[], &mut buf[offset..offset + payload.len()]);
                buf[offset + payload.len()..offset + payload.len() + 16].copy_from_slice(&tag);
                offset + payload.len() + 16
            }
        }
    }

    pub fn deserialize(crypto: &Crypto, buf: &mut [u8]) -> Result<Self, &'static str> {
        if buf.len() < 19 {
            return Err(ERROR_INVALID_BUFFER_SIZE);
        }
        if buf[0] == PacketIdentifier::ReliablePayloadNoAcks as u8 {
            let channel_id = buf[1];
            let Some((packet_id, packet_id_size)) = u64::decode_var(&buf[2..]) else {
                return Err(ERROR_MALFORMED_PACKET);
            };
            let len = buf.len();
            if 18 + packet_id_size > len {
                return Err(ERROR_INVALID_BUFFER_SIZE);
            }
            let mut nonce = [0u8; 12];
            nonce[0] = buf[0];
            nonce[1] = buf[1];
            nonce[2..2 + packet_id_size].copy_from_slice(&buf[2..2 + packet_id_size]);
            let tag: [u8; 16] = buf[len - 16..len].try_into().unwrap();
            if crypto
                .decrypt(&nonce, &[], &mut buf[2 + packet_id_size..len - 16], &tag)
                .is_err()
            {
                return Err(ERROR_INVALID_TAG);
            }
            return Ok(ReliablePayloadOwned::NoAcks {
                channel_id,
                packet_id,
                payload: buf[2 + packet_id_size..len - 16].to_vec(),
            });
        }
        Err(ERROR_INVALID_PACKET_IDENTIFIER)
    }
}

#[cfg(test)]
mod tests {
    use rand::Rng;
    use x25519_dalek::{PublicKey, ReusableSecret};

    use crate::common::{crypto::Crypto, Cipher};

    use super::ReliablePayload;

    #[test]
    fn test_reliable_no_ack() {
        let mut rng = rand::thread_rng();
        let s1 = ReusableSecret::random_from_rng(&mut rng);
        let s2 = ReusableSecret::random_from_rng(&mut rng);
        let shared_secret_0 = s1.diffie_hellman(&PublicKey::from(&s2));
        let shared_secret_1 = s2.diffie_hellman(&PublicKey::from(&s1));
        let crypto_server = Crypto::new(shared_secret_0, [44u8; 32], true, Cipher::AES256GCM);
        let crypto_client = Crypto::new(shared_secret_1, [44u8; 32], false, Cipher::AES256GCM);

        let mut buf = [0u8; 1200];
        let mut payload = [0u8; 4000];
        for packet_id in 0..44444 {
            let channel_id: u8 = rng.gen();
            let len = rng.gen_range(0..ReliablePayload::max_payload_size(None, packet_id));
            payload[..len].fill((len % 256) as u8);
            let reliable_payload = ReliablePayload::NoAcks {
                channel_id,
                packet_id,
                payload: &payload[..len],
            };
            let size = reliable_payload.serialize(&crypto_client, &mut buf);
            let reliable_payload =
                ReliablePayload::deserialize(&crypto_server, &mut buf[..size]).unwrap();
            match reliable_payload {
                ReliablePayload::NoAcks {
                    channel_id: channel_id2,
                    packet_id: packet_id2,
                    payload: payload2,
                } => {
                    assert_eq!(channel_id, channel_id2);
                    assert_eq!(packet_id, packet_id2);
                    assert_eq!(&payload[..len], payload2);
                }
            }
        }
    }
}
