// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use integer_encoding::VarInt;

use crate::common::{
    crypto::Crypto,
    packets::{PacketIdentifier, ERROR_INVALID_TAG, ERROR_MALFORMED_PACKET},
};

use super::{ERROR_INVALID_BUFFER_SIZE, ERROR_INVALID_PACKET_IDENTIFIER};

pub const MAX_ACK_BITFIELD_SIZE_IN_BYTES: usize = 128;

#[derive(Debug)]
pub struct Acks<'a> {
    pub channel_id: u8,
    pub packet_id: u64,
    pub lowest_unreceived: u64,
    pub ack_bitfield: &'a [u8],
}

impl<'a> Acks<'a> {
    pub fn serialize(&self, crypto: &Crypto, buf: &mut [u8]) -> usize {
        assert!(self.ack_bitfield.len() <= MAX_ACK_BITFIELD_SIZE_IN_BYTES);
        buf[0] = PacketIdentifier::Acks as u8;
        buf[1] = self.channel_id;
        let packet_id_size = self.packet_id.encode_var(&mut buf[2..]);
        let offset = 2
            + packet_id_size
            + self
                .lowest_unreceived
                .encode_var(&mut buf[2 + packet_id_size..]);
        buf[offset..offset + self.ack_bitfield.len()].copy_from_slice(self.ack_bitfield);
        let hash = crypto.hash_out(&buf[..offset + self.ack_bitfield.len()]);
        buf[offset + self.ack_bitfield.len()..offset + self.ack_bitfield.len() + 8]
            .copy_from_slice(&hash.to_le_bytes());
        offset + self.ack_bitfield.len() + 8
    }

    pub fn deserialize(crypto: &Crypto, buf: &'a mut [u8]) -> Result<Self, &'static str> {
        if buf.len() < 12 {
            return Err(ERROR_INVALID_BUFFER_SIZE);
        }
        if buf[0] != PacketIdentifier::Acks as u8 {
            return Err(ERROR_INVALID_PACKET_IDENTIFIER);
        }
        let hash = crypto.hash_in(&buf[..buf.len() - 8]).to_le_bytes();
        if hash != buf[buf.len() - 8..buf.len()] {
            return Err(ERROR_INVALID_TAG);
        }
        let channel_id = buf[1];
        let Some((packet_id, packet_id_size)) = u64::decode_var(&buf[2..]) else {
            return Err(ERROR_MALFORMED_PACKET);
        };
        let Some((lowest_unreceived, lowest_unreceived_size)) =
            u64::decode_var(&buf[2 + packet_id_size..])
        else {
            return Err(ERROR_MALFORMED_PACKET);
        };
        let ack_bitfield = &buf[2 + packet_id_size + lowest_unreceived_size..buf.len() - 8];
        if ack_bitfield.len() > MAX_ACK_BITFIELD_SIZE_IN_BYTES {
            return Err(ERROR_INVALID_BUFFER_SIZE);
        }
        Ok(Acks {
            channel_id,
            packet_id,
            lowest_unreceived,
            ack_bitfield,
        })
    }
}

#[cfg(test)]
mod tests {
    use rand::Rng;
    use x25519_dalek::{PublicKey, ReusableSecret};

    use crate::common::{crypto::Crypto, Cipher};

    use super::Acks;

    #[test]
    fn test_acks() {
        let mut rng = rand::thread_rng();
        let s1 = ReusableSecret::random_from_rng(&mut rng);
        let s2 = ReusableSecret::random_from_rng(&mut rng);
        let shared_secret_0 = s1.diffie_hellman(&PublicKey::from(&s2));
        let shared_secret_1 = s2.diffie_hellman(&PublicKey::from(&s1));
        let crypto_server = Crypto::new(shared_secret_0, [44u8; 32], true, Cipher::AES256GCM);
        let crypto_client = Crypto::new(shared_secret_1, [44u8; 32], false, Cipher::AES256GCM);

        let mut buf = [0u8; 1200];
        let mut ack_bitfield = [0u8; 128];
        for packet_id in 0..4444 {
            let channel_id: u8 = rng.gen();
            let lowest_unreceived: u64 = rng.gen();
            let ack_bitfield = &mut ack_bitfield[..rng.gen_range(0..129)];
            ack_bitfield.fill(rng.gen());
            let acks = Acks {
                channel_id,
                packet_id,
                lowest_unreceived,
                ack_bitfield,
            };
            let len = acks.serialize(&crypto_server, &mut buf);
            let acks = Acks::deserialize(&crypto_client, &mut buf[..len]).unwrap();
            assert_eq!(acks.channel_id, channel_id);
            assert_eq!(acks.packet_id, packet_id);
            assert_eq!(acks.lowest_unreceived, lowest_unreceived);
            assert_eq!(acks.ack_bitfield, ack_bitfield);
        }
    }
}
