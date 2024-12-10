// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::common::crypto::Crypto;

use super::{PacketIdentifier, *};

pub struct LatencyDiscoveryResponse {
    pub sequence_number: u32,
    pub truncated_siphash: u32,
}

impl LatencyDiscoveryResponse {
    pub fn serialize(&mut self, crypto: &Crypto, buf: &mut [u8]) -> usize {
        buf[0] = PacketIdentifier::LatencyDiscoveryResponse as u8;
        buf[1..5].copy_from_slice(&self.sequence_number.to_le_bytes());
        let hash = crypto.hash_out(&buf[0..5]).to_le_bytes();
        self.truncated_siphash = u32::from_le_bytes(hash[..4].try_into().unwrap());
        buf[5..9].copy_from_slice(&self.truncated_siphash.to_le_bytes());
        9
    }

    pub fn deserialize(crypto: &Crypto, buf: &[u8]) -> Result<Self, &'static str> {
        if buf.len() != 9 {
            return Err(ERROR_INVALID_BUFFER_SIZE);
        }
        if PacketIdentifier::try_from(buf[0])? != PacketIdentifier::LatencyDiscoveryResponse {
            return Err(ERROR_INVALID_PACKET_IDENTIFIER);
        }
        let sequence_number = u32::from_le_bytes(buf[1..5].try_into().unwrap());
        let truncated_siphash = u32::from_le_bytes(buf[5..9].try_into().unwrap());
        let hash = crypto.hash_in(&buf[0..5]).to_le_bytes();
        let expected_truncated_siphash = u32::from_le_bytes(hash[..4].try_into().unwrap());
        if truncated_siphash != expected_truncated_siphash {
            return Err(ERROR_SIPHASH_MISMATCH);
        }
        Ok(Self {
            sequence_number,
            truncated_siphash,
        })
    }
}
