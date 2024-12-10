// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::common::crypto::Crypto;

use super::*;

pub struct LoginRequest<'a> {
    pub salt: [u8; 4],
    pub auth_data: &'a [u8],
}

// 2^96 - 2
const NONCE: [u8; 12] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
];
impl<'a> LoginRequest<'a> {
    pub fn deserialize_salt(buf: &[u8]) -> Option<[u8; 4]> {
        if buf.len() < 5 {
            return None;
        }
        Some(buf[1..5].try_into().unwrap())
    }

    pub fn serialize(&self, crypto: &Crypto, buf: &mut [u8]) -> usize {
        assert!(
            self.auth_data.len() <= 1177,
            "Auth data in LoginRequest cannot be larger than 1177 bytes"
        );
        buf[0] = PacketIdentifier::LoginRequest as u8;
        buf[1..5].copy_from_slice(&self.salt);
        buf[5..7].copy_from_slice(&(self.auth_data.len() as u16).to_le_bytes());
        buf[7..7 + self.auth_data.len()].copy_from_slice(self.auth_data);
        buf[7 + self.auth_data.len()..1184].fill(0);

        let aad: [u8; 5] = buf[0..5].try_into().unwrap();
        let tag = crypto.encrypt(&NONCE, &aad, &mut buf[5..1184]);
        buf[1184..1200].copy_from_slice(&tag);

        1200
    }

    pub fn deserialize(crypto: &Crypto, buf: &'a mut [u8]) -> Result<Self, &'static str> {
        if buf.len() != 1200 {
            return Err(ERROR_INVALID_BUFFER_SIZE);
        }

        if buf[0] != PacketIdentifier::LoginRequest as u8 {
            return Err(ERROR_INVALID_PACKET_IDENTIFIER);
        }

        let tag: [u8; 16] = buf[1184..1200].try_into().unwrap();
        let aad: [u8; 5] = buf[0..5].try_into().unwrap();
        if crypto
            .decrypt(&NONCE, &aad, &mut buf[5..1184], &tag)
            .is_err()
        {
            return Err(ERROR_INVALID_TAG);
        }

        let auth_data_len = u16::from_le_bytes(buf[5..7].try_into().unwrap()) as usize;
        if auth_data_len > 1177 {
            return Err(ERROR_INVALID_DATA_SIZE);
        }
        let auth_data = &buf[7..7 + auth_data_len];

        Ok(LoginRequest {
            salt: buf[1..5].try_into().unwrap(),
            auth_data: &auth_data,
        })
    }
}
