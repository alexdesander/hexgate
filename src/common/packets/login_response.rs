// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::common::crypto::Crypto;

use super::*;

pub enum LoginResponse<'a> {
    Success,
    Failure { failure_data: &'a [u8] },
}

// 2^96 - 3
const NONCE: [u8; 12] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfd,
];
impl<'a> LoginResponse<'a> {
    pub fn serialize(&self, crypto: &Crypto, buf: &mut [u8]) -> usize {
        match self {
            LoginResponse::Success => {
                buf[0] = PacketIdentifier::LoginSuccess as u8;
                let tag = crypto.encrypt(&NONCE, &buf[0..1], &mut []);
                buf[1..17].copy_from_slice(&tag);
                17
            }
            LoginResponse::Failure { failure_data } => {
                assert!(
                    failure_data.len() <= 1181,
                    "Failure data in LoginResponse cannot be larger than 1181 bytes"
                );
                buf[0] = PacketIdentifier::LoginFailure as u8;
                buf[1..3].copy_from_slice(&(failure_data.len() as u16).to_le_bytes());
                buf[3..3 + failure_data.len()].copy_from_slice(failure_data);
                buf[3 + failure_data.len()..1184].fill(0);

                let aad: [u8; 1] = buf[0..1].try_into().unwrap();
                let tag = crypto.encrypt(&NONCE, &aad, &mut buf[1..1184]);
                buf[1184..1200].copy_from_slice(&tag);
                1200
            }
        }
    }

    pub fn deserialize(crypto: &Crypto, buf: &'a mut [u8]) -> Result<Self, &'static str> {
        if buf[0] == PacketIdentifier::LoginSuccess as u8 {
            if buf.len() != 17 {
                return Err(ERROR_INVALID_BUFFER_SIZE);
            }
            let tag: [u8; 16] = buf[1..17].try_into().unwrap();
            if crypto.decrypt(&NONCE, &buf[0..1], &mut [], &tag).is_err() {
                return Err(ERROR_INVALID_TAG);
            }
            return Ok(LoginResponse::Success);
        }

        if buf[0] == PacketIdentifier::LoginFailure as u8 {
            if buf.len() != 1200 {
                return Err(ERROR_INVALID_BUFFER_SIZE);
            }
            let tag: [u8; 16] = buf[1184..1200].try_into().unwrap();
            let aad: [u8; 1] = buf[0..1].try_into().unwrap();
            if crypto
                .decrypt(&NONCE, &aad, &mut buf[1..1184], &tag)
                .is_err()
            {
                return Err(ERROR_INVALID_TAG);
            }

            let data_size = u16::from_le_bytes(buf[1..3].try_into().unwrap()) as usize;
            if data_size > 1181 {
                return Err(ERROR_INVALID_DATA_SIZE);
            }
            let failure_data = &buf[3..3 + data_size];
            return Ok(LoginResponse::Failure { failure_data });
        }

        Err(ERROR_INVALID_PACKET_IDENTIFIER)
    }
}
