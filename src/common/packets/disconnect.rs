// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::common::crypto::Crypto;

use super::*;

pub struct Disconnect<'a> {
    pub data: &'a [u8],
}

// 2^96 - 5
const NONCE: [u8; 12] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfb,
];
impl<'a> Disconnect<'a> {
    pub fn serialize(&self, crypto: &Crypto, buf: &mut [u8]) -> usize {
        assert!(
            self.data.len() <= 1183,
            "Disconnect payload cannot be larger than 1183 bytes"
        );
        buf[0] = PacketIdentifier::Disconnect as u8;
        buf[1..1 + self.data.len()].copy_from_slice(self.data);
        let aad: [u8; 1] = buf[0..1].try_into().unwrap();
        let tag = crypto.encrypt(&NONCE, &aad, &mut buf[1..1 + self.data.len()]);
        buf[1 + self.data.len()..17 + self.data.len()].copy_from_slice(&tag);
        17 + self.data.len()
    }

    pub fn deserialize(crypto: &Crypto, buf: &'a mut [u8]) -> Result<Self, &'static str> {
        if buf.len() < 17 || buf.len() > 1200 {
            return Err(ERROR_INVALID_DATA_SIZE);
        }
        let aad: [u8; 1] = buf[0..1].try_into().unwrap();
        let tag: [u8; 16] = buf[buf.len() - 16..].try_into().unwrap();
        let len = buf.len();
        if crypto
            .decrypt(&NONCE, &aad, &mut buf[1..len - 16], &tag)
            .is_err()
        {
            return Err(ERROR_INVALID_TAG);
        }
        Ok(Disconnect {
            data: &buf[1..buf.len() - 16],
        })
    }
}
