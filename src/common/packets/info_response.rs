// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::*;

pub struct InfoResponse<'a> {
    pub data: &'a [u8],
}

impl<'a> InfoResponse<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        assert!(
            data.len() <= 256,
            "Data in InfoResponse cannot be larger than 256 bytes"
        );
        InfoResponse { data }
    }

    pub fn serialize(&self, buf: &mut [u8]) -> usize {
        buf[0] = PacketIdentifier::InfoResponse as u8;
        buf[1..self.data.len() + 1].copy_from_slice(self.data);
        1 + self.data.len()
    }

    pub fn deserialize(buf: &'a [u8]) -> Result<Self, &'static str> {
        if buf.len() > 257 || buf.len() < 1 {
            return Err(ERROR_INVALID_BUFFER_SIZE);
        }

        if buf[0] != PacketIdentifier::InfoResponse as u8 {
            return Err(ERROR_INVALID_PACKET_IDENTIFIER);
        }

        Ok(InfoResponse { data: &buf[1..] })
    }
}
