// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::common::PROTOCOL_VERSION;

use super::*;

pub struct InfoRequest;

impl InfoRequest {
    pub fn new() -> Self {
        InfoRequest
    }

    pub fn serialize(&self, buf: &mut [u8]) -> usize {
        buf[0] = PacketIdentifier::InfoRequest as u8;
        buf[1..8].copy_from_slice(MAGIC.as_bytes());
        buf[8] = PROTOCOL_VERSION;
        buf[9..257].fill(0);
        257
    }

    pub fn deserialize(buf: &[u8]) -> Result<Self, PacketError> {
        if buf.len() != 257 {
            return Err(PacketError::Size);
        }

        if buf[0] != PacketIdentifier::InfoRequest as u8 {
            return Err(PacketError::Identifier);
        }

        if &buf[1..8] != MAGIC.as_bytes() {
            return Err(PacketError::Magic);
        }

        if buf[8] != PROTOCOL_VERSION {
            return Err(PacketError::ProtocolVersion);
        }

        Ok(InfoRequest)
    }
}
