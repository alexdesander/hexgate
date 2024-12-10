// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::common::{ClientVersion, PROTOCOL_VERSION};

use super::*;

pub struct ClientHello {
    pub salt: [u8; 4],
    pub client_version: ClientVersion,
}

impl ClientHello {
    pub fn serialize(&self, buf: &mut [u8]) -> usize {
        buf[0] = PacketIdentifier::ClientHello as u8;
        buf[1..8].copy_from_slice(MAGIC.as_bytes());
        buf[8] = PROTOCOL_VERSION;
        buf[9..13].copy_from_slice(&self.salt);
        buf[13..15].copy_from_slice(&self.client_version.major.to_le_bytes());
        buf[15..17].copy_from_slice(&self.client_version.minor.to_le_bytes());
        buf[17..19].copy_from_slice(&self.client_version.patch.to_le_bytes());
        buf[19..1200].fill(0);
        1200
    }

    pub fn deserialize(buf: &[u8]) -> Result<Self, &'static str> {
        if buf.len() != 1200 {
            return Err(ERROR_INVALID_BUFFER_SIZE);
        }

        if buf[0] != PacketIdentifier::ClientHello as u8 {
            return Err(ERROR_INVALID_PACKET_IDENTIFIER);
        }

        if &buf[1..8] != MAGIC.as_bytes() {
            return Err(ERROR_INVALID_MAGIC);
        }

        if buf[8] != PROTOCOL_VERSION {
            // TODO: Handle protocol version mismatch better
            return Err(ERROR_INVALID_PROTOCOL_VERSION);
        }

        Ok(ClientHello {
            salt: buf[9..13].try_into().unwrap(),
            client_version: ClientVersion {
                major: u16::from_le_bytes(buf[13..15].try_into().unwrap()),
                minor: u16::from_le_bytes(buf[15..17].try_into().unwrap()),
                patch: u16::from_le_bytes(buf[17..19].try_into().unwrap()),
            },
        })
    }
}
