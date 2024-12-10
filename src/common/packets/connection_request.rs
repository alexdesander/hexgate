// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use ed25519_dalek::VerifyingKey;
use x25519_dalek::PublicKey;

use super::*;

pub struct ConnectionRequest {
    pub salt: [u8; 4],
    pub timestamp: [u8; 8],
    pub server_ed25519_pubkey: VerifyingKey,
    pub siphash: [u8; 8],
    pub client_x25519_pubkey: PublicKey,
    pub hkdf_salt: [u8; 32],
}

impl ConnectionRequest {
    pub fn serialize(&self, buf: &mut [u8]) -> usize {
        buf[0] = PacketIdentifier::ConnectionRequest as u8;
        buf[1..5].copy_from_slice(&self.salt);
        buf[5..13].copy_from_slice(&self.timestamp);
        buf[13..45].copy_from_slice(self.server_ed25519_pubkey.as_bytes());
        buf[45..53].copy_from_slice(&self.siphash);
        buf[53..85].copy_from_slice(self.client_x25519_pubkey.as_bytes());
        buf[85..117].copy_from_slice(&self.hkdf_salt);
        117
    }

    pub fn deserialize(buf: &[u8]) -> Result<Self, &'static str> {
        if buf.len() != 117 {
            return Err(ERROR_INVALID_BUFFER_SIZE);
        }

        if buf[0] != PacketIdentifier::ConnectionRequest as u8 {
            return Err(ERROR_INVALID_PACKET_IDENTIFIER);
        }

        let Ok(server_ed25519_pubkey) = VerifyingKey::from_bytes(buf[13..45].try_into().unwrap())
        else {
            return Err(ERROR_INVALID_SERVER_ED25519_PUBKEY);
        };

        let client_x25519_pubkey: [u8; 32] = buf[53..85].try_into().unwrap();
        let client_x25519_pubkey = PublicKey::from(client_x25519_pubkey);

        Ok(ConnectionRequest {
            salt: buf[1..5].try_into().unwrap(),
            timestamp: buf[5..13].try_into().unwrap(),
            server_ed25519_pubkey,
            siphash: buf[45..53].try_into().unwrap(),
            client_x25519_pubkey,
            hkdf_salt: buf[85..117].try_into().unwrap(),
        })
    }
}
