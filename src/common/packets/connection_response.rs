// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use ed25519_dalek::{ed25519::signature::Signer, SigningKey, VerifyingKey};
use x25519_dalek::{PublicKey, ReusableSecret};

use crate::common::{crypto::Crypto, Cipher};

use super::*;

pub struct ConnectionResponse {
    pub salt: [u8; 4],
    pub server_x25519_pubkey: PublicKey,
    pub auth_salt: [u8; 16],
}

const NONCE: [u8; 12] = [0xff; 12];
impl ConnectionResponse {
    pub fn serialize(
        &self,
        crypto: &Crypto,
        server_ed25519_key: &SigningKey,
        buf: &mut [u8],
    ) -> usize {
        buf[0] = PacketIdentifier::ConnectionResponse as u8;
        buf[1..5].copy_from_slice(&self.salt);
        buf[5..37].copy_from_slice(self.server_x25519_pubkey.as_bytes());
        buf[37..53].copy_from_slice(&self.auth_salt);

        let tag = crypto.encrypt(&NONCE, &[], &mut buf[37..53]);
        buf[53..69].copy_from_slice(&tag);

        let signature = server_ed25519_key.sign(&buf[..69]);
        buf[69..133].copy_from_slice(&signature.to_bytes());
        133
    }

    pub fn deserialize(
        buf: &[u8],
        served_ed25519_pub_key: VerifyingKey,
        client_x25519_key: ReusableSecret,
        hkdf_salt: [u8; 32],
        cipher: Cipher,
    ) -> Result<(Self, Crypto), &'static str> {
        if buf.len() != 133 {
            return Err(ERROR_INVALID_BUFFER_SIZE);
        }

        if buf[0] != PacketIdentifier::ConnectionResponse as u8 {
            return Err(ERROR_INVALID_PACKET_IDENTIFIER);
        }

        let signature = buf[69..133].try_into().unwrap();
        if served_ed25519_pub_key
            .verify_strict(&buf[..69], &signature)
            .is_err()
        {
            return Err(ERROR_INVALID_SIGNATURE);
        }

        let server_x25519_pubkey: [u8; 32] = buf[5..37].try_into().unwrap();
        let server_x25519_pubkey = PublicKey::from(server_x25519_pubkey);

        let shared_secret = client_x25519_key.diffie_hellman(&server_x25519_pubkey);
        let crypto = Crypto::new(shared_secret, hkdf_salt, false, cipher);

        let tag: [u8; 16] = buf[53..69].try_into().unwrap();
        let mut auth_salt: [u8; 16] = buf[37..53].try_into().unwrap();
        if crypto.decrypt(&NONCE, &[], &mut auth_salt, &tag).is_err() {
            return Err(ERROR_INVALID_TAG);
        }

        Ok((
            ConnectionResponse {
                salt: buf[1..5].try_into().unwrap(),
                server_x25519_pubkey,
                auth_salt,
            },
            crypto,
        ))
    }
}
