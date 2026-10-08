// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::ops::Range;

use ed25519_dalek::{ed25519::signature::Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha512};
use x25519_dalek::{PublicKey, ReusableSecret};

use crate::common::{crypto::Crypto, Cipher};

use super::*;

pub struct ConnectionResponse {
    pub salt: [u8; 4],
    pub server_x25519_pubkey: PublicKey,
    pub auth_salt: [u8; 16],
}

pub const SIZE: usize = 133;

/// The ConnectionRequest bytes the signature covers: the echoed ServerHello fields, the
/// client's x25519 key and the HKDF salt.
pub const SIGNED_REQUEST: Range<usize> = 1..117;

/// Everything besides the response itself that the server signs, so neither side's key
/// exchange parameters nor the cipher and channel counts can be changed on the path.
pub struct Transcript<'a> {
    pub request: &'a [u8],
    pub cipher: Cipher,
    pub channel_counts: [u16; 2],
}

impl Transcript<'_> {
    fn digest(&self, response: &[u8]) -> [u8; 64] {
        Sha512::new()
            .chain_update(b"hexgate ConnectionResponse")
            .chain_update(self.request)
            .chain_update([self.cipher as u8])
            .chain_update(self.channel_counts[0].to_le_bytes())
            .chain_update(self.channel_counts[1].to_le_bytes())
            .chain_update(response)
            .finalize()
            .into()
    }
}

/// Fixed, see the `packets` docs: once per key exchange, retransmitted requests get the stored
/// response.
const NONCE: [u8; 12] = [0xff; 12];
impl ConnectionResponse {
    pub fn serialize(
        &self,
        crypto: &Crypto,
        server_ed25519_key: &SigningKey,
        transcript: &Transcript,
        buf: &mut [u8],
    ) -> usize {
        buf[0] = PacketIdentifier::ConnectionResponse as u8;
        buf[1..5].copy_from_slice(&self.salt);
        buf[5..37].copy_from_slice(self.server_x25519_pubkey.as_bytes());
        buf[37..53].copy_from_slice(&self.auth_salt);

        let tag = crypto.encrypt(&NONCE, &[], &mut buf[37..53]);
        buf[53..69].copy_from_slice(&tag);

        let signature = server_ed25519_key.sign(&transcript.digest(&buf[..69]));
        buf[69..SIZE].copy_from_slice(&signature.to_bytes());
        SIZE
    }

    pub fn deserialize(
        buf: &[u8],
        server_ed25519_pubkey: VerifyingKey,
        client_x25519_key: &ReusableSecret,
        hkdf_salt: [u8; 32],
        transcript: &Transcript,
    ) -> Result<(Self, Crypto), PacketError> {
        if buf.len() != SIZE {
            return Err(PacketError::Size);
        }

        if buf[0] != PacketIdentifier::ConnectionResponse as u8 {
            return Err(PacketError::Identifier);
        }

        let signature = buf[69..SIZE].try_into().unwrap();
        if server_ed25519_pubkey
            .verify_strict(&transcript.digest(&buf[..69]), &signature)
            .is_err()
        {
            return Err(PacketError::Signature);
        }

        let server_x25519_pubkey: [u8; 32] = buf[5..37].try_into().unwrap();
        let server_x25519_pubkey = PublicKey::from(server_x25519_pubkey);

        let shared_secret = client_x25519_key.diffie_hellman(&server_x25519_pubkey);
        let crypto = Crypto::new(shared_secret, hkdf_salt, false, transcript.cipher);

        let tag: [u8; 16] = buf[53..69].try_into().unwrap();
        let mut auth_salt: [u8; 16] = buf[37..53].try_into().unwrap();
        if crypto.decrypt(&NONCE, &[], &mut auth_salt, &tag).is_err() {
            return Err(PacketError::Tag);
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
