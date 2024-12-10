// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use aes_gcm::{aead::AeadInPlace, Aes256Gcm, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;

use crate::common::Cipher;

pub enum SymCipher {
    AES256GCM(Aes256Gcm),
    ChaCha20Poly1305(ChaCha20Poly1305),
}

impl SymCipher {
    pub fn new(cipher: Cipher, key: [u8; 32]) -> Self {
        match cipher {
            Cipher::AES256GCM => SymCipher::AES256GCM(Aes256Gcm::new(&key.into())),
            Cipher::ChaCha20Poly1305 => {
                SymCipher::ChaCha20Poly1305(ChaCha20Poly1305::new(&key.into()))
            }
        }
    }

    pub fn encrypt(&self, nonce: &[u8; 12], aad: &[u8], to_encrypt: &mut [u8]) -> [u8; 16] {
        match self {
            SymCipher::AES256GCM(cipher) => cipher
                .encrypt_in_place_detached(nonce.into(), aad, to_encrypt)
                .unwrap()
                .into(),
            SymCipher::ChaCha20Poly1305(cipher) => cipher
                .encrypt_in_place_detached(nonce.into(), aad, to_encrypt)
                .unwrap()
                .into(),
        }
    }

    pub fn decrypt(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        to_decrypt: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), ()> {
        match self {
            SymCipher::AES256GCM(cipher) => cipher
                .decrypt_in_place_detached(nonce.into(), aad, to_decrypt, tag.into())
                .map_err(|_| ()),
            SymCipher::ChaCha20Poly1305(cipher) => cipher
                .decrypt_in_place_detached(nonce.into(), aad, to_decrypt, tag.into())
                .map_err(|_| ()),
        }
    }
}
