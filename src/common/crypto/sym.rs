// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::time::Instant;

use aes_gcm::{aead::AeadInPlace, Aes256Gcm, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use rand::{thread_rng, Rng};

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

    /// Benchmarking function that returns the most efficient cipher
    pub fn better() -> Cipher {
        let aes = SymCipher::new(Cipher::AES256GCM, thread_rng().gen());
        let chacha = SymCipher::new(Cipher::ChaCha20Poly1305, thread_rng().gen());

        let mut data = [0u8; 1200];
        let nonce: [u8; 12] = thread_rng().gen();

        // Warmup
        aes.encrypt(&nonce, &[], &mut data);
        chacha.encrypt(&nonce, &[], &mut data);

        let runs = 500;

        let start = Instant::now();
        for _ in 0..runs {
            aes.encrypt(&nonce, &[], &mut data);
        }
        let aes_time = start.elapsed();

        let start = Instant::now();
        for _ in 0..runs {
            chacha.encrypt(&nonce, &[], &mut data);
        }
        let chacha_time = start.elapsed();

        if aes_time < chacha_time {
            Cipher::AES256GCM
        } else {
            Cipher::ChaCha20Poly1305
        }
    }
}
