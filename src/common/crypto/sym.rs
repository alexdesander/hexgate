// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use aes_gcm::{aead::AeadInPlace, Aes256Gcm, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;

use crate::common::Cipher;

pub enum SymCipher {
    AES256GCM(Box<Aes256Gcm>),
    ChaCha20Poly1305(ChaCha20Poly1305),
}

impl SymCipher {
    pub fn new(cipher: Cipher, key: [u8; 32]) -> Self {
        match cipher {
            Cipher::AES256GCM => SymCipher::AES256GCM(Box::new(Aes256Gcm::new(&key.into()))),
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

    /// AES-256-GCM on CPUs with AES and carry-less multiplication instructions, otherwise
    /// ChaCha20-Poly1305 (faster in software). On aarch64 the `aes` and `polyval` crates use
    /// these instructions only when built with `--cfg aes_armv8 --cfg polyval_armv8`.
    pub fn better() -> Cipher {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        let aes_hardware = std::arch::is_x86_feature_detected!("aes")
            && std::arch::is_x86_feature_detected!("pclmulqdq");
        #[cfg(target_arch = "aarch64")]
        let aes_hardware =
            cfg!(all(aes_armv8, polyval_armv8)) && std::arch::is_aarch64_feature_detected!("aes");
        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
        let aes_hardware = false;
        if aes_hardware {
            Cipher::AES256GCM
        } else {
            Cipher::ChaCha20Poly1305
        }
    }
}
