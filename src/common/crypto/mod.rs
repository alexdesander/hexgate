// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use hkdf::Hkdf;
use sha2::Sha512;
use siphasher::sip::SipHasher;
use sym::SymCipher;
use x25519_dalek::SharedSecret;

use super::Cipher;

pub mod sym;

pub(crate) struct Crypto {
    sym_out: SymCipher,
    sym_in: SymCipher,
    siphash_out: SipHasher,
    siphash_in: SipHasher,
}

impl Crypto {
    pub fn new(
        shared_secret: SharedSecret,
        salt: [u8; 32],
        is_server: bool,
        cipher: Cipher,
    ) -> Self {
        let hk = Hkdf::<Sha512>::new(Some(&salt), shared_secret.as_bytes());
        let mut sym_out_key = [0u8; 32];
        let mut sym_in_key = [0u8; 32];
        let mut siphash_out_key = [0u8; 16];
        let mut siphash_in_key = [0u8; 16];

        hk.expand(b"Sym Client->Server", &mut sym_out_key).unwrap();
        hk.expand(b"Sym Server->Client", &mut sym_in_key).unwrap();
        hk.expand(b"Sip Client->Server", &mut siphash_out_key)
            .unwrap();
        hk.expand(b"Sip Server->Client", &mut siphash_in_key)
            .unwrap();
        if is_server {
            std::mem::swap(&mut sym_out_key, &mut sym_in_key);
            std::mem::swap(&mut siphash_out_key, &mut siphash_in_key);
        }

        Self {
            sym_out: SymCipher::new(cipher, sym_out_key),
            sym_in: SymCipher::new(cipher, sym_in_key),
            siphash_out: SipHasher::new_with_key(&siphash_out_key),
            siphash_in: SipHasher::new_with_key(&siphash_in_key),
        }
    }

    pub fn encrypt(&self, nonce: &[u8; 12], aad: &[u8], to_encrypt: &mut [u8]) -> [u8; 16] {
        self.sym_out.encrypt(nonce, aad, to_encrypt)
    }

    pub fn decrypt(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        to_decrypt: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), ()> {
        self.sym_in.decrypt(nonce, aad, to_decrypt, tag)
    }

    pub fn hash_out(&self, data: &[u8]) -> u64 {
        self.siphash_out.hash(data)
    }

    pub fn hash_in(&self, data: &[u8]) -> u64 {
        self.siphash_in.hash(data)
    }
}
