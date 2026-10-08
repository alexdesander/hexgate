// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::sync::Arc;

use crossbeam_channel::{Receiver, Sender};
use ed25519_dalek::SigningKey;
use mio::Waker;
use rand::thread_rng;
use x25519_dalek::{EphemeralSecret, PublicKey};

use super::auth::LoginAttempt;
use crate::common::{
    Cipher,
    crypto::Crypto,
    packets::connection_response::{ConnectionResponse, Transcript},
};

/// A ConnectionRequest that passed the cookie check and the rate limit.
pub(crate) struct KeyExchange {
    pub attempt: LoginAttempt,
    /// The signed ConnectionRequest bytes, see `connection_response::SIGNED_REQUEST`.
    pub request: [u8; 116],
    pub client_x25519_pubkey: PublicKey,
    pub hkdf_salt: [u8; 32],
}

pub(crate) struct KeyExchanged {
    pub attempt: LoginAttempt,
    pub request: [u8; 116],
    pub crypto: Crypto,
    pub response: Vec<u8>,
}

/// Runs the key exchanges and signatures of new handshakes off the network thread. It stops
/// once the network thread drops its end of either channel.
pub(crate) struct HandshakeThreadState {
    pub signing_key: SigningKey,
    pub cipher: Cipher,
    pub auth_salt: [u8; 16],
    pub channel_counts: [u16; 2],
    pub requests: Receiver<KeyExchange>,
    pub results: Sender<KeyExchanged>,
    pub waker: Arc<Waker>,
}

pub(crate) fn handshake_thread(state: HandshakeThreadState) {
    let mut buf = [0; 1201];
    while let Ok(exchange) = state.requests.recv() {
        let secret = EphemeralSecret::random_from_rng(thread_rng());
        let public = PublicKey::from(&secret);
        let crypto = Crypto::new(
            secret.diffie_hellman(&exchange.client_x25519_pubkey),
            exchange.hkdf_salt,
            true,
            state.cipher,
        );
        let transcript = Transcript {
            request: &exchange.request,
            cipher: state.cipher,
            channel_counts: state.channel_counts,
        };
        let size = ConnectionResponse {
            salt: exchange.attempt.1,
            server_x25519_pubkey: public,
            auth_salt: state.auth_salt,
        }
        .serialize(&crypto, &state.signing_key, &transcript, &mut buf);
        let result = KeyExchanged {
            attempt: exchange.attempt,
            request: exchange.request,
            crypto,
            response: buf[..size].to_vec(),
        };
        if state.results.send(result).is_err() {
            break;
        }
        let _ = state.waker.wake();
    }
}
