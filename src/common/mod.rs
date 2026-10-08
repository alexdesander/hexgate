// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use mio::Token;

pub mod channel;
pub mod congestion;
pub(crate) mod crypto;
pub mod error;
pub(crate) mod events;
pub mod keys;
pub(crate) mod packets;
pub mod socket;
pub mod stats;
pub(crate) mod timed_event_queue;

pub(crate) const PROTOCOL_VERSION: u8 = 0;
pub(crate) const RECV_TOKEN: Token = Token(0);
pub(crate) const WAKE_TOKEN: Token = Token(1);

/// The symmetric cipher of all connections, chosen by the server (`cipher`, by default the
/// faster one on its CPU).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Cipher {
    AES256GCM = 0,
    ChaCha20Poly1305 = 1,
}

impl TryFrom<u8> for Cipher {
    type Error = &'static str;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Cipher::AES256GCM),
            1 => Ok(Cipher::ChaCha20Poly1305),
            _ => Err("Invalid cipher"),
        }
    }
}

/// A server key as groups of four hex digits, for users comparing it against a published one.
pub fn fingerprint(key: &[u8; 32]) -> String {
    key.chunks(2)
        .map(|pair| format!("{:02x}{:02x}", pair[0], pair[1]))
        .collect::<Vec<_>>()
        .join(" ")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ClientVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl ClientVersion {
    pub const ZERO: Self = Self {
        major: 0,
        minor: 0,
        patch: 0,
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct AllowedClientVersions {
    pub min: ClientVersion,
    pub max: ClientVersion,
}
