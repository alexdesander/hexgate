// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use mio::Token;

pub mod channel;
pub(crate) mod congestion;
pub(crate) mod crypto;
pub(crate) mod packets;
pub mod socket;
pub(crate) mod timed_event_queue;

const PROTOCOL_VERSION: u8 = 0;
pub(crate) const RECV_TOKEN: Token = Token(0);
pub(crate) const WAKE_TOKEN: Token = Token(1);

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Cipher {
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
