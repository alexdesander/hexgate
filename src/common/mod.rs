// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::fmt;

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
    /// AES-256-GCM, fastest with AES hardware instructions.
    AES256GCM = 0,
    /// ChaCha20-Poly1305, fastest without them.
    ChaCha20Poly1305 = 1,
}

impl Cipher {
    pub(crate) fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Cipher::AES256GCM),
            1 => Some(Cipher::ChaCha20Poly1305),
            _ => None,
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

/// The version of the app using hexgate, which the server can restrict
/// (`allowed_client_versions`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ClientVersion {
    /// Incompatible changes.
    pub major: u16,
    /// Compatible additions.
    pub minor: u16,
    /// Fixes.
    pub patch: u16,
}

impl ClientVersion {
    /// Version 0.0.0.
    pub const ZERO: Self = Self {
        major: 0,
        minor: 0,
        patch: 0,
    };
}

impl fmt::Display for ClientVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// An inclusive range of client versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct AllowedClientVersions {
    /// The oldest allowed version.
    pub min: ClientVersion,
    /// The newest allowed version.
    pub max: ClientVersion,
}

impl fmt::Display for AllowedClientVersions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} to {}", self.min, self.max)
    }
}

impl AllowedClientVersions {
    /// A version check for the server's `allowed_client_versions`.
    pub fn check(&self, version: ClientVersion) -> Result<(), Self> {
        if (self.min..=self.max).contains(&version) {
            Ok(())
        } else {
            Err(*self)
        }
    }
}
