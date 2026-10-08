// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{
    hash::Hasher,
    net::{IpAddr, SocketAddr},
};

use ed25519_dalek::VerifyingKey;
use siphasher::sip::SipHasher;

use crate::common::{AllowedClientVersions, Cipher, ClientVersion};

use super::*;

#[expect(
    clippy::large_enum_variant,
    reason = "only lives while (de)serializing"
)]
pub enum ServerHello {
    VersionSupported {
        salt: [u8; 4],
        timestamp: [u8; 8],
        cipher: Cipher,
        server_ed25519_pubkey: VerifyingKey,
        siphash: Option<u64>,
        /// Unreliable ordered and reliable channel counts, the client's must match.
        channel_counts: [u16; 2],
    },
    VersionNotSupported {
        salt: [u8; 4],
        allowed_versions: AllowedClientVersions,
    },
    ServerFull {
        salt: [u8; 4],
    },
    /// The client speaks another protocol version.
    ProtocolMismatch {
        salt: [u8; 4],
        server_version: u8,
    },
}

/// The cookie a client echoes in its ConnectionRequest: a MAC over the echoed salt, timestamp
/// and server key, bound to the client's address so it can't be used from anywhere else.
pub fn cookie(siphasher: &SipHasher, echoed: &[u8], client: SocketAddr) -> u64 {
    let mut hasher = *siphasher;
    hasher.write(echoed);
    match client.ip() {
        IpAddr::V4(ip) => hasher.write(&ip.octets()),
        IpAddr::V6(ip) => hasher.write(&ip.octets()),
    }
    hasher.write(&client.port().to_le_bytes());
    hasher.finish()
}

impl ServerHello {
    pub fn serialize(&self, siphasher: &SipHasher, client: SocketAddr, buf: &mut [u8]) -> usize {
        match self {
            ServerHello::VersionSupported {
                salt,
                timestamp,
                cipher,
                server_ed25519_pubkey,
                siphash,
                channel_counts,
            } => {
                buf[0] = PacketIdentifier::ServerHelloVersionSupported as u8;
                buf[1..5].copy_from_slice(salt);
                buf[5..13].copy_from_slice(timestamp);
                buf[13..45].copy_from_slice(server_ed25519_pubkey.as_bytes());
                let siphash = siphash.unwrap_or_else(|| cookie(siphasher, &buf[1..45], client));
                buf[45..53].copy_from_slice(&siphash.to_le_bytes());
                buf[53] = *cipher as u8;
                buf[54..56].copy_from_slice(&channel_counts[0].to_le_bytes());
                buf[56..58].copy_from_slice(&channel_counts[1].to_le_bytes());
                58
            }
            ServerHello::VersionNotSupported {
                salt,
                allowed_versions,
            } => {
                buf[0] = PacketIdentifier::ServerHelloVersionNotSupported as u8;
                buf[1..5].copy_from_slice(salt);
                buf[5..7].copy_from_slice(&allowed_versions.min.major.to_le_bytes());
                buf[7..9].copy_from_slice(&allowed_versions.min.minor.to_le_bytes());
                buf[9..11].copy_from_slice(&allowed_versions.min.patch.to_le_bytes());
                buf[11..13].copy_from_slice(&allowed_versions.max.major.to_le_bytes());
                buf[13..15].copy_from_slice(&allowed_versions.max.minor.to_le_bytes());
                buf[15..17].copy_from_slice(&allowed_versions.max.patch.to_le_bytes());
                17
            }
            ServerHello::ServerFull { salt } => {
                buf[0] = PacketIdentifier::ServerHelloServerFull as u8;
                buf[1..5].copy_from_slice(salt);
                5
            }
            ServerHello::ProtocolMismatch {
                salt,
                server_version,
            } => {
                buf[0] = PacketIdentifier::ServerHelloProtocolMismatch as u8;
                buf[1..5].copy_from_slice(salt);
                buf[5] = *server_version;
                6
            }
        }
    }

    pub fn deserialize(buf: &[u8]) -> Result<Self, PacketError> {
        if buf.is_empty() {
            return Err(PacketError::Size);
        }
        if buf[0] == PacketIdentifier::ServerHelloVersionSupported as u8 {
            if buf.len() != 58 {
                return Err(PacketError::Size);
            }
            let salt = buf[1..5].try_into().unwrap();
            let timestamp = buf[5..13].try_into().unwrap();
            let Ok(server_ed25519_pubkey) =
                VerifyingKey::from_bytes(&buf[13..45].try_into().unwrap())
            else {
                return Err(PacketError::ServerKey);
            };
            let siphash = u64::from_le_bytes(buf[45..53].try_into().unwrap());
            let Some(cipher) = Cipher::from_byte(buf[53]) else {
                return Err(PacketError::Cipher);
            };
            return Ok(ServerHello::VersionSupported {
                salt,
                timestamp,
                cipher,
                server_ed25519_pubkey,
                siphash: Some(siphash),
                channel_counts: [
                    u16::from_le_bytes(buf[54..56].try_into().unwrap()),
                    u16::from_le_bytes(buf[56..58].try_into().unwrap()),
                ],
            });
        }

        if buf[0] == PacketIdentifier::ServerHelloVersionNotSupported as u8 {
            if buf.len() != 17 {
                return Err(PacketError::Size);
            }
            let salt = buf[1..5].try_into().unwrap();
            let allowed_versions = AllowedClientVersions {
                min: ClientVersion {
                    major: u16::from_le_bytes(buf[5..7].try_into().unwrap()),
                    minor: u16::from_le_bytes(buf[7..9].try_into().unwrap()),
                    patch: u16::from_le_bytes(buf[9..11].try_into().unwrap()),
                },
                max: ClientVersion {
                    major: u16::from_le_bytes(buf[11..13].try_into().unwrap()),
                    minor: u16::from_le_bytes(buf[13..15].try_into().unwrap()),
                    patch: u16::from_le_bytes(buf[15..17].try_into().unwrap()),
                },
            };
            return Ok(ServerHello::VersionNotSupported {
                salt,
                allowed_versions,
            });
        }

        if buf[0] == PacketIdentifier::ServerHelloServerFull as u8 {
            if buf.len() != 5 {
                return Err(PacketError::Size);
            }
            return Ok(ServerHello::ServerFull {
                salt: buf[1..5].try_into().unwrap(),
            });
        }

        if buf[0] == PacketIdentifier::ServerHelloProtocolMismatch as u8 {
            if buf.len() != 6 {
                return Err(PacketError::Size);
            }
            return Ok(ServerHello::ProtocolMismatch {
                salt: buf[1..5].try_into().unwrap(),
                server_version: buf[5],
            });
        }

        Err(PacketError::Identifier)
    }
}
