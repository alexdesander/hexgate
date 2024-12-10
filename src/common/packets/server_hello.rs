// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use ed25519_dalek::VerifyingKey;
use siphasher::sip::SipHasher;

use crate::common::{AllowedClientVersions, Cipher, ClientVersion};

use super::*;

pub enum ServerHello {
    VersionSupported {
        salt: [u8; 4],
        timestamp: [u8; 8],
        cipher: Cipher,
        server_ed25519_pubkey: VerifyingKey,
        siphash: Option<u64>,
    },
    VersionNotSupported {
        salt: [u8; 4],
        allowed_versions: AllowedClientVersions,
    },
}

impl ServerHello {
    pub fn serialize(&self, siphasher: &SipHasher, buf: &mut [u8]) -> usize {
        match self {
            ServerHello::VersionSupported {
                salt,
                timestamp,
                cipher,
                server_ed25519_pubkey,
                siphash,
            } => {
                buf[0] = PacketIdentifier::ServerHelloVersionSupported as u8;
                buf[1..5].copy_from_slice(salt);
                buf[5..13].copy_from_slice(timestamp);
                buf[13..45].copy_from_slice(server_ed25519_pubkey.as_bytes());
                let siphash = siphash.unwrap_or_else(|| siphasher.hash(&buf[1..45]));
                buf[45..53].copy_from_slice(&siphash.to_le_bytes());
                buf[54] = *cipher as u8;
                55
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
        }
    }

    pub fn deserialize(buf: &[u8]) -> Result<Self, &'static str> {
        if buf[0] == PacketIdentifier::ServerHelloVersionSupported as u8 {
            if buf.len() != 55 {
                return Err(ERROR_INVALID_BUFFER_SIZE);
            }
            let salt = buf[1..5].try_into().unwrap();
            let timestamp = buf[5..13].try_into().unwrap();
            let Ok(server_ed25519_pubkey) =
                VerifyingKey::from_bytes(&buf[13..45].try_into().unwrap())
            else {
                return Err(&ERROR_INVALID_SERVER_ED25519_PUBKEY);
            };
            let siphash = u64::from_le_bytes(buf[45..53].try_into().unwrap());
            let Ok(cipher) = Cipher::try_from(buf[54]) else {
                return Err(ERROR_INVALID_CIPHER);
            };
            return Ok(ServerHello::VersionSupported {
                salt,
                timestamp,
                cipher,
                server_ed25519_pubkey,
                siphash: Some(siphash),
            });
        }

        if buf[0] == PacketIdentifier::ServerHelloVersionNotSupported as u8 {
            if buf.len() != 17 {
                return Err(ERROR_INVALID_BUFFER_SIZE);
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

        Err(ERROR_INVALID_PACKET_IDENTIFIER)
    }
}
