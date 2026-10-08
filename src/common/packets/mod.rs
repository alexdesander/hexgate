// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Handshake packets. After the handshake, everything is a DATA packet (`transport::packet`).
//!
//! AEAD nonces: DATA packets use their packet number (the first byte is 0), the handshake
//! packets use fixed nonces beginning with 0xff. A fixed nonce is only safe while each key
//! encrypts a single plaintext under it, so such a packet is serialized once per key and only
//! ever resent as the same bytes.

pub mod client_hello;
pub mod connection_request;
pub mod connection_response;
pub mod info_request;
pub mod info_response;
pub mod login_request;
pub mod login_response;
pub mod server_hello;

use std::fmt::Display;

const MAGIC: &str = "HEXGATE";

/// Logs a datagram that was dropped because it isn't a valid `packet`.
#[cfg_attr(not(feature = "tracing"), allow(unused_variables))]
pub(crate) fn rejected(packet: &str, from: impl Display, error: PacketError) {
    log!(trace, %from, %error, "dropped {packet}");
}

/// Why a datagram was not accepted as a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PacketError {
    #[error("invalid protocol version")]
    ProtocolVersion,
    #[error("invalid magic")]
    Magic,
    #[error("invalid packet size")]
    Size,
    #[error("invalid packet identifier")]
    Identifier,
    #[error("invalid cipher")]
    Cipher,
    #[error("invalid server ed25519 key")]
    ServerKey,
    #[error("invalid signature")]
    Signature,
    #[error("invalid authentication tag")]
    Tag,
    #[error("invalid data size")]
    DataSize,
    #[error("malformed packet")]
    Malformed,
    #[error("duplicate or too old packet number")]
    Replay,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PacketIdentifier {
    InfoRequest = 0,
    InfoResponse = 1,
    ClientHello = 2,
    ServerHelloVersionNotSupported = 3,
    ServerHelloVersionSupported = 4,
    ConnectionRequest = 5,
    ConnectionResponse = 6,
    LoginRequest = 7,
    LoginSuccess = 8,
    LoginFailure = 9,
    Data = 10,
    /// A DATA packet that asks for an immediate acknowledgement.
    DataAckNow = 11,
    ServerHelloServerFull = 22,
    /// Stays the same in every protocol version, like the ClientHello prefix.
    ServerHelloProtocolMismatch = 23,
}

impl TryFrom<u8> for PacketIdentifier {
    type Error = PacketError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(PacketIdentifier::InfoRequest),
            1 => Ok(PacketIdentifier::InfoResponse),
            2 => Ok(PacketIdentifier::ClientHello),
            3 => Ok(PacketIdentifier::ServerHelloVersionNotSupported),
            4 => Ok(PacketIdentifier::ServerHelloVersionSupported),
            5 => Ok(PacketIdentifier::ConnectionRequest),
            6 => Ok(PacketIdentifier::ConnectionResponse),
            7 => Ok(PacketIdentifier::LoginRequest),
            8 => Ok(PacketIdentifier::LoginSuccess),
            9 => Ok(PacketIdentifier::LoginFailure),
            10 => Ok(PacketIdentifier::Data),
            11 => Ok(PacketIdentifier::DataAckNow),
            22 => Ok(PacketIdentifier::ServerHelloServerFull),
            23 => Ok(PacketIdentifier::ServerHelloProtocolMismatch),
            _ => Err(PacketError::Identifier),
        }
    }
}
