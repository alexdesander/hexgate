// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! AEAD nonces: payload packets begin theirs with the packet identifier (never 0xff), the
//! handshake packets and Disconnect use fixed nonces beginning with 0xff. A fixed nonce is only
//! safe while each key encrypts a single plaintext under it, so such a packet is serialized once
//! per key and only ever resent as the same bytes.

pub mod acks;
pub mod client_hello;
pub mod connection_request;
pub mod connection_response;
pub mod disconnect;
pub mod info_request;
pub mod info_response;
pub mod latency_discovery;
pub mod latency_discovery_response;
pub mod latency_discovery_response_2;
pub mod login_request;
pub mod login_response;
pub mod reliable_payload;
pub mod server_hello;
pub mod unreliable_payload;

use std::fmt::Display;

use integer_encoding::VarInt;

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
    #[error("siphash mismatch")]
    SipHash,
    #[error("malformed packet")]
    Malformed,
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
    LatencyDiscovery = 10,
    LatencyDiscoveryResponse = 11,
    LatencyDiscoveryResponse2 = 12,
    Disconnect = 13,
    UnreliableStandalonePayload = 14,
    UnreliableFragmentedPayload = 15,
    UnreliableFragmentedPayloadLast = 16,
    UnreliableOrderedStandalonePayload = 17,
    UnreliableOrderedFragmentedPayload = 18,
    UnreliableOrderedFragmentedPayloadLast = 19,
    Acks = 20,
    ReliablePayloadNoAcks = 21,
    ServerHelloServerFull = 22,
    ServerHelloProtocolMismatch = 23,
}

/// Decodes a `u32` varint, rejecting values above `u32::MAX` and encodings longer than 5 bytes.
fn decode_var_u32(buf: &[u8]) -> Option<(u32, usize)> {
    let (value, size) = u64::decode_var(buf)?;
    (size <= 5).then_some((u32::try_from(value).ok()?, size))
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
            10 => Ok(PacketIdentifier::LatencyDiscovery),
            11 => Ok(PacketIdentifier::LatencyDiscoveryResponse),
            12 => Ok(PacketIdentifier::LatencyDiscoveryResponse2),
            13 => Ok(PacketIdentifier::Disconnect),
            14 => Ok(PacketIdentifier::UnreliableStandalonePayload),
            15 => Ok(PacketIdentifier::UnreliableFragmentedPayload),
            16 => Ok(PacketIdentifier::UnreliableFragmentedPayloadLast),
            17 => Ok(PacketIdentifier::UnreliableOrderedStandalonePayload),
            18 => Ok(PacketIdentifier::UnreliableOrderedFragmentedPayload),
            19 => Ok(PacketIdentifier::UnreliableOrderedFragmentedPayloadLast),
            20 => Ok(PacketIdentifier::Acks),
            21 => Ok(PacketIdentifier::ReliablePayloadNoAcks),
            22 => Ok(PacketIdentifier::ServerHelloServerFull),
            23 => Ok(PacketIdentifier::ServerHelloProtocolMismatch),
            _ => Err(PacketError::Identifier),
        }
    }
}
