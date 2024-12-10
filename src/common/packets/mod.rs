// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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

const MAGIC: &str = "HEXGATE";

const ERROR_INVALID_PROTOCOL_VERSION: &str = "Invalid protocol version";
const ERROR_INVALID_MAGIC: &str = "Invalid magic";
const ERROR_INVALID_BUFFER_SIZE: &str = "Invalid buffer size";
const ERROR_INVALID_PACKET_IDENTIFIER: &str = "Invalid packet identifier";
const ERROR_INVALID_CIPHER: &str = "Invalid cipher";
const ERROR_INVALID_SERVER_ED25519_PUBKEY: &str = "Invalid server ed25519 pubkey";
const ERROR_INVALID_SIGNATURE: &str = "Invalid signature";
const ERROR_INVALID_TAG: &str = "Invalid tag";
const ERROR_INVALID_DATA_SIZE: &str = "Invalid auth data size";
const ERROR_SIPHASH_MISMATCH: &str = "Siphash mismatch";
const ERROR_MALFORMED_PACKET: &str = "Malformed packet";

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
}

impl TryFrom<u8> for PacketIdentifier {
    type Error = &'static str;

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
            _ => Err(ERROR_INVALID_PACKET_IDENTIFIER),
        }
    }
}
