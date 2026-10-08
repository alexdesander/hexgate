// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Entry points for the cargo-fuzz targets in `fuzz/`. Only built with `--cfg fuzzing`, which
//! also turns off AEAD and SipHash verification (authenticated hashes must be zero), so inputs
//! reach the parsing a malicious peer with valid keys controls.

use std::{rc::Rc, sync::OnceLock};

use rand::{rngs::StdRng, SeedableRng};
use x25519_dalek::{PublicKey, ReusableSecret};

use crate::common::{
    channel::{scheduler::ChannelConfiguration, Channel, Channels, Pop},
    congestion::{CongestionConfiguration, CongestionController},
    crypto::Crypto,
    packets::{
        acks::Acks, client_hello::ClientHello, connection_request::ConnectionRequest,
        connection_response::ConnectionResponse, disconnect::Disconnect, info_request::InfoRequest,
        info_response::InfoResponse, latency_discovery::LatencyDiscovery,
        latency_discovery_response::LatencyDiscoveryResponse,
        latency_discovery_response_2::LatencyDiscoveryResponse2, login_request::LoginRequest,
        login_response::LoginResponse, reliable_payload::ReliablePayload,
        server_hello::ServerHello, unreliable_payload::UnreliablePayload, PacketIdentifier,
    },
    Cipher,
};

const MAX_MESSAGE_SIZE: usize = 1 << 16;

fn secret() -> &'static ReusableSecret {
    static SECRET: OnceLock<ReusableSecret> = OnceLock::new();
    SECRET.get_or_init(|| ReusableSecret::random_from_rng(StdRng::seed_from_u64(0)))
}

fn crypto() -> &'static Crypto {
    static CRYPTO: OnceLock<Crypto> = OnceLock::new();
    CRYPTO.get_or_init(|| {
        let shared_secret = secret().diffie_hellman(&PublicKey::from(secret()));
        Crypto::new(shared_secret, [0; 32], true, Cipher::ChaCha20Poly1305)
    })
}

/// Every deserializer on the same bytes.
pub fn packets(data: &[u8]) {
    let crypto = crypto();
    let mut buf = data.to_vec();
    let _ = InfoRequest::deserialize(&buf);
    let _ = InfoResponse::deserialize(&buf);
    let _ = ClientHello::deserialize(&buf);
    let _ = ServerHello::deserialize(&buf);
    let _ = ConnectionRequest::deserialize(&buf);
    let _ = LoginRequest::deserialize_salt(&buf);
    let _ = LatencyDiscovery::deserialize(crypto, &buf);
    let _ = LatencyDiscoveryResponse::deserialize(crypto, &buf);
    let _ = LatencyDiscoveryResponse2::deserialize(crypto, &buf);
    let _ = Acks::deserialize(crypto, &buf);
    if let Ok(server_hello) = ServerHello::deserialize(&buf) {
        if let ServerHello::VersionSupported {
            server_ed25519_pubkey,
            cipher,
            ..
        } = server_hello
        {
            let _ = ConnectionResponse::deserialize(
                &buf,
                server_ed25519_pubkey,
                secret(),
                [0; 32],
                cipher,
            );
        }
    }
    let _ = LoginRequest::deserialize(crypto, &mut buf);
    let _ = LoginResponse::deserialize(crypto, &mut buf);
    let _ = Disconnect::deserialize(crypto, &mut buf);
    let _ = UnreliablePayload::deserialize(crypto, &mut buf);
    let _ = ReliablePayload::deserialize(crypto, &mut buf);
}

/// Feeds packets from a peer to one connection's channels. Inputs that aren't payloads or acks
/// queue a message and send, so acks find packets in flight.
pub fn channels(packets: &[Vec<u8>]) {
    let config = ChannelConfiguration {
        weight_unreliable: 1,
        weights_unreliable_ordered: vec![1, 2],
        weights_reliable: vec![1, 2],
    };
    let mut channels = Channels::new(&config, MAX_MESSAGE_SIZE);
    let mut congestion = CongestionController::new(CongestionConfiguration::default());
    let crypto = crypto();
    let mut buf = [0u8; 1201];
    for packet in packets {
        let mut packet = packet.clone();
        let Some(&identifier) = packet.first() else {
            continue;
        };
        let messages = match PacketIdentifier::try_from(identifier) {
            Ok(PacketIdentifier::Acks) => {
                if let Ok(acks) = Acks::deserialize(crypto, &packet) {
                    channels.handle_acks(acks, &mut congestion);
                }
                continue;
            }
            Ok(PacketIdentifier::ReliablePayloadNoAcks) => {
                match ReliablePayload::deserialize(crypto, &mut packet) {
                    Ok(payload) => channels.handle_reliable(payload),
                    Err(_) => continue,
                }
            }
            Ok(_) => match UnreliablePayload::deserialize(crypto, &mut packet) {
                Ok(payload) => channels
                    .handle_unreliable(payload)
                    .map(|message| message.into_iter().collect()),
                Err(_) => continue,
            },
            Err(_) => {
                let channel = match packet.get(1).map_or(0, |byte| byte % 5) {
                    0 => Channel::Unreliable,
                    id @ (1 | 2) => Channel::UnreliableOrdered(id - 1),
                    id => Channel::Reliable(id - 3),
                };
                let message = packet.get(2..).unwrap_or_default().to_vec();
                channels.push(channel, Rc::new(message));
                for _ in 0..64 {
                    if !matches!(
                        channels.pop(&mut congestion, crypto, &mut buf),
                        Pop::Packet(_)
                    ) {
                        break;
                    }
                }
                continue;
            }
        };
        match messages {
            Ok(messages) => assert!(messages.iter().all(|m| m.len() <= MAX_MESSAGE_SIZE)),
            // The peer broke the protocol, the connection would be closed.
            Err(_) => return,
        }
    }
}
