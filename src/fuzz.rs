// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Entry points for the cargo-fuzz targets in `fuzz/`. Only built with `--cfg fuzzing`, which
//! also turns off AEAD verification (DATA packets are not decrypted), so inputs reach the
//! parsing a malicious peer with valid keys controls.

use std::{
    rc::Rc,
    sync::OnceLock,
    time::{Duration, Instant},
};

use rand::{rngs::StdRng, SeedableRng};
use x25519_dalek::{PublicKey, ReusableSecret};

use crate::common::{
    channel::{Channel, ChannelConfiguration},
    codec::Reader,
    congestion::CongestionConfig,
    crypto::Crypto,
    packets::{
        client_hello::ClientHello,
        connection_request::ConnectionRequest,
        connection_response::{ConnectionResponse, Transcript},
        info_request::InfoRequest,
        info_response::InfoResponse,
        login_request::LoginRequest,
        login_response::LoginResponse,
        server_hello::ServerHello,
    },
    transport::{self, frame, packet, Connection, Output},
    Cipher,
};

const MAX_MESSAGE_SIZE: usize = 1 << 16;

fn secret() -> &'static ReusableSecret {
    static SECRET: OnceLock<ReusableSecret> = OnceLock::new();
    SECRET.get_or_init(|| ReusableSecret::random_from_rng(StdRng::seed_from_u64(0)))
}

fn crypto() -> Crypto {
    let shared_secret = secret().diffie_hellman(&PublicKey::from(secret()));
    Crypto::new(shared_secret, [0; 32], true, Cipher::ChaCha20Poly1305)
}

/// Every deserializer on the same bytes.
pub fn packets(data: &[u8]) {
    let crypto = crypto();
    let mut buf = data.to_vec();
    let _ = InfoRequest::deserialize(&buf);
    let _ = InfoResponse::deserialize(&buf);
    let _ = ClientHello::deserialize(&buf);
    let _ = ClientHello::other_protocol_salt(&buf);
    let _ = ServerHello::deserialize(&buf);
    let _ = ConnectionRequest::deserialize(&buf);
    let _ = LoginRequest::deserialize_salt(&buf);
    if let Ok(ServerHello::VersionSupported {
        server_ed25519_pubkey,
        cipher,
        channel_counts,
        ..
    }) = ServerHello::deserialize(&buf)
    {
        let transcript = Transcript {
            request: &[0; 116],
            cipher,
            channel_counts,
        };
        let _ = ConnectionResponse::deserialize(
            &buf,
            server_ed25519_pubkey,
            secret(),
            [0; 32],
            &transcript,
        );
    }
    let _ = LoginRequest::deserialize(&crypto, &mut buf);
    let _ = LoginResponse::deserialize(&crypto, &mut buf);
    if let Ok(header) = packet::parse_header(&buf) {
        if let Ok(payload) = packet::open(&crypto, &header, &mut buf) {
            let mut r = Reader::new(payload);
            while let Ok(Some(frame)) = frame::parse(&mut r) {
                if let frame::Frame::Ack(ack) = frame {
                    ack.ranges().for_each(drop);
                    ack.timestamps().for_each(drop);
                }
            }
        }
    }
}

/// A connection fed with a peer's packets (the input's DATA headers and frames as they are).
/// Inputs that aren't DATA packets queue a message and let time pass, so acknowledgements
/// find packets in flight.
pub fn channels(inputs: &[Vec<u8>]) {
    let config = transport::Config {
        channels: ChannelConfiguration {
            weight_unreliable: 1,
            weights_unreliable_ordered: vec![1, 2],
            weights_reliable: vec![1, 2],
            ..ChannelConfiguration::default()
        },
        congestion: CongestionConfig::default(),
        max_recv_msg_size: MAX_MESSAGE_SIZE,
        timeout: Duration::from_secs(10),
    };
    let mut now = Instant::now();
    let mut connection = Connection::new(crypto(), &config, now);
    let mut outputs = Vec::new();
    let mut buf = [0u8; 1201];
    for input in inputs {
        let mut input = input.clone();
        now += Duration::from_millis(1);
        if packet::parse_header(&input).is_ok() {
            let _ = connection.handle(now, &mut input, true, &mut outputs);
            for output in outputs.drain(..) {
                match output {
                    Output::Message(message) => assert!(message.len() <= MAX_MESSAGE_SIZE),
                    // The connection would be closed.
                    Output::Closed(_) | Output::Violation(_) => return,
                }
            }
        } else {
            let channel = match input.first().map_or(0, |byte| byte % 5) {
                0 => Channel::Unreliable,
                id @ (1 | 2) => Channel::UnreliableOrdered(id - 1),
                id => Channel::Reliable(id - 3),
            };
            let message = input.get(1..).unwrap_or_default().to_vec();
            connection.push(channel, Rc::new(message), now);
            connection.on_timeout(now);
        }
        while connection.poll_transmit(now, &mut buf).is_some() {}
    }
}
