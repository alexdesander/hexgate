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

use rand::{SeedableRng, rngs::StdRng};
use x25519_dalek::{PublicKey, ReusableSecret};

use crate::common::{
    Cipher,
    channel::{Channel, ChannelConfiguration},
    codec::Reader,
    congestion::CongestionConfig,
    crypto::Crypto,
    events::DeliveryBudget,
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
    transport::{self, Connection, Output, frame, packet},
};

const MAX_MESSAGE_SIZE: usize = 1 << 20;

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
    for input in inputs.iter().take(512) {
        let mut input = input.clone();
        now += Duration::from_millis(1);
        let mut budget = DeliveryBudget {
            messages: input
                .first()
                .map_or(256, |byte| usize::from(byte % 3) * 128),
            bytes: MAX_MESSAGE_SIZE,
            work: 64 << 10,
        };
        if packet::parse_header(&input).is_ok() {
            let _ = connection.handle_with_budget(now, &mut input, &mut budget, &mut outputs);
            for output in outputs.drain(..) {
                match output {
                    Output::Message(_, message) => assert!(message.len() <= MAX_MESSAGE_SIZE),
                    Output::SendResult(..) => {}
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
            let message = if input.get(1) == Some(&255) {
                let boundaries = [0, 1, 127, 128, 1180, 65_536, 80_000, MAX_MESSAGE_SIZE];
                vec![
                    input.first().copied().unwrap_or_default();
                    boundaries
                        [input.get(2).copied().unwrap_or_default() as usize % boundaries.len()]
                ]
            } else {
                input
                    .get(1..)
                    .unwrap_or_default()
                    .iter()
                    .take(MAX_MESSAGE_SIZE)
                    .copied()
                    .collect()
            };
            if connection.stats().queued_bytes > 4 * MAX_MESSAGE_SIZE {
                continue;
            }
            if input.get(3) == Some(&254) {
                connection.reset_channel(0);
            }
            if input.get(3) == Some(&253) {
                connection.flush();
            }
            connection.push(channel, Rc::new(message), now);
            connection.on_timeout(now);
        }
        for _ in 0..64 {
            if connection.poll_transmit(now, &mut buf).is_none() {
                break;
            }
        }
    }
}

/// Reliable delivery must resume after finite loss, duplication, reset, and stalled polling
pub fn progress(input: &[u8]) {
    use crate::common::{
        channel::{Channels, StreamFrames},
        codec::{Writer, varint_len},
    };
    use std::collections::VecDeque;
    let config = ChannelConfiguration {
        weights_reliable: vec![1, 2],
        ..ChannelConfiguration::default()
    };
    let mut sender = Channels::new(&config, MAX_MESSAGE_SIZE);
    let mut receiver = Channels::new(&config, MAX_MESSAGE_SIZE);
    type Expected = [VecDeque<(u64, Vec<u8>)>; 2];
    let mut expected: Expected = Default::default();
    let mut end = [0; 2];
    let mut now = Instant::now();
    let sizes = [0, 1, 127, 128, 1180, 65_536, 80_000, MAX_MESSAGE_SIZE];
    for (id, &byte) in input.iter().take(4).enumerate() {
        let channel = id % 2;
        let message = vec![byte; sizes[byte as usize % sizes.len()]];
        end[channel] += (varint_len(message.len() as u64) + message.len()) as u64;
        expected[channel].push_back((end[channel], message.clone()));
        sender.push_message(
            Channel::Reliable(channel as u8),
            crate::common::send::Message::untracked(Rc::new(message), now),
        );
    }
    let mut held: Option<(Vec<u8>, StreamFrames)> = None;
    let mut received = 0;
    for round in 0..20_000 {
        now += Duration::from_millis(1);
        if round == 16 && input.first().is_some_and(|byte| byte & 128 != 0) {
            sender.reset_channel(0);
        }
        if round == 32 {
            let sentinel = b"resumed".to_vec();
            sender.push_message(
                Channel::Reliable(0),
                crate::common::send::Message::untracked(Rc::new(sentinel.clone()), now),
            );
            end[0] += (varint_len(sentinel.len() as u64) + sentinel.len()) as u64;
            expected[0].push_back((end[0], sentinel));
        }
        let mut buf = [0; 1180];
        let mut writer = Writer::new(&mut buf);
        let mut frames = StreamFrames::default();
        if sender.write(now, &mut writer, 1180, &mut frames) {
            let size = writer.len();
            let action = input
                .get(round % input.len().max(1))
                .copied()
                .unwrap_or_default();
            if round < 32 && action & 3 == 0 {
                sender.on_lost(&frames);
            } else if round < 32 && action & 3 == 1 && held.is_none() {
                held = Some((buf[..size].to_vec(), frames));
            } else {
                receive_frames(&mut receiver, &buf[..size], Some(&mut expected));
                if action & 8 != 0 {
                    receive_frames(&mut receiver, &buf[..size], Some(&mut expected));
                }
                sender.on_acked(&frames);
            }
        }
        if round % 4 == 3 {
            if let Some((packet, frames)) = held.take() {
                receive_frames(&mut receiver, &packet, Some(&mut expected));
                sender.on_acked(&frames);
            }
        }
        if round >= 32 || round % 8 == 0 {
            let mut budget = DeliveryBudget {
                messages: 2,
                bytes: MAX_MESSAGE_SIZE,
                work: 64 << 10,
            };
            receiver
                .drain_received(&mut budget, &mut |channel, message| {
                    let Channel::Reliable(channel) = channel else {
                        unreachable!()
                    };
                    assert_eq!(
                        expected[channel as usize]
                            .pop_front()
                            .map(|(_, message)| message),
                        Some(message)
                    );
                    received += 1;
                })
                .unwrap();
        }
        let mut writer = Writer::new(&mut buf);
        let mut frames = StreamFrames::default();
        if receiver.write(now, &mut writer, 1180, &mut frames) {
            let size = writer.len();
            receive_frames(&mut sender, &buf[..size], None);
            receiver.on_acked(&frames);
        }
        if round > 32 && expected.iter().all(VecDeque::is_empty) && sender.queued_bytes() == 0 {
            assert!(received > 0);
            return;
        }
    }
    panic!("reliable delivery failed to resume");

    fn receive_frames(channels: &mut Channels, packet: &[u8], mut expected: Option<&mut Expected>) {
        let mut reader = Reader::new(packet);
        while let Some(frame) = frame::parse(&mut reader).unwrap() {
            match frame {
                frame::Frame::Reliable {
                    channel,
                    offset,
                    data,
                } => channels.on_reliable(channel, offset, data).unwrap(),
                frame::Frame::Credit { channel, limit } => {
                    channels.on_credit(channel, limit).unwrap()
                }
                frame::Frame::Reset { channel, offset } => {
                    channels.on_reset(channel, offset).unwrap();
                    if let Some(expected) = &mut expected {
                        expected[channel as usize].retain(|&(end, _)| end > offset);
                    }
                }
                _ => unreachable!(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_allows_delivery_until_the_reset_reaches_the_receiver() {
        let mut input = [0; 33];
        input[..4].fill(128);
        input[9] = 1;
        progress(&input);
    }

    #[test]
    fn progress_covers_message_boundaries_and_post_reset_sentinels() {
        for byte in [0, 1, 2, 3, 4, 5, 6, 7, 135, 255] {
            progress(&[byte; 4]);
        }
    }
}
