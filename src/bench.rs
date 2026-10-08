// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Entry points for the criterion benchmarks in `benches/`, only built with the `bench` feature.

use std::rc::Rc;

use ed25519_dalek::{ed25519::signature::Signer, SigningKey};
use rand::thread_rng;
use x25519_dalek::{EphemeralSecret, PublicKey, ReusableSecret};

use crate::common::{
    channel::{Channel, ChannelConfiguration, Channels, Pop},
    congestion::{CongestionConfiguration, CongestionController},
    crypto::Crypto,
    packets::{
        acks::Acks, reliable_payload::ReliablePayload, unreliable_payload::UnreliablePayload,
        PacketIdentifier,
    },
    Cipher,
};

/// The keys of both ends of a connection.
fn crypto_pair(cipher: Cipher) -> (Crypto, Crypto) {
    let client = ReusableSecret::random_from_rng(thread_rng());
    let server = ReusableSecret::random_from_rng(thread_rng());
    let salt = rand::random();
    (
        Crypto::new(
            client.diffie_hellman(&PublicKey::from(&server)),
            salt,
            false,
            cipher,
        ),
        Crypto::new(
            server.diffie_hellman(&PublicKey::from(&client)),
            salt,
            true,
            cipher,
        ),
    )
}

/// The server's work for a new ConnectionRequest: an x25519 key exchange, key derivation and
/// an ed25519 signature.
pub fn key_exchange(signing_key: &SigningKey, client_key: &PublicKey) -> [u8; 64] {
    let secret = EphemeralSecret::random_from_rng(thread_rng());
    let crypto = Crypto::new(
        secret.diffie_hellman(client_key),
        [0; 32],
        true,
        Cipher::AES256GCM,
    );
    let tag = crypto.encrypt(&[0; 12], &[], &mut [0; 16]);
    signing_key.sign(&[tag; 4].concat()).to_bytes()
}

/// Encrypts packets on one end and decrypts them on the other.
pub struct Packets {
    sender: Crypto,
    receiver: Crypto,
    payload: Vec<u8>,
    buf: [u8; 1201],
}

impl Packets {
    pub fn new(cipher: Cipher) -> Self {
        let (sender, receiver) = crypto_pair(cipher);
        Self {
            sender,
            receiver,
            payload: vec![7; 1200],
            buf: [0; 1201],
        }
    }

    /// A reliable packet with `len` payload bytes (at most 1172), returns the packet size.
    pub fn reliable(&mut self, len: usize) -> usize {
        let packet = ReliablePayload::NoAcks {
            channel_id: 0,
            packet_id: 1000,
            payload: &self.payload[..len],
        };
        let size = packet.serialize(&self.sender, &mut self.buf);
        ReliablePayload::deserialize(&self.receiver, &mut self.buf[..size]).unwrap();
        size
    }

    /// An unreliable standalone packet with `len` payload bytes (at most 1178), returns the
    /// packet size.
    pub fn unreliable(&mut self, len: usize) -> usize {
        let packet = UnreliablePayload::Standalone {
            message_id: 1000,
            payload: &self.payload[..len],
        };
        let size = packet.serialize(&self.sender, &mut self.buf);
        UnreliablePayload::deserialize(&self.receiver, &mut self.buf[..size]).unwrap();
        size
    }

    /// An ack packet (SipHash only).
    pub fn acks(&mut self) -> usize {
        let acks = Acks {
            channel_id: 0,
            packet_id: 1000,
            lowest_unreceived: 1000,
            ack_bitfield: [0x55; 16],
        };
        let size = acks.serialize(&self.sender, &mut self.buf);
        Acks::deserialize(&self.receiver, &self.buf[..size]).unwrap();
        size
    }
}

/// The channels of both ends of a connection, joined without loss or delay.
pub struct Link {
    sender: Channels,
    receiver: Channels,
    congestion: CongestionController,
    keys: (Crypto, Crypto),
    buf: [u8; 1201],
}

impl Link {
    pub fn new(cipher: Cipher) -> Self {
        let config = ChannelConfiguration::default();
        Self {
            sender: Channels::new(&config, usize::MAX),
            receiver: Channels::new(&config, usize::MAX),
            congestion: CongestionController::new(CongestionConfiguration::default()),
            keys: crypto_pair(cipher),
            buf: [0; 1201],
        }
    }

    /// Sends `count` messages of `size` bytes on `channel` (pacing aside), with acks for
    /// reliable ones. Returns the delivered bytes.
    pub fn transfer(&mut self, channel: Channel, size: usize, count: usize) -> usize {
        let message = Rc::new(vec![7u8; size]);
        for _ in 0..count {
            self.sender.push(channel, message.clone());
        }
        let mut delivered = 0;
        loop {
            while let Pop::Packet(len) =
                self.sender
                    .pop(&mut self.congestion, &self.keys.0, &mut self.buf)
            {
                delivered += self.receive(len);
            }
            if delivered >= size * count || !matches!(channel, Channel::Reliable(_)) {
                return delivered;
            }
            let acks = self.receiver.acks(channel);
            let len = acks.serialize(&self.keys.1, &mut self.buf);
            let acks = Acks::deserialize(&self.keys.0, &self.buf[..len]).unwrap();
            self.sender.handle_acks(acks, &mut self.congestion);
        }
    }

    fn receive(&mut self, len: usize) -> usize {
        let packet = &mut self.buf[..len];
        if packet[0] == PacketIdentifier::ReliablePayloadNoAcks as u8 {
            let packet = ReliablePayload::deserialize(&self.keys.1, packet).unwrap();
            let messages = self.receiver.handle_reliable(packet).unwrap();
            messages.iter().map(Vec::len).sum()
        } else {
            let packet = UnreliablePayload::deserialize(&self.keys.1, packet).unwrap();
            let message = self.receiver.handle_unreliable(packet).unwrap();
            message.map_or(0, |message| message.len())
        }
    }
}
