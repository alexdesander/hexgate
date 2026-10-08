// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Entry points for the benchmarks in `benches/`, only built with the `bench` feature.

use std::{
    cmp::Reverse,
    collections::BinaryHeap,
    net::SocketAddr,
    rc::Rc,
    sync::Arc,
    time::{Duration, Instant},
};

use ed25519_dalek::{SigningKey, ed25519::signature::Signer};
use x25519_dalek::{EphemeralSecret, PublicKey, ReusableSecret};

use crate::common::{
    Cipher,
    channel::{Channel, ChannelConfiguration},
    codec::Writer,
    congestion::CongestionConfig,
    crypto::Crypto,
    events::DeliveryBudget,
    send::{Message, SendOptions, SendOutcome},
    socket::sim::{Fate, NetworkSimulator},
    stats::Stats,
    transport::{self, Connection, Output, frame, packet},
};

/// The keys of both ends of a connection.
fn crypto_pair(cipher: Cipher) -> (Crypto, Crypto) {
    let client = ReusableSecret::random_from_rng(&mut rand::rng());
    let server = ReusableSecret::random_from_rng(&mut rand::rng());
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
    let secret = EphemeralSecret::random_from_rng(&mut rand::rng());
    let crypto = Crypto::new(
        secret.diffie_hellman(client_key),
        [0; 32],
        true,
        Cipher::AES256GCM,
    );
    let tag = crypto.encrypt(&[0; 12], &[], &mut [0; 16]);
    signing_key.sign(&[tag; 4].concat()).to_bytes()
}

/// Encrypts DATA packets on one end and decrypts them on the other.
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

    /// A packet with a reliable frame of `len` bytes (at most about 1170), returns its size.
    pub fn reliable(&mut self, len: usize) -> usize {
        self.data(|w, payload| {
            frame::write_reliable_header(w, 0, 1 << 20, len);
            w.bytes(&payload[..len]);
        })
    }

    /// A packet with an unreliable frame of `len` bytes (at most about 1175), returns its size.
    pub fn unreliable(&mut self, len: usize) -> usize {
        self.data(|w, payload| frame::write_unreliable(w, None, 0, None, &payload[..len]))
    }

    /// A packet with an ACK frame of 4 ranges and 16 receive timestamps.
    pub fn acks(&mut self) -> usize {
        let ranges = [(990, 1000), (900, 980), (500, 800), (0, 400)];
        let timestamps: Vec<(u64, u64)> = (985..1001).rev().map(|pn| (pn, pn * 300)).collect();
        self.data(|w, _| {
            frame::write_ack(w, 1234, &ranges, &timestamps);
        })
    }

    fn data(&mut self, write: impl FnOnce(&mut Writer, &[u8])) -> usize {
        let pn = 100_000;
        let header = packet::write_header(&mut self.buf, pn, false);
        let mut w = Writer::new(&mut self.buf[header..header + packet::capacity(pn)]);
        write(&mut w, &self.payload);
        let end = header + w.len();
        let size = packet::seal(&self.sender, pn, &mut self.buf, header, end);
        let header = packet::parse_header(&self.buf[..size]).unwrap();
        packet::open(&self.receiver, &header, &mut self.buf[..size]).unwrap();
        size
    }
}

/// One end of a pair.
pub struct End {
    connection: Connection,
    /// Applied to the packets this end sends.
    simulator: Option<Box<dyn NetworkSimulator>>,
    timed_out: bool,
}

/// A packet on the wire: delivery time, order, receiving end, bytes.
type Wire = BinaryHeap<Reverse<(Instant, u64, usize, Vec<u8>)>>;

/// Client-server pairs of connections that exchange packets through simulators, in virtual
/// time: seconds of traffic take milliseconds. Wake-ups are rounded up to the timer
/// granularity, like the network thread's (1 ms).
pub struct Pairs {
    epoch: Instant,
    now: Instant,
    granularity: Duration,
    ends: Vec<End>,
    wire: Wire,
    sent: u64,
    buf: [u8; 1201],
    outputs: Vec<Output>,
}

/// Which end of a pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Client = 0,
    Server = 1,
}

/// Something an end received.
#[derive(Debug)]
pub enum Delivery {
    Message(Vec<u8>),
    SendResult(u64, SendOutcome),
    Closed(Vec<u8>),
    TimedOut,
}

const PEER: SocketAddr = SocketAddr::V4(std::net::SocketAddrV4::new(
    std::net::Ipv4Addr::LOCALHOST,
    1,
));

impl Pairs {
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            epoch: now,
            now,
            granularity: Duration::from_millis(1),
            ends: Vec::new(),
            wire: BinaryHeap::new(),
            sent: 0,
            buf: [0; 1201],
            outputs: Vec::new(),
        }
    }

    /// Adds a pair, returns its index. `up` and `down` simulate client to server and back.
    pub fn add(
        &mut self,
        channels: ChannelConfiguration,
        congestion: CongestionConfig,
        up: Option<Box<dyn NetworkSimulator>>,
        down: Option<Box<dyn NetworkSimulator>>,
    ) -> usize {
        let (client, server) = crypto_pair(Cipher::AES256GCM);
        let config = transport::Config {
            channels,
            congestion,
            max_recv_msg_size: 1 << 20,
            timeout: Duration::from_secs(10),
        };
        for (crypto, simulator) in [(client, up), (server, down)] {
            self.ends.push(End {
                connection: Connection::new(crypto, &config, self.now),
                simulator,
                timed_out: false,
            });
        }
        self.ends.len() / 2 - 1
    }

    pub fn now(&self) -> Instant {
        self.now
    }

    /// Time since the start.
    pub fn elapsed(&self) -> Duration {
        self.now - self.epoch
    }

    fn end(&mut self, pair: usize, side: Side) -> &mut End {
        &mut self.ends[pair * 2 + side as usize]
    }

    pub fn send(&mut self, pair: usize, from: Side, channel: Channel, message: Vec<u8>) {
        let now = self.now;
        self.end(pair, from)
            .connection
            .push(channel, Rc::new(message), now);
    }

    pub fn flush(&mut self, pair: usize, side: Side) {
        self.end(pair, side).connection.flush();
    }

    pub fn send_with(
        &mut self,
        pair: usize,
        from: Side,
        channel: Channel,
        message: Vec<u8>,
        options: SendOptions,
    ) {
        let submitted = self.now;
        self.end(pair, from).connection.push_message(
            channel,
            Message {
                data: Arc::new(message),
                submitted,
                options,
                reservation: None,
            },
        );
    }

    pub fn reset_channel(&mut self, pair: usize, side: Side, channel: u8) {
        self.end(pair, side).connection.reset_channel(channel);
    }

    pub fn set_priority(&mut self, pair: usize, side: Side, channel: Channel, priority: i8) {
        self.end(pair, side)
            .connection
            .set_priority(channel, priority);
    }

    pub fn stats(&mut self, pair: usize, side: Side) -> Stats {
        self.end(pair, side).connection.stats()
    }

    fn wake(&self, at: Instant) -> Instant {
        let since = at.saturating_duration_since(self.epoch).as_nanos();
        let granularity = self.granularity.as_nanos();
        self.epoch + Duration::from_nanos((since.div_ceil(granularity) * granularity) as u64)
    }

    /// Runs until `until`. `on_delivery(pair, receiving side, time, delivery)`.
    pub fn run(
        &mut self,
        until: Instant,
        on_delivery: &mut impl FnMut(usize, Side, Instant, Delivery),
    ) {
        let mut spins = 0;
        loop {
            let mut next = until;
            for end in &mut self.ends {
                if let Some(at) = end.connection.timeout(self.now).filter(|_| !end.timed_out) {
                    next = next.min(at);
                }
            }
            if let Some(Reverse((at, ..))) = self.wire.peek() {
                next = next.min(*at);
            }
            let next = self.wake(next).max(self.now);
            if next == self.now {
                spins += 1;
                assert!(spins < 100_000, "no progress at {:?}", self.elapsed());
            } else {
                spins = 0;
            }
            self.now = next;
            while self
                .wire
                .peek()
                .is_some_and(|Reverse((at, ..))| *at <= self.now)
            {
                let Reverse((_, _, to, mut packet)) = self.wire.pop().unwrap();
                let end = &mut self.ends[to];
                if end.timed_out
                    || end
                        .connection
                        .handle(self.now, &mut packet, true, &mut self.outputs)
                        .is_err()
                {
                    continue;
                }
                let side = if to % 2 == 0 {
                    Side::Client
                } else {
                    Side::Server
                };
                for output in self.outputs.drain(..) {
                    let delivery = match output {
                        Output::Message(_, message) => Delivery::Message(message),
                        Output::SendResult(cookie, outcome) => {
                            Delivery::SendResult(cookie, outcome)
                        }
                        Output::Closed(reason) => Delivery::Closed(reason),
                        Output::Violation(violation) => panic!("{violation}"),
                    };
                    on_delivery(to / 2, side, self.now, delivery);
                }
            }
            for index in 0..self.ends.len() {
                let end = &mut self.ends[index];
                if end.timed_out {
                    continue;
                }
                if end.connection.on_timeout(self.now) {
                    end.timed_out = true;
                    let side = if index % 2 == 0 {
                        Side::Client
                    } else {
                        Side::Server
                    };
                    on_delivery(index / 2, side, self.now, Delivery::TimedOut);
                    continue;
                }
                while let Some(size) = end.connection.poll_transmit(self.now, &mut self.buf) {
                    let mut packet = self.buf[..size].to_vec();
                    let fate = match &mut end.simulator {
                        Some(simulator) => simulator.simulate(self.now, PEER, &mut packet),
                        None => Fate::Deliver(self.now),
                    };
                    let to = index ^ 1;
                    let mut deliver = |at: Instant, packet: Vec<u8>| {
                        self.sent += 1;
                        self.wire
                            .push(Reverse((at.max(self.now), self.sent, to, packet)));
                    };
                    match fate {
                        Fate::Drop => {}
                        Fate::Deliver(at) => deliver(at, packet),
                        Fate::Duplicate(first, second) => {
                            deliver(first, packet.clone());
                            deliver(second, packet);
                        }
                    }
                }
                end.connection
                    .take_send_results(&mut DeliveryBudget::unlimited(), &mut self.outputs);
                for output in self.outputs.drain(..) {
                    let side = if index % 2 == 0 {
                        Side::Client
                    } else {
                        Side::Server
                    };
                    let delivery = match output {
                        Output::Message(_, message) => Delivery::Message(message),
                        Output::SendResult(cookie, outcome) => {
                            Delivery::SendResult(cookie, outcome)
                        }
                        Output::Closed(reason) => Delivery::Closed(reason),
                        Output::Violation(violation) => panic!("{violation}"),
                    };
                    on_delivery(index / 2, side, self.now, delivery);
                }
            }
            if self.now >= until {
                return;
            }
        }
    }
}

impl Default for Pairs {
    fn default() -> Self {
        Self::new()
    }
}

/// The channels of both ends of a connection, joined without loss or delay.
pub struct Link {
    pairs: Pairs,
}

impl Link {
    pub fn new(_cipher: Cipher) -> Self {
        let mut pairs = Pairs::new();
        let congestion = CongestionConfig {
            min_rate: u32::MAX,
            initial_rate: u32::MAX,
            max_rate: u32::MAX,
            ..CongestionConfig::default()
        };
        pairs.add(ChannelConfiguration::default(), congestion, None, None);
        Self { pairs }
    }

    /// Sends `count` messages of `size` bytes on `channel` and returns the delivered bytes.
    pub fn transfer(&mut self, channel: Channel, size: usize, count: usize) -> usize {
        for _ in 0..count {
            self.pairs.send(0, Side::Client, channel, vec![7u8; size]);
        }
        let mut delivered = 0;
        while delivered < size * count {
            let until = self.pairs.now() + Duration::from_millis(1);
            self.pairs.run(until, &mut |_, _, _, delivery| {
                if let Delivery::Message(message) = delivery {
                    delivered += message.len();
                }
            });
            if !matches!(channel, Channel::Reliable(_)) && self.pairs.wire.is_empty() {
                break;
            }
        }
        delivered
    }
}
