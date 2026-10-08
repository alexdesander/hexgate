// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![allow(dead_code)]

use std::{
    net::SocketAddr,
    ops::Range,
    time::{Duration, Instant},
};

use hexgate::{
    error::RecvError,
    server,
    sim::{Fate, NetworkSimulator},
    Authenticator, ChannelConfiguration, Client, ClientVersion, Server, ServerKey, Simulator,
};
use rand::{Rng, SeedableRng};
use rand_xoshiro::Xoshiro256PlusPlus;

pub const TIMEOUT: Duration = Duration::from_secs(10);
/// The transfer tests queue tens of thousands of messages at once and poll with sleeps: a
/// full event queue would drop unreliable ones (see `max_events`).
pub const MAX_EVENTS: usize = 1 << 20;
pub const SECRET_KEY: [u8; 32] = [7; 32];

pub struct AcceptAll;

impl Authenticator<()> for AcceptAll {
    fn authenticate(&mut self, _: SocketAddr, _: Vec<u8>) -> Result<(), Vec<u8>> {
        Ok(())
    }
}

pub type TestServer = Server<()>;

/// Unreliable messages don't expire: the tests queue thousands at once and check delivery.
pub fn channel_config() -> ChannelConfiguration {
    ChannelConfiguration {
        weight_unreliable: 10,
        weights_unreliable_ordered: vec![10; 5],
        weights_reliable: vec![10; 5],
        unreliable_max_age: Duration::from_secs(60),
    }
}

/// Loss probability and delay range of one direction.
#[derive(Clone)]
pub struct Network {
    pub loss: f64,
    pub delay_ms: Range<u64>,
}

pub const OKAY: Network = Network {
    loss: 0.01,
    delay_ms: 20..23,
};
pub const BAD: Network = Network {
    loss: 0.1,
    delay_ms: 100..140,
};
pub const TERRIBLE: Network = Network {
    loss: 0.7,
    delay_ms: 300..500,
};

/// Drops and delays packets with a seeded RNG, so every run sees the same decisions.
pub struct Lossy {
    rng: Xoshiro256PlusPlus,
    network: Network,
}

impl Lossy {
    pub fn new(seed: u64, network: Network) -> Self {
        Self {
            rng: Xoshiro256PlusPlus::seed_from_u64(seed),
            network,
        }
    }
}

impl NetworkSimulator for Lossy {
    fn simulate(&mut self, now: Instant, _: SocketAddr, _: &mut [u8]) -> Fate {
        if self.rng.gen_bool(self.network.loss) {
            return Fate::Drop;
        }
        let delay = self.rng.gen_range(self.network.delay_ms.clone());
        Fate::Deliver(now + Duration::from_millis(delay))
    }
}

/// Drops the `n`-th packet (counting from 0) and nothing else.
pub struct DropNth {
    n: usize,
    seen: usize,
}

impl DropNth {
    pub fn new(n: usize) -> Self {
        Self { n, seen: 0 }
    }
}

impl NetworkSimulator for DropNth {
    fn simulate(&mut self, now: Instant, _: SocketAddr, _: &mut [u8]) -> Fate {
        self.seen += 1;
        if self.seen - 1 == self.n {
            Fate::Drop
        } else {
            Fate::Deliver(now)
        }
    }
}

/// Drops every packet.
pub struct Blackhole;

impl NetworkSimulator for Blackhole {
    fn simulate(&mut self, _: Instant, _: SocketAddr, _: &mut [u8]) -> Fate {
        Fate::Drop
    }
}

/// The next event within `timeout`, `None` on timeout or once the network thread stopped.
pub fn next_event<E>(
    try_next: impl Fn() -> Result<Option<E>, RecvError>,
    timeout: Duration,
) -> Option<E> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match try_next() {
            Ok(Some(event)) => return Some(event),
            Ok(None) => std::thread::sleep(Duration::from_millis(1)),
            Err(_) => return None,
        }
    }
    None
}

pub fn server(timeout_dur: Duration) -> TestServer {
    Server::prepare()
        .bind_addr("127.0.0.1:0".parse().unwrap())
        .info(b"test server".to_vec())
        .allowed_client_versions(|_| Ok(()))
        .secret_key(SECRET_KEY)
        .auth_salt([0u8; 16])
        .authenticator(AcceptAll)
        .channel_config(channel_config())
        .timeout_dur(timeout_dur)
        .max_events(MAX_EVENTS)
        .run()
        .unwrap()
}

pub fn client(server_addr: SocketAddr, timeout_dur: Duration) -> Client {
    Client::prepare()
        .client_version(ClientVersion::ZERO)
        .server_socket_addr(server_addr)
        .server_key(ServerKey::Pinned(server::public_key(&SECRET_KEY)))
        .auth_data(vec![])
        .hash_auth_data(false)
        .channel_config(channel_config())
        .timeout_dur(timeout_dur)
        .max_events(MAX_EVENTS)
        .connect()
        .unwrap()
}

/// A connected client and server; the network is simulated once the handshake is done.
pub fn connected(network: Option<Network>, timeout_dur: Duration) -> (TestServer, Client) {
    let server = server(timeout_dur);
    let client = client(server.local_addr(), timeout_dur);
    if let Some(network) = network {
        server.set_simulator(Simulator::sending(Lossy::new(1, network.clone())));
        client.set_simulator(Simulator::sending(Lossy::new(2, network)));
    }
    (server, client)
}
