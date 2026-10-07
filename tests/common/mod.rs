// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![allow(dead_code)]

use std::{net::SocketAddr, ops::Range, time::Duration};

use hexgate::{
    client::Client,
    common::{
        channel::scheduler::ChannelConfiguration, socket::net_sym::NetworkSimulator, ClientVersion,
    },
    server::{auth::Authenticator, Server},
};
use rand::{Rng, SeedableRng};
use rand_xoshiro::Xoshiro256PlusPlus;

pub const TIMEOUT: Duration = Duration::from_secs(10);

pub struct AcceptAll;

impl Authenticator<()> for AcceptAll {
    fn authenticate(&mut self, _: SocketAddr, _: Vec<u8>) -> Result<(), Vec<u8>> {
        Ok(())
    }
}

pub type TestServer = Server<(), AcceptAll>;

pub fn channel_config() -> ChannelConfiguration {
    ChannelConfiguration {
        weight_unreliable: 10,
        weights_unreliable_ordered: vec![10; 5],
        weights_reliable: vec![10; 5],
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
    pub fn new(seed: u64, network: Network) -> Box<Self> {
        Box::new(Self {
            rng: Xoshiro256PlusPlus::seed_from_u64(seed),
            network,
        })
    }
}

impl NetworkSimulator for Lossy {
    fn simulate(&mut self, _: SocketAddr, _: usize) -> Option<Duration> {
        if self.rng.gen_bool(self.network.loss) {
            return None;
        }
        Some(Duration::from_millis(
            self.rng.gen_range(self.network.delay_ms.clone()),
        ))
    }
}

pub fn server(timeout_dur: Duration) -> TestServer {
    Server::prepare()
        .bind_addr("127.0.0.1:0".parse().unwrap())
        .info(b"test server".to_vec())
        .allowed_client_versions(|_| Ok(()))
        .secret_key([0u8; 32])
        .auth_salt([0u8; 16])
        .authenticator(AcceptAll)
        .channel_config(channel_config())
        .timeout_dur(timeout_dur)
        .run()
        .unwrap()
}

pub fn client(server_addr: SocketAddr, timeout_dur: Duration) -> Client {
    Client::prepare()
        .client_version(ClientVersion::ZERO)
        .server_socket_addr(server_addr)
        .auth_data(vec![])
        .hash_auth_data(false)
        .channel_config(channel_config())
        .timeout_dur(timeout_dur)
        .connect()
        .unwrap()
}

/// A connected client and server; the network is simulated once the handshake is done.
pub fn connected(network: Option<Network>, timeout_dur: Duration) -> (TestServer, Client) {
    let server = server(timeout_dur);
    let client = client(server.local_addr(), timeout_dur);
    if let Some(network) = network {
        server.set_simulator(Some(Lossy::new(1, network.clone())));
        client.set_simulator(Some(Lossy::new(2, network)));
    }
    (server, client)
}
