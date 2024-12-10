// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use ahash::HashMap;
use hexgate::{
    common::{
        channel::{scheduler::ChannelConfiguration, Channel},
        socket::net_sym::NetworkSimulator,
    },
    server::{auth::Authenticator, Event, Server},
};
use rand::{thread_rng, Rng};

const SERVER_ADDR: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), 44444);

struct Simulator;
impl NetworkSimulator for Simulator {
    fn simulate(&mut self, _to: SocketAddr, _size: usize) -> Option<Duration> {
        if thread_rng().gen_bool(0.0) {
            return None;
        }
        Some(Duration::from_millis(thread_rng().gen_range(150..351)))
    }
}

struct MockAuthenticator;
impl Authenticator<String> for MockAuthenticator {
    /// Accept every client and return the username the client sent.
    /// Normally you would do more advanced authentication, for example: Https request to an auth server with session tokens etc.
    fn authenticate(
        &mut self,
        _: std::net::SocketAddr,
        auth_data: Vec<u8>,
    ) -> Result<String, Vec<u8>> {
        String::from_utf8(auth_data).map_err(|_| "Invalid UTF-8".as_bytes().to_owned())
    }
}

fn main() -> anyhow::Result<()> {
    let server = Server::prepare()
        .bind_addr(SERVER_ADDR)
        .info(b"Example of a chat server".to_vec())
        .allowed_client_versions(|_| Ok(()))
        .secret_key([0u8; 32])
        .auth_salt([0u8; 16])
        .authenticator(MockAuthenticator)
        .channel_config(ChannelConfiguration {
            weight_unreliable: 10,
            weights_unreliable_ordered: vec![10, 10, 10, 10, 10],
            weights_reliable: vec![10, 10, 10, 10, 10],
        })
        .run()?;
    server.set_simulator(Some(Box::new(Simulator)));

    let mut clients: HashMap<SocketAddr, String> = HashMap::default();

    loop {
        let (text, sender) = match server.next() {
            Ok(event) => match event {
                Event::Connected(addr, username) => {
                    clients.insert(addr, username.clone());
                    (format!("{} connected", username), addr)
                }
                Event::Disconnected(addr, data) => {
                    let data = String::from_utf8_lossy(&data);
                    (
                        format!("{} disconnected: {}", clients.remove(&addr).unwrap(), data),
                        addr,
                    )
                }
                Event::TimedOut(addr) => (
                    format!("{} timed out", clients.remove(&addr).unwrap()),
                    addr,
                ),
                Event::Received(addr, vec) => {
                    let data = String::from_utf8_lossy(&vec);
                    (format!("{}: {}", clients.get(&addr).unwrap(), data), addr)
                }
            },
            Err(()) => {
                break;
            }
        };
        println!("{}", text);
        for (client_addr, _) in clients.iter() {
            if *client_addr == sender {
                continue;
            }
            let _ = server.send(*client_addr, Channel::Reliable(0), text.as_bytes().to_vec());
        }
    }
    println!("Server has shutdown");
    Ok(())
}
