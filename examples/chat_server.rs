// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::net::{Ipv4Addr, SocketAddr};

use ahash::HashMap;
use hexgate::{
    Authenticator, Channel, ChannelConfiguration, Server, fingerprint, keys,
    server::{self, Event},
};

const SERVER_ADDR: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), 44444);

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
    // Generated on the first run. Clients pin the public key, so keep the file.
    let secret_key = keys::load_or_generate("chat_server.key")?;
    println!(
        "Server key: {}",
        fingerprint(&server::public_key(&secret_key))
    );
    let server = Server::prepare()
        .bind_addr(SERVER_ADDR)
        .info(b"Example of a chat server".to_vec())
        .allowed_client_versions(|_| Ok(()))
        .secret_key(secret_key)
        .auth_salt(keys::load_or_generate("chat_server.salt")?)
        .authenticator(MockAuthenticator)
        .channel_config(ChannelConfiguration {
            weight_unreliable: 10,
            weights_unreliable_ordered: vec![10, 10, 10, 10, 10],
            weights_reliable: vec![10, 10, 10, 10, 10],
            ..ChannelConfiguration::default()
        })
        .run()?;

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
                Event::SendResult(..) => continue,
                Event::Received(addr, _, vec) => {
                    let data = String::from_utf8_lossy(&vec);
                    (format!("{}: {}", clients.get(&addr).unwrap(), data), addr)
                }
                Event::Violation(addr, violation) => (
                    format!(
                        "{} was kicked: {}",
                        clients.remove(&addr).unwrap(),
                        violation
                    ),
                    addr,
                ),
            },
            Err(e) => {
                println!("Server has shutdown: {e}");
                break;
            }
        };
        println!("{}", text);
        for client_addr in clients.keys() {
            if *client_addr == sender {
                continue;
            }
            let _ = server.send(*client_addr, Channel::Reliable(0), text.as_bytes().to_vec());
        }
    }
    Ok(())
}
