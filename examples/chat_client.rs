// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::net::{Ipv4Addr, SocketAddr};

use hexgate::{
    client::Event, fingerprint, keys, sim::Profile, Channel, ChannelConfiguration, Client,
    ClientVersion, ServerKey,
};
use text_io::read;

const SERVER_ADDR: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), 44444);
const USERNAME: &str = "Anon";
/// The server key trusted on the first connection.
const KNOWN_SERVER_KEY: &str = "chat_client_known_server.key";

fn main() -> anyhow::Result<()> {
    let known_server_key = keys::load(KNOWN_SERVER_KEY)?;
    let client = Client::prepare()
        .client_version(ClientVersion::ZERO)
        .server_socket_addr(SERVER_ADDR)
        .server_key(known_server_key.map_or(ServerKey::Unverified, ServerKey::Pinned))
        .auth_data(USERNAME.as_bytes().to_vec())
        .hash_auth_data(false)
        .channel_config(ChannelConfiguration {
            weight_unreliable: 10,
            weights_unreliable_ordered: vec![10, 10, 10, 10, 10],
            weights_reliable: vec![10, 10, 10, 10, 10],
            ..ChannelConfiguration::default()
        })
        .connect()?;
    if let (None, Some(server_key)) = (known_server_key, client.get_server_key()) {
        println!("Trusting server key {}", fingerprint(&server_key));
        keys::save(KNOWN_SERVER_KEY, &server_key)?;
    }
    // Both directions as on an average home connection.
    client.set_simulator(Profile::average().client(1));

    let _client = client.clone();
    let thread = std::thread::spawn(move || {
        while let Ok(event) = _client.next() {
            match event {
                Event::Disconnected(vec) => {
                    let data = String::from_utf8_lossy(&vec);
                    println!("Disconnected: {}", data);
                    break;
                }
                Event::TimedOut => {
                    println!("Timed out!");
                    break;
                }
                Event::Received(message) => {
                    let text = String::from_utf8_lossy(&message);
                    println!("{}", text);
                }
                Event::Violation(violation) => {
                    println!("Disconnected: {}", violation);
                    break;
                }
                // Only reported to clients started with `start()`.
                Event::Connected | Event::ConnectFailed(_) => {}
            }
        }
    });

    let mut channel = Channel::Reliable(0);
    loop {
        let text: String = read!("{}\n");
        let text = text.trim();
        let mut words = text.split(' ');
        match words.next() {
            Some("/quit") => {
                client.disconnect("Used /quit".as_bytes().to_vec())?;
                break;
            }
            // Switch channels using /ch [CHANNEL_NAME] [CHANNEL_NUMBER]
            Some("/ch") => {
                channel = match words.next() {
                    Some("unreliable") => Channel::Unreliable,
                    Some("unreliable_ordered") => match words.next() {
                        Some(channel) => Channel::UnreliableOrdered(channel.parse().unwrap()),
                        _ => {
                            println!("Invalid channel");
                            continue;
                        }
                    },
                    Some("reliable") => match words.next() {
                        Some(channel) => Channel::Reliable(channel.parse().unwrap()),
                        _ => {
                            println!("Invalid channel");
                            continue;
                        }
                    },
                    _ => {
                        println!("Invalid channel");
                        continue;
                    }
                };
                continue;
            }
            _ => {
                if client.send(channel, text.as_bytes().to_vec()).is_err() {
                    break;
                }
            }
        }
    }

    thread.join().unwrap();
    Ok(())
}
