// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

pub mod client;
pub mod common;
pub mod server;

#[cfg(test)]
mod tests {
    #![allow(unused)]

    use std::{
        net::SocketAddr,
        time::{Duration, Instant},
    };

    use rand::{thread_rng, Rng};

    use crate::{
        client::Client,
        common::{
            channel::{scheduler::ChannelConfiguration, Channel},
            socket::net_sym::NetworkSimulator,
            ClientVersion,
        },
        server::{self, auth::Authenticator, Server},
    };

    struct MockAuthenticator;
    impl Authenticator<()> for MockAuthenticator {
        fn authenticate(
            &mut self,
            _: std::net::SocketAddr,
            auth_data: Vec<u8>,
        ) -> Result<(), Vec<u8>> {
            Ok(())
        }
    }

    #[test]
    fn test_reliable_no_simulator() {
        let server_addr: SocketAddr = "127.0.0.1:30000".parse().unwrap();
        let server = Server::prepare()
            .bind_addr(server_addr)
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
            .run()
            .unwrap();

        let client = Client::prepare()
            .client_version(ClientVersion::ZERO)
            .server_socket_addr(server_addr)
            .auth_data(vec![])
            .hash_auth_data(false)
            .channel_config(ChannelConfiguration {
                weight_unreliable: 10,
                weights_unreliable_ordered: vec![10, 10, 10, 10, 10],
                weights_reliable: vec![10, 10, 10, 10, 10],
            })
            .connect()
            .unwrap();

        let amount_messages = 50000;
        for i in 0..amount_messages {
            client
                .send(Channel::Reliable(0), format!("{}", i).as_bytes().to_vec())
                .unwrap();
        }
        let mut i = 0;
        while let Ok(event) = server.next() {
            match event {
                server::Event::Connected(_, _) => {}
                server::Event::Received(_, message) => {
                    assert_eq!(message, format!("{}", i).as_bytes());
                    if i == amount_messages - 1 {
                        break;
                    }
                    i += 1;
                }
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn test_reliable_okay_network() {
        struct Simulator;
        impl NetworkSimulator for Simulator {
            fn simulate(&mut self, to: SocketAddr, size: usize) -> Option<std::time::Duration> {
                if thread_rng().gen_bool(0.01) {
                    return None;
                }
                Some(Duration::from_millis(thread_rng().gen_range(20..23)))
            }
        }
        let server_addr: SocketAddr = "127.0.0.1:30001".parse().unwrap();
        let server = Server::prepare()
            .bind_addr(server_addr)
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
            .run()
            .unwrap();

        let client = Client::prepare()
            .client_version(ClientVersion::ZERO)
            .server_socket_addr(server_addr)
            .auth_data(vec![])
            .hash_auth_data(false)
            .channel_config(ChannelConfiguration {
                weight_unreliable: 10,
                weights_unreliable_ordered: vec![10, 10, 10, 10, 10],
                weights_reliable: vec![10, 10, 10, 10, 10],
            })
            .connect()
            .unwrap();

        server.set_simulator(Some(Box::new(Simulator)));
        client.set_simulator(Some(Box::new(Simulator)));

        let amount_messages = 50000;
        for i in 0..amount_messages {
            client
                .send(Channel::Reliable(0), format!("{}", i).as_bytes().to_vec())
                .unwrap();
        }
        let mut i = 0;
        while let Ok(event) = server.next() {
            match event {
                server::Event::Connected(_, _) => {}
                server::Event::Received(_, message) => {
                    assert_eq!(message, format!("{}", i).as_bytes());
                    if i == amount_messages - 1 {
                        break;
                    }
                    i += 1;
                }
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn test_reliable_bad_network() {
        struct Simulator;
        impl NetworkSimulator for Simulator {
            fn simulate(&mut self, to: SocketAddr, size: usize) -> Option<std::time::Duration> {
                if thread_rng().gen_bool(0.1) {
                    return None;
                }
                Some(Duration::from_millis(thread_rng().gen_range(100..140)))
            }
        }
        let server_addr: SocketAddr = "127.0.0.1:30002".parse().unwrap();
        let server = Server::prepare()
            .bind_addr(server_addr)
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
            .run()
            .unwrap();

        let client = Client::prepare()
            .client_version(ClientVersion::ZERO)
            .server_socket_addr(server_addr)
            .auth_data(vec![])
            .hash_auth_data(false)
            .channel_config(ChannelConfiguration {
                weight_unreliable: 10,
                weights_unreliable_ordered: vec![10, 10, 10, 10, 10],
                weights_reliable: vec![10, 10, 10, 10, 10],
            })
            .connect()
            .unwrap();

        server.set_simulator(Some(Box::new(Simulator)));
        client.set_simulator(Some(Box::new(Simulator)));

        let amount_messages = 25000;
        for i in 0..amount_messages {
            client
                .send(Channel::Reliable(0), format!("{}", i).as_bytes().to_vec())
                .unwrap();
        }
        let mut i = 0;
        while let Ok(event) = server.next() {
            match event {
                server::Event::Connected(_, _) => {}
                server::Event::Received(_, message) => {
                    assert_eq!(message, format!("{}", i).as_bytes());
                    if i == amount_messages - 1 {
                        break;
                    }
                    i += 1;
                }
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn test_reliable_terrible_network() {
        struct Simulator;
        impl NetworkSimulator for Simulator {
            fn simulate(&mut self, to: SocketAddr, size: usize) -> Option<std::time::Duration> {
                if thread_rng().gen_bool(0.7) {
                    return None;
                }
                Some(Duration::from_millis(thread_rng().gen_range(300..500)))
            }
        }
        let server_addr: SocketAddr = "127.0.0.1:30003".parse().unwrap();
        let server = Server::prepare()
            .bind_addr(server_addr)
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
            .run()
            .unwrap();

        let client = Client::prepare()
            .client_version(ClientVersion::ZERO)
            .server_socket_addr(server_addr)
            .auth_data(vec![])
            .hash_auth_data(false)
            .channel_config(ChannelConfiguration {
                weight_unreliable: 10,
                weights_unreliable_ordered: vec![10, 10, 10, 10, 10],
                weights_reliable: vec![10, 10, 10, 10, 10],
            })
            .connect()
            .unwrap();

        server.set_simulator(Some(Box::new(Simulator)));
        client.set_simulator(Some(Box::new(Simulator)));

        let amount_messages = 25000;
        for i in 0..amount_messages {
            client
                .send(Channel::Reliable(0), format!("{}", i).as_bytes().to_vec())
                .unwrap();
        }
        let mut i = 0;
        while let Ok(event) = server.next() {
            match event {
                server::Event::Connected(_, _) => {}
                server::Event::Received(_, message) => {
                    assert_eq!(message, format!("{}", i).as_bytes());
                    if i == amount_messages - 1 {
                        break;
                    }
                    i += 1;
                }
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn test_unreliable_ordered_no_simulator() {
        let server_addr: SocketAddr = "127.0.0.1:30004".parse().unwrap();
        let server = Server::prepare()
            .bind_addr(server_addr)
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
            .run()
            .unwrap();

        let client = Client::prepare()
            .client_version(ClientVersion::ZERO)
            .server_socket_addr(server_addr)
            .auth_data(vec![])
            .hash_auth_data(false)
            .channel_config(ChannelConfiguration {
                weight_unreliable: 10,
                weights_unreliable_ordered: vec![10, 10, 10, 10, 10],
                weights_reliable: vec![10, 10, 10, 10, 10],
            })
            .connect()
            .unwrap();

        let amount_messages = 50000;
        for i in 0..amount_messages {
            client
                .send(Channel::Reliable(0), format!("{}", i).as_bytes().to_vec())
                .unwrap();
        }
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut i = 0;
        while let Ok(event) = server.try_next() {
            match event {
                Some(server::Event::Connected(_, _)) => {}
                Some(server::Event::Received(_, message)) => {
                    let j: u32 = String::from_utf8(message).unwrap().parse().unwrap();
                    assert!(j > i || (j == 0 && i == 0));
                    i = j;
                }
                None => {
                    if Instant::now() > deadline {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(300));
                    continue;
                }
                _ => unreachable!(),
            }
        }
        assert!(i > amount_messages - 1000);
    }

    #[test]
    fn test_unreliable_ordered_okay_network() {
        struct Simulator;
        impl NetworkSimulator for Simulator {
            fn simulate(&mut self, to: SocketAddr, size: usize) -> Option<std::time::Duration> {
                if thread_rng().gen_bool(0.01) {
                    return None;
                }
                Some(Duration::from_millis(thread_rng().gen_range(20..23)))
            }
        }

        let server_addr: SocketAddr = "127.0.0.1:30005".parse().unwrap();
        let server = Server::prepare()
            .bind_addr(server_addr)
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
            .run()
            .unwrap();

        let client = Client::prepare()
            .client_version(ClientVersion::ZERO)
            .server_socket_addr(server_addr)
            .auth_data(vec![])
            .hash_auth_data(false)
            .channel_config(ChannelConfiguration {
                weight_unreliable: 10,
                weights_unreliable_ordered: vec![10, 10, 10, 10, 10],
                weights_reliable: vec![10, 10, 10, 10, 10],
            })
            .connect()
            .unwrap();

        server.set_simulator(Some(Box::new(Simulator)));
        client.set_simulator(Some(Box::new(Simulator)));

        let amount_messages = 50000;
        for i in 0..amount_messages {
            client
                .send(Channel::Reliable(0), format!("{}", i).as_bytes().to_vec())
                .unwrap();
        }
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut i = 0;
        while let Ok(event) = server.try_next() {
            match event {
                Some(server::Event::Connected(_, _)) => {}
                Some(server::Event::Received(_, message)) => {
                    let j: u32 = String::from_utf8(message).unwrap().parse().unwrap();
                    assert!(j > i || (j == 0 && i == 0));
                    i = j;
                }
                None => {
                    if Instant::now() > deadline {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(300));
                    continue;
                }
                _ => unreachable!(),
            }
        }
        assert!(i > amount_messages - 1000);
    }

    #[test]
    fn test_unreliable_ordered_bad_network() {
        struct Simulator;
        impl NetworkSimulator for Simulator {
            fn simulate(&mut self, to: SocketAddr, size: usize) -> Option<std::time::Duration> {
                if thread_rng().gen_bool(0.1) {
                    return None;
                }
                Some(Duration::from_millis(thread_rng().gen_range(100..140)))
            }
        }

        let server_addr: SocketAddr = "127.0.0.1:30006".parse().unwrap();
        let server = Server::prepare()
            .bind_addr(server_addr)
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
            .run()
            .unwrap();

        let client = Client::prepare()
            .client_version(ClientVersion::ZERO)
            .server_socket_addr(server_addr)
            .auth_data(vec![])
            .hash_auth_data(false)
            .channel_config(ChannelConfiguration {
                weight_unreliable: 10,
                weights_unreliable_ordered: vec![10, 10, 10, 10, 10],
                weights_reliable: vec![10, 10, 10, 10, 10],
            })
            .connect()
            .unwrap();

        server.set_simulator(Some(Box::new(Simulator)));
        client.set_simulator(Some(Box::new(Simulator)));

        let amount_messages = 50000;
        for i in 0..amount_messages {
            client
                .send(Channel::Reliable(0), format!("{}", i).as_bytes().to_vec())
                .unwrap();
        }
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut i = 0;
        while let Ok(event) = server.try_next() {
            match event {
                Some(server::Event::Connected(_, _)) => {}
                Some(server::Event::Received(_, message)) => {
                    let j: u32 = String::from_utf8(message).unwrap().parse().unwrap();
                    assert!(j > i || (j == 0 && i == 0));
                    i = j;
                }
                None => {
                    if Instant::now() > deadline {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(300));
                    continue;
                }
                _ => unreachable!(),
            }
        }
        assert!(i > amount_messages - 1000);
    }

    #[test]
    fn test_unreliable_ordered_terrible_network() {
        struct Simulator;
        impl NetworkSimulator for Simulator {
            fn simulate(&mut self, to: SocketAddr, size: usize) -> Option<std::time::Duration> {
                if thread_rng().gen_bool(0.7) {
                    return None;
                }
                Some(Duration::from_millis(thread_rng().gen_range(300..500)))
            }
        }

        let server_addr: SocketAddr = "127.0.0.1:30007".parse().unwrap();
        let server = Server::prepare()
            .bind_addr(server_addr)
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
            .run()
            .unwrap();

        let client = Client::prepare()
            .client_version(ClientVersion::ZERO)
            .server_socket_addr(server_addr)
            .auth_data(vec![])
            .hash_auth_data(false)
            .channel_config(ChannelConfiguration {
                weight_unreliable: 10,
                weights_unreliable_ordered: vec![10, 10, 10, 10, 10],
                weights_reliable: vec![10, 10, 10, 10, 10],
            })
            .connect()
            .unwrap();

        server.set_simulator(Some(Box::new(Simulator)));
        client.set_simulator(Some(Box::new(Simulator)));

        let amount_messages = 50000;
        for i in 0..amount_messages {
            client
                .send(Channel::Reliable(0), format!("{}", i).as_bytes().to_vec())
                .unwrap();
        }
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut i = 0;
        while let Ok(event) = server.try_next() {
            match event {
                Some(server::Event::Connected(_, _)) => {}
                Some(server::Event::Received(_, message)) => {
                    let j: u32 = String::from_utf8(message).unwrap().parse().unwrap();
                    assert!(j > i || (j == 0 && i == 0));
                    i = j;
                }
                None => {
                    if Instant::now() > deadline {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(300));
                    continue;
                }
                _ => unreachable!(),
            }
        }
        assert!(i > amount_messages - 1000);
    }

    #[test]
    fn test_connecting() {
        let server_addr: SocketAddr = "127.0.0.1:30008".parse().unwrap();
        for i in 0..10 {
            let server = Server::prepare()
                .bind_addr(server_addr)
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
                .run()
                .unwrap();

            let client = Client::prepare()
                .client_version(ClientVersion::ZERO)
                .server_socket_addr(server_addr)
                .auth_data(vec![])
                .hash_auth_data(false)
                .channel_config(ChannelConfiguration {
                    weight_unreliable: 10,
                    weights_unreliable_ordered: vec![10, 10, 10, 10, 10],
                    weights_reliable: vec![10, 10, 10, 10, 10],
                })
                .connect()
                .unwrap();
        }
    }
}
