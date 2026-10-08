// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

mod common;

use std::{
    net::{SocketAddr, UdpSocket},
    sync::mpsc,
    time::{Duration, Instant},
};

use common::{
    channel_config, client, connected, next_event, server, AcceptAll, Blackhole, DropNth, OKAY,
    SECRET_KEY, TIMEOUT,
};
use hexgate::{
    client::{self as hexclient, ConnectError},
    error::SendError,
    server as hexserver, AllowedClientVersions, Authenticator, Channel, ChannelConfiguration,
    Client, ClientVersion, Server, ServerKey, Simulator,
};
use rand::Rng;

const WAIT: Duration = Duration::from_secs(5);

fn client_with(
    server_addr: SocketAddr,
    server_key: ServerKey,
    channel_config: ChannelConfiguration,
    simulator: Option<Simulator>,
) -> Result<Client, ConnectError> {
    Client::prepare()
        .client_version(ClientVersion::ZERO)
        .server_socket_addr(server_addr)
        .server_key(server_key)
        .auth_data(vec![])
        .hash_auth_data(false)
        .channel_config(channel_config)
        .maybe_simulator(simulator)
        .connect()
}

fn pinned() -> ServerKey {
    ServerKey::Pinned(hexserver::public_key(&SECRET_KEY))
}

#[test]
fn connect_repeatedly() {
    for _ in 0..10 {
        let server = server(TIMEOUT);
        let _client = client(server.local_addr(), TIMEOUT);
    }
}

/// Each step is retransmitted after 250 ms instead of restarting the handshake, and the server
/// answers retransmissions without creating a second connection.
#[test]
fn handshake_survives_a_lost_packet_at_each_step() {
    for lost in 0..3 {
        for client_side in [true, false] {
            let server = Server::prepare()
                .bind_addr("127.0.0.1:0".parse().unwrap())
                .info(vec![])
                .allowed_client_versions(|_| Ok(()))
                .secret_key(SECRET_KEY)
                .auth_salt([0; 16])
                .authenticator(AcceptAll)
                .channel_config(channel_config())
                .maybe_simulator((!client_side).then(|| Simulator::sending(DropNth::new(lost))))
                .run()
                .unwrap();
            let start = Instant::now();
            let simulator = client_side.then(|| Simulator::sending(DropNth::new(lost)));
            let _client =
                client_with(server.local_addr(), pinned(), channel_config(), simulator).unwrap();
            let elapsed = start.elapsed();
            assert!(
                elapsed < Duration::from_secs(2),
                "packet {lost}: {elapsed:?}"
            );
            assert!(matches!(
                next_event(|| server.try_next(), WAIT),
                Some(hexserver::Event::Connected(..))
            ));
            let extra = next_event(|| server.try_next(), Duration::from_millis(300));
            assert!(extra.is_none(), "packet {lost}: {extra:?}");
        }
    }
}

#[test]
fn rejects_unsupported_client_version() {
    const ALLOWED: AllowedClientVersions = AllowedClientVersions {
        min: ClientVersion {
            major: 1,
            minor: 0,
            patch: 0,
        },
        max: ClientVersion {
            major: 1,
            minor: 9,
            patch: 0,
        },
    };
    let server = Server::prepare()
        .bind_addr("127.0.0.1:0".parse().unwrap())
        .info(vec![])
        .allowed_client_versions(|version| (version.major == 1).then_some(()).ok_or(ALLOWED))
        .secret_key(SECRET_KEY)
        .auth_salt([0; 16])
        .authenticator(AcceptAll)
        .channel_config(channel_config())
        .run()
        .unwrap();
    let result = client_with(server.local_addr(), pinned(), channel_config(), None);
    assert!(
        matches!(result, Err(ConnectError::VersionNotSupported(allowed)) if allowed == ALLOWED)
    );
}

#[test]
fn rejects_wrong_server_key() {
    let server = server(TIMEOUT);
    let wrong = ServerKey::Pinned(hexserver::public_key(&[8; 32]));
    let result = client_with(server.local_addr(), wrong, channel_config(), None);
    assert!(matches!(
        result,
        Err(ConnectError::ServerKeyMismatch { received_key }) if received_key == hexserver::public_key(&SECRET_KEY)
    ));
}

#[test]
fn reports_authentication_failure() {
    struct RejectAll;
    impl Authenticator<()> for RejectAll {
        fn authenticate(&mut self, _: SocketAddr, _: Vec<u8>) -> Result<(), Vec<u8>> {
            Err(b"wrong password".to_vec())
        }
    }
    let server = Server::prepare()
        .bind_addr("127.0.0.1:0".parse().unwrap())
        .info(vec![])
        .allowed_client_versions(|_| Ok(()))
        .secret_key(SECRET_KEY)
        .auth_salt([0; 16])
        .authenticator(RejectAll)
        .channel_config(channel_config())
        .run()
        .unwrap();
    let result = client_with(server.local_addr(), pinned(), channel_config(), None);
    assert!(
        matches!(result, Err(ConnectError::ServerDeniedLogin(data)) if data == b"wrong password")
    );
}

#[test]
fn rejects_mismatched_channels() {
    let server = server(TIMEOUT);
    let mut config = channel_config();
    config.weights_reliable.push(1);
    let result = client_with(server.local_addr(), pinned(), config, None);
    assert!(matches!(
        result,
        Err(ConnectError::ChannelMismatch {
            client: [5, 6],
            server: [5, 5]
        })
    ));
}

#[test]
fn rejects_clients_when_full() {
    let server = Server::prepare()
        .bind_addr("127.0.0.1:0".parse().unwrap())
        .info(vec![])
        .allowed_client_versions(|_| Ok(()))
        .secret_key(SECRET_KEY)
        .auth_salt([0; 16])
        .authenticator(AcceptAll)
        .channel_config(channel_config())
        .max_connections(1)
        .run()
        .unwrap();
    let _first = client(server.local_addr(), TIMEOUT);
    let result = client_with(server.local_addr(), pinned(), channel_config(), None);
    assert!(matches!(result, Err(ConnectError::ServerFull)));
}

#[test]
fn server_times_out_silent_client() {
    let timeout = Duration::from_secs(1);
    let (server, client) = connected(None, timeout);
    assert!(matches!(
        next_event(|| server.try_next(), WAIT),
        Some(hexserver::Event::Connected(..))
    ));
    std::thread::sleep(Duration::from_secs(2));
    client.set_simulator(Simulator::sending(Blackhole));
    let start = Instant::now();
    let event = next_event(|| server.try_next(), WAIT);
    let elapsed = start.elapsed();
    assert!(
        matches!(event, Some(hexserver::Event::TimedOut(_))),
        "{event:?}"
    );
    assert!(
        elapsed > timeout / 2 && elapsed < timeout * 2,
        "{elapsed:?}"
    );
}

#[test]
fn client_times_out_silent_server() {
    let timeout = Duration::from_secs(1);
    let (server, client) = connected(None, timeout);
    std::thread::sleep(Duration::from_secs(2));
    server.set_simulator(Simulator::sending(Blackhole));
    let start = Instant::now();
    let event = next_event(|| client.try_next(), WAIT);
    let elapsed = start.elapsed();
    assert!(
        matches!(event, Some(hexclient::Event::TimedOut)),
        "{event:?}"
    );
    assert!(
        elapsed > timeout / 2 && elapsed < timeout * 2,
        "{elapsed:?}"
    );
}

#[test]
fn disconnect_flushes_queued_messages() {
    let (server, client) = connected(Some(OKAY), TIMEOUT);
    for i in 0..100u32 {
        client
            .send(Channel::Reliable(1), vec![i as u8; 1000])
            .unwrap();
    }
    client.disconnect(b"bye".to_vec()).unwrap();
    drop(client);
    let mut received = 0;
    loop {
        match next_event(|| server.try_next(), WAIT) {
            Some(hexserver::Event::Connected(..)) => {}
            Some(hexserver::Event::Received(_, message)) => {
                assert_eq!(message, vec![received as u8; 1000]);
                received += 1;
            }
            Some(hexserver::Event::Disconnected(_, reason)) => {
                assert_eq!(reason, b"bye");
                break;
            }
            event => panic!("{event:?}"),
        }
    }
    assert_eq!(received, 100);
}

#[test]
fn shutdown_flushes_queued_messages() {
    let (server, client) = connected(Some(OKAY), TIMEOUT);
    let Some(hexserver::Event::Connected(peer, ())) = next_event(|| server.try_next(), WAIT) else {
        panic!("not connected");
    };
    for i in 0..100u32 {
        server
            .send(peer, Channel::Reliable(1), vec![i as u8; 1000])
            .unwrap();
    }
    server.shutdown(b"maintenance".to_vec()).unwrap();
    drop(server);
    for i in 0..100u32 {
        match next_event(|| client.try_next(), WAIT) {
            Some(hexclient::Event::Received(message)) => assert_eq!(message, vec![i as u8; 1000]),
            event => panic!("{event:?}"),
        }
    }
    assert!(matches!(
        next_event(|| client.try_next(), WAIT),
        Some(hexclient::Event::Disconnected(reason)) if reason == b"maintenance"
    ));
}

#[test]
fn kick_disconnects_one_client() {
    let server = server(TIMEOUT);
    let kicked = client(server.local_addr(), TIMEOUT);
    let other = client(server.local_addr(), TIMEOUT);
    let kicked_addr = SocketAddr::new(server.local_addr().ip(), kicked.local_addr().port());
    server
        .send(kicked_addr, Channel::Reliable(0), b"banned".to_vec())
        .unwrap();
    server.disconnect(kicked_addr, b"kicked".to_vec()).unwrap();
    assert!(matches!(
        server.send(kicked_addr, Channel::Reliable(0), b"too late".to_vec()),
        Err(SendError::NotConnected(_))
    ));
    assert!(matches!(
        next_event(|| kicked.try_next(), WAIT),
        Some(hexclient::Event::Received(message)) if message == b"banned"
    ));
    assert!(matches!(
        next_event(|| kicked.try_next(), WAIT),
        Some(hexclient::Event::Disconnected(reason)) if reason == b"kicked"
    ));
    assert!(kicked.try_next().is_err());

    other.send(Channel::Reliable(0), b"hi".to_vec()).unwrap();
    loop {
        match next_event(|| server.try_next(), WAIT) {
            Some(hexserver::Event::Connected(..)) => {}
            Some(hexserver::Event::Received(from, message)) => {
                assert_ne!(from, kicked_addr);
                assert_eq!(message, b"hi");
                break;
            }
            event => panic!("{event:?}"),
        }
    }
}

#[test]
fn many_clients() {
    let server = server(TIMEOUT);
    let clients: Vec<Client> = (0..50)
        .map(|_| client(server.local_addr(), TIMEOUT))
        .collect();
    for (i, client) in clients.iter().enumerate() {
        client
            .send(Channel::Reliable(0), i.to_string().into_bytes())
            .unwrap();
    }
    let mut echoed = 0;
    while echoed < clients.len() {
        match next_event(|| server.try_next(), WAIT) {
            Some(hexserver::Event::Connected(..)) => {}
            Some(hexserver::Event::Received(from, message)) => {
                server.send(from, Channel::Reliable(0), message).unwrap();
                echoed += 1;
            }
            event => panic!("{event:?}"),
        }
    }
    for (i, client) in clients.iter().enumerate() {
        assert!(matches!(
            next_event(|| client.try_next(), WAIT),
            Some(hexclient::Event::Received(message)) if message == i.to_string().as_bytes()
        ));
    }
}

/// Garbage from unknown addresses must neither crash the server nor disturb its clients.
#[test]
fn survives_malformed_packets() {
    let (server, client) = connected(None, TIMEOUT);
    let attacker = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut rng = rand::thread_rng();
    for identifier in 0..=30u8 {
        for size in [
            1, 2, 5, 9, 17, 18, 19, 54, 58, 117, 133, 257, 1199, 1200, 1300,
        ] {
            let mut packet = vec![0u8; size];
            rng.fill(&mut packet[..]);
            packet[0] = identifier;
            attacker.send_to(&packet, server.local_addr()).unwrap();
        }
    }
    // A varint longer than the packet, see C2.
    let mut overlong = vec![14];
    overlong.extend([0x80; 9]);
    overlong.extend([0x01, 0, 0, 0, 0, 0, 0, 0]);
    attacker.send_to(&overlong, server.local_addr()).unwrap();

    client
        .send(Channel::Reliable(0), b"still fine".to_vec())
        .unwrap();
    loop {
        match next_event(|| server.try_next(), WAIT) {
            Some(hexserver::Event::Connected(..)) => {}
            Some(hexserver::Event::Received(_, message)) => {
                assert_eq!(message, b"still fine");
                break;
            }
            event => panic!("{event:?}"),
        }
    }
}

/// Neither side may block or deadlock when the app never drains its events (C9).
#[test]
fn drop_without_draining_events() {
    let (server, client) = connected(None, TIMEOUT);
    let peer = SocketAddr::new(server.local_addr().ip(), client.local_addr().port());
    for i in 0..5000u32 {
        let message = i.to_string().into_bytes();
        client.send(Channel::Unreliable, message.clone()).unwrap();
        client.send(Channel::Reliable(0), message.clone()).unwrap();
        server.send(peer, Channel::Reliable(0), message).unwrap();
    }
    std::thread::sleep(Duration::from_secs(1));
    let (done_tx, done_rx) = mpsc::channel();
    std::thread::spawn(move || {
        drop(client);
        drop(server);
        let _ = done_tx.send(());
    });
    assert!(done_rx.recv_timeout(Duration::from_secs(10)).is_ok());
}
