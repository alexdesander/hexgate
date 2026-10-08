mod common;

use std::{
    io,
    net::{SocketAddr, ToSocketAddrs, UdpSocket},
    sync::mpsc,
    time::{Duration, Instant},
};

use common::{client_builder, server_builder, AcceptAll, Blackhole, TIMEOUT};
use hexgate::{
    client, error::SendError, server, Channel, ChannelConfiguration, Client, ClientVersion,
    SendOptions, SendQueueLimits, ServerKey, Simulator,
};

struct Resolver {
    started: mpsc::Sender<()>,
    release: mpsc::Receiver<()>,
    addresses: Vec<SocketAddr>,
}

impl ToSocketAddrs for Resolver {
    type Iter = std::vec::IntoIter<SocketAddr>;

    fn to_socket_addrs(&self) -> io::Result<Self::Iter> {
        self.started.send(()).unwrap();
        self.release.recv().unwrap();
        Ok(self.addresses.clone().into_iter())
    }
}

fn limits() -> SendQueueLimits {
    SendQueueLimits {
        max_bytes: 128,
        max_messages: 3,
        max_channel_bytes: 64,
        max_channel_messages: 2,
    }
}

#[test]
fn startup_and_drop_do_not_wait_for_resolution_and_admission_includes_pending_commands() {
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let now = Instant::now();
    let client = Client::prepare()
        .server_socket_addr(Resolver {
            started: started_tx,
            release: release_rx,
            addresses: vec!["127.0.0.1:9".parse().unwrap()],
        })
        .server_key(ServerKey::Unverified)
        .auth_data(vec![])
        .hash_auth_data(false)
        .client_version(ClientVersion::ZERO)
        .channel_config(ChannelConfiguration::default())
        .send_queue_limits(limits())
        .start()
        .unwrap();
    assert!(now.elapsed() < Duration::from_millis(250));
    started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_eq!(client.local_addr(), None);
    assert!(client.stats().is_none());
    client.send(Channel::Reliable(0), vec![]).unwrap();
    client.send(Channel::Reliable(0), vec![]).unwrap();
    assert!(matches!(
        client.send(Channel::Reliable(0), vec![]),
        Err(SendError::Backpressure)
    ));
    client.send(Channel::Unreliable, vec![1; 64]).unwrap();
    assert!(matches!(
        client.send(Channel::UnreliableOrdered(0), vec![]),
        Err(SendError::Backpressure)
    ));
    let mut queued = 0;
    while client.flush().is_ok() {
        queued += 1;
    }
    assert!(queued > 0 && queued <= 1024);
    let now = Instant::now();
    drop(client);
    assert!(now.elapsed() < Duration::from_millis(250));
    release_tx.send(()).unwrap();
}

#[test]
fn oversized_capacity_is_charged_and_reliable_deadlines_are_rejected() {
    let (server, client) = common::connected(None, TIMEOUT);
    let mut buffer = Vec::with_capacity(16 << 20);
    buffer.push(1);
    assert!(matches!(
        client.send(Channel::Unreliable, buffer),
        Err(SendError::Backpressure)
    ));
    assert!(matches!(
        client.send_with(
            Channel::Reliable(0),
            vec![],
            SendOptions {
                deadline: Some(Instant::now()),
                ..SendOptions::default()
            }
        ),
        Err(SendError::InvalidOptions)
    ));
    drop(server);
}

#[test]
fn slow_peer_admission_isolated_and_broadcast_rolls_back_all_reservations() {
    let server = server_builder!(AcceptAll)
        .channel_config(common::channel_config())
        .send_queue_limits(limits())
        .close_linger(Duration::ZERO)
        .run()
        .unwrap();
    let first = common::client(server.local_addr(), TIMEOUT);
    let second = common::client(server.local_addr(), TIMEOUT);
    let server::Event::Connected(slow, ()) = server.next().unwrap() else {
        panic!()
    };
    let server::Event::Connected(fast, ()) = server.next().unwrap() else {
        panic!()
    };
    server.set_simulator(Simulator::sending(Blackhole)).unwrap();
    server
        .send(slow, Channel::Reliable(0), vec![1; 32])
        .unwrap();
    server
        .send(slow, Channel::Reliable(0), vec![2; 32])
        .unwrap();
    assert!(matches!(
        server.broadcast(Channel::Reliable(0), vec![3; 32]),
        Err(SendError::Backpressure)
    ));
    server
        .send(fast, Channel::Reliable(0), vec![4; 32])
        .unwrap();
    server
        .send(fast, Channel::Reliable(0), vec![5; 32])
        .unwrap();
    assert!(matches!(
        server.send(fast, Channel::Reliable(0), vec![]),
        Err(SendError::Backpressure)
    ));
    server.set_simulator(Simulator::default()).unwrap();
    for (client, expected) in [(&first, [1, 2]), (&second, [4, 5])] {
        for fill in expected {
            let event = common::next_event(|| client.try_next(), Duration::from_secs(5));
            assert!(
                matches!(event, Some(client::Event::Received(Channel::Reliable(0), ref message)) if message == &vec![fill;32]),
                "{event:?}"
            );
        }
    }
}

struct Addresses(Vec<SocketAddr>);
impl ToSocketAddrs for Addresses {
    type Iter = std::vec::IntoIter<SocketAddr>;
    fn to_socket_addrs(&self) -> io::Result<Self::Iter> {
        Ok(self.0.clone().into_iter())
    }
}

#[test]
fn startup_falls_back_after_an_unreachable_resolved_address() {
    let server = common::server(TIMEOUT);
    let blackhole = UdpSocket::bind("127.0.0.1:0").unwrap();
    let client = client_builder!(Addresses(vec![
        blackhole.local_addr().unwrap(),
        server.local_addr(),
    ]))
    .channel_config(common::channel_config())
    .handshake_timeout(Duration::from_millis(50))
    .handshake_tries(1)
    .connect()
    .unwrap();
    client
        .send(Channel::Reliable(0), b"fallback".to_vec())
        .unwrap();
    assert!(matches!(
        server.next().unwrap(),
        server::Event::Connected(..)
    ));
    assert!(
        matches!(server.next().unwrap(), server::Event::Received(_, Channel::Reliable(0), ref message) if message == b"fallback")
    );
}
