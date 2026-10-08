mod common;

use std::time::{Duration, Instant};

use common::{client_builder, server_builder, AcceptAll};
use hexgate::{client, server, Channel, CongestionConfig, SendOptions, SendOutcome};

#[test]
fn socket_threads_preserve_channel_stats_resets_priorities_and_receipts() {
    let rate = CongestionConfig {
        min_rate: 32_000,
        initial_rate: 32_000,
        max_rate: 32_000,
        ..CongestionConfig::default()
    };
    let server = server_builder!(AcceptAll)
        .channel_config(common::channel_config())
        .congestion_config(rate)
        .close_linger(Duration::ZERO)
        .run()
        .unwrap();
    let client = client_builder!(server.local_addr())
        .channel_config(common::channel_config())
        .congestion_config(rate)
        .close_linger(Duration::ZERO)
        .connect()
        .unwrap();
    let server::Event::Connected(peer, ()) = server.next().unwrap() else {
        panic!()
    };

    client.set_priority(Channel::Reliable(0), -10).unwrap();
    server
        .set_priority(peer, Channel::Reliable(0), -10)
        .unwrap();
    client.set_priority(Channel::Reliable(1), 10).unwrap();
    server.set_priority(peer, Channel::Reliable(1), 10).unwrap();
    let receipt = |cookie| SendOptions {
        receipt: Some(cookie),
        ..SendOptions::default()
    };
    client
        .send_with(Channel::Reliable(0), vec![1; 1 << 20], receipt(1))
        .unwrap();
    server
        .send_with(peer, Channel::Reliable(0), vec![2; 1 << 20], receipt(3))
        .unwrap();
    let client_stats = client.channel_stats(Channel::Reliable(0)).unwrap();
    let server_stats = server.channel_stats(peer, Channel::Reliable(0)).unwrap();
    for stats in [client_stats, server_stats] {
        assert!(stats.unsent_bytes > 900_000, "{stats:?}");
        assert!(stats.oldest_queued.is_some());
        assert!(stats
            .send_delay
            .is_some_and(|delay| delay > Duration::from_secs(20)));
    }
    client.reset_channel(0).unwrap();
    server.reset_channel(peer, 0).unwrap();
    client
        .send_with(Channel::Reliable(0), vec![9], receipt(2))
        .unwrap();
    server
        .send_with(peer, Channel::Reliable(0), vec![8], receipt(4))
        .unwrap();
    client
        .send_with(Channel::UnreliableOrdered(1), vec![7], receipt(5))
        .unwrap();
    server
        .send_with(peer, Channel::UnreliableOrdered(1), vec![6], receipt(6))
        .unwrap();
    client.send(Channel::Reliable(1), vec![5]).unwrap();
    server.send(peer, Channel::Reliable(1), vec![4]).unwrap();

    let mut received_client = Vec::new();
    let mut received_server = Vec::new();
    let mut outcomes = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline
        && (received_client.len() < 3 || received_server.len() < 3 || outcomes.len() < 6)
    {
        while let Some(event) = client.try_next().unwrap() {
            match event {
                client::Event::Received(channel, message) => {
                    received_client.push((channel, message))
                }
                client::Event::SendResult(cookie, outcome) => outcomes.push((cookie, outcome)),
                _ => panic!("{event:?}"),
            }
        }
        while let Some(event) = server.try_next().unwrap() {
            match event {
                server::Event::Received(addr, channel, message) => {
                    assert_eq!(addr, peer);
                    received_server.push((channel, message));
                }
                server::Event::SendResult(addr, cookie, outcome) => {
                    assert_eq!(addr, peer);
                    outcomes.push((cookie, outcome));
                }
                _ => panic!("{event:?}"),
            }
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    received_client.sort();
    received_server.sort();
    outcomes.sort_by_key(|&(cookie, _)| cookie);
    assert_eq!(
        received_client,
        [
            (Channel::UnreliableOrdered(1), vec![6]),
            (Channel::Reliable(0), vec![8]),
            (Channel::Reliable(1), vec![4])
        ]
    );
    assert_eq!(
        received_server,
        [
            (Channel::UnreliableOrdered(1), vec![7]),
            (Channel::Reliable(0), vec![9]),
            (Channel::Reliable(1), vec![5])
        ]
    );
    assert_eq!(
        outcomes,
        [
            (1, SendOutcome::Dropped),
            (2, SendOutcome::Acked),
            (3, SendOutcome::Dropped),
            (4, SendOutcome::Acked),
            (5, SendOutcome::Acked),
            (6, SendOutcome::Acked)
        ]
    );
    for stats in [
        client.channel_stats(Channel::Reliable(0)).unwrap(),
        server.channel_stats(peer, Channel::Reliable(0)).unwrap(),
    ] {
        assert_eq!((stats.unsent_bytes, stats.unacked_bytes), (0, 0));
        assert!(stats.oldest_queued.is_none());
    }
}
