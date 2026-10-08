mod common;

use std::{
    net::{SocketAddr, UdpSocket},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, Sender},
        Arc,
    },
    time::{Duration, Instant},
};

use common::{client_builder, next_event, server_builder, AcceptAll};
use hexgate::{
    client, server, Authenticator, Channel, ChannelConfiguration, Client, Server, Simulator,
};

const WAIT: Duration = Duration::from_secs(3);

struct PausedAuth {
    entered: Sender<()>,
    release: Receiver<()>,
    finished: Sender<()>,
}

impl Authenticator<()> for PausedAuth {
    fn authenticate(&mut self, _: SocketAddr, _: Vec<u8>) -> Result<(), Vec<u8>> {
        self.entered.send(()).unwrap();
        let _ = self.release.recv_timeout(WAIT);
        let _ = self.finished.send(());
        Ok(())
    }
}

fn paused_server() -> (Server<()>, Receiver<()>, Sender<()>, Receiver<()>) {
    let (entered_tx, entered) = mpsc::channel();
    let (release, release_rx) = mpsc::channel();
    let (finished_tx, finished) = mpsc::channel();
    let server = server_builder!(PausedAuth {
        entered: entered_tx,
        release: release_rx,
        finished: finished_tx,
    })
    .channel_config(ChannelConfiguration::default())
    .close_linger(Duration::ZERO)
    .run()
    .unwrap();
    (server, entered, release, finished)
}

fn start_client(addr: SocketAddr) -> Client {
    client_builder!(addr)
        .channel_config(ChannelConfiguration::default())
        .close_linger(Duration::ZERO)
        .start()
        .unwrap()
}

#[test]
fn dropping_server_does_not_wait_for_a_stalled_authenticator() {
    let (server, entered, release, finished) = paused_server();
    let client = start_client(server.local_addr());
    entered.recv_timeout(WAIT).unwrap();
    let (dropped_tx, dropped_rx) = mpsc::channel();
    let dropper = std::thread::spawn(move || {
        drop(server);
        dropped_tx.send(()).unwrap();
    });
    let result = dropped_rx.recv_timeout(Duration::from_millis(500));
    release.send(()).unwrap();
    finished.recv_timeout(WAIT).unwrap();
    dropper.join().unwrap();
    assert!(result.is_ok(), "server drop waited for authentication");
    assert!(!matches!(
        client.try_next(),
        Ok(Some(client::Event::Connected))
    ));
}

#[test]
fn auth_completion_cannot_revive_a_shutdown_server() {
    let (server, entered, release, finished) = paused_server();
    let _client = start_client(server.local_addr());
    entered.recv_timeout(WAIT).unwrap();
    server.shutdown(vec![]).unwrap();
    let deadline = Instant::now() + WAIT;
    while server.try_next().is_ok() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(server.try_next().is_err());
    release.send(()).unwrap();
    finished.recv_timeout(WAIT).unwrap();
    assert!(server.connections().is_empty());
    assert!(server.try_next().is_err());
}

#[test]
fn unreliable_age_includes_time_waiting_for_authentication() {
    let (server, entered, release, _) = paused_server();
    let client = start_client(server.local_addr());
    entered.recv_timeout(WAIT).unwrap();
    client.send(Channel::Unreliable, b"old".to_vec()).unwrap();
    client
        .send(Channel::Reliable(0), b"reliable".to_vec())
        .unwrap();
    std::thread::sleep(Duration::from_millis(150));
    release.send(()).unwrap();
    assert!(matches!(
        next_event(|| client.try_next(), WAIT),
        Some(client::Event::Connected)
    ));
    client.send(Channel::Unreliable, b"new".to_vec()).unwrap();
    let deadline = Instant::now() + WAIT;
    let (mut reliable, mut new) = (false, false);
    while Instant::now() < deadline && !(reliable && new) {
        if let Some(server::Event::Received(_, channel, message)) =
            next_event(|| server.try_next(), Duration::from_millis(20))
        {
            assert_ne!(message, b"old");
            reliable |= channel == Channel::Reliable(0) && message == b"reliable";
            new |= channel == Channel::Unreliable && message == b"new";
        }
    }
    assert!(reliable && new);
}

#[test]
fn polling_resumes_reliable_delivery_with_a_single_event_slot() {
    let server = server_builder!(AcceptAll)
        .channel_config(ChannelConfiguration::default())
        .max_events(1)
        .close_linger(Duration::ZERO)
        .run()
        .unwrap();
    let client = start_client(server.local_addr());
    assert!(matches!(
        next_event(|| client.try_next(), WAIT),
        Some(client::Event::Connected)
    ));
    let large = vec![7; 256 << 10];
    client.send(Channel::Reliable(0), large.clone()).unwrap();
    for value in 0..100u8 {
        client.send(Channel::Reliable(0), vec![value]).unwrap();
    }
    std::thread::sleep(Duration::from_millis(50));
    assert!(matches!(
        next_event(|| server.try_next(), WAIT),
        Some(server::Event::Connected(..))
    ));
    assert!(matches!(
        next_event(|| server.try_next(), WAIT),
        Some(server::Event::Received(_, Channel::Reliable(0), data)) if data == large
    ));
    for value in 0..100u8 {
        assert!(matches!(
            next_event(|| server.try_next(), WAIT),
            Some(server::Event::Received(_, Channel::Reliable(0), data)) if data == [value]
        ));
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn command_flood_does_not_postpone_connection_timeout() {
    let server = common::server(Duration::from_secs(10));
    let client = client_builder!(server.local_addr())
        .channel_config(common::channel_config())
        .timeout_dur(Duration::from_millis(200))
        .close_linger(Duration::ZERO)
        .connect()
        .unwrap();
    server
        .set_simulator(Simulator::sending(common::Blackhole))
        .unwrap();
    let running = Arc::new(AtomicBool::new(true));
    let floods: Vec<_> = (0..2)
        .map(|_| {
            let client = client.clone();
            let running = running.clone();
            std::thread::spawn(move || {
                while running.load(Ordering::Relaxed) {
                    let _ = client.set_priority(Channel::Reliable(0), 1);
                }
            })
        })
        .collect();
    let start = Instant::now();
    let result = next_event(|| client.try_next(), WAIT);
    running.store(false, Ordering::Relaxed);
    for flood in floods {
        flood.join().unwrap();
    }
    assert!(
        matches!(result, Some(client::Event::TimedOut)),
        "{result:?}"
    );
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "timer lateness: {:?}",
        start.elapsed()
    );
}

#[test]
fn receive_flood_keeps_servicing_another_peer() {
    let (server, client) = common::connected(None, common::TIMEOUT);
    assert!(matches!(
        next_event(|| server.try_next(), WAIT),
        Some(server::Event::Connected(..))
    ));
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(server.local_addr()).unwrap();
    socket.set_nonblocking(true).unwrap();
    let running = Arc::new(AtomicBool::new(true));
    let flood_running = running.clone();
    let flood = std::thread::spawn(move || {
        let invalid = [255; 1200];
        while flood_running.load(Ordering::Relaxed) {
            let _ = socket.send(&invalid);
        }
    });
    let start = Instant::now();
    client
        .send(Channel::Reliable(0), b"sentinel".to_vec())
        .unwrap();
    let result = next_event(|| server.try_next(), WAIT);
    running.store(false, Ordering::Relaxed);
    flood.join().unwrap();
    assert!(
        matches!(result, Some(server::Event::Received(_, Channel::Reliable(0), ref data)) if data == b"sentinel"),
        "{result:?}"
    );
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "sentinel latency: {:?}",
        start.elapsed()
    );
}
