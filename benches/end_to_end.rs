// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Round trips through a client and a server on localhost: the server echoes every message.

use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

use criterion::{criterion_group, criterion_main, Criterion};
use hexgate::{
    client, server, Authenticator, Channel, ChannelConfiguration, Client, ClientVersion, Server,
    ServerKey,
};

struct AcceptAll;

impl Authenticator<()> for AcceptAll {
    fn authenticate(&mut self, _: SocketAddr, _: Vec<u8>) -> Result<(), Vec<u8>> {
        Ok(())
    }
}

fn round_trip(client: &Client, channel: Channel, message: &[u8]) {
    client.send(channel, message.to_vec()).unwrap();
    loop {
        if let client::Event::Received(_, echo) = client.next().unwrap() {
            assert_eq!(echo, message);
            return;
        }
    }
}

fn end_to_end(c: &mut Criterion) {
    let server = Server::prepare()
        .bind_addr("127.0.0.1:0".parse().unwrap())
        .info(vec![])
        .allowed_client_versions(|_| Ok(()))
        .secret_key([1; 32])
        .auth_salt([0; 16])
        .authenticator(AcceptAll)
        .channel_config(ChannelConfiguration::default())
        .run()
        .unwrap();
    let echo = server.clone();
    std::thread::spawn(move || {
        while let Ok(event) = echo.next() {
            if let server::Event::Received(from, _, message) = event {
                let channel = if message[0] == 0 {
                    Channel::Unreliable
                } else {
                    Channel::Reliable(0)
                };
                let _ = echo.send(from, channel, message);
            }
        }
    });
    let client = Client::prepare()
        .client_version(ClientVersion::ZERO)
        .server_socket_addr(server.local_addr())
        .server_key(ServerKey::Unverified)
        .auth_data(vec![])
        .hash_auth_data(false)
        .channel_config(ChannelConfiguration::default())
        .connect()
        .unwrap();

    let mut group = c.benchmark_group("end_to_end");
    group.sample_size(20);
    group.measurement_time(Duration::from_secs(5));
    group.bench_function("round_trip/unreliable/100B", |b| {
        b.iter(|| round_trip(&client, Channel::Unreliable, &[0; 100]))
    });
    group.bench_function("round_trip/reliable/100B", |b| {
        b.iter(|| round_trip(&client, Channel::Reliable(0), &[1; 100]))
    });
    // Sends wait for the next batch (BATCHES_DOWNTIME) unless the last one was long enough ago.
    group.bench_function("round_trip_after_idle/reliable/100B", |b| {
        b.iter_custom(|iterations| {
            let mut total = Duration::ZERO;
            for _ in 0..iterations {
                std::thread::sleep(Duration::from_millis(40));
                let start = Instant::now();
                round_trip(&client, Channel::Reliable(0), &[1; 100]);
                total += start.elapsed();
            }
            total
        })
    });
    group.finish();
}

criterion_group!(benches, end_to_end);
criterion_main!(benches);
