// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Encrypting a packet and decrypting it on the other end. Run with `--features bench`.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ed25519_dalek::SigningKey;
use hexgate::{
    bench::{key_exchange, Packets},
    Cipher,
};
use x25519_dalek::PublicKey;

fn packets(c: &mut Criterion) {
    let mut group = c.benchmark_group("packets");
    for cipher in [Cipher::AES256GCM, Cipher::ChaCha20Poly1305] {
        let mut packets = Packets::new(cipher);
        for len in [100, 1100] {
            group.throughput(Throughput::Bytes(len as u64));
            group.bench_function(BenchmarkId::new(format!("reliable/{cipher:?}"), len), |b| {
                b.iter(|| packets.reliable(len))
            });
            group.bench_function(
                BenchmarkId::new(format!("unreliable/{cipher:?}"), len),
                |b| b.iter(|| packets.unreliable(len)),
            );
        }
    }
    let mut packets = Packets::new(Cipher::AES256GCM);
    group.throughput(Throughput::Elements(1));
    group.bench_function("acks", |b| b.iter(|| packets.acks()));
    let signing_key = SigningKey::from_bytes(&[1; 32]);
    let client_key = PublicKey::from([9; 32]);
    group.bench_function("key_exchange", |b| {
        b.iter(|| key_exchange(&signing_key, &client_key))
    });
    group.finish();
}

criterion_group!(benches, packets);
criterion_main!(benches);
