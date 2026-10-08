// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Channel throughput without pacing, loss or a socket: splitting, encryption, reassembly and
//! acks. Run with `--features bench`.

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use hexgate::{bench::Link, Channel, Cipher};

fn channels(c: &mut Criterion) {
    let mut group = c.benchmark_group("channels");
    let cases = [
        ("reliable/1x1MiB", Channel::Reliable(0), 1 << 20, 1),
        ("reliable/1000x100B", Channel::Reliable(0), 100, 1000),
        ("unreliable/1000x100B", Channel::Unreliable, 100, 1000),
        ("unreliable/16x64KiB", Channel::Unreliable, 1 << 16, 16),
        (
            "unreliable_ordered/1000x100B",
            Channel::UnreliableOrdered(0),
            100,
            1000,
        ),
    ];
    for (name, channel, size, count) in cases {
        let mut link = Link::new(Cipher::AES256GCM);
        group.throughput(Throughput::Bytes((size * count) as u64));
        group.bench_function(name, |b| {
            b.iter(|| assert_eq!(link.transfer(channel, size, count), size * count))
        });
    }
    group.finish();
}

criterion_group!(benches, channels);
criterion_main!(benches);
