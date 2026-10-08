# Hexgate

**Hexgate is an efficient and easy to use UDP client-server game networking crate supporting encryption, reliability, authentication, and network simulation.**

---
⚠️ HEXGATE IS USABLE BUT NOT PRODUCTION READY ⚠️

API MAY CHANGE QUITE A BIT.

CHECK OUT THE [ISSUES](https://github.com/alexdesander/hexgate/issues) FOR MORE INFORMATION

---

Documentation: [docs.rs/hexgate](https://docs.rs/hexgate)

## Features
- Simple API: builders, blocking (`next`) and polling (`try_next`) event queues, cheap cloneable handles
- Pure UDP, multi-platform (see [mio's supported platforms](https://github.com/tokio-rs/mio#platforms))
- Connection and message oriented
- Delivery guarantees per channel:
    - Unreliable
    - UnreliableOrdered (sequenced, up to 256 channels)
    - Reliable (ordered, up to 256 channels)
    - ReliableUnordered (each message delivered once complete, up to 256 channels)
- Channel priorities with weighted byte fairness and periodic service for lower priorities
- Bounded send admission, receiver flow control, reliable channel reset, per-channel queue statistics
- Unreliable deadlines and replacement; optional transport acknowledgments through send receipts
- Runs on its own network thread; non-blocking connect (`start()`) or blocking (`connect()`)
- Server: per-client kick, broadcast, connection limit, connection queries
- Security:
    - Server identity: ed25519 key pinned by the client, signed x25519 key exchange over the whole handshake
    - AES-256-GCM or ChaCha20-Poly1305 encryption, one key per direction, replay protection
    - Client authentication through your own `Authenticator` (optionally Argon2id-hashed passwords, `argon2`
      feature, on by default)
    - DoS hardening: stateless handshake cookies bound to the client address, per-IP rate limits, requests padded
      so the server never amplifies traffic
    - Key file helpers (`hexgate::keys`)
- Paced congestion window controlled by standing RTT and loss; all channels share the same network budget.
  Tuned for average or better connections; bad ones (heavy jitter, loss, outages) are survived, not optimized for
- Freshness measured from application submission, including connection startup
- Per-tick API for games: `flush()` sends a tick as one burst, `gross_send_budget(tick)` gives an approximate gross packet budget
- Timeouts, keepalives and connection statistics (RTT, queueing delay, send and delivery rate, loss, queued bytes)
- Network simulation (`hexgate::sim`, `sim` feature), both directions, on the network thread: presets from perfect to terrible,
  bottleneck with buffer and cross traffic, jitter distributions, bursty loss, spikes, stalls, outages, reordering,
  duplication, corruption
- Optional `tracing` instrumentation (`tracing` feature)

Hexgate does NOT do:
- Serialization (recommendations: [bitcode](https://crates.io/crates/bitcode), [bincode](https://crates.io/crates/bincode) (2.0))
- Compression (recommendation: [zstd](https://crates.io/crates/zstd))
- Peer-to-peer
- MTU discovery (minimum assumed MTU size is ~1250 bytes)

## Keys
The server needs a `secret_key` (its ed25519 identity) and an `auth_salt`. Generate them once and keep them secret
and stable, e.g. with `keys::load_or_generate("server.key")`. Clients pin the server's public key
(`server::public_key(&secret_key)`, shipped with the game) through `ServerKey::Pinned`, so nobody else can pose as the
server; `hexgate::fingerprint` formats it for comparing. `ServerKey::Unverified` turns this off explicitly. For trust
on first use, connect unverified once and store `client.get_server_key()` with `keys::save`.

## Example
A server that relays chat messages, polled once per game tick:
```rust
use std::{net::SocketAddr, time::Duration};

use hexgate::{keys, server::Event, Authenticator, Channel, ChannelConfiguration, Server};

/// Accepts everyone, using the auth data as the player name.
struct AcceptAll;

impl Authenticator<String> for AcceptAll {
    fn authenticate(&mut self, _: SocketAddr, name: Vec<u8>) -> Result<String, Vec<u8>> {
        String::from_utf8(name).map_err(|_| b"invalid name".to_vec())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server = Server::prepare()
        .bind_addr("0.0.0.0:44444".parse()?)
        .info(b"My game server".to_vec())
        .allowed_client_versions(|_| Ok(()))
        .secret_key(keys::load_or_generate("server.key")?)
        .auth_salt(keys::load_or_generate("server.salt")?)
        .authenticator(AcceptAll)
        .channel_config(ChannelConfiguration {
            weight_unreliable: 10,
            weights_unreliable_ordered: vec![10],
            weights_reliable: vec![10],
            ..ChannelConfiguration::default()
        })
        .run()?;

    loop {
        while let Some(event) = server.try_next()? {
            match event {
                Event::Connected(addr, name) => println!("{name} joined from {addr}"),
                Event::Received(_, _, message) => server.broadcast(Channel::Reliable(0), message)?,
                Event::Disconnected(addr, _) | Event::TimedOut(addr) => println!("{addr} left"),
                Event::Violation(addr, violation) => println!("{addr} was kicked: {violation}"),
                Event::SendResult(..) => {}
            }
        }
        // Simulate the world, then send state updates on Channel::Unreliable...
        std::thread::sleep(Duration::from_millis(16));
    }
}
```

A client that connects without blocking the game loop:
```rust
use std::time::Duration;

use hexgate::{client::Event, Channel, ChannelConfiguration, Client, ClientVersion, ServerKey};

/// `hexgate::server::public_key` of the server's secret key.
const SERVER_KEY: [u8; 32] = [0; 32];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::prepare()
        .client_version(ClientVersion { major: 1, minor: 0, patch: 0 })
        .server_socket_addr("example.com:44444")
        .server_key(ServerKey::Pinned(SERVER_KEY))
        .auth_data(b"Alice".to_vec())
        .channel_config(ChannelConfiguration {
            weight_unreliable: 10,
            weights_unreliable_ordered: vec![10],
            weights_reliable: vec![10],
            ..ChannelConfiguration::default()
        })
        .start()?;
    // Queued until the connection is up.
    client.send(Channel::Reliable(0), b"Hello!".to_vec())?;

    loop {
        while let Some(event) = client.try_next()? {
            match event {
                Event::Connected => println!("connected"),
                Event::SendResult(..) => {}
                Event::ConnectFailed(e) => return Err(e.into()),
                Event::Received(_, message) => println!("{}", String::from_utf8_lossy(&message)),
                Event::Disconnected(_) | Event::TimedOut | Event::Violation(_) => return Ok(()),
            }
        }
        std::thread::sleep(Duration::from_millis(16));
    }
}
```

See `examples/game_loop.rs` for tick flushing, fresh snapshots and cancellable bulk transfers.
Send receipts acknowledge transport packets; they do not guarantee application delivery or processing.

## Inspiration

Hexgate draws inspiration from the following projects and resources:

- [redpine-rs](https://github.com/lowquark/redpine-rs)
- [GameNetworkingSockets](https://github.com/ValveSoftware/GameNetworkingSockets)
- [RakNet](https://github.com/facebookarchive/RakNet)
- [ENet](http://enet.bespin.org/)
- [Gaffer on Games](https://gafferongames.com/)
- [message-io](https://github.com/lemunozm/message-io)

## Contributor License Agreement (CLA)

By contributing to this project, you agree that your contributions will be licensed under the [Mozilla Public License, Version 2.0](https://www.mozilla.org/en-US/MPL/2.0/).

This ensures that:
1. Your contributions are compatible with the project license.
2. The project remains open and accessible under the MPL 2.0.

If you do not agree to these terms, please refrain from contributing.

For more details about the license, refer to the [LICENSE](./LICENSE) file included in this repository.

Thank you for contributing to the project! 🚀
