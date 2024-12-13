# Hexgate

**Hexgate is an efficient and easy to use UDP client-server game networking crate supporting encryption, reliability, authentication, and network simulation.**

---
⚠️ HEXGATE IS USABLE BUT NOT PRODUCTION READY ⚠️

API MAY CHANGE QUITE A BIT.

CHECK OUT THE [ISSUES](https://github.com/alexdesander/hexgate/issues) FOR MORE INFORMATION

---

## Features
- Userfriendly API
    - with blocking and polling api calls
- Pure UDP
- Multi-platform (check out [mio's supported platforms](https://github.com/tokio-rs/mio#platforms))
- Connection oriented
- Message oriented
- Different delivery guarantees:
    - Unreliable
    - UnreliableOrdered (aka Sequenced)
    - Reliable
- Multiple virtual channels with weights (to avoid head-of-line blocking (problem in TCP))
    - Up to 256 reliable channels
    - Up to 256 unreliable ordered channels
- Runs on a dedicated thread
- Simple but powerful network simulation
- Cryptography:
    - SipHash authenticated initial server-hello (ddos protection)
    - Server auth based on ed25519 signatures
    - x25519 diffie hellman key exchange
    - AES256GCM / ChaCha20Poly1305 authenticated encryption
    - SipHash authenticated acks (for performance reasons)
- Timeout detection
- Latency (Delay/Ping) probing
- Congestion control


Hexgate does NOT do:
- Serialization (recommendations: [bitcode](https://crates.io/crates/bitcode), [bincode](https://crates.io/crates/bincode) (2.0))
- Compression (recommendation: [zstd](https://crates.io/crates/zstd))
- Peer-to-peer
- MTU discovery (minimum assumed MTU size is ~1250 bytes)

## Example
Creating and running a hexgate server:
```rust
/// Only for simplicity, allows every client to join.
struct UselessAuthenticator;
impl Authenticator<()> for UselessAuthenticator {
    fn authenticate(&mut self, _: SocketAddr, _: Vec<u8>) -> Result<(), Vec<u8>> {
        Ok(())
    }
}

let server = Server::prepare()
    .bind_addr(SERVER_ADDR)
    .info(b"Example of a hexgate server".to_vec())
    .allowed_client_versions(|_| Ok(()))
    .secret_key([0u8; 32])
    .auth_salt([0u8; 16])
    .authenticator(UselessAuthenticator)
    .channel_config(ChannelConfiguration {
        weight_unreliable: 15,
        weights_unreliable_ordered: vec![4, 4],
        weights_reliable: vec![10, 10, 10],
    })
    .run()?;

match server.next() {
    _ => todo!("Handle server events")
}
```

Creating a hexgate client and connecting to a server:
```rust
let client = Client::prepare()
    .client_version(ClientVersion::ZERO)
    .server_socket_addr(SERVER_ADDR)
    .auth_data(username)
    .hash_auth_data(false)
    .channel_config(ChannelConfiguration {
        weight_unreliable: 15,
        weights_unreliable_ordered: vec![4, 4],
        weights_reliable: vec![10, 10, 10],
    })
    .connect()?;

client.send(Channel::Unreliable, vec![1, 2, 3])?;

match client.next() {
    _ => todo!("Handle client events")
}
```

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
