// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Encrypted, connection-oriented UDP networking for client-server games.
//!
//! A [`Server`] accepts [`Client`]s after a handshake that authenticates the server by its
//! ed25519 key and the client through your [`Authenticator`]. Both sides then exchange messages
//! on [`Channel`]s with different delivery guarantees and read [`client::Event`]s /
//! [`server::Event`]s.
//!
//! ```no_run
//! use std::net::SocketAddr;
//!
//! use hexgate::{
//!     client, keys, server, Authenticator, Channel, ChannelConfiguration, Client, ClientVersion,
//!     Server, ServerKey,
//! };
//!
//! struct AcceptAll;
//!
//! impl Authenticator<String> for AcceptAll {
//!     fn authenticate(&mut self, _: SocketAddr, name: Vec<u8>) -> Result<String, Vec<u8>> {
//!         String::from_utf8(name).map_err(|_| b"invalid name".to_vec())
//!     }
//! }
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let secret_key = keys::load_or_generate("server.key")?;
//! let server = Server::prepare()
//!     .bind_addr("0.0.0.0:44444".parse()?)
//!     .info(b"My server".to_vec())
//!     .allowed_client_versions(|_| Ok(()))
//!     .secret_key(secret_key)
//!     .auth_salt(keys::load_or_generate("server.salt")?)
//!     .authenticator(AcceptAll)
//!     .channel_config(ChannelConfiguration::default())
//!     .run()?;
//!
//! // Usually in another process: the client ships with the server's public key.
//! let client = Client::prepare()
//!     .client_version(ClientVersion::ZERO)
//!     .server_socket_addr("localhost:44444")
//!     .server_key(ServerKey::Pinned(server::public_key(&secret_key)))
//!     .auth_data(b"Alice".to_vec())
//!     .hash_auth_data(false)
//!     .channel_config(ChannelConfiguration::default())
//!     .connect()?;
//! client.send(Channel::Reliable(0), b"Hello".to_vec())?;
//!
//! // A game loop polls instead of blocking with `next()`.
//! while let Some(event) = server.try_next()? {
//!     match event {
//!         server::Event::Connected(addr, name) => println!("{name} joined from {addr}"),
//!         server::Event::Received(addr, message) => server.send(addr, Channel::Reliable(0), message)?,
//!         _ => {}
//!     }
//! }
//! while let Some(event) = client.try_next()? {
//!     if let client::Event::Received(message) = event {
//!         println!("echo: {message:?}");
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Threads
//!
//! Each `Server` and `Client` runs a network thread (`hexgate-server`, `hexgate-client`) that
//! does all socket IO, encryption, retransmission and timers. The server runs your
//! `Authenticator` on a second thread (`hexgate-auth`). A [`Simulator`] runs on the network
//! thread. `Server` and `Client` are cheap handles (`Clone`, `Send`, `Sync`)
//! that talk to the network thread through channels, so they can be used from any thread.
//! Dropping the last handle closes the connections gracefully (see `close_linger`) and joins the
//! threads.
//!
//! # Backpressure
//!
//! Events are queued for the app. Connection events are always delivered; received messages
//! only while fewer than `max_events` events are queued. Above that, unreliable messages are
//! dropped and reliable packets stay unacknowledged until the app catches up, so the peer resends
//! them. Sent messages are queued without a limit and leave at the congestion controller's rate;
//! [`Stats::queued_bytes`] tells how much is waiting.
//!
//! # Size limits
//!
//! - Messages: `max_send_msg_size` and `max_recv_msg_size` (1 MiB by default). A peer sending a
//!   larger message violates the protocol and is disconnected.
//! - `auth_data`: 1177 bytes, unless hashed with `hash_auth_data`.
//! - Login failure data (returned by the `Authenticator`): 1181 bytes, longer data is truncated.
//! - Disconnect and shutdown reasons: 1183 bytes.
//! - Server info (see [`client::request_infos`]): 256 bytes.
//!
//! # Security
//!
//! - **Handshake.** The server answers a `ClientHello` with a SipHash cookie bound to the
//!   client's address and keeps no state until the cookie comes back. Then client and server
//!   run an x25519 key exchange, which the server signs with its ed25519 key over the whole
//!   handshake transcript. Handshake requests are at least as large as their answers, and key
//!   exchanges and hellos are rate-limited per IPv4 address or IPv6 /64.
//! - **Server identity.** Only [`ServerKey::Pinned`] protects against impersonation: with
//!   `ServerKey::Unverified`, anyone on the network path can pose as the server and read
//!   `auth_data`.
//! - **Client identity** is up to your `Authenticator`. `auth_data` is encrypted;
//!   `hash_auth_data` sends an Argon2id hash salted with the server's key and `auth_salt`
//!   instead. That hash is as good as the password for this server, so hash it again before
//!   storing it. Limit failed attempts per account in the authenticator.
//! - **Traffic.** Messages are encrypted and authenticated with AES-256-GCM or
//!   ChaCha20-Poly1305 ([`Cipher`]), with one key per direction. Acks and latency probes are
//!   only authenticated (SipHash). Replayed and duplicated packets are dropped. A connection is
//!   closed before its message ids would wrap; there is no rekeying.
//! - Keep the server's `secret_key` and `auth_salt` secret and stable, see [`keys`].

#![warn(missing_docs)]

/// A `tracing` event with the `tracing` feature, nothing otherwise.
macro_rules! log {
    ($level:ident, $($arg:tt)+) => {{
        #[cfg(feature = "tracing")]
        tracing::$level!($($arg)+);
    }};
}

#[cfg(feature = "bench")]
#[doc(hidden)]
pub mod bench;
pub mod client;
mod common;
#[cfg(fuzzing)]
#[doc(hidden)]
pub mod fuzz;
pub mod server;

pub use client::{Client, ServerKey};
pub use common::{
    channel::{Channel, ChannelConfiguration},
    congestion::CongestionConfiguration,
    error, fingerprint, keys,
    socket::sim::{self, NetworkSimulator, Simulator},
    stats::Stats,
    AllowedClientVersions, Cipher, ClientVersion,
};
pub use server::{Authenticator, Server};
