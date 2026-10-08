// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{
    borrow::Cow,
    io::{self, ErrorKind},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

#[cfg(feature = "argon2")]
use argon2::{Argon2, Params};
use crossbeam_channel::Receiver;
use ed25519_dalek::VerifyingKey;
use mio::{Events, Poll};
#[cfg(feature = "argon2")]
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, ReusableSecret};

use super::{ConnectError, ServerKey, thread::Cmd};
use crate::common::{
    ClientVersion, PROTOCOL_VERSION,
    crypto::Crypto,
    packets::{
        client_hello::ClientHello,
        connection_request::ConnectionRequest,
        connection_response::{self, ConnectionResponse, Transcript},
        login_request::LoginRequest,
        login_response::LoginResponse,
        server_hello::ServerHello,
    },
    socket::Socket,
};

/// First retransmission interval of a handshake step, doubled up to the maximum.
const HANDSHAKE_RESEND_INTERVAL: Duration = Duration::from_millis(250);
const MAX_HANDSHAKE_RESEND_INTERVAL: Duration = Duration::from_secs(1);

pub(super) struct Handshake {
    pub server_key: ServerKey,
    pub auth_data: Vec<u8>,
    #[cfg(feature = "argon2")]
    pub hash_auth_data: bool,
    pub client_version: ClientVersion,
    pub channel_counts: [u16; 2],
    pub timeout: Duration,
    pub tries: u8,
}

/// The network thread's socket, and the commands the app sends during the handshake.
pub(super) struct Link<'a> {
    pub socket: &'a mut Socket,
    pub poll: &'a mut Poll,
    pub cmds: &'a Receiver<Cmd>,
    /// Run once connected.
    pub pending: Vec<Cmd>,
    pub cancelled: &'a AtomicBool,
}

impl Handshake {
    /// Returns the connection's keys and the server's key.
    pub fn run(&self, link: &mut Link) -> Result<(Crypto, VerifyingKey), ConnectError> {
        let mut buf = [0u8; 1201];
        for _ in 0..self.tries {
            // ClientHello -> ServerHello
            let real_salt: [u8; 4] = rand::random();
            let client_hello = ClientHello {
                salt: real_salt,
                client_version: self.client_version,
            };
            let size = client_hello.serialize(&mut buf);
            let server_hello =
                link.step(
                    &buf[..size],
                    self.timeout,
                    |packet| match ServerHello::deserialize(packet).ok()? {
                        ServerHello::VersionNotSupported {
                            salt,
                            allowed_versions,
                        } => (salt == real_salt)
                            .then_some(Err(ConnectError::VersionNotSupported(allowed_versions))),
                        ServerHello::ServerFull { salt } => {
                            (salt == real_salt).then_some(Err(ConnectError::ServerFull))
                        }
                        ServerHello::ProtocolMismatch {
                            salt,
                            server_version,
                        } => (salt == real_salt).then_some(Err(ConnectError::ProtocolMismatch {
                            client: PROTOCOL_VERSION,
                            server: server_version,
                        })),
                        ServerHello::VersionSupported {
                            salt,
                            timestamp,
                            cipher,
                            server_ed25519_pubkey,
                            siphash,
                            channel_counts,
                        } => (salt == real_salt).then_some(Ok((
                            timestamp,
                            cipher,
                            server_ed25519_pubkey,
                            siphash,
                            channel_counts,
                        ))),
                    },
                )?;
            let Some((timestamp, cipher, server_ed25519_pubkey, siphash, channel_counts)) =
                server_hello
            else {
                log!(debug, "no ServerHello, restarting the handshake");
                continue;
            };

            if let ServerKey::Pinned(key) = self.server_key {
                if server_ed25519_pubkey.to_bytes() != key {
                    return Err(ConnectError::ServerKeyMismatch {
                        received_key: server_ed25519_pubkey.to_bytes(),
                    });
                }
            }
            if channel_counts != self.channel_counts {
                return Err(ConnectError::ChannelMismatch {
                    client: self.channel_counts,
                    server: channel_counts,
                });
            }

            // ConnectionRequest -> ConnectionResponse
            let client_x25519_key = ReusableSecret::random_from_rng(&mut rand::rng());
            let hkdf_salt: [u8; 32] = rand::random();
            let connection_request = ConnectionRequest {
                salt: real_salt,
                timestamp,
                server_ed25519_pubkey,
                siphash: siphash.unwrap().to_le_bytes(),
                client_x25519_pubkey: PublicKey::from(&client_x25519_key),
                hkdf_salt,
            };
            let size = connection_request.serialize(&mut buf);
            let transcript = Transcript {
                request: &buf[connection_response::SIGNED_REQUEST],
                cipher,
                channel_counts,
            };
            let connection_response = link.step(&buf[..size], self.timeout, |packet| {
                let (response, crypto) = ConnectionResponse::deserialize(
                    packet,
                    server_ed25519_pubkey,
                    &client_x25519_key,
                    hkdf_salt,
                    &transcript,
                )
                .ok()?;
                (response.salt == real_salt).then_some(Ok((crypto, response.auth_salt)))
            })?;
            let Some((crypto, auth_salt)) = connection_response else {
                log!(debug, "no ConnectionResponse, restarting the handshake");
                continue;
            };

            // LoginRequest -> LoginResponse
            let login_request = LoginRequest {
                salt: real_salt,
                auth_data: &self.login_auth_data(&server_ed25519_pubkey, auth_salt),
            };
            let size = login_request.serialize(&crypto, &mut buf);
            let login =
                link.step(
                    &buf[..size],
                    self.timeout,
                    |packet| match LoginResponse::deserialize(&crypto, packet).ok()? {
                        LoginResponse::Failure { failure_data } => {
                            Some(Err(ConnectError::ServerDeniedLogin(failure_data.to_vec())))
                        }
                        LoginResponse::Success => Some(Ok(())),
                    },
                )?;
            if login.is_some() {
                return Ok((crypto, server_ed25519_pubkey));
            }
            log!(debug, "no LoginResponse, restarting the handshake");
        }
        Err(ConnectError::IoError(io::Error::new(
            ErrorKind::TimedOut,
            format!("Hexgate Handshake timed out after {} tries", self.tries),
        )))
    }

    #[cfg_attr(not(feature = "argon2"), allow(unused_variables))]
    fn login_auth_data(&self, server_key: &VerifyingKey, auth_salt: [u8; 16]) -> Cow<'_, [u8]> {
        #[cfg(feature = "argon2")]
        if self.hash_auth_data {
            // A rogue server reusing another server's auth_salt must not get hashes valid there.
            let argon2_salt = Sha256::new()
                .chain_update(server_key.as_bytes())
                .chain_update(auth_salt)
                .finalize();
            let mut hashed = vec![0u8; 20];
            Argon2::new(
                argon2::Algorithm::Argon2id,
                argon2::Version::V0x13,
                Params::new(65536, 2, 1, Some(20)).unwrap(),
            )
            .hash_password_into(&self.auth_data, &argon2_salt, &mut hashed)
            .unwrap();
            return Cow::Owned(hashed);
        }
        Cow::Borrowed(&self.auth_data)
    }
}

impl Link<'_> {
    /// Sends `packet` with backoff until `parse` accepts a response, `Ok(None)` after `timeout`.
    fn step<T>(
        &mut self,
        packet: &[u8],
        timeout: Duration,
        mut parse: impl FnMut(&mut [u8]) -> Option<Result<T, ConnectError>>,
    ) -> Result<Option<T>, ConnectError> {
        let mut events = Events::with_capacity(4);
        let mut buf = [0u8; 1201];
        let deadline = Instant::now() + timeout;
        let mut resend_interval = HANDSHAKE_RESEND_INTERVAL;
        let mut resend_at = Instant::now();
        let mut receive_pending = false;
        loop {
            self.take_cmds()?;
            self.socket.flush();
            let now = Instant::now();
            if now >= deadline {
                return Ok(None);
            }
            if now >= resend_at {
                log!(trace, packet = packet[0], "sending handshake packet");
                self.socket.send(packet);
                resend_at = now + resend_interval;
                resend_interval = (resend_interval * 2).min(MAX_HANDSHAKE_RESEND_INTERVAL);
            }
            for _ in 0..128 {
                let Some((size, _)) = self.socket.recv_from(&mut buf)? else {
                    receive_pending = false;
                    break;
                };
                receive_pending = true;
                if (1..=1200).contains(&size) {
                    if let Some(result) = parse(&mut buf[..size]) {
                        return result.map(Some);
                    }
                }
            }
            let wait = resend_at
                .min(deadline)
                .min(self.socket.next_deadline().unwrap_or(deadline))
                .saturating_duration_since(Instant::now());
            let wait = if receive_pending || !self.cmds.is_empty() {
                Duration::ZERO
            } else {
                wait
            };
            match self.poll.poll(&mut events, Some(wait)) {
                Err(e) if e.kind() != ErrorKind::Interrupted => return Err(e.into()),
                _ => {}
            }
        }
    }

    /// A disconnect cancels the handshake, stats aren't available yet (`Client::stats` returns
    /// `None`), everything else waits for the connection.
    fn take_cmds(&mut self) -> Result<(), ConnectError> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(ConnectError::Cancelled);
        }
        for cmd in self.cmds.try_iter().take(256) {
            match cmd {
                Cmd::Disconnect(_) => return Err(ConnectError::Cancelled),
                Cmd::Stats(_) | Cmd::ChannelStats(_, _) => {}
                Cmd::SetSimulator(simulator) => {
                    self.pending.retain(|cmd| !matches!(cmd, Cmd::SetSimulator(_)));
                    self.pending.push(Cmd::SetSimulator(simulator));
                }
                Cmd::Flush => {
                    if !self.pending.iter().rev().take_while(|cmd| !matches!(cmd, Cmd::Send(..)))
                        .any(|cmd| matches!(cmd, Cmd::Flush)) {
                        self.pending.push(Cmd::Flush);
                    }
                }
                Cmd::SetPriority(channel, priority) => {
                    self.pending.retain(|cmd| !matches!(cmd, Cmd::SetPriority(previous, _) if *previous == channel));
                    self.pending.push(Cmd::SetPriority(channel, priority));
                }
                Cmd::ResetChannel(channel) => {
                    if !self.pending.iter().rev()
                        .take_while(|cmd| !matches!(cmd, Cmd::Send(crate::common::channel::Channel::Reliable(previous), _) if *previous == channel))
                        .any(|cmd| matches!(cmd, Cmd::ResetChannel(previous) if *previous == channel)) {
                        self.pending.push(Cmd::ResetChannel(channel));
                    }
                }
                cmd => self.pending.push(cmd),
            }
        }
        Ok(())
    }
}
