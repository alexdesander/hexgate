// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{
    io::{self, ErrorKind},
    net::{SocketAddr, UdpSocket},
    sync::{mpsc, Arc},
    thread::JoinHandle,
    time::{Duration, Instant},
};

use argon2::{Argon2, Params};
use bon::bon;
use crossbeam::channel::{bounded, unbounded, Receiver, Sender, TryRecvError};
use ed25519_dalek::VerifyingKey;
use mio::{Poll, Waker};
use rand::thread_rng;
use thread::{ClientThreadState, Cmd};
use x25519_dalek::{PublicKey, ReusableSecret};

use crate::common::{
    channel::{scheduler::ChannelConfiguration, Channel, Channels},
    congestion::{CongestionConfiguration, CongestionController},
    crypto::Crypto,
    packets::{
        client_hello::ClientHello, connection_request::ConnectionRequest,
        connection_response::ConnectionResponse, info_request::InfoRequest,
        info_response::InfoResponse, login_request::LoginRequest, login_response::LoginResponse,
        server_hello::ServerHello,
    },
    socket::{net_sym::NetworkSimulator, Socket},
    timed_event_queue::TimedEventQueue,
    AllowedClientVersions, Cipher, ClientVersion, WAKE_TOKEN,
};

mod thread;

#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error("Some io error occurred: {0}")]
    IoError(#[from] io::Error),
    #[error("Client version not supported by server: {0:?}")]
    VersionNotSupported(AllowedClientVersions),
    #[error("Server denied login")]
    ServerDeniedLogin(Vec<u8>),
    #[error("The server's public key does not match the expected key (possible SECURITY IMPLICATIONS!!!)")]
    ServerKeyMismatch { received_key: [u8; 32] },
}

/// Request server infos from a list of servers.
/// This will block until duration has elapsed (even if all servers responded already).
/// This would normally be used to get data to display to the user in a server browser.
///
/// This does not handle lost packets, so it is possible that some servers will not respond.
/// This would easily be fixed by just sending the requests again for servers that did not respond yet.
pub fn request_infos(
    socket: &UdpSocket,
    duration: Duration,
    server_addrs: &[SocketAddr],
    results: mpsc::Sender<(SocketAddr, Vec<u8>)>,
) -> Result<(), io::Error> {
    // Send info requests
    let mut buf = [0u8; 257];
    let request = InfoRequest::new();
    request.serialize(&mut buf);

    for addr in server_addrs {
        socket.send_to(&buf, addr)?;
    }

    // Wait for responses
    let start = Instant::now();
    loop {
        if start.elapsed() >= duration {
            break;
        }
        socket.set_read_timeout(Some(duration.saturating_sub(start.elapsed())))?;
        let (size, server_addr) = match socket.recv_from(&mut buf) {
            Ok(x) => x,
            Err(ref e)
                if e.kind() == ErrorKind::WouldBlock
                    || e.kind() == ErrorKind::TimedOut
                    // Windows shenanigans
                    || e.kind() == ErrorKind::ConnectionReset =>
            {
                continue
            }
            Err(e) => return Err(e),
        };
        let Ok(info_response) = InfoResponse::deserialize(&buf[..size]) else {
            continue;
        };
        if results
            .send((server_addr, info_response.data.to_vec()))
            .is_err()
        {
            break;
        }
    }
    Ok(())
}

pub enum Event {
    Disconnected(Vec<u8>),
    TimedOut,
    Received(Vec<u8>),
}

#[derive(Clone)]
pub struct Client {
    inner: Arc<ClientInner>,
}

impl Client {
    /// This is non-blocking, Err(()) means the client has shutdown
    pub fn try_next(&self) -> Result<Option<Event>, ()> {
        match self.inner.event_rx.try_recv() {
            Ok(event) => Ok(Some(event)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(()),
        }
    }

    /// This is blocking, Err(()) means the client has shutdown
    pub fn next(&self) -> Result<Event, ()> {
        self.inner.event_rx.recv().map_err(|_| ())
    }

    pub fn send(&self, channel: Channel, message: Vec<u8>) -> Result<(), ()> {
        self.inner
            .cmd_tx
            .send(Cmd::Send(channel, message))
            .map_err(|_| ())?;
        let _ = self.inner.waker.wake();
        Ok(())
    }

    pub fn disconnect(&self, data: Vec<u8>) {
        let _ = self.inner.cmd_tx.send(Cmd::Disconnect(data));
        let _ = self.inner.waker.wake();
    }

    pub fn set_simulator(&self, simulator: Option<Box<dyn NetworkSimulator>>) {
        let _ = self.inner.cmd_tx.send(Cmd::SetSimulator(simulator));
        let _ = self.inner.waker.wake();
    }

    pub fn get_server_key(&self) -> [u8; 32] {
        self.inner.server_ed25519_pubkey.to_bytes()
    }
}

struct ClientInner {
    server_ed25519_pubkey: VerifyingKey,
    cmd_tx: Sender<Cmd>,
    event_rx: Receiver<Event>,
    waker: Arc<Waker>,
    thread: Option<JoinHandle<Result<(), io::Error>>>,
}

impl Drop for ClientInner {
    fn drop(&mut self) {
        let _ = self.cmd_tx.send(Cmd::Disconnect(vec![]));
        let _ = self.waker.wake();
        let _ = self.thread.take().unwrap().join();
    }
}

#[bon]
impl Client {
    /// Prepares the client and connects to the server (when connect is called).
    /// This is blocking as long as the handshake with the server is not done.
    /// You can freely run this on a different thread and then send the client back to your main thread.
    #[builder(finish_fn = connect)]
    pub fn prepare(
        #[builder(default = "0.0.0.0:0".parse().unwrap())] bind_addr: SocketAddr,
        server_socket_addr: SocketAddr,
        expected_server_key: Option<[u8; 32]>,
        auth_data: Vec<u8>,
        hash_auth_data: bool,
        simulator: Option<Box<dyn NetworkSimulator>>,
        socket_buffer_size: Option<usize>,
        client_version: ClientVersion,
        #[builder(default = Duration::from_secs(10))] timeout_dur: Duration,
        channel_config: ChannelConfiguration,
        #[builder(default)] congestion_config: CongestionConfiguration,
    ) -> Result<Self, ConnectError> {
        const READ_COOLDOWN: Duration = Duration::from_millis(50);

        let mut socket = Socket::builder()
            .bind_addr(bind_addr)
            .connected_to(server_socket_addr)
            .maybe_buffer_size_bytes(socket_buffer_size)
            .maybe_simulator(simulator)
            .build()?;
        let mut buf = [0u8; 1201];

        // Send ClientHello
        let real_salt: [u8; 4] = rand::random();
        let client_hello = ClientHello {
            salt: real_salt,
            client_version,
        };
        let size = client_hello.serialize(&mut buf);
        socket.send(&buf[..size])?;

        let start = Instant::now();

        // Wait for ServerHello
        let timestamp: [u8; 8];
        let cipher: Cipher;
        let server_ed25519_pubkey: VerifyingKey;
        let siphash: u64;
        loop {
            check_timeout_handshake(timeout_dur, start)?;
            let Some(size) = read_socket(&mut socket, &mut buf)? else {
                std::thread::sleep(READ_COOLDOWN);
                continue;
            };
            if size == 0 || size > 1200 {
                continue;
            }
            let Ok(server_hello) = ServerHello::deserialize(&buf[..size]) else {
                continue;
            };
            match server_hello {
                ServerHello::VersionNotSupported {
                    salt,
                    allowed_versions,
                } => {
                    if salt == real_salt {
                        return Err(ConnectError::VersionNotSupported(allowed_versions));
                    }
                }
                ServerHello::VersionSupported {
                    salt,
                    timestamp: _timestamp,
                    cipher: _cipher,
                    server_ed25519_pubkey: _server_ed25519_pubkey,
                    siphash: _siphash,
                } => {
                    if salt != real_salt {
                        continue;
                    }
                    timestamp = _timestamp;
                    cipher = _cipher;
                    server_ed25519_pubkey = _server_ed25519_pubkey;
                    siphash = _siphash.unwrap();
                    break;
                }
            }
        }

        if let Some(expected_server_key) = expected_server_key {
            if server_ed25519_pubkey.to_bytes() != expected_server_key {
                return Err(ConnectError::ServerKeyMismatch {
                    received_key: server_ed25519_pubkey.to_bytes(),
                });
            }
        }

        // Send ConnectionRequest
        let client_x25519_key = ReusableSecret::random_from_rng(&mut thread_rng());
        let hkdf_salt: [u8; 32] = rand::random();
        let connection_request = ConnectionRequest {
            salt: real_salt,
            timestamp,
            server_ed25519_pubkey,
            siphash: siphash.to_le_bytes(),
            client_x25519_pubkey: PublicKey::from(&client_x25519_key),
            hkdf_salt,
        };
        let size = connection_request.serialize(&mut buf);
        socket.send(&buf[..size])?;

        // Wait for ConnectionResponse
        let crypto: Crypto;
        let auth_salt: [u8; 16];
        loop {
            check_timeout_handshake(timeout_dur, start)?;
            let Some(size) = read_socket(&mut socket, &mut buf)? else {
                std::thread::sleep(READ_COOLDOWN);
                continue;
            };
            if size == 0 || size > 1200 {
                continue;
            }
            let Ok((connection_response, _crypto)) = ConnectionResponse::deserialize(
                &buf[..size],
                server_ed25519_pubkey,
                client_x25519_key.clone(),
                hkdf_salt,
                cipher,
            ) else {
                continue;
            };
            if connection_response.salt != real_salt {
                continue;
            }
            crypto = _crypto;
            auth_salt = connection_response.auth_salt;
            break;
        }

        // Send LoginRequest
        let auth_data = if hash_auth_data {
            let mut new_auth_data = vec![0u8; 20];
            Argon2::new(
                argon2::Algorithm::Argon2id,
                argon2::Version::V0x13,
                Params::new(65536, 2, 1, Some(20)).unwrap(),
            )
            .hash_password_into(&auth_data, &auth_salt, &mut new_auth_data)
            .unwrap();
            new_auth_data
        } else {
            auth_data
        };
        let login_request = LoginRequest {
            salt: real_salt,
            auth_data: &auth_data,
        };
        let size = login_request.serialize(&crypto, &mut buf);
        socket.send(&buf[..size])?;

        // Receive LoginResponse
        loop {
            check_timeout_handshake(timeout_dur, start)?;
            let Some(size) = read_socket(&mut socket, &mut buf)? else {
                std::thread::sleep(READ_COOLDOWN);
                continue;
            };
            if size == 0 || size > 1200 {
                continue;
            }
            let Ok(login_response) = LoginResponse::deserialize(&crypto, &mut buf[..size]) else {
                continue;
            };
            match login_response {
                LoginResponse::Failure { failure_data } => {
                    return Err(ConnectError::ServerDeniedLogin(failure_data.to_vec()));
                }
                LoginResponse::Success => {
                    break;
                }
            }
        }

        // Handshake done, run thread
        let (event_tx, event_rx) = bounded(1024);
        let (cmd_tx, cmd_rx) = unbounded();
        let poll = Poll::new()?;
        let waker = Arc::new(Waker::new(poll.registry(), WAKE_TOKEN)?);
        let _waker = waker.clone();
        let thread = std::thread::spawn(move || {
            let congestion = CongestionController::new(congestion_config);
            let mut state = ClientThreadState {
                cmds: cmd_rx,
                event_tx,
                poll,
                _waker,
                socket,
                buf: [0u8; 1201],

                timed_events: TimedEventQueue::new(),
                crypto,

                latency_discoveries: Default::default(),
                latencies: Default::default(),

                last_received: Instant::now(),
                timeout_dur,

                channels: Channels::new(&congestion, &channel_config),
                channel_config,
                congestion,
                last_sent: Instant::now(),
            };
            state.run()
        });

        Ok(Client {
            inner: Arc::new(ClientInner {
                server_ed25519_pubkey,
                cmd_tx,
                event_rx,
                waker,
                thread: Some(thread),
            }),
        })
    }
}

fn check_timeout_handshake(timeout_dur: Duration, start: Instant) -> Result<(), io::Error> {
    let time_left = timeout_dur.saturating_sub(start.elapsed());
    if time_left == Duration::ZERO {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "Hexgate Handshake timed out",
        ));
    }
    Ok(())
}

fn read_socket(socket: &mut Socket, buf: &mut [u8]) -> Result<Option<usize>, io::Error> {
    match socket.mio_socket().recv(buf) {
        Ok(size) => return Ok(Some(size)),
        Err(ref e)
            if e.kind() == ErrorKind::WouldBlock
                || e.kind() == ErrorKind::TimedOut
                || e.kind() == ErrorKind::ConnectionReset =>
        {
            Ok(None)
        }
        Err(e) => return Err(e),
    }
}
