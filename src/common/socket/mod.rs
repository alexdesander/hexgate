// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{io, net::SocketAddr, time::Instant};

use bon::bon;
#[cfg(feature = "sim")]
use sim::{DelayQueue, Fate, Simulator};

#[cfg(feature = "sim")]
pub mod sim;

pub(crate) struct Socket {
    inner: SocketInner,
}

struct SocketInner {
    connected_to: Option<SocketAddr>,
    socket: std::net::UdpSocket,
    mio_socket: mio::net::UdpSocket,
    #[cfg(feature = "sim")]
    simulator: Simulator,
    #[cfg(feature = "sim")]
    outbound: DelayQueue,
    #[cfg(feature = "sim")]
    inbound: DelayQueue,
    receive_pending: bool,
}

#[bon]
impl Socket {
    #[builder(finish_fn = build)]
    pub fn builder(
        bind_addr: SocketAddr,
        buffer_size_bytes: Option<usize>,
        #[cfg(feature = "sim")] simulator: Option<Simulator>,
        connected_to: Option<SocketAddr>,
    ) -> Result<Self, io::Error> {
        let socket = std::net::UdpSocket::bind(bind_addr)?;
        socket.set_nonblocking(true)?;
        let socket = socket2::Socket::from(socket);
        if let Some(buffer_size_bytes) = buffer_size_bytes {
            socket.set_recv_buffer_size(buffer_size_bytes)?;
            socket.set_send_buffer_size(buffer_size_bytes)?;
        }
        let socket: std::net::UdpSocket = socket.into();
        if let Some(connected_to) = connected_to {
            socket.connect(connected_to)?;
        }

        Ok(Self {
            inner: SocketInner {
                connected_to,
                mio_socket: mio::net::UdpSocket::from_std(socket.try_clone()?),
                socket,
                #[cfg(feature = "sim")]
                simulator: simulator.unwrap_or_default(),
                #[cfg(feature = "sim")]
                outbound: DelayQueue::default(),
                #[cfg(feature = "sim")]
                inbound: DelayQueue::default(),
                receive_pending: false,
            },
        })
    }
}

impl Socket {
    pub fn local_addr(&self) -> Result<SocketAddr, io::Error> {
        self.inner.socket.local_addr()
    }

    pub fn mio_socket(&mut self) -> &mut mio::net::UdpSocket {
        &mut self.inner.mio_socket
    }

    /// Packets already delayed keep their delivery time.
    #[cfg(feature = "sim")]
    pub fn set_simulator(&mut self, simulator: Simulator) {
        self.inner.simulator = simulator;
    }

    pub fn discard_pending(&mut self) {
        #[cfg(feature = "sim")]
        {
            self.inner.inbound = DelayQueue::default();
            self.inner.outbound = DelayQueue::default();
        }
        self.inner.receive_pending = false;
    }

    #[cfg(feature = "sim")]
    pub fn take_simulator(&mut self) -> Simulator {
        std::mem::take(&mut self.inner.simulator)
    }

    /// Send errors are treated like lost packets: transient conditions (full buffers, ICMP
    /// errors, an unreachable peer) must not take down the connection, timeouts handle the rest.
    pub fn send_to(&mut self, to: SocketAddr, data: &[u8]) {
        assert!(data.len() <= 1200);
        #[cfg(feature = "sim")]
        {
            // Packets due earlier leave first.
            self.flush();
            if self.inner.simulator.send.is_some() {
                self.inner.simulate_send(to, data);
                return;
            }
        }
        self.inner.send_now(to, data);
    }

    pub fn send(&mut self, data: &[u8]) {
        self.send_to(self.inner.connected_to.unwrap(), data);
    }

    /// Sends the delayed packets that are due.
    pub fn flush(&mut self) {
        #[cfg(feature = "sim")]
        if !self.inner.outbound.is_empty() {
            self.inner.flush(Instant::now());
        }
    }

    /// When the next delayed packet is due, see `flush` and `inbound_due`.
    pub fn next_deadline(&self) -> Option<Instant> {
        let receive = self.inner.receive_pending.then(Instant::now);
        #[cfg(feature = "sim")]
        let receive = [
            self.inner.outbound.next_deadline(),
            self.inner.inbound.next_deadline(),
            receive,
        ]
        .into_iter()
        .flatten()
        .min();
        receive
    }

    /// Whether a delayed received packet is due, `recv_from` returns it.
    pub fn inbound_due(&self) -> bool {
        #[cfg(feature = "sim")]
        if self
            .inner
            .inbound
            .next_deadline()
            .is_some_and(|at| at <= Instant::now())
        {
            return true;
        }
        self.inner.receive_pending
    }

    /// Receives the next datagram, `None` means there is none right now. Errors caused by a
    /// single datagram or an ICMP message are skipped, only fatal errors are returned.
    pub fn recv_from(&mut self, buf: &mut [u8]) -> Result<Option<(usize, SocketAddr)>, io::Error> {
        #[cfg(feature = "sim")]
        if self.inner.simulator.recv.is_some() || !self.inner.inbound.is_empty() {
            return self.inner.simulate_recv(buf);
        }
        self.inner.recv_now(buf)
    }
}

impl SocketInner {
    fn send_now(&self, to: SocketAddr, data: &[u8]) {
        send(&self.socket, self.connected_to.is_some(), to, data);
    }

    fn recv_now(&mut self, buf: &mut [u8]) -> Result<Option<(usize, SocketAddr)>, io::Error> {
        for _ in 0..32 {
            match self.mio_socket.recv_from(buf) {
                Ok(received) => {
                    self.receive_pending = true;
                    return Ok(Some(received));
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    self.receive_pending = false;
                    return Ok(None);
                }
                Err(e) if is_transient(&e) => {
                    log!(trace, error = %e, "transient socket error");
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
        self.receive_pending = true;
        Ok(None)
    }
}

#[cfg(feature = "sim")]
impl SocketInner {
    fn simulate_send(&mut self, to: SocketAddr, data: &[u8]) {
        let Some(simulator) = &mut self.simulator.send else {
            return;
        };
        let now = Instant::now();
        let mut packet = self.outbound.buffer(data);
        match simulator.simulate(now, to, &mut packet) {
            Fate::Drop => self.outbound.recycle(packet),
            Fate::Deliver(at) if at <= now => {
                self.send_now(to, &packet);
                self.outbound.recycle(packet);
            }
            Fate::Deliver(at) => self.outbound.push(at, to, packet),
            Fate::Duplicate(first, second) => {
                let copy = self.outbound.buffer(&packet);
                self.outbound.push(first, to, packet);
                self.outbound.push(second, to, copy);
                self.flush(now);
            }
        }
    }

    fn flush(&mut self, now: Instant) {
        for _ in 0..128 {
            let Some(pending) = self.outbound.pop_due(now) else {
                break;
            };
            self.send_now(pending.peer, &pending.data);
            self.outbound.recycle(pending.data);
        }
    }

    fn simulate_recv(&mut self, buf: &mut [u8]) -> Result<Option<(usize, SocketAddr)>, io::Error> {
        let now = Instant::now();
        if self.inbound.next_deadline().is_none_or(|at| at > now) {
            for _ in 0..128 {
                let Some((size, from)) = self.recv_now(buf)? else {
                    break;
                };
                let Some(simulator) = &mut self.simulator.recv else {
                    return Ok(Some((size, from)));
                };
                let mut packet = self.inbound.buffer(&buf[..size]);
                match simulator.simulate(now, from, &mut packet) {
                    Fate::Drop => self.inbound.recycle(packet),
                    Fate::Deliver(at) => self.inbound.push(at, from, packet),
                    Fate::Duplicate(first, second) => {
                        let copy = self.inbound.buffer(&packet);
                        self.inbound.push(first, from, packet);
                        self.inbound.push(second, from, copy);
                    }
                }
            }
        }
        Ok(self.inbound.pop_due(now).map(|pending| {
            let size = pending.data.len();
            buf[..size].copy_from_slice(&pending.data);
            let peer = pending.peer;
            self.inbound.recycle(pending.data);
            (size, peer)
        }))
    }
}

fn send(socket: &std::net::UdpSocket, connected: bool, to: SocketAddr, data: &[u8]) {
    // BSD-derived stacks reject send_to on connected sockets (EISCONN).
    let sent = if connected {
        socket.send(data)
    } else {
        socket.send_to(data, to)
    };
    if let Err(_e) = sent {
        log!(trace, %to, error = %_e, "send failed");
    }
}

/// Errors caused by a single datagram or an ICMP message, the socket itself still works.
pub(crate) fn is_transient(e: &io::Error) -> bool {
    // WSAEMSGSIZE: Windows reports oversized datagrams as an error.
    const WSAEMSGSIZE: i32 = 10040;
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::Interrupted
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkUnreachable
    ) || (cfg!(windows) && e.raw_os_error() == Some(WSAEMSGSIZE))
}

#[cfg(feature = "sim")]
impl Drop for SocketInner {
    /// Packets still delayed are on the wire already, a short-lived thread delivers them.
    fn drop(&mut self) {
        let outbound = std::mem::take(&mut self.outbound);
        if outbound.is_empty() {
            return;
        }
        let Ok(socket) = self.socket.try_clone() else {
            return;
        };
        let connected = self.connected_to.is_some();
        let _ = std::thread::Builder::new()
            .name("hexgate-sim".into())
            .spawn(move || {
                for pending in outbound.into_sorted() {
                    std::thread::sleep(pending.at.saturating_duration_since(Instant::now()));
                    send(&socket, connected, pending.peer, &pending.data);
                }
            });
    }
}
