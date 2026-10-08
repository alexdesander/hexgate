// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{io, net::SocketAddr};

use bon::bon;
use crossbeam::channel::Sender;
use net_sym::SimulatorThreadCmd;

pub mod net_sym;

pub(crate) struct Socket {
    inner: SocketInner,
}

struct SocketInner {
    connected_to: Option<SocketAddr>,
    socket: std::net::UdpSocket,
    mio_socket: mio::net::UdpSocket,
    use_simulator: bool,
    simulator: Option<Sender<SimulatorThreadCmd>>,
}

#[bon]
impl Socket {
    #[builder(finish_fn = build)]
    pub fn builder(
        bind_addr: SocketAddr,
        buffer_size_bytes: Option<usize>,
        simulator: Option<Box<dyn net_sym::NetworkSimulator>>,
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

        let simulator = simulator
            .map(|simulator| spawn_simulator(&socket, simulator))
            .transpose()?;

        Ok(Self {
            inner: SocketInner {
                connected_to,
                mio_socket: mio::net::UdpSocket::from_std(socket.try_clone()?),
                socket,
                use_simulator: simulator.is_some(),
                simulator,
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

    pub fn set_network_simulator(
        &mut self,
        simulator: Box<dyn net_sym::NetworkSimulator>,
    ) -> Result<(), io::Error> {
        if let Some(sim_cmd_tx) = &self.inner.simulator {
            sim_cmd_tx
                .send(SimulatorThreadCmd::ChangeSimulator(simulator))
                .map_err(|_| {
                    io::Error::other(
                        "Simulator thread not running anymore (changing simulator failed)",
                    )
                })?;
        } else {
            self.inner.simulator = Some(spawn_simulator(&self.inner.socket, simulator)?);
        }
        Ok(())
    }

    pub fn set_use_simulator(&mut self, use_simulator: bool) {
        self.inner.use_simulator = use_simulator;
    }

    /// Send errors are treated like lost packets: transient conditions (full buffers, ICMP
    /// errors, an unreachable peer) must not take down the connection, timeouts handle the rest.
    pub fn send_to(&self, to: SocketAddr, data: &[u8]) {
        assert!(data.len() <= 1200);
        if let Some(sim_cmd_tx) = self
            .inner
            .simulator
            .as_ref()
            .filter(|_| self.inner.use_simulator)
        {
            let _ = sim_cmd_tx.send(SimulatorThreadCmd::Send(to, data.to_vec()));
        } else {
            // BSD-derived stacks reject send_to on connected sockets (EISCONN).
            let sent = match self.inner.connected_to {
                Some(_) => self.inner.socket.send(data),
                None => self.inner.socket.send_to(data, to),
            };
            if let Err(_e) = sent {
                log!(trace, %to, error = %_e, "send failed");
            }
        }
    }

    pub fn send(&self, data: &[u8]) {
        self.send_to(self.inner.connected_to.unwrap(), data);
    }

    /// Receives the next datagram, `None` means there is none right now. Errors caused by a
    /// single datagram or an ICMP message are skipped, only fatal errors are returned.
    pub fn recv_from(&mut self, buf: &mut [u8]) -> Result<Option<(usize, SocketAddr)>, io::Error> {
        loop {
            match self.inner.mio_socket.recv_from(buf) {
                Ok(received) => return Ok(Some(received)),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    return Ok(None)
                }
                Err(e) if is_transient(&e) => {
                    log!(trace, error = %e, "transient socket error");
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }
}

fn spawn_simulator(
    socket: &std::net::UdpSocket,
    simulator: Box<dyn net_sym::NetworkSimulator>,
) -> Result<Sender<SimulatorThreadCmd>, io::Error> {
    let socket = socket.try_clone()?;
    let (sim_cmd_tx, sim_cmd_rx) = crossbeam::channel::unbounded();
    std::thread::Builder::new()
        .name("hexgate-sim".into())
        .spawn(move || net_sym::simulator_thread(sim_cmd_rx, socket, simulator))?;
    Ok(sim_cmd_tx)
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

impl Drop for SocketInner {
    /// The simulator thread delivers the packets it still delays, then exits on its own.
    fn drop(&mut self) {
        if let Some(sim_cmd_tx) = &self.simulator {
            let _ = sim_cmd_tx.send(SimulatorThreadCmd::Shutdown);
        }
    }
}
