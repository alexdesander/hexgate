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
    simulator: Option<(Sender<SimulatorThreadCmd>, std::thread::JoinHandle<()>)>,
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

        let simulator = if let Some(simulator) = simulator {
            let _socket = socket.try_clone()?;
            let (sim_cmd_tx, sim_cmd_rx) = crossbeam::channel::unbounded();
            let thread = std::thread::spawn(move || {
                net_sym::simulator_thread(sim_cmd_rx, _socket, simulator)
            });
            Some((sim_cmd_tx, thread))
        } else {
            None
        };

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
    pub fn mio_socket(&mut self) -> &mut mio::net::UdpSocket {
        &mut self.inner.mio_socket
    }

    pub fn set_network_simulator(
        &mut self,
        simulator: Box<dyn net_sym::NetworkSimulator>,
    ) -> Result<(), io::Error> {
        if let Some((sim_cmd_tx, _)) = &self.inner.simulator {
            sim_cmd_tx
                .send(SimulatorThreadCmd::ChangeSimulator(simulator))
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        "Simulator thread not running anymore (changing simulator failed)",
                    )
                })?;
        } else {
            let _socket = self.inner.socket.try_clone()?;
            let (sim_cmd_tx, sim_cmd_rx) = crossbeam::channel::unbounded();
            let thread = std::thread::spawn(move || {
                net_sym::simulator_thread(sim_cmd_rx, _socket, simulator)
            });
            self.inner.simulator = Some((sim_cmd_tx, thread));
        }
        Ok(())
    }

    pub fn set_use_simulator(&mut self, use_simulator: bool) {
        self.inner.use_simulator = use_simulator;
    }

    pub fn send_to(&self, to: SocketAddr, data: &[u8]) -> Result<(), io::Error> {
        assert!(data.len() <= 1200);
        if self.inner.use_simulator && self.inner.simulator.is_some() {
            let (sim_cmd_tx, _) = self.inner.simulator.as_ref().unwrap();
            sim_cmd_tx
                .send(SimulatorThreadCmd::Send(to, data.to_vec()))
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        "Simulator thread not running anymore (sending packet failed)",
                    )
                })?;
        } else {
            if self.inner.socket.send_to(data, to)? != data.len() {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Failed to send all data",
                ));
            }
        }
        Ok(())
    }

    pub fn send(&self, data: &[u8]) -> Result<(), io::Error> {
        self.send_to(self.inner.connected_to.unwrap(), data)?;
        Ok(())
    }
}

impl Drop for SocketInner {
    fn drop(&mut self) {
        self.simulator.take().map(|(cmd, handle)| {
            let _ = cmd.send(SimulatorThreadCmd::Shutdown);
            let _ = handle.join();
        });
    }
}
