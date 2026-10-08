use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    sync::{
        Arc, PoisonError, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use crossbeam_channel::{Receiver, TryRecvError, bounded};
use ed25519_dalek::VerifyingKey;
use mio::{Events, Interest, Poll, Waker};

use super::{
    ConnectError,
    handshake::{Handshake, Link},
    thread::Cmd,
};
#[cfg(feature = "sim")]
use crate::common::socket::sim::Simulator;
use crate::common::{RECV_TOKEN, crypto::Crypto, socket::Socket};

type Connected = (Socket, Crypto, VerifyingKey, Vec<Cmd>);

#[allow(clippy::too_many_arguments)]
pub(super) fn connect<A: ToSocketAddrs + Send + 'static>(
    address: A,
    bind: Option<SocketAddr>,
    buffer: Option<usize>,
    #[cfg(feature = "sim")] mut simulator: Option<Simulator>,
    handshake: &Handshake,
    poll: &mut Poll,
    cmds: &Receiver<Cmd>,
    cancelled: &AtomicBool,
    waker: &Arc<Waker>,
    local_addr: &RwLock<Option<SocketAddr>>,
) -> Result<Connected, ConnectError> {
    let (tx, rx) = bounded(1);
    let resolver_waker = waker.clone();
    std::thread::Builder::new()
        .name("hexgate-resolve".into())
        .spawn(move || {
            let result = address
                .to_socket_addrs()
                .map(|addresses| addresses.collect::<Vec<_>>());
            let _ = tx.send(result);
            let _ = resolver_waker.wake();
        })?;
    let mut events = Events::with_capacity(4);
    let addresses = loop {
        if cancelled.load(Ordering::Relaxed) {
            return Err(ConnectError::Cancelled);
        }
        match rx.try_recv() {
            Ok(addresses) => break addresses?,
            Err(TryRecvError::Disconnected) => {
                return Err(io::Error::other("address resolver stopped").into());
            }
            Err(TryRecvError::Empty) => {}
        }
        match poll.poll(&mut events, Some(Duration::from_millis(50))) {
            Err(error) if error.kind() != io::ErrorKind::Interrupted => return Err(error.into()),
            _ => {}
        }
    };
    let mut last_error = io::Error::new(
        io::ErrorKind::InvalidInput,
        "no server address matches bind_addr's IP version",
    );
    let mut pending = Vec::new();
    for address in addresses
        .into_iter()
        .filter(|address| bind.is_none_or(|bind| bind.is_ipv4() == address.is_ipv4()))
    {
        if cancelled.load(Ordering::Relaxed) {
            return Err(ConnectError::Cancelled);
        }
        let bind = bind.unwrap_or_else(|| match address {
            SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
            SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
        });
        let mut socket = match Socket::builder()
            .bind_addr(bind)
            .connected_to(address)
            .maybe_buffer_size_bytes(buffer)
            .build()
        {
            Ok(socket) => socket,
            Err(error) => {
                last_error = error;
                continue;
            }
        };
        #[cfg(feature = "sim")]
        socket.set_simulator(simulator.take().unwrap_or_default());
        *local_addr.write().unwrap_or_else(PoisonError::into_inner) = Some(socket.local_addr()?);
        poll.registry()
            .register(socket.mio_socket(), RECV_TOKEN, Interest::READABLE)?;
        let mut link = Link {
            socket: &mut socket,
            poll,
            cmds,
            pending,
            cancelled,
        };
        let result = handshake.run(&mut link);
        pending = link.pending;
        match result {
            Ok((crypto, key)) => return Ok((socket, crypto, key, pending)),
            Err(ConnectError::IoError(error)) => last_error = error,
            Err(error) => return Err(error),
        }
        poll.registry().deregister(socket.mio_socket())?;
        #[cfg(feature = "sim")]
        {
            simulator = Some(socket.take_simulator());
        }
        socket.discard_pending();
    }
    Err(last_error.into())
}
