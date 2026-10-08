// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{
    io,
    rc::Rc,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use crossbeam::channel::{Receiver, Sender, TryRecvError};
use mio::{Events, Poll, Waker};

use crate::common::{
    channel::Channel,
    error::RecvError,
    events::EventSender,
    packets::rejected,
    socket::sim::Simulator,
    stats::Stats,
    transport::{Connection, Output},
    RECV_TOKEN, WAKE_TOKEN,
};

use super::{Event, Socket};

pub enum Cmd {
    SetSimulator(Simulator),
    Disconnect(Vec<u8>),
    Send(Channel, Vec<u8>),
    Flush,
    Stats(Sender<Stats>),
}

pub struct ClientThreadState {
    pub cmds: Receiver<Cmd>,
    pub event_tx: EventSender<Event>,
    pub poll: Poll,
    pub _waker: Arc<Waker>,
    pub socket: Socket,
    pub buf: [u8; 1201],
    pub connection: Connection,
    /// The send rate, for `Client::budget_for`.
    pub rate: Arc<AtomicU64>,
    pub close_linger: Duration,
    pub outputs: Vec<Output>,
}

impl ClientThreadState {
    /// `pending`: commands sent during the handshake.
    pub fn run(&mut self, pending: Vec<Cmd>) -> Result<(), RecvError> {
        for cmd in pending {
            self.handle_cmd(cmd);
        }
        let mut events = Events::with_capacity(16);
        loop {
            if self.handle_all_cmds() {
                return Ok(());
            }
            let now = Instant::now();
            if self.connection.on_timeout(now) {
                let size = self.connection.close_now(b"Timeout", now, &mut self.buf);
                self.socket.send(&self.buf[..size]);
                log!(debug, "timed out");
                self.event_tx.send(Event::TimedOut);
                return Ok(());
            }
            self.transmit(now);
            if self.connection.is_closed() {
                log!(debug, "closed");
                return Ok(());
            }
            let deadline = self
                .connection
                .timeout(now)
                .into_iter()
                .chain(self.socket.next_deadline())
                .min();
            let max_poll_time =
                deadline.map(|deadline| deadline.saturating_duration_since(Instant::now()));
            // A signal handler ran, nothing happened on the socket.
            match self.poll.poll(&mut events, max_poll_time) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                result => result?,
            }
            self.socket.flush();
            let readable = events.iter().any(|event| event.token() == RECV_TOKEN);
            debug_assert!(events
                .iter()
                .all(|event| [RECV_TOKEN, WAKE_TOKEN].contains(&event.token())));
            if (readable || self.socket.inbound_due()) && self.handle_all_recvs()? {
                return Ok(());
            }
        }
    }

    fn transmit(&mut self, now: Instant) {
        while let Some(size) = self.connection.poll_transmit(now, &mut self.buf) {
            self.socket.send(&self.buf[..size]);
        }
        self.rate
            .store(self.connection.rate() as u64, Ordering::Relaxed);
    }

    /// Returns true once all `Client` handles are gone.
    fn handle_all_cmds(&mut self) -> bool {
        loop {
            match self.cmds.try_recv() {
                Ok(cmd) => self.handle_cmd(cmd),
                Err(TryRecvError::Empty) => return false,
                Err(TryRecvError::Disconnected) => return true,
            }
        }
    }

    fn handle_cmd(&mut self, cmd: Cmd) {
        let now = Instant::now();
        match cmd {
            Cmd::Disconnect(reason) => self.connection.close(reason.into(), self.close_linger, now),
            Cmd::Send(channel, message) => self.connection.push(channel, Rc::new(message), now),
            Cmd::Flush => self.connection.flush(),
            Cmd::Stats(reply) => {
                let _ = reply.send(self.connection.stats());
            }
            Cmd::SetSimulator(simulator) => self.socket.set_simulator(simulator),
        }
    }

    /// Returns true when the connection ended.
    fn handle_all_recvs(&mut self) -> Result<bool, io::Error> {
        while let Some((size, _)) = self.socket.recv_from(&mut self.buf)? {
            if size == 0 || size > 1200 {
                log!(trace, size, "dropped datagram of invalid size");
                continue;
            }
            let now = Instant::now();
            let accept = self.event_tx.has_room();
            if let Err(error) =
                self.connection
                    .handle(now, &mut self.buf[..size], accept, &mut self.outputs)
            {
                rejected("datagram", "server", error);
            }
            for output in std::mem::take(&mut self.outputs) {
                match output {
                    Output::Message(message) => self.event_tx.send(Event::Received(message)),
                    Output::Closed(reason) => {
                        self.transmit(now);
                        log!(debug, "disconnected by server");
                        self.event_tx.send(Event::Disconnected(reason));
                        return Ok(true);
                    }
                    Output::Violation(violation) => {
                        let reason = violation.to_string();
                        let size = self
                            .connection
                            .close_now(reason.as_bytes(), now, &mut self.buf);
                        self.socket.send(&self.buf[..size]);
                        log!(warn, %violation, "protocol violation");
                        self.event_tx.send(Event::Violation(violation));
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }
}
