// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{
    collections::VecDeque,
    io,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use crossbeam_channel::{Receiver, Sender, TryRecvError};
use mio::{Events, Poll, Waker};

use crate::common::{
    RECV_TOKEN, WAKE_TOKEN,
    channel::Channel,
    error::RecvError,
    events::{DeliveryBudget, EventSender},
    packets::rejected,
    send::Message,
    socket::sim::Simulator,
    stats::{ChannelStats, Stats},
    transport::{Connection, Output},
};

use super::{Event, Socket};

pub enum Cmd {
    SetSimulator(Simulator),
    Disconnect(Vec<u8>),
    Send(Channel, Message),
    Flush,
    Stats(Sender<Stats>),
    ChannelStats(Channel, Sender<Option<ChannelStats>>),
    ResetChannel(u8),
    SetPriority(Channel, i8),
}

pub struct ClientThreadState {
    pub cmds: Receiver<Cmd>,
    pub event_tx: EventSender<Event>,
    pub poll: Poll,
    pub _waker: Arc<Waker>,
    pub socket: Socket,
    pub buf: [u8; 1201],
    pub connection: Connection,
    /// The send rate, for `Client::gross_send_budget`.
    pub rate: Arc<AtomicU64>,
    pub close_linger: Duration,
    pub outputs: Vec<Output>,
    pub receive_pending: bool,
}

impl ClientThreadState {
    /// `pending`: commands sent during the handshake.
    pub fn run(&mut self, pending: Vec<Cmd>) -> Result<(), RecvError> {
        let mut pending: VecDeque<_> = pending.into();
        let mut events = Events::with_capacity(16);
        loop {
            if self.handle_all_cmds(&mut pending) {
                return Ok(());
            }
            let now = Instant::now();
            let mut budget = self.event_tx.budget();
            let before_delivery = (budget.messages, budget.work);
            self.connection
                .drain_received(&mut budget, &mut self.outputs);
            if self.handle_outputs(now) {
                return Ok(());
            }
            if self.connection.on_timeout(now) {
                let size = self.connection.close_now(b"Timeout", now, &mut self.buf);
                self.socket.send(&self.buf[..size]);
                log!(debug, "timed out");
                self.event_tx.send(Event::TimedOut);
                return Ok(());
            }
            self.transmit(now);
            self.connection
                .take_send_results(&mut budget, &mut self.outputs);
            if self.handle_outputs(now) {
                return Ok(());
            }
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
            let delivery_pending = before_delivery != (budget.messages, budget.work)
                && self.connection.has_pending_delivery()
                && self.event_tx.budget().messages > 0
                && self.event_tx.budget().bytes > 0;
            let max_poll_time = if self.receive_pending
                || delivery_pending
                || !pending.is_empty()
                || !self.cmds.is_empty()
            {
                Some(Duration::ZERO)
            } else {
                deadline.map(|deadline| deadline.saturating_duration_since(Instant::now()))
            };
            // A signal handler ran, nothing happened on the socket.
            match self.poll.poll(&mut events, max_poll_time) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                result => result?,
            }
            self.socket.flush();
            let readable = events.iter().any(|event| event.token() == RECV_TOKEN);
            debug_assert!(
                events
                    .iter()
                    .all(|event| [RECV_TOKEN, WAKE_TOKEN].contains(&event.token()))
            );
            if (self.receive_pending || readable || self.socket.inbound_due())
                && self.handle_all_recvs(&mut budget)?
            {
                return Ok(());
            }
        }
    }

    fn transmit(&mut self, now: Instant) {
        for _ in 0..64 {
            let Some(size) = self.connection.poll_transmit(now, &mut self.buf) else {
                break;
            };
            self.socket.send(&self.buf[..size]);
        }
        self.rate
            .store(self.connection.rate() as u64, Ordering::Relaxed);
    }

    /// Returns true once all `Client` handles are gone.
    fn handle_all_cmds(&mut self, pending: &mut VecDeque<Cmd>) -> bool {
        for _ in 0..256 {
            if let Some(cmd) = pending.pop_front() {
                self.handle_cmd(cmd);
                continue;
            }
            match self.cmds.try_recv() {
                Ok(cmd) => self.handle_cmd(cmd),
                Err(TryRecvError::Empty) => return false,
                Err(TryRecvError::Disconnected) => return true,
            }
        }
        false
    }

    fn handle_cmd(&mut self, cmd: Cmd) {
        let now = Instant::now();
        match cmd {
            Cmd::Disconnect(reason) => self.connection.close(reason.into(), self.close_linger, now),
            Cmd::Send(channel, message) => self.connection.push_message(channel, message),
            Cmd::Flush => self.connection.flush(),
            Cmd::Stats(reply) => {
                let _ = reply.send(self.connection.stats());
            }
            Cmd::ChannelStats(channel, reply) => {
                let _ = reply.send(self.connection.channel_stats(channel, now));
            }
            Cmd::ResetChannel(channel) => self.connection.reset_channel(channel),
            Cmd::SetPriority(channel, priority) => self.connection.set_priority(channel, priority),
            Cmd::SetSimulator(simulator) => self.socket.set_simulator(simulator),
        }
    }

    /// Returns true when the connection ended.
    fn handle_all_recvs(&mut self, budget: &mut DeliveryBudget) -> Result<bool, io::Error> {
        self.receive_pending = true;
        for _ in 0..128 {
            let Some((size, _)) = self.socket.recv_from(&mut self.buf)? else {
                self.receive_pending = false;
                break;
            };
            if size == 0 || size > 1200 {
                log!(trace, size, "dropped datagram of invalid size");
                continue;
            }
            let now = Instant::now();
            if let Err(error) = self.connection.handle_with_budget(
                now,
                &mut self.buf[..size],
                budget,
                &mut self.outputs,
            ) {
                rejected("datagram", "server", error);
            }
            if self.handle_outputs(now) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn handle_outputs(&mut self, now: Instant) -> bool {
        for output in std::mem::take(&mut self.outputs) {
            match output {
                Output::SendResult(cookie, outcome) => {
                    self.event_tx.send(Event::SendResult(cookie, outcome))
                }
                Output::Message(channel, message) => {
                    self.event_tx.send(Event::Received(channel, message))
                }
                Output::Closed(reason) => {
                    self.transmit(now);
                    log!(debug, "disconnected by server");
                    self.event_tx.send(Event::Disconnected(reason));
                    return true;
                }
                Output::Violation(violation) => {
                    let reason = violation.to_string();
                    let size = self
                        .connection
                        .close_now(reason.as_bytes(), now, &mut self.buf);
                    self.socket.send(&self.buf[..size]);
                    log!(warn, %violation, "protocol violation");
                    self.event_tx.send(Event::Violation(violation));
                    return true;
                }
            }
        }
        false
    }
}
