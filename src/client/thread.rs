// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    rc::Rc,
    sync::Arc,
    time::{Duration, Instant},
};

use crossbeam::channel::{Receiver, TryRecvError};
use mio::{Events, Poll, Waker};

use crate::common::{
    channel::{scheduler::ChannelConfiguration, Channel, Channels, Pop, IDS_EXHAUSTED},
    congestion::CongestionController,
    crypto::Crypto,
    error::ProtocolViolation,
    events::EventSender,
    packets::{
        acks::Acks,
        disconnect::{self, Disconnect},
        latency_discovery::LatencyDiscovery,
        latency_discovery_response::LatencyDiscoveryResponse,
        latency_discovery_response_2::LatencyDiscoveryResponse2,
        reliable_payload::ReliablePayload,
        unreliable_payload::UnreliablePayload,
        PacketIdentifier,
    },
    socket::net_sym::NetworkSimulator,
    timed_event_queue::TimedEventQueue,
    RECV_TOKEN, WAKE_TOKEN,
};

use super::{Event, Socket};

/// Timeouts are checked this many times per timeout duration.
const TIMEOUT_CHECKS: u32 = 4;

pub enum Cmd {
    SetSimulator(Option<Box<dyn NetworkSimulator>>),
    Disconnect(Vec<u8>),
    Send(Channel, Vec<u8>),
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum TimedEventKey {
    CheckForTimeout,
    Send,
    SendAcks(u8),
    CloseDeadline,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TimedEventData {
    Nothing,
}

pub struct ClientThreadState {
    pub cmds: Receiver<Cmd>,
    pub event_tx: EventSender<Event>,
    pub poll: Poll,
    pub _waker: Arc<Waker>,
    pub socket: Socket,
    pub buf: [u8; 1201],

    pub timed_events: TimedEventQueue<TimedEventKey, TimedEventData>,
    pub crypto: Crypto,

    pub latency_discoveries: BTreeMap<u32, Instant>,
    pub latencies: BTreeSet<u32>,

    pub last_received: Instant,
    pub timeout_dur: Duration,

    pub channel_config: ChannelConfiguration,
    pub channels: Channels,
    pub congestion: CongestionController,
    pub last_sent: Instant,

    pub close_linger: Duration,
    /// Reason of a graceful disconnect in progress.
    pub closing: Option<Vec<u8>>,
}

impl ClientThreadState {
    pub fn run(&mut self) -> Result<(), io::Error> {
        self.timed_events.push(
            TimedEventKey::CheckForTimeout,
            Instant::now() + self.timeout_dur / TIMEOUT_CHECKS,
            TimedEventData::Nothing,
        );

        let mut events = Events::with_capacity(16);

        'outer: loop {
            if self.handle_all_cmds()? || self.handle_all_events() {
                break;
            }
            let max_poll_time = self.timed_events.next().map(|deadline| {
                deadline
                    .saturating_duration_since(Instant::now())
                    .max(Duration::from_millis(1))
            });
            self.poll.poll(&mut events, max_poll_time)?;
            for event in events.iter() {
                match event.token() {
                    RECV_TOKEN => {
                        if self.handle_all_recvs()? {
                            break 'outer;
                        }
                    }
                    WAKE_TOKEN => {}
                    _ => unreachable!(),
                }
            }
        }
        Ok(())
    }

    fn handle_all_cmds(&mut self) -> Result<bool, io::Error> {
        loop {
            let cmd = match self.cmds.try_recv() {
                Ok(cmd) => cmd,
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return Ok(true),
            };

            match cmd {
                Cmd::Disconnect(data) => {
                    if self.closing.is_none() {
                        let now = Instant::now();
                        self.closing = Some(data);
                        self.timed_events.push(
                            TimedEventKey::CloseDeadline,
                            now + self.close_linger,
                            TimedEventData::Nothing,
                        );
                        self.timed_events
                            .push(TimedEventKey::Send, now, TimedEventData::Nothing);
                    }
                }
                Cmd::Send(..) if self.closing.is_some() => {}
                Cmd::Send(channel, payload) => {
                    self.channels.push(channel, Rc::new(payload));
                    self.timed_events.push(
                        TimedEventKey::Send,
                        self.last_sent + self.congestion.downtime_between_batches(),
                        TimedEventData::Nothing,
                    );
                }
                Cmd::SetSimulator(network_simulator) => {
                    if let Some(network_simulator) = network_simulator {
                        self.socket.set_network_simulator(network_simulator)?;
                        self.socket.set_use_simulator(true);
                    } else {
                        self.socket.set_use_simulator(false);
                    }
                }
            }
        }
        Ok(false)
    }

    fn handle_all_events(&mut self) -> bool {
        while self
            .timed_events
            .next()
            .map_or(false, |deadline| deadline <= Instant::now())
        {
            let (key, _event) = self.timed_events.pop().unwrap();
            match key {
                TimedEventKey::Send => {
                    if self.handle_event_send() {
                        return true;
                    }
                }
                TimedEventKey::SendAcks(channel_id) => self.handle_event_send_acks(channel_id),
                TimedEventKey::CloseDeadline => {
                    self.finish_close();
                    return true;
                }
                TimedEventKey::CheckForTimeout => {
                    if self.last_received.elapsed() > self.timeout_dur {
                        let disconnect = Disconnect { data: b"Timeout" };
                        let size = disconnect.serialize(&self.crypto, &mut self.buf);
                        self.socket.send(&self.buf[..size]);
                        self.event_tx.send(Event::TimedOut);
                        return true;
                    } else {
                        self.timed_events.push(
                            TimedEventKey::CheckForTimeout,
                            Instant::now() + self.timeout_dur / TIMEOUT_CHECKS,
                            TimedEventData::Nothing,
                        );
                    }
                }
            }
        }
        false
    }

    fn handle_all_recvs(&mut self) -> Result<bool, io::Error> {
        while let Some((size, _)) = self.socket.recv_from(&mut self.buf)? {
            if size == 0 || size > 1200 {
                continue;
            }
            let Ok(packet_identifier) = PacketIdentifier::try_from(self.buf[0]) else {
                continue;
            };
            let shutdown = match packet_identifier {
                PacketIdentifier::Disconnect => self.handle_packet_disconnect(size),
                PacketIdentifier::LatencyDiscovery => self.handle_packet_latency_discovery(size),
                PacketIdentifier::LatencyDiscoveryResponse2 => {
                    self.handle_packet_latency_response_2(size)
                }
                PacketIdentifier::UnreliableStandalonePayload
                | PacketIdentifier::UnreliableFragmentedPayload
                | PacketIdentifier::UnreliableFragmentedPayloadLast
                | PacketIdentifier::UnreliableOrderedStandalonePayload
                | PacketIdentifier::UnreliableOrderedFragmentedPayload
                | PacketIdentifier::UnreliableOrderedFragmentedPayloadLast => {
                    self.handle_packet_unreliable_payload(size)
                }
                PacketIdentifier::ReliablePayloadNoAcks => {
                    self.handle_packet_reliable_payload(size)
                }
                PacketIdentifier::Acks => self.handle_packet_acks(size),
                _ => false,
            };
            if shutdown {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Returns true when the connection had to be closed.
    fn handle_event_send(&mut self) -> bool {
        let now = Instant::now();
        let downtime = self.congestion.downtime_between_batches();
        while self.congestion.can_send(now) {
            match self
                .channels
                .pop(&mut self.congestion, &self.crypto, &mut self.buf)
            {
                Pop::Packet(size) => {
                    self.last_sent = now;
                    self.socket.send(&self.buf[..size]);
                    self.congestion.consume(size);
                }
                Pop::Wait(time_till_resend) => {
                    let deadline = (now + time_till_resend).max(self.last_sent + downtime);
                    self.timed_events
                        .push(TimedEventKey::Send, deadline, TimedEventData::Nothing);
                    return false;
                }
                Pop::Idle if self.closing.is_some() => {
                    self.finish_close();
                    return true;
                }
                Pop::Idle => return false,
                Pop::Exhausted => {
                    let disconnect = Disconnect {
                        data: IDS_EXHAUSTED,
                    };
                    let size = disconnect.serialize(&self.crypto, &mut self.buf);
                    self.socket.send(&self.buf[..size]);
                    self.event_tx
                        .send(Event::Disconnected(IDS_EXHAUSTED.to_vec()));
                    return true;
                }
            }
        }
        self.timed_events.push(
            TimedEventKey::Send,
            now + self.congestion.time_until_send().max(downtime),
            TimedEventData::Nothing,
        );
        false
    }

    /// Ends a graceful disconnect: everything was sent and acked, or the linger ran out.
    fn finish_close(&mut self) {
        let Some(reason) = &self.closing else {
            return;
        };
        let size = Disconnect { data: reason }.serialize(&self.crypto, &mut self.buf);
        for _ in 0..disconnect::REPEATS {
            self.socket.send(&self.buf[..size]);
        }
    }

    fn handle_event_send_acks(&mut self, channel_id: u8) {
        let acks = self.channels.acks(Channel::Reliable(channel_id));
        let size = acks.serialize(&self.crypto, &mut self.buf);
        self.socket.send(&self.buf[..size]);
    }

    fn handle_packet_disconnect(&mut self, size: usize) -> bool {
        let Ok(disconnect) = Disconnect::deserialize(&self.crypto, &mut self.buf[..size]) else {
            return false;
        };
        self.event_tx
            .send(Event::Disconnected(disconnect.data.to_vec()));
        true
    }

    fn handle_packet_latency_discovery(&mut self, size: usize) -> bool {
        let Ok(latency_discovery) =
            LatencyDiscovery::deserialize(&self.crypto, &mut self.buf[..size])
        else {
            return false;
        };
        if self
            .latency_discoveries
            .contains_key(&latency_discovery.sequence_number)
        {
            return false;
        }
        self.latency_discoveries
            .insert(latency_discovery.sequence_number, Instant::now());
        if self.latency_discoveries.len() > 63 {
            self.latency_discoveries.pop_first();
        }

        let mut latency_discovery_response = LatencyDiscoveryResponse {
            sequence_number: latency_discovery.sequence_number,
            truncated_siphash: 0,
        };
        let size = latency_discovery_response.serialize(&self.crypto, &mut self.buf);
        self.socket.send(&self.buf[..size]);

        self.last_received = Instant::now();
        false
    }

    fn handle_packet_latency_response_2(&mut self, size: usize) -> bool {
        let Ok(latency_discovery_response_2) =
            LatencyDiscoveryResponse2::deserialize(&self.crypto, &mut self.buf[..size])
        else {
            return false;
        };
        if self
            .latencies
            .contains(&latency_discovery_response_2.sequence_number)
        {
            return false;
        }
        let Some(sent) = self
            .latency_discoveries
            .get(&latency_discovery_response_2.sequence_number)
        else {
            // TODO: Deal with really bad connections
            return false;
        };
        let latency = sent.elapsed();
        self.congestion.update_latency(latency);
        self.latencies
            .insert(latency_discovery_response_2.sequence_number);
        if self.latencies.len() > 19 {
            self.latencies.pop_first();
        }

        self.last_received = Instant::now();
        false
    }

    fn handle_packet_unreliable_payload(&mut self, size: usize) -> bool {
        if self.closing.is_some() || !self.event_tx.has_room() {
            return false;
        }
        let Ok(packet) = UnreliablePayload::deserialize(&self.crypto, &mut self.buf[0..size])
        else {
            return false;
        };
        self.last_received = Instant::now();
        match self.channels.handle_unreliable(packet) {
            Ok(Some(message)) => self.event_tx.send(Event::Received(message)),
            Ok(None) => {}
            Err(violation) => return self.handle_violation(violation),
        }
        false
    }

    fn handle_packet_reliable_payload(&mut self, size: usize) -> bool {
        if self.closing.is_some() || !self.event_tx.has_room() {
            return false;
        }
        let Ok(packet) = ReliablePayload::deserialize(&self.crypto, &mut self.buf[..size]) else {
            return false;
        };
        self.last_received = Instant::now();
        if packet.channel_id() as usize >= self.channel_config.weights_reliable.len() {
            return false;
        }
        self.timed_events.push(
            TimedEventKey::SendAcks(packet.channel_id()),
            Instant::now() + self.congestion.ack_delay(),
            TimedEventData::Nothing,
        );
        match self.channels.handle_reliable(packet) {
            Ok(messages) => {
                for message in messages {
                    self.event_tx.send(Event::Received(message));
                }
            }
            Err(violation) => return self.handle_violation(violation),
        }
        false
    }

    fn handle_packet_acks(&mut self, size: usize) -> bool {
        let Ok(acks) = Acks::deserialize(&self.crypto, &self.buf[..size]) else {
            return false;
        };
        self.last_received = Instant::now();
        self.channels.handle_acks(acks, &mut self.congestion);
        // Acks can open the window or reveal losses.
        self.timed_events.push(
            TimedEventKey::Send,
            self.last_sent + self.congestion.downtime_between_batches(),
            TimedEventData::Nothing,
        );
        false
    }

    fn handle_violation(&mut self, violation: ProtocolViolation) -> bool {
        let reason = violation.to_string();
        let disconnect = Disconnect {
            data: reason.as_bytes(),
        };
        let size = disconnect.serialize(&self.crypto, &mut self.buf);
        self.socket.send(&self.buf[..size]);
        self.event_tx.send(Event::Violation(violation));
        true
    }
}
