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

use crossbeam::channel::{Receiver, Sender, TryRecvError};
use either::Either;
use mio::{Events, Interest, Poll, Waker};

use crate::common::{
    channel::{scheduler::ChannelConfiguration, Channel, Channels},
    congestion::CongestionController,
    crypto::Crypto,
    packets::{
        acks::Acks, disconnect::Disconnect, latency_discovery::LatencyDiscovery,
        latency_discovery_response::LatencyDiscoveryResponse,
        latency_discovery_response_2::LatencyDiscoveryResponse2, reliable_payload::ReliablePayload,
        unreliable_payload::UnreliablePayload, PacketIdentifier,
    },
    socket::net_sym::NetworkSimulator,
    timed_event_queue::TimedEventQueue,
    RECV_TOKEN, WAKE_TOKEN,
};

use super::{Event, Socket};

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
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TimedEventData {
    Nothing,
}

pub struct ClientThreadState {
    pub cmds: Receiver<Cmd>,
    pub event_tx: Sender<Event>,
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
}

impl ClientThreadState {
    pub fn run(&mut self) -> Result<(), io::Error> {
        self.timed_events.push(
            TimedEventKey::CheckForTimeout,
            Instant::now() + self.timeout_dur + Duration::from_secs(1),
            TimedEventData::Nothing,
        );

        let mut events = Events::with_capacity(16);
        self.poll
            .registry()
            .register(self.socket.mio_socket(), RECV_TOKEN, Interest::READABLE)?;

        'outer: loop {
            if self.handle_all_cmds()? || self.handle_all_events()? {
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
                    let disconnect = Disconnect { data: &data };
                    let size = disconnect.serialize(&self.crypto, &mut self.buf);
                    self.socket.send(&self.buf[..size])?;
                    return Ok(true);
                }
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
                        self.socket
                            .set_network_simulator(network_simulator)
                            .unwrap();
                        self.socket.set_use_simulator(true);
                    } else {
                        self.socket.set_use_simulator(false);
                    }
                }
            }
        }
        Ok(false)
    }

    fn handle_all_events(&mut self) -> Result<bool, io::Error> {
        while self
            .timed_events
            .next()
            .map_or(false, |deadline| deadline <= Instant::now())
        {
            let (key, _event) = self.timed_events.pop().unwrap();
            match key {
                TimedEventKey::Send => self.handle_event_send()?,
                TimedEventKey::SendAcks(channel_id) => self.handle_event_send_acks(channel_id)?,
                TimedEventKey::CheckForTimeout => {
                    if self.last_received.elapsed() > self.timeout_dur {
                        let disconnect = Disconnect { data: b"Timeout" };
                        let size = disconnect.serialize(&self.crypto, &mut self.buf);
                        self.socket.send(&self.buf[..size])?;
                        let _ = self.event_tx.send(Event::TimedOut);
                        return Ok(true);
                    } else {
                        self.timed_events.push(
                            TimedEventKey::CheckForTimeout,
                            Instant::now() + self.timeout_dur + Duration::from_secs(1),
                            TimedEventData::Nothing,
                        );
                    }
                }
            }
        }
        Ok(false)
    }

    fn handle_all_recvs(&mut self) -> Result<bool, io::Error> {
        loop {
            let size = match self.socket.mio_socket().recv(&mut self.buf) {
                Ok(x) => x,
                Err(ref e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    break
                }
                // Windows shenanigans
                Err(e) if e.kind() == io::ErrorKind::ConnectionReset => continue,
                Err(e) => return Err(e),
            };
            if size == 0 || size > 1200 {
                continue;
            }
            let Ok(packet_identifier) = PacketIdentifier::try_from(self.buf[0]) else {
                continue;
            };
            let shutdown = match packet_identifier {
                PacketIdentifier::Disconnect => self.handle_packet_disconnect(size)?,
                PacketIdentifier::LatencyDiscovery => self.handle_packet_latency_discovery(size)?,
                PacketIdentifier::LatencyDiscoveryResponse2 => {
                    self.handle_packet_latency_response_2(size)?
                }
                PacketIdentifier::UnreliableStandalonePayload
                | PacketIdentifier::UnreliableFragmentedPayload
                | PacketIdentifier::UnreliableFragmentedPayloadLast
                | PacketIdentifier::UnreliableOrderedStandalonePayload
                | PacketIdentifier::UnreliableOrderedFragmentedPayload
                | PacketIdentifier::UnreliableOrderedFragmentedPayloadLast => {
                    self.handle_packet_unreliable_payload(size)?
                }
                PacketIdentifier::ReliablePayloadNoAcks => {
                    self.handle_packet_reliable_payload(size)?
                }
                PacketIdentifier::Acks => self.handle_packet_acks(size)?,
                _ => false,
            };
            if shutdown {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn handle_event_send(&mut self) -> Result<(), io::Error> {
        let now = Instant::now();
        let mut batch_size = self.congestion.allowed_to_send_this_batch();
        while batch_size > 0 {
            match self.channels.pop(
                &self.channel_config,
                &mut self.congestion,
                &self.crypto,
                &mut self.buf,
            ) {
                Either::Left(size) => {
                    self.last_sent = now;
                    self.socket.send(&self.buf[..size])?;
                    batch_size = batch_size.saturating_sub(size as u32);
                }
                Either::Right(Some(time_till_resend)) => {
                    let mut new_deadline = now + time_till_resend;
                    new_deadline = new_deadline
                        .max(self.last_sent + self.congestion.downtime_between_batches());
                    self.timed_events.push(
                        TimedEventKey::Send,
                        new_deadline,
                        TimedEventData::Nothing,
                    );

                    break;
                }
                Either::Right(None) => {
                    return Ok(());
                }
            }
        }
        self.timed_events.push(
            TimedEventKey::Send,
            now + self.congestion.downtime_between_batches(),
            TimedEventData::Nothing,
        );
        Ok(())
    }

    fn handle_event_send_acks(&mut self, channel_id: u8) -> Result<(), io::Error> {
        let acks = self.channels.acks(Channel::Reliable(channel_id));
        let size = acks.serialize(&self.crypto, &mut self.buf);
        self.socket.send(&self.buf[..size])?;
        Ok(())
    }

    fn handle_packet_disconnect(&mut self, size: usize) -> Result<bool, io::Error> {
        let Ok(disconnect) = Disconnect::deserialize(&self.crypto, &mut self.buf[..size]) else {
            return Ok(false);
        };
        if self
            .event_tx
            .send(Event::Disconnected(disconnect.data.to_vec()))
            .is_err()
        {
            return Ok(true);
        }
        Ok(true)
    }

    fn handle_packet_latency_discovery(&mut self, size: usize) -> Result<bool, io::Error> {
        let Ok(latency_discovery) =
            LatencyDiscovery::deserialize(&self.crypto, &mut self.buf[..size])
        else {
            return Ok(false);
        };
        if self
            .latency_discoveries
            .contains_key(&latency_discovery.sequence_number)
        {
            return Ok(false);
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
        self.socket.send(&self.buf[..size])?;

        self.last_received = Instant::now();
        Ok(false)
    }

    fn handle_packet_latency_response_2(&mut self, size: usize) -> Result<bool, io::Error> {
        let Ok(latency_discovery_response_2) =
            LatencyDiscoveryResponse2::deserialize(&self.crypto, &mut self.buf[..size])
        else {
            return Ok(false);
        };
        if self
            .latencies
            .contains(&latency_discovery_response_2.sequence_number)
        {
            return Ok(false);
        }
        let Some(sent) = self
            .latency_discoveries
            .get(&latency_discovery_response_2.sequence_number)
        else {
            // TODO: Deal with really bad connections
            return Ok(false);
        };
        let latency = sent.elapsed();
        self.congestion.update_latency(latency);
        self.latencies
            .insert(latency_discovery_response_2.sequence_number);
        if self.latencies.len() > 19 {
            self.latencies.pop_first();
        }

        self.last_received = Instant::now();
        Ok(false)
    }

    fn handle_packet_unreliable_payload(&mut self, size: usize) -> Result<bool, io::Error> {
        let Ok(packet) = UnreliablePayload::deserialize(&self.crypto, &mut self.buf[0..size])
        else {
            return Ok(false);
        };
        let Some(message) = self.channels.handle_unreliable(packet) else {
            return Ok(false);
        };
        let _ = self.event_tx.send(Event::Received(message));
        Ok(false)
    }

    fn handle_packet_reliable_payload(&mut self, size: usize) -> Result<bool, io::Error> {
        let Ok(packet) = ReliablePayload::deserialize(&self.crypto, &mut self.buf[..size]) else {
            return Ok(false);
        };
        if packet.channel_id() as usize >= self.channel_config.weights_reliable.len() {
            return Ok(false);
        }
        self.timed_events.push(
            TimedEventKey::SendAcks(packet.channel_id()),
            Instant::now() + self.congestion.ack_delay(),
            TimedEventData::Nothing,
        );
        for message in self.channels.handle_reliable(packet) {
            self.event_tx.send(Event::Received(message)).unwrap();
        }
        Ok(false)
    }

    fn handle_packet_acks(&mut self, size: usize) -> Result<bool, io::Error> {
        let Ok(acks) = Acks::deserialize(&self.crypto, &mut self.buf[..size]) else {
            return Ok(false);
        };
        self.channels.handle_acks(acks);
        Ok(false)
    }
}
