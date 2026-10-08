// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The connection after the handshake, without IO: numbered DATA packets carrying frames,
//! acknowledgements with receive timestamps, loss recovery, channels and congestion control.
//! The network thread feeds it datagrams and timeouts and sends what `poll_transmit` returns.

use std::{
    rc::Rc,
    time::{Duration, Instant},
};

use ack::AckState;
use frame::Frame;
use recovery::{History, Rtt, SentPacket, State};

use super::{
    channel::{Channel, ChannelConfiguration, Channels, SendResult, StreamFrames},
    codec::{Reader, Writer},
    congestion::{CongestionConfig, Controller, SendPermit, SentInfo},
    crypto::Crypto,
    error::ProtocolViolation,
    events::DeliveryBudget,
    packets::PacketError,
    send::{Message, SendOutcome},
    stats::{ChannelStats, Stats},
};

pub mod ack;
pub mod frame;
pub mod packet;
pub mod recovery;

/// Longest reason a CLOSE frame carries in any packet.
pub const MAX_REASON_SIZE: usize = 1170;
/// CLOSE is sent this many times until acknowledged, a probe timeout apart but at most this
/// long (dropping a client whose server is gone waits for all of them).
const CLOSE_ATTEMPTS: u8 = 3;
const MAX_CLOSE_INTERVAL: Duration = Duration::from_millis(200);
/// An idle connection sends a PING this often (at most a quarter of the timeout).
const KEEPALIVE: Duration = Duration::from_secs(1);
/// With `flush()`, queued messages wait for the next flush at most this many tick intervals.
const CORK_TICKS: u32 = 2;
const MAX_CORK: Duration = Duration::from_millis(100);
// Below RFC 9001 section 6.6 limits for every supported cipher
const MAX_KEY_PACKETS: u64 = 1 << 22;
const MAX_AUTH_FAILURES: u64 = 1 << 22;
const KEY_LIMIT_REASON: &[u8] = b"Session key limit; reconnect";
const HISTORY_LIMIT_REASON: &[u8] = b"Recovery history limit; reconnect";

#[derive(Debug, Clone)]
pub(crate) struct Config {
    pub channels: ChannelConfiguration,
    pub congestion: CongestionConfig,
    pub max_recv_msg_size: usize,
    pub timeout: Duration,
}

/// What a received packet produced.
#[derive(Debug)]
pub(crate) enum Output {
    Message(Channel, Vec<u8>),
    SendResult(u64, SendOutcome),
    /// The peer closed the connection.
    Closed(Vec<u8>),
    Violation(ProtocolViolation),
}

enum Close {
    /// Sending what is queued until it is acknowledged or the deadline passes.
    Flushing {
        reason: Rc<[u8]>,
        deadline: Instant,
    },
    /// CLOSE was sent `attempts` times, the last in packet `pn`.
    Closing {
        reason: Rc<[u8]>,
        attempts: u8,
        pn: Option<u64>,
        next: Instant,
    },
    Closed,
}

pub(crate) struct Connection {
    crypto: Crypto,
    epoch: Instant,
    history: History,
    rtt: Rtt,
    pto_count: u32,
    /// Probe packets to send now, past the congestion controller.
    probes: u8,
    acks: AckState,
    controller: Controller,
    channels: Channels,
    last_received: Instant,
    last_eliciting: Instant,
    timeout: Duration,
    ping: bool,
    /// `flush()` was used: new messages wait for the next flush.
    corked: bool,
    staged: Vec<(Channel, Message)>,
    send_results: Vec<SendResult>,
    /// When the oldest message waiting for a flush was queued, `None` once flushed.
    cork_since: Option<Instant>,
    close: Option<Close>,
    /// The peer closed: acknowledge its CLOSE once.
    final_ack: bool,
    auth_failures: u64,
    key_exhausted: bool,
    limit_closed: Option<&'static [u8]>,
}

impl Connection {
    pub fn new(crypto: Crypto, config: &Config, now: Instant) -> Self {
        Self {
            crypto,
            epoch: now,
            history: History::default(),
            rtt: Rtt::default(),
            pto_count: 0,
            probes: 0,
            acks: AckState::default(),
            controller: Controller::new(config.congestion, now),
            channels: Channels::new(&config.channels, config.max_recv_msg_size),
            last_received: now,
            last_eliciting: now,
            timeout: config.timeout,
            ping: false,
            corked: false,
            staged: Vec::new(),
            send_results: Vec::new(),
            cork_since: None,
            close: None,
            final_ack: false,
            auth_failures: 0,
            key_exhausted: false,
            limit_closed: None,
        }
    }

    fn keepalive(&self) -> Duration {
        KEEPALIVE.min(self.timeout / 4)
    }

    pub fn is_closing(&self) -> bool {
        self.close.is_some()
    }

    pub fn is_closed(&self) -> bool {
        matches!(self.close, Some(Close::Closed))
    }

    /// Queues a message (dropped while closing).
    #[cfg(any(test, feature = "bench", fuzzing))]
    pub fn push(&mut self, channel: Channel, message: Rc<Vec<u8>>, now: Instant) {
        self.push_message(channel, Message::untracked(message, now));
    }

    pub fn push_message(&mut self, channel: Channel, message: Message) {
        if self.close.is_some() {
            if let Some(receipt) = message.options.receipt {
                self.send_results.push((
                    receipt,
                    SendOutcome::Dropped,
                    message.reservation.clone(),
                ));
            }
            return;
        }
        if self.corked {
            self.cork_since.get_or_insert(message.submitted);
            if message.options.replace {
                self.staged.retain(|(queued_channel, queued)| {
                    if *queued_channel != channel {
                        return true;
                    }
                    if let Some(receipt) = queued.options.receipt {
                        self.send_results.push((
                            receipt,
                            SendOutcome::Dropped,
                            queued.reservation.clone(),
                        ));
                    }
                    false
                });
            }
            self.staged.push((channel, message));
        } else {
            self.channels.push_message(channel, message);
        }
    }

    pub fn reset_channel(&mut self, channel: u8) {
        self.staged.retain(|(queued_channel, message)| {
            if *queued_channel != Channel::Reliable(channel) {
                return true;
            }
            if let Some(receipt) = message.options.receipt {
                self.send_results.push((
                    receipt,
                    SendOutcome::Dropped,
                    message.reservation.clone(),
                ));
            }
            false
        });
        self.channels.reset_channel(channel);
    }

    pub fn set_priority(&mut self, channel: Channel, priority: i8) {
        self.channels.set_priority(channel, priority);
    }

    pub fn channel_stats(&self, channel: Channel, now: Instant) -> Option<ChannelStats> {
        let mut stats = self.channels.stats(channel, now, self.rate())?;
        for (_, message) in self.staged.iter().filter(|(queued, _)| *queued == channel) {
            stats.unsent_bytes += message.len();
            let age = now.saturating_duration_since(message.submitted);
            stats.oldest_queued = Some(stats.oldest_queued.map_or(age, |oldest| oldest.max(age)));
        }
        stats.send_delay = (self.rate() > 0.0)
            .then(|| Duration::from_secs_f64(stats.unsent_bytes as f64 / self.rate()));
        Some(stats)
    }

    pub fn take_send_results(&mut self, budget: &mut DeliveryBudget, out: &mut Vec<Output>) {
        self.channels.take_results(&mut self.send_results);
        let take = budget.messages.min(self.send_results.len());
        budget.messages -= take;
        out.extend(
            self.send_results
                .drain(..take)
                .map(|(cookie, outcome, _)| Output::SendResult(cookie, outcome)),
        );
        if let Some(reason) = self.limit_closed.take() {
            out.push(Output::Closed(reason.to_vec()));
        }
    }

    /// Ends a tick: the queued messages leave as one burst. From the first call on, messages
    /// wait for the next flush.
    pub fn flush(&mut self) {
        self.corked = true;
        self.release_staged();
    }

    fn release_staged(&mut self) {
        for (channel, message) in self.staged.drain(..) {
            self.channels.push_message(channel, message);
        }
        self.cork_since = None;
    }

    fn corked(&self, now: Instant) -> bool {
        let Some(since) = self.cork_since else {
            return false;
        };
        let limit = self
            .controller
            .tick()
            .map_or(MAX_CORK, |tick| (tick * CORK_TICKS).min(MAX_CORK));
        now.saturating_duration_since(since) < limit
    }

    /// Starts a graceful close: queued messages are sent until acknowledged or `linger` ran
    /// out, then CLOSE.
    pub fn close(&mut self, reason: Rc<[u8]>, linger: Duration, now: Instant) {
        if self.close.is_none() {
            self.close = Some(Close::Flushing {
                reason,
                deadline: now + linger,
            });
            self.release_staged();
        }
    }

    /// A packet with only a CLOSE frame, for closing without waiting (timeouts, violations).
    pub fn close_now(&mut self, reason: &[u8], now: Instant, buf: &mut [u8]) -> usize {
        let pn = self.history.next_pn();
        if pn >= MAX_KEY_PACKETS || self.history.is_full() {
            self.close = Some(Close::Closed);
            return 0;
        }
        let header = packet::write_header(buf, pn, true);
        let mut w = Writer::new(&mut buf[header..packet::MAX_DATAGRAM - packet::TAG_LEN]);
        frame::write_close(&mut w, &reason[..reason.len().min(MAX_REASON_SIZE)]);
        let end = header + w.len();
        self.close = Some(Close::Closed);
        self.record(
            now,
            end + packet::TAG_LEN,
            false,
            StreamFrames::default(),
            SentInfo::default(),
        );
        packet::seal(&self.crypto, pn, buf, header, end)
    }

    fn recv_us(&self, now: Instant) -> u64 {
        now.saturating_duration_since(self.epoch).as_micros() as u64
    }

    /// Handles a datagram. `accept_data`: whether messages can be taken (else data packets
    /// are left unacknowledged, so the peer resends their reliable data).
    pub fn handle_with_budget(
        &mut self,
        now: Instant,
        datagram: &mut [u8],
        budget: &mut DeliveryBudget,
        out: &mut Vec<Output>,
    ) -> Result<(), PacketError> {
        let header = packet::parse_header(datagram)?;
        if !self.acks.received.is_new(header.pn) {
            return Err(PacketError::Replay);
        }
        if self.key_exhausted {
            return Err(PacketError::Tag);
        }
        let payload = match packet::open(&self.crypto, &header, datagram) {
            Ok(payload) => payload,
            Err(error) => {
                if error == PacketError::Tag {
                    self.auth_failures += 1;
                    self.key_exhausted = self.auth_failures >= MAX_AUTH_FAILURES;
                }
                return Err(error);
            }
        };
        if header.pn >= MAX_KEY_PACKETS {
            self.key_exhausted = true;
            return Err(PacketError::Malformed);
        }
        let (mut eliciting, mut data, mut close) = (false, false, false);
        let mut r = Reader::new(payload);
        while let Some(frame) = frame::parse(&mut r)? {
            eliciting |= !matches!(frame, Frame::Ack(_));
            data |= matches!(frame, Frame::Unreliable { .. } | Frame::Reliable { .. });
            close |= matches!(frame, Frame::Close(_));
        }
        let accept = self.close.is_none();
        let record = accept || !data || close;
        if record {
            self.acks.on_packet(
                now,
                self.recv_us(now),
                header.pn,
                eliciting,
                header.ack_now || close,
            );
        }
        self.last_received = now;
        let mut r = Reader::new(payload);
        while let Some(frame) = frame::parse(&mut r)? {
            let result = match frame {
                Frame::Ping => Ok(()),
                Frame::Credit { channel, limit } => self.channels.on_credit(channel, limit),
                Frame::Reset { channel, offset } => self.channels.on_reset(channel, offset),
                Frame::Ack(ack) => {
                    if ack.largest >= self.history.next_pn() {
                        Err(ProtocolViolation::Malformed)
                    } else {
                        self.on_ack(now, &ack);
                        Ok(())
                    }
                }
                Frame::Close(reason) => {
                    out.push(Output::Closed(reason.to_vec()));
                    self.close = Some(Close::Closed);
                    self.final_ack = true;
                    return Ok(());
                }
                _ if !(record && accept) => Ok(()),
                Frame::Unreliable {
                    channel,
                    msg_id,
                    fragment,
                    data,
                } => self
                    .channels
                    .on_unreliable(now, channel, msg_id, fragment, data)
                    .map(|message| {
                        if let Some(message) = message {
                            if budget.take(message.len()) {
                                out.push(Output::Message(
                                    channel.map_or(Channel::Unreliable, Channel::UnreliableOrdered),
                                    message,
                                ));
                            }
                        }
                    }),
                Frame::Reliable {
                    channel,
                    offset,
                    data,
                } => self.channels.on_reliable(channel, offset, data),
            };
            if let Err(violation) = result {
                out.push(Output::Violation(violation));
                return Ok(());
            }
        }
        self.drain_received(budget, out);
        Ok(())
    }

    pub fn drain_received(&mut self, budget: &mut DeliveryBudget, out: &mut Vec<Output>) {
        if self.close.is_some() {
            return;
        }
        if let Err(error) = self
            .channels
            .drain_received(budget, &mut |channel, message| {
                out.push(Output::Message(channel, message))
            })
        {
            out.push(Output::Violation(error));
        }
    }

    pub fn has_pending_delivery(&self) -> bool {
        !self.send_results.is_empty()
            || (self.close.is_none() && self.channels.has_pending_delivery())
    }

    #[cfg(any(test, feature = "bench"))]
    pub fn handle(
        &mut self,
        now: Instant,
        datagram: &mut [u8],
        accept: bool,
        out: &mut Vec<Output>,
    ) -> Result<(), PacketError> {
        let mut budget = DeliveryBudget::unlimited();
        if !accept {
            budget.messages = 0;
        }
        self.handle_with_budget(now, datagram, &mut budget, out)
    }

    fn on_ack(&mut self, now: Instant, ack: &frame::AckFrame) {
        for (pn, recv_us) in ack.timestamps() {
            if let Some(packet) = self.history.get(pn).filter(|p| p.state == State::InFlight) {
                self.controller
                    .on_timestamp(now, usize::from(packet.size), recv_us);
            }
        }
        let mut acked = recovery::Acked::default();
        let mut close_acked = false;
        let close_pn = match self.close {
            Some(Close::Closing { pn, .. }) => pn,
            _ => None,
        };
        for range in ack.ranges() {
            let (low, high) = (*range.start(), *range.end());
            close_acked |= close_pn.is_some_and(|pn| (low..=high).contains(&pn));
            let (channels, controller) = (&mut self.channels, &mut self.controller);
            self.history
                .on_ack_range(low, high, &mut acked, ack.largest, now, |_, packet| {
                    channels.on_acked(&packet.frames);
                    if packet.state == State::InFlight {
                        controller.on_acked(packet.cc);
                    }
                });
        }
        if close_acked {
            self.close = Some(Close::Closed);
        }
        if let Some(sample) = acked.rtt_sample {
            let adjusted = self
                .rtt
                .update(now, sample, Duration::from_micros(ack.delay_us));
            self.controller.on_rtt(now, adjusted);
        }
        if acked.newly_acked > 0 {
            self.pto_count = 0;
        }
        self.detect_lost(now);
        self.controller.on_ack_end(now, &self.rtt);
    }

    fn detect_lost(&mut self, now: Instant) {
        let (channels, controller) = (&mut self.channels, &mut self.controller);
        let persistent = self.history.detect_lost(now, &self.rtt, |_, packet| {
            channels.on_lost(&packet.frames);
            controller.on_lost(packet.cc);
        });
        if persistent {
            self.controller.on_persistent_congestion();
        }
    }

    /// When `on_timeout` has to run next.
    pub fn timeout(&mut self, now: Instant) -> Option<Instant> {
        if self.is_closed() {
            return None;
        }
        if self.key_exhausted || self.channels.exhausted() || self.history.at_capacity() {
            return Some(now);
        }
        let mut next = self.last_received + self.timeout;
        let mut at = |deadline: Option<Instant>| {
            if let Some(deadline) = deadline {
                next = next.min(deadline);
            }
        };
        at(self.history.timeout(&self.rtt, self.pto_count));
        at(self.acks.deadline());
        at(self.channels.deadline());
        at(Some(self.last_eliciting + self.keepalive()));
        match &self.close {
            Some(Close::Flushing { deadline, .. }) => at(Some(*deadline)),
            Some(Close::Closing { next, .. }) => at(Some(*next)),
            _ => {}
        }
        if let Some(since) = self.cork_since {
            at(Some(
                since
                    + self
                        .controller
                        .tick()
                        .map_or(MAX_CORK, |t| (t * CORK_TICKS).min(MAX_CORK)),
            ));
        }
        if self.channels.has_data(now) {
            match self.controller.permit(now, self.history.in_flight) {
                SendPermit::Now => at(Some(now)),
                SendPermit::At(when) => at(Some(when)),
                SendPermit::Blocked => {}
            }
        }
        Some(next)
    }

    /// Runs the timers. Returns true if the connection timed out.
    pub fn on_timeout(&mut self, now: Instant) -> bool {
        self.channels.maintain(now);
        if now >= self.last_received + self.timeout {
            return true;
        }
        if self
            .history
            .timeout(&self.rtt, self.pto_count)
            .is_some_and(|at| at <= now)
        {
            let lost_before = self.history.in_flight;
            self.detect_lost(now);
            if self.history.in_flight == lost_before {
                // A probe timeout: probe with new or resent data, or a PING; two packets, in
                // case losses come in bursts.
                self.pto_count += 1;
                self.probes = 2;
                if !self.channels.has_data(now) {
                    if let Some(frames) = self.history.oldest_frames().copied() {
                        self.channels.on_lost(&frames);
                    }
                }
            }
        }
        if now >= self.last_eliciting + self.keepalive() {
            self.ping = true;
        }
        if let Some(Close::Closing { attempts, next, .. }) = &self.close {
            if *attempts >= CLOSE_ATTEMPTS && now >= *next {
                self.close = Some(Close::Closed);
            }
        }
        self.controller.maintain(now);
        false
    }

    /// The next packet to send, written to `buf` (at least `MAX_DATAGRAM` bytes).
    pub fn poll_transmit(&mut self, now: Instant, buf: &mut [u8]) -> Option<usize> {
        if !self.is_closed() && self.history.at_capacity() {
            self.limit_closed = Some(HISTORY_LIMIT_REASON);
            self.key_exhausted = true;
            return Some(self.close_now(HISTORY_LIMIT_REASON, now, buf));
        }
        if !self.is_closed()
            && (self.key_exhausted
                || self.channels.exhausted()
                || self.history.next_pn() >= MAX_KEY_PACKETS - 1)
        {
            self.limit_closed = Some(KEY_LIMIT_REASON);
            self.key_exhausted = true;
            return Some(self.close_now(KEY_LIMIT_REASON, now, buf));
        }
        if !self.corked(now) {
            self.release_staged();
        }
        match &mut self.close {
            Some(Close::Closed) if self.final_ack => {
                self.final_ack = false;
                let pn = self.history.next_pn();
                let header = packet::write_header(buf, pn, false);
                let mut w = Writer::new(&mut buf[header..header + packet::capacity(pn)]);
                self.acks.write(now, &mut w);
                let end = header + w.len();
                self.record(
                    now,
                    end + packet::TAG_LEN,
                    false,
                    StreamFrames::default(),
                    SentInfo::default(),
                );
                return Some(packet::seal(&self.crypto, pn, buf, header, end));
            }
            Some(Close::Closed) => return None,
            Some(Close::Flushing { reason, deadline })
                if now >= *deadline || self.channels.queued_bytes() == 0 =>
            {
                self.close = Some(Close::Closing {
                    reason: reason.clone(),
                    attempts: 0,
                    pn: None,
                    next: now,
                });
            }
            _ => {}
        }
        if let Some(Close::Closing {
            reason,
            attempts,
            pn,
            next,
        }) = &mut self.close
        {
            if *attempts >= CLOSE_ATTEMPTS || now < *next {
                return None;
            }
            let reason = reason.clone();
            let packet_pn = self.history.next_pn();
            *attempts += 1;
            *pn = Some(packet_pn);
            *next = now + self.rtt.pto().min(MAX_CLOSE_INTERVAL);
            return Some(self.write_close(now, &reason, buf));
        }

        let probe = self.probes > 0;
        let ack_due = self.acks.deadline().is_some_and(|at| at <= now);
        let data = (probe
            || matches!(
                self.controller.permit(now, self.history.in_flight),
                SendPermit::Now
            ))
            && self.channels.has_data(now);
        if !(data || ack_due || self.ping || probe) {
            return None;
        }

        let pn = self.history.next_pn();
        let header = packet::write_header(buf, pn, false);
        let capacity = packet::capacity(pn);
        let mut w = Writer::new(&mut buf[header..header + capacity]);
        if self.acks.pending() {
            self.acks.write(now, &mut w);
        }
        let mut frames = StreamFrames::default();
        let wrote_data = data && self.channels.write(now, &mut w, capacity, &mut frames);
        if (self.ping || probe) && !wrote_data && w.remaining() > 0 {
            frame::write_ping(&mut w);
        }
        let eliciting = wrote_data || self.ping || probe;
        let end = header + w.len();
        if end == header {
            return None;
        }
        let size = end + packet::TAG_LEN;
        let mut cc = SentInfo::default();
        if eliciting {
            let app_limited = !self.channels.has_data(now);
            let burst_end = app_limited || self.controller.ends_burst(now, size);
            cc = self.controller.on_sent(now, size, burst_end, app_limited);
            if burst_end && !cc.is_first() {
                packet::write_header(buf, pn, true);
            }
            self.last_eliciting = now;
            self.ping = false;
            self.probes = self.probes.saturating_sub(1);
        }
        self.record(now, size, eliciting, frames, cc);
        Some(packet::seal(&self.crypto, pn, buf, header, end))
    }

    fn write_close(&mut self, now: Instant, reason: &[u8], buf: &mut [u8]) -> usize {
        let pn = self.history.next_pn();
        let header = packet::write_header(buf, pn, true);
        let mut w = Writer::new(&mut buf[header..header + packet::capacity(pn)]);
        if self.acks.pending() {
            let room = w.remaining() - frame::close_len(reason);
            let mut ack_buf = [0u8; packet::MAX_DATAGRAM];
            let mut ack = Writer::new(&mut ack_buf[..room]);
            if self.acks.write(now, &mut ack) {
                let len = ack.len();
                w.bytes(&ack_buf[..len]);
            }
        }
        frame::write_close(&mut w, reason);
        let end = header + w.len();
        self.last_eliciting = now;
        self.record(
            now,
            end + packet::TAG_LEN,
            true,
            StreamFrames::default(),
            SentInfo::default(),
        );
        packet::seal(&self.crypto, pn, buf, header, end)
    }

    fn record(
        &mut self,
        now: Instant,
        size: usize,
        eliciting: bool,
        frames: StreamFrames,
        cc: SentInfo,
    ) {
        self.history.on_sent(SentPacket {
            time: now,
            size: size as u16,
            state: if eliciting {
                State::InFlight
            } else {
                State::Control
            },
            frames,
            cc,
        });
    }

    /// Bytes the congestion controller allows per second.
    pub fn rate(&self) -> f64 {
        self.controller.rate()
    }

    pub fn stats(&self) -> Stats {
        Stats {
            rtt: self.rtt.smoothed,
            min_rtt: self.controller.min_rtt(),
            rtt_var: self.rtt.var,
            queue_delay: self.controller.queue_delay(),
            send_rate: self.controller.rate() as u64,
            delivery_rate: self.controller.delivery_rate() as u64,
            packet_loss: self.controller.loss() as f32,
            congestion: self.controller.congestion(),
            queued_bytes: self.channels.queued_bytes()
                + self.staged.iter().map(|(_, m)| m.len()).sum::<usize>(),
            expired_messages: self.channels.expired(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{
        Cipher,
        send::{Admission, SendOptions, SendQueueLimits},
    };
    use std::sync::Arc;
    use x25519_dalek::{PublicKey, ReusableSecret};

    fn pair(now: Instant) -> (Connection, Connection) {
        let client = ReusableSecret::random_from_rng(&mut rand::rng());
        let server = ReusableSecret::random_from_rng(&mut rand::rng());
        let config = Config {
            channels: ChannelConfiguration::default(),
            congestion: CongestionConfig::default(),
            max_recv_msg_size: 1 << 20,
            timeout: Duration::from_secs(10),
        };
        let make = |secret: &ReusableSecret, peer: &ReusableSecret, is_server| {
            Connection::new(
                Crypto::new(
                    secret.diffie_hellman(&PublicKey::from(peer)),
                    [0; 32],
                    is_server,
                    Cipher::AES256GCM,
                ),
                &config,
                now,
            )
        };
        (make(&client, &server, false), make(&server, &client, true))
    }

    #[test]
    fn key_limit_reserves_one_close_and_stops_encryption() {
        let now = Instant::now();
        let (mut client, mut server) = pair(now);
        client.history.set_next_pn_for_test(MAX_KEY_PACKETS - 1);
        let mut packet = [0; 1200];
        let len = client.poll_transmit(now, &mut packet).unwrap();
        assert!(client.is_closed());
        assert!(client.poll_transmit(now, &mut packet).is_none());
        let mut output = Vec::new();
        server
            .handle(now, &mut packet[..len], true, &mut output)
            .unwrap();
        assert!(matches!(&output[..], [Output::Closed(reason)] if reason == KEY_LIMIT_REASON));
        output.clear();
        client.take_send_results(&mut DeliveryBudget::unlimited(), &mut output);
        assert!(matches!(&output[..], [Output::Closed(reason)] if reason == KEY_LIMIT_REASON));
    }

    #[test]
    fn pinned_recovery_history_closes_with_a_bounded_local_resource_reason() {
        let now = Instant::now();
        let (mut client, _) = pair(now);
        client.history.on_sent(SentPacket {
            time: now,
            size: 100,
            state: State::InFlight,
            frames: StreamFrames::default(),
            cc: SentInfo::default(),
        });
        while !client.history.at_capacity() {
            client.history.on_sent(SentPacket {
                time: now,
                size: 30,
                state: State::Control,
                frames: StreamFrames::default(),
                cc: SentInfo::default(),
            });
        }
        let mut packet = [0; 1200];
        assert!(client.poll_transmit(now, &mut packet).is_some());
        assert!(client.history.is_full());
        assert!(client.poll_transmit(now, &mut packet).is_none());
        let mut output = Vec::new();
        client.take_send_results(&mut DeliveryBudget::unlimited(), &mut output);
        assert!(matches!(&output[..], [Output::Closed(reason)] if reason == HISTORY_LIMIT_REASON));
    }

    #[test]
    fn receipt_backpressure_remains_until_budgeted_feedback_is_taken() {
        let now = Instant::now();
        let (mut client, _) = pair(now);
        let admission = Admission::new(SendQueueLimits {
            max_messages: 1,
            ..SendQueueLimits::default()
        });
        let reservation = admission.reserve(Channel::Unreliable, 10).unwrap();
        client.push_message(
            Channel::Unreliable,
            Message {
                data: Arc::new(vec![1; 10]),
                submitted: now,
                options: SendOptions {
                    deadline: Some(now),
                    receipt: Some(7),
                    ..SendOptions::default()
                },
                reservation: Some(reservation),
            },
        );
        let mut packet = [0; 1200];
        assert!(client.poll_transmit(now, &mut packet).is_none());
        let mut output = Vec::new();
        client.take_send_results(
            &mut DeliveryBudget {
                messages: 0,
                bytes: 0,
                work: 0,
            },
            &mut output,
        );
        assert!(output.is_empty());
        assert!(client.has_pending_delivery());
        assert!(admission.reserve(Channel::Unreliable, 10).is_err());
        client.take_send_results(&mut DeliveryBudget::unlimited(), &mut output);
        assert!(matches!(
            &output[..],
            [Output::SendResult(7, SendOutcome::Dropped)]
        ));
        assert!(admission.reserve(Channel::Unreliable, 10).is_ok());
    }

    #[test]
    fn future_ack_is_a_violation_without_acknowledging_payload() {
        let now = Instant::now();
        let (mut client, server) = pair(now);
        client.push(Channel::Reliable(0), Rc::new(vec![1; 100]), now);
        let mut packet = [0; 1200];
        client.poll_transmit(now, &mut packet).unwrap();
        let before = client.stats().queued_bytes;
        let pn = 0;
        let header = packet::write_header(&mut packet, pn, false);
        let mut w = Writer::new(&mut packet[header..header + packet::capacity(pn)]);
        assert!(frame::write_ack(&mut w, 0, &[(0, 1_000_000)], &[]));
        let end = header + w.len();
        let len = packet::seal(&server.crypto, pn, &mut packet, header, end);
        let mut output = Vec::new();
        client
            .handle(now, &mut packet[..len], true, &mut output)
            .unwrap();
        assert!(matches!(
            &output[..],
            [Output::Violation(ProtocolViolation::Malformed)]
        ));
        assert_eq!(client.stats().queued_bytes, before);
    }
}
