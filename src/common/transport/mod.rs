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
    channel::{Channel, ChannelConfiguration, Channels, StreamFrames},
    codec::{Reader, Writer},
    congestion::{CongestionConfig, Controller, SendPermit, SentInfo},
    crypto::Crypto,
    error::ProtocolViolation,
    packets::PacketError,
    stats::Stats,
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
    Message(Vec<u8>),
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
    /// When the oldest message waiting for a flush was queued, `None` once flushed.
    cork_since: Option<Instant>,
    close: Option<Close>,
    /// The peer closed: acknowledge its CLOSE once.
    final_ack: bool,
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
            cork_since: None,
            close: None,
            final_ack: false,
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
    pub fn push(&mut self, channel: Channel, message: Rc<Vec<u8>>, now: Instant) {
        if self.close.is_some() {
            return;
        }
        self.channels.push(channel, message, now);
        if self.corked {
            self.cork_since.get_or_insert(now);
        }
    }

    /// Ends a tick: the queued messages leave as one burst. From the first call on, messages
    /// wait for the next flush.
    pub fn flush(&mut self) {
        self.corked = true;
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
            self.cork_since = None;
        }
    }

    /// A packet with only a CLOSE frame, for closing without waiting (timeouts, violations).
    pub fn close_now(&mut self, reason: &[u8], now: Instant, buf: &mut [u8]) -> usize {
        let pn = self.history.next_pn();
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
    pub fn handle(
        &mut self,
        now: Instant,
        datagram: &mut [u8],
        accept_data: bool,
        out: &mut Vec<Output>,
    ) -> Result<(), PacketError> {
        let header = packet::parse_header(datagram)?;
        if !self.acks.received.is_new(header.pn) {
            return Err(PacketError::Replay);
        }
        let payload = packet::open(&self.crypto, &header, datagram)?;
        let (mut eliciting, mut data, mut close) = (false, false, false);
        let mut r = Reader::new(payload);
        while let Some(frame) = frame::parse(&mut r)? {
            eliciting |= !matches!(frame, Frame::Ack(_));
            data |= matches!(frame, Frame::Unreliable { .. } | Frame::Reliable { .. });
            close |= matches!(frame, Frame::Close(_));
        }
        let accept = accept_data && self.close.is_none();
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
                Frame::Ack(ack) => {
                    self.on_ack(now, &ack);
                    Ok(())
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
                    .on_unreliable(channel, msg_id, fragment, data)
                    .map(|message| out.extend(message.map(Output::Message))),
                Frame::Reliable {
                    channel,
                    offset,
                    data,
                } => self
                    .channels
                    .on_reliable(channel, offset, data, &mut |message| {
                        out.push(Output::Message(message))
                    }),
            };
            if let Err(violation) = result {
                out.push(Output::Violation(violation));
                return Ok(());
            }
        }
        Ok(())
    }

    fn on_ack(&mut self, now: Instant, ack: &frame::AckFrame) {
        for (pn, recv_us) in ack.timestamps() {
            if let Some(packet) = self.history.get(pn).filter(|p| p.state != State::Control) {
                self.controller.on_timestamp(
                    (pn, packet.cc),
                    packet.time,
                    usize::from(packet.size),
                    recv_us,
                    now,
                );
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
                .on_ack_range(low, high, &mut acked, ack.largest, now, |pn, packet| {
                    channels.on_acked(&packet.frames);
                    controller.on_acked(packet.cc, pn);
                });
        }
        if close_acked {
            self.close = Some(Close::Closed);
        }
        if let Some(sample) = acked.rtt_sample {
            self.rtt.update(sample, Duration::from_micros(ack.delay_us));
            self.controller.on_rtt(now, self.rtt.latest);
        }
        if acked.newly_acked > 0 {
            self.pto_count = 0;
        }
        self.detect_lost(now);
        self.controller.on_ack_end(
            now,
            self.history.next_pn(),
            self.history.in_flight,
            &self.rtt,
        );
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
        let mut next = self.last_received + self.timeout;
        let mut at = |deadline: Option<Instant>| {
            if let Some(deadline) = deadline {
                next = next.min(deadline);
            }
        };
        at(self.history.timeout(&self.rtt, self.pto_count));
        at(self.acks.deadline());
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
        if !self.corked(now) && self.channels.has_data(now) {
            match self
                .controller
                .permit(now, self.history.in_flight, &self.rtt)
            {
                SendPermit::Now => at(Some(now)),
                SendPermit::Realtime(_) if self.channels.has_realtime(now) => at(Some(now)),
                SendPermit::Realtime(when) | SendPermit::At(when) => at(Some(when)),
                SendPermit::Blocked => {}
            }
        }
        Some(next)
    }

    /// Runs the timers. Returns true if the connection timed out.
    pub fn on_timeout(&mut self, now: Instant) -> bool {
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
        self.controller.check_stall(now, &self.rtt);
        false
    }

    /// The next packet to send, written to `buf` (at least `MAX_DATAGRAM` bytes).
    pub fn poll_transmit(&mut self, now: Instant, buf: &mut [u8]) -> Option<usize> {
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
        let (data, realtime) = if self.corked(now) {
            (false, false)
        } else if probe {
            (self.channels.has_data(now), false)
        } else {
            match self
                .controller
                .permit(now, self.history.in_flight, &self.rtt)
            {
                SendPermit::Now => (self.channels.has_data(now), false),
                SendPermit::Realtime(_) => (self.channels.has_realtime(now), true),
                SendPermit::At(_) | SendPermit::Blocked => (false, false),
            }
        };
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
        let wrote_data = data
            && self
                .channels
                .write(now, &mut w, (capacity, realtime), &mut frames);
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
            cc = self
                .controller
                .on_sent(now, size, (burst_end, app_limited, realtime));
            if burst_end && !cc.is_first() {
                packet::write_header(buf, pn, true);
            }
            self.last_eliciting = now;
            self.ping = false;
            self.probes = self.probes.saturating_sub(1);
        }
        if !self.channels.has_data(now) {
            self.cork_since = None;
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
            utilization: self.controller.utilization() as f32,
            packet_loss: self.controller.loss() as f32,
            congestion: self.controller.congestion(),
            queued_bytes: self.channels.queued_bytes(),
            expired_messages: self.channels.expired(),
        }
    }
}
