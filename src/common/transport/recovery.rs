// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! RTT estimation, loss detection and probe timeouts (RFC 9002).

use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use super::ack::MAX_ACK_DELAY;
use crate::common::{channel::StreamFrames, congestion::SentInfo};

/// RTT assumed before the first sample.
const INITIAL_RTT: Duration = Duration::from_millis(333);
const GRANULARITY: Duration = Duration::from_millis(1);
/// A packet is lost once a packet this many numbers later is acknowledged...
const PACKET_THRESHOLD: u64 = 3;
/// ... or once it is older than this many RTTs (as eighths) and a later one was acknowledged.
const TIME_THRESHOLD_EIGHTHS: u32 = 9;
/// Persistent congestion: losses spanning this many PTOs without an acknowledgement between.
const PERSISTENT_CONGESTION_PTOS: u32 = 3;
/// Probe timeouts back off exponentially up to this power of two: games need the connection
/// to recover within seconds once packets get through again.
const MAX_PTO_BACKOFF: u32 = 2;

#[derive(Debug, Clone, Copy)]
pub struct Rtt {
    pub latest: Duration,
    pub smoothed: Option<Duration>,
    pub var: Duration,
    pub min: Duration,
}

impl Default for Rtt {
    fn default() -> Self {
        Self {
            latest: INITIAL_RTT,
            smoothed: None,
            var: INITIAL_RTT / 2,
            min: Duration::MAX,
        }
    }
}

impl Rtt {
    pub fn update(&mut self, sample: Duration, ack_delay: Duration) {
        self.latest = sample;
        self.min = self.min.min(sample);
        let Some(smoothed) = self.smoothed else {
            self.smoothed = Some(sample);
            self.var = sample / 2;
            return;
        };
        let ack_delay = ack_delay.min(MAX_ACK_DELAY);
        let adjusted = if sample >= self.min + ack_delay {
            sample - ack_delay
        } else {
            sample
        };
        self.var = (self.var * 3 + smoothed.abs_diff(adjusted)) / 4;
        self.smoothed = Some((smoothed * 7 + adjusted) / 8);
    }

    pub fn smoothed(&self) -> Duration {
        self.smoothed.unwrap_or(INITIAL_RTT)
    }

    /// The probe timeout before backoff.
    pub fn pto(&self) -> Duration {
        self.smoothed() + (self.var * 4).max(GRANULARITY) + MAX_ACK_DELAY
    }

    fn loss_delay(&self) -> Duration {
        (self.latest.max(self.smoothed()) * TIME_THRESHOLD_EIGHTHS / 8).max(GRANULARITY)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Ack-eliciting and neither acknowledged nor lost.
    InFlight,
    Acked,
    Lost,
    /// Not ack-eliciting (ACK frames only), never tracked.
    Control,
}

#[derive(Debug, Clone, Copy)]
pub struct SentPacket {
    pub time: Instant,
    pub size: u16,
    pub state: State,
    pub frames: StreamFrames,
    pub cc: SentInfo,
}

/// Sent packets from the oldest one still in flight on.
#[derive(Default)]
pub struct History {
    first_pn: u64,
    packets: VecDeque<SentPacket>,
    pub in_flight: usize,
    in_flight_packets: usize,
    largest_acked: Option<u64>,
    last_eliciting_sent: Option<Instant>,
    /// When the earliest in-flight packet below the largest acknowledged one is lost.
    loss_time: Option<Instant>,
}

/// What an ACK changed.
#[derive(Default)]
pub struct Acked {
    /// The largest acknowledged packet was newly acknowledged and ack-eliciting.
    pub rtt_sample: Option<Duration>,
    pub newly_acked: usize,
}

impl History {
    pub fn next_pn(&self) -> u64 {
        self.first_pn + self.packets.len() as u64
    }

    pub fn get(&self, pn: u64) -> Option<&SentPacket> {
        self.packets
            .get(usize::try_from(pn.checked_sub(self.first_pn)?).ok()?)
    }

    pub fn has_in_flight(&self) -> bool {
        self.in_flight_packets > 0
    }

    pub fn on_sent(&mut self, packet: SentPacket) {
        if packet.state == State::InFlight {
            self.in_flight += usize::from(packet.size);
            self.in_flight_packets += 1;
            self.last_eliciting_sent = Some(packet.time);
        }
        self.packets.push_back(packet);
    }

    /// Marks the packets in `low..=high` acknowledged, calling `on_acked` for each newly
    /// acknowledged in-flight one.
    pub fn on_ack_range(
        &mut self,
        low: u64,
        high: u64,
        acked: &mut Acked,
        largest: u64,
        now: Instant,
        mut on_acked: impl FnMut(u64, &SentPacket),
    ) {
        let end = self.next_pn().min(high.saturating_add(1));
        for pn in low.max(self.first_pn)..end {
            let packet = &mut self.packets[(pn - self.first_pn) as usize];
            if packet.state != State::InFlight {
                continue;
            }
            packet.state = State::Acked;
            self.in_flight -= usize::from(packet.size);
            self.in_flight_packets -= 1;
            acked.newly_acked += 1;
            if pn == largest {
                acked.rtt_sample = Some(now.saturating_duration_since(packet.time));
            }
            on_acked(pn, packet);
        }
        if end > low {
            self.largest_acked = self.largest_acked.max(Some(end - 1));
        }
    }

    /// Declares packets lost (RFC 9002 §6.1), calling `on_lost` for each. Returns whether
    /// the losses amount to persistent congestion.
    pub fn detect_lost(
        &mut self,
        now: Instant,
        rtt: &Rtt,
        mut on_lost: impl FnMut(u64, &SentPacket),
    ) -> bool {
        self.loss_time = None;
        let Some(largest) = self.largest_acked else {
            return false;
        };
        let loss_delay = rtt.loss_delay();
        let persistent = rtt.pto() * PERSISTENT_CONGESTION_PTOS;
        // The current run of lost packets without an acknowledged one between: first and last
        // send time.
        let mut run: Option<(Instant, Instant)> = None;
        let mut persistent_congestion = false;
        for (i, packet) in self.packets.iter_mut().enumerate() {
            let pn = self.first_pn + i as u64;
            if pn >= largest {
                break;
            }
            if packet.state != State::InFlight {
                if packet.state == State::Acked {
                    run = None;
                }
                continue;
            }
            let lost_at = packet.time + loss_delay;
            if pn + PACKET_THRESHOLD <= largest || lost_at <= now {
                packet.state = State::Lost;
                self.in_flight -= usize::from(packet.size);
                self.in_flight_packets -= 1;
                let (first, _) = *run.get_or_insert((packet.time, packet.time));
                run = Some((first, packet.time));
                persistent_congestion |= rtt.smoothed.is_some()
                    && packet.time.saturating_duration_since(first) >= persistent;
                on_lost(pn, packet);
            } else {
                self.loss_time = Some(self.loss_time.map_or(lost_at, |at| at.min(lost_at)));
            }
        }
        self.prune();
        persistent_congestion
    }

    fn prune(&mut self) {
        while self
            .packets
            .front()
            .is_some_and(|packet| packet.state != State::InFlight)
        {
            self.packets.pop_front();
            self.first_pn += 1;
        }
    }

    /// The loss timer, or else the probe timeout.
    pub fn timeout(&self, rtt: &Rtt, pto_count: u32) -> Option<Instant> {
        if let Some(loss_time) = self.loss_time {
            return Some(loss_time);
        }
        let last = self.last_eliciting_sent.filter(|_| self.has_in_flight())?;
        Some(last + rtt.pto() * (1 << pto_count.min(MAX_PTO_BACKOFF)))
    }

    /// The oldest in-flight packet's reliable frames, to resend on a probe timeout.
    pub fn oldest_frames(&self) -> Option<&StreamFrames> {
        self.packets
            .iter()
            .find(|packet| packet.state == State::InFlight)
            .map(|packet| &packet.frames)
    }
}
