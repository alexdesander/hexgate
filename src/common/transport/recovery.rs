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
// Close before an unacknowledged packet can pin unbounded control history
const MAX_HISTORY: usize = 16_384;

#[derive(Debug, Clone, Copy)]
pub struct Rtt {
    pub latest: Duration,
    pub smoothed: Option<Duration>,
    pub var: Duration,
    pub min: Duration,
    pub first_sample: Option<Instant>,
}

impl Default for Rtt {
    fn default() -> Self {
        Self {
            latest: INITIAL_RTT,
            smoothed: None,
            var: INITIAL_RTT / 2,
            min: Duration::MAX,
            first_sample: None,
        }
    }
}

impl Rtt {
    pub fn update(&mut self, now: Instant, sample: Duration, ack_delay: Duration) -> Duration {
        self.first_sample.get_or_insert(now);
        self.latest = sample;
        self.min = self.min.min(sample);
        let Some(smoothed) = self.smoothed else {
            self.smoothed = Some(sample);
            self.var = sample / 2;
            return sample;
        };
        let ack_delay = ack_delay.min(MAX_ACK_DELAY);
        let adjusted = if sample >= self.min + ack_delay {
            sample - ack_delay
        } else {
            sample
        };
        self.var = (self.var * 3 + smoothed.abs_diff(adjusted)) / 4;
        self.smoothed = Some((smoothed * 7 + adjusted) / 8);
        adjusted
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
    pruned_loss_start: Option<(u64, Instant)>,
    late: VecDeque<(u64, SentPacket)>,
    persistent_end: Option<Instant>,
}

/// What an ACK changed.
#[derive(Default)]
pub struct Acked {
    /// The largest acknowledged packet was newly acknowledged and ack-eliciting.
    pub rtt_sample: Option<Duration>,
    pub newly_acked: usize,
}

impl History {
    #[cfg(test)]
    pub fn set_next_pn_for_test(&mut self, pn: u64) {
        assert!(self.packets.is_empty());
        self.first_pn = pn;
    }

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

    pub fn at_capacity(&self) -> bool {
        self.packets.len() >= MAX_HISTORY - 1
    }

    pub fn is_full(&self) -> bool {
        self.packets.len() >= MAX_HISTORY
    }

    pub fn on_sent(&mut self, packet: SentPacket) {
        if self.packets.is_empty() && packet.state == State::Control {
            self.first_pn += 1;
            return;
        }
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
        if high >= self.next_pn() || low > high {
            return;
        }
        if self
            .pruned_loss_start
            .is_some_and(|(first, _)| high >= first && low < self.first_pn)
        {
            self.pruned_loss_start = None;
        }
        self.late.retain(|(pn, packet)| {
            if (low..=high).contains(pn) {
                on_acked(*pn, packet);
                false
            } else {
                true
            }
        });
        let end = self.next_pn().min(high.saturating_add(1));
        for pn in low.max(self.first_pn)..end {
            let packet = &mut self.packets[(pn - self.first_pn) as usize];
            if packet.state == State::Control {
                packet.state = State::Acked;
            }
            if !matches!(packet.state, State::InFlight | State::Lost) {
                continue;
            }
            if packet.state == State::InFlight {
                self.in_flight -= usize::from(packet.size);
                self.in_flight_packets -= 1;
                acked.newly_acked += 1;
                if pn == largest {
                    acked.rtt_sample = Some(now.saturating_duration_since(packet.time));
                }
            }
            on_acked(pn, packet);
            packet.state = State::Acked;
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
        let mut run = self
            .pruned_loss_start
            .map(|(_, sent)| sent)
            .filter(|&sent| rtt.first_sample.is_none_or(|at| sent >= at));
        let mut persistent_congestion = false;
        for (i, packet) in self.packets.iter_mut().enumerate() {
            let pn = self.first_pn + i as u64;
            if pn >= largest {
                break;
            }
            if packet.state != State::InFlight {
                if packet.state == State::Acked {
                    run = None;
                } else if packet.state == State::Lost
                    && rtt.first_sample.is_none_or(|at| packet.time >= at)
                {
                    run.get_or_insert(packet.time);
                }
                continue;
            }
            let lost_at = packet.time + loss_delay;
            if pn + PACKET_THRESHOLD <= largest || lost_at <= now {
                packet.state = State::Lost;
                self.in_flight -= usize::from(packet.size);
                self.in_flight_packets -= 1;
                let eligible = rtt.first_sample.is_none_or(|at| packet.time >= at);
                if !eligible {
                    run = None;
                }
                let first = if eligible {
                    *run.get_or_insert(packet.time)
                } else {
                    packet.time
                };
                if rtt.smoothed.is_some()
                    && rtt.first_sample.is_none_or(|at| first >= at)
                    && packet.time.saturating_duration_since(first) >= persistent
                    && self.persistent_end.is_none_or(|end| first > end)
                {
                    persistent_congestion = true;
                    self.persistent_end = Some(packet.time);
                }
                on_lost(pn, packet);
            } else {
                run = None;
                self.loss_time = Some(self.loss_time.map_or(lost_at, |at| at.min(lost_at)));
            }
        }
        self.prune(rtt.first_sample);
        persistent_congestion
    }

    fn prune(&mut self, eligible_after: Option<Instant>) {
        while self
            .packets
            .front()
            .is_some_and(|p| p.state != State::InFlight)
        {
            let packet = self.packets.pop_front().unwrap();
            match packet.state {
                State::Lost => {
                    if eligible_after.is_none_or(|at| packet.time >= at) {
                        self.pruned_loss_start
                            .get_or_insert((self.first_pn, packet.time));
                    } else {
                        self.pruned_loss_start = None;
                    }
                    if !packet.frames.is_empty() {
                        self.late.push_back((self.first_pn, packet));
                        if self.late.len() > 4096 {
                            self.late.pop_front();
                        }
                    }
                }
                State::Acked => self.pruned_loss_start = None,
                _ => {}
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sent(time: Instant) -> SentPacket {
        let mut frames = StreamFrames::default();
        frames.push(crate::common::channel::StreamRange {
            channel: 0,
            start: 0,
            len: 100,
        });
        SentPacket {
            time,
            size: 100,
            state: State::InFlight,
            frames,
            cc: SentInfo::default(),
        }
    }

    fn rtt(now: Instant) -> Rtt {
        Rtt {
            latest: Duration::from_millis(10),
            smoothed: Some(Duration::from_millis(10)),
            var: Duration::ZERO,
            min: Duration::from_millis(10),
            first_sample: Some(now),
        }
    }

    #[test]
    fn persistent_episode_survives_split_detection_passes() {
        let now = Instant::now();
        let mut history = History::default();
        for ms in [0, 20, 65, 66, 70] {
            history.on_sent(sent(now + Duration::from_millis(ms)));
        }
        history.on_ack_range(
            4,
            4,
            &mut Acked::default(),
            4,
            now + Duration::from_millis(70),
            |_, _| {},
        );
        assert!(!history.detect_lost(now + Duration::from_millis(70), &rtt(now), |_, _| {}));
        assert_eq!(history.first_pn, 2);
        assert!(history.detect_lost(now + Duration::from_millis(80), &rtt(now), |_, _| {}));
        assert!(!history.detect_lost(now + Duration::from_millis(90), &rtt(now), |_, _| {}));
    }

    #[test]
    fn acknowledgments_and_pre_sample_packets_break_persistent_episodes() {
        let now = Instant::now();
        for first_sample in [now, now + Duration::from_millis(30)] {
            let mut history = History::default();
            for ms in [0, 20, 65, 66, 70] {
                history.on_sent(sent(now + Duration::from_millis(ms)));
            }
            history.on_ack_range(
                4,
                4,
                &mut Acked::default(),
                4,
                now + Duration::from_millis(70),
                |_, _| {},
            );
            if first_sample == now {
                history.on_ack_range(
                    1,
                    1,
                    &mut Acked::default(),
                    4,
                    now + Duration::from_millis(70),
                    |_, _| {},
                );
            }
            assert!(!history.detect_lost(
                now + Duration::from_millis(80),
                &rtt(first_sample),
                |_, _| {}
            ));
        }
    }

    #[test]
    fn late_ack_delivers_without_new_congestion_sample_and_future_ack_is_ignored() {
        let now = Instant::now();
        let mut history = History::default();
        for _ in 0..4 {
            history.on_sent(sent(now));
        }
        let mut acked = Acked::default();
        history.on_ack_range(0, 1_000_000, &mut acked, 1_000_000, now, |_, _| panic!());
        assert_eq!(history.in_flight, 400);
        history.on_ack_range(3, 3, &mut acked, 3, now, |_, _| {});
        history.detect_lost(now + Duration::from_millis(20), &rtt(now), |_, _| {});
        assert_eq!(history.in_flight, 0);
        let mut acked = Acked::default();
        let mut delivered = 0;
        history.on_ack_range(0, 2, &mut acked, 2, now, |_, packet| {
            assert_eq!(packet.state, State::Lost);
            delivered += 1;
        });
        assert_eq!(delivered, 3);
        assert_eq!(acked.newly_acked, 0);
        assert!(acked.rtt_sample.is_none());
        assert!(history.late.is_empty());
    }

    #[test]
    fn unpinned_control_history_is_reclaimed_immediately() {
        let now = Instant::now();
        let mut history = History::default();
        for _ in 0..100_000 {
            let mut packet = sent(now);
            packet.state = State::Control;
            history.on_sent(packet);
        }
        assert!(history.packets.is_empty());
        assert_eq!(history.next_pn(), 100_000);
        history.on_sent(sent(now));
        while !history.at_capacity() {
            let mut packet = sent(now);
            packet.state = State::Control;
            history.on_sent(packet);
        }
        assert_eq!(history.packets.len(), MAX_HISTORY - 1);
    }
}
