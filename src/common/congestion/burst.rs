// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Bursts: runs of packets sent back to back at the pacing rate (a tick's messages, or one
//! micro-burst of backlogged data). Once every packet of a burst is acknowledged or lost and
//! the next burst began, it yields a sample: how fast the bottleneck delivered it (from the
//! receive timestamps) against how fast we sent.

use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

/// A burst whose next packet comes this much later than the pacing schedule allows is closed.
const MAX_GAP: Duration = Duration::from_millis(4);
/// A packet this soon after a burst that emptied the queue continues it (the app's messages
/// of one tick that reached the network thread one by one).
const MERGE: Duration = Duration::from_millis(1);
/// Receive spreads below this are measured as this: arrivals within the same wake-up of the
/// network thread can't be told apart. The delivery rate is then a lower bound.
const MIN_SPREAD: f64 = 0.001;

struct Burst {
    seq: u64,
    start: Instant,
    last_sent: Instant,
    bytes: u64,
    packets: u32,
    open: bool,
    /// Ended because the queue was empty.
    app_limited: bool,
    /// Realtime packets sent past the pacer between micro-bursts.
    interleaved: bool,
    /// Packets neither acknowledged nor lost.
    outstanding: u32,
    lost: u32,
    /// One-way delay (raw, with clock offset) of the first packet, µs.
    first_owd: Option<i64>,
    /// Packet number and receive time (µs) of the timestamped packets with the lowest and the
    /// highest number, the earliest and latest receive time, bytes and packets.
    lowest: (u64, i64),
    highest: (u64, i64),
    first_recv: i64,
    last_recv: i64,
    recv_bytes: u64,
    recv_packets: u32,
    /// Timestamps out of packet number order: the spread says nothing about the bottleneck.
    reordered: bool,
    /// The stall check fired for this burst.
    stalled: bool,
}

/// A resolved burst.
#[derive(Debug, Clone, Copy)]
pub struct Sample {
    /// When the burst began, on our clock.
    pub start: Instant,
    /// Until the next burst began (L).
    pub period: Duration,
    pub bytes: u64,
    pub packets: u32,
    pub app_limited: bool,
    /// Realtime packets between micro-bursts: only `first_owd` and `recv` mean something.
    pub interleaved: bool,
    /// One-way delay of the first packet (raw, seconds).
    pub first_owd: Option<f64>,
    /// The rate the bottleneck delivered the burst at, if two or more packets arrived in
    /// order and apart.
    pub delivery_rate: Option<f64>,
    /// Receive span (µs, receiver clock), bytes and packets.
    pub recv: Option<(i64, i64, u64, u32)>,
}

#[derive(Default)]
pub struct Bursts {
    bursts: VecDeque<Burst>,
    next_seq: u64,
}

impl Bursts {
    fn get(&mut self, seq: u64) -> Option<&mut Burst> {
        let front = self.bursts.front()?.seq;
        self.bursts
            .get_mut(usize::try_from(seq.checked_sub(front)?).ok()?)
    }

    /// Adds a sent packet, returns its burst and whether it is the burst's first packet.
    /// `end`: the burst ends, `app_limited` because the queue is empty, `realtime`: sent past
    /// the pacer (its own burst unless one is open). `pacing_gap`: the expected time to the
    /// next packet of the same burst.
    pub fn on_sent(
        &mut self,
        now: Instant,
        size: usize,
        (end, app_limited, realtime): (bool, bool, bool),
        pacing_gap: Duration,
    ) -> (u64, bool) {
        let open = self.bursts.back_mut().filter(|burst| {
            let gap = now.saturating_duration_since(burst.last_sent);
            !burst.interleaved
                && ((burst.open && gap <= MAX_GAP.max(pacing_gap * 4))
                    || (burst.app_limited && gap <= MERGE && !realtime))
        });
        let interleaved = open.is_none() && realtime;
        let burst = match open {
            Some(burst) => burst,
            None => {
                if let Some(previous) = self.bursts.back_mut() {
                    previous.open = false;
                }
                self.bursts.push_back(Burst {
                    seq: self.next_seq,
                    start: now,
                    last_sent: now,
                    bytes: 0,
                    packets: 0,
                    open: true,
                    app_limited: false,
                    interleaved,
                    outstanding: 0,
                    lost: 0,
                    first_owd: None,
                    lowest: (u64::MAX, 0),
                    highest: (0, 0),
                    first_recv: i64::MAX,
                    last_recv: i64::MIN,
                    recv_bytes: 0,
                    recv_packets: 0,
                    reordered: false,
                    stalled: false,
                });
                self.next_seq += 1;
                self.bursts.back_mut().unwrap()
            }
        };
        burst.last_sent = now;
        burst.bytes += size as u64;
        burst.packets += 1;
        burst.outstanding += 1;
        if !realtime || !interleaved {
            burst.open = !end;
            burst.app_limited = end && app_limited;
        }
        if interleaved {
            burst.open = false;
        }
        (burst.seq, burst.packets == 1)
    }

    /// Packet `pn` of `burst` arrived at `recv_us` with the raw one-way delay `owd`.
    pub fn on_timestamp(
        &mut self,
        burst: u64,
        pn: u64,
        first: bool,
        (recv_us, owd): (i64, i64),
        size: usize,
    ) {
        let Some(burst) = self.get(burst) else {
            return;
        };
        if first {
            burst.first_owd = Some(owd);
        }
        if burst.recv_packets > 0
            && ((pn > burst.highest.0 && recv_us < burst.highest.1)
                || (pn < burst.lowest.0 && recv_us > burst.lowest.1))
        {
            burst.reordered = true;
        }
        if pn > burst.highest.0 || burst.recv_packets == 0 {
            burst.highest = (pn, recv_us);
        }
        if pn < burst.lowest.0 {
            burst.lowest = (pn, recv_us);
        }
        burst.first_recv = burst.first_recv.min(recv_us);
        burst.last_recv = burst.last_recv.max(recv_us);
        burst.recv_bytes += size as u64;
        burst.recv_packets += 1;
    }

    /// A packet of `burst` was acknowledged or declared lost.
    pub fn on_done(&mut self, burst: u64, lost: bool) {
        if let Some(burst) = self.get(burst) {
            burst.outstanding = burst.outstanding.saturating_sub(1);
            burst.lost += u32::from(lost);
        }
    }

    /// The oldest burst if it can be resolved: all of its packets are done and the next
    /// regular burst began. Interleaved bursts in between count to its bytes.
    pub fn resolve(&mut self) -> Option<Sample> {
        let burst = self.bursts.front()?;
        if burst.open || burst.outstanding > 0 {
            return None;
        }
        let (next, interleaved_bytes) = if burst.interleaved {
            (burst.start, 0)
        } else {
            let mut bytes = 0;
            let next = self.bursts.iter().skip(1).find(|next| {
                bytes += if next.interleaved { next.bytes } else { 0 };
                !next.interleaved
            })?;
            (next.start, bytes)
        };
        let period = next.saturating_duration_since(burst.start);
        let packets = burst.recv_packets;
        let delivery_rate = (packets >= 2 && !burst.reordered).then(|| {
            let spread = ((burst.last_recv - burst.first_recv) as f64 / 1e6).max(MIN_SPREAD);
            burst.recv_bytes as f64 * f64::from(packets - 1) / f64::from(packets) / spread
        });
        let sample = Sample {
            start: burst.start,
            period: period.max(Duration::from_micros(100)),
            bytes: burst.bytes + interleaved_bytes,
            packets: burst.packets,
            app_limited: burst.app_limited,
            interleaved: burst.interleaved,
            first_owd: burst.first_owd.map(|owd| owd as f64 / 1e6),
            delivery_rate,
            recv: (packets > 0).then_some((
                burst.first_recv,
                burst.last_recv,
                burst.recv_bytes,
                packets,
            )),
        };
        self.bursts.pop_front();
        Some(sample)
    }

    /// The oldest burst with packets in flight (Pudica's "next delay"): its start and a
    /// handle for `mark_stalled`, unless it was reported already.
    pub fn stall_candidate(&self) -> Option<(Instant, u64)> {
        let burst = self.bursts.iter().find(|burst| burst.outstanding > 0)?;
        (!burst.stalled).then_some((burst.start, burst.seq))
    }

    pub fn mark_stalled(&mut self, seq: u64) {
        if let Some(burst) = self.get(seq) {
            burst.stalled = true;
        }
    }

    /// Drops all bursts (persistent congestion: nothing will resolve them).
    pub fn clear(&mut self) {
        self.bursts.clear();
    }
}
