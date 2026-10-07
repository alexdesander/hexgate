// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::time::Duration;

use super::{channel::Channels, congestion::CongestionController};

/// Weight of the newest probe in the loss estimate (about the last 10 probes count).
const LOSS_SMOOTHING: f32 = 0.1;
/// More missing probes than this in a row count as this many.
const MAX_PROBE_GAP: u32 = 16;

/// Connection statistics, see `Client::stats` and `Server::stats`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Stats {
    /// Average round-trip time of the recent latency probes, `None` before the first answer.
    pub rtt: Option<Duration>,
    /// Mean deviation of those round-trip times.
    pub jitter: Duration,
    /// Smoothed fraction of latency probes without an answer (loss in both directions).
    pub packet_loss: f32,
    /// The congestion controller's current send rate in bytes per second.
    pub send_rate: u64,
    /// Bytes waiting to be sent, plus reliable bytes waiting for an acknowledgement.
    pub queued_bytes: usize,
}

impl Stats {
    pub(crate) fn new(
        congestion: &CongestionController,
        channels: &Channels,
        probe_loss: &ProbeLoss,
    ) -> Self {
        Self {
            rtt: congestion.rtt(),
            jitter: congestion.jitter(),
            packet_loss: probe_loss.loss,
            send_rate: congestion.send_rate(),
            queued_bytes: channels.queued_bytes(),
        }
    }
}

/// Smoothed fraction of latency probes that were not answered before the next one.
#[derive(Default)]
pub(crate) struct ProbeLoss {
    loss: f32,
    /// Sequence number of the latest probe and whether it was answered.
    latest: Option<(u32, bool)>,
}

impl ProbeLoss {
    /// Probe `seq` was sent (server) or received (client, where gaps are lost probes).
    pub fn probe(&mut self, seq: u32) {
        if let Some((latest, answered)) = self.latest {
            if seq <= latest {
                return;
            }
            for _ in 0..(seq - latest - 1).min(MAX_PROBE_GAP) {
                self.record(true);
            }
            self.record(!answered);
        }
        self.latest = Some((seq, false));
    }

    pub fn answered(&mut self, seq: u32) {
        if let Some((latest, answered)) = &mut self.latest {
            *answered |= *latest == seq;
        }
    }

    fn record(&mut self, lost: bool) {
        self.loss += (f32::from(u8::from(lost)) - self.loss) * LOSS_SMOOTHING;
    }
}
