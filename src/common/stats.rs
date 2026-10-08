// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::time::Duration;

use super::congestion::Congestion;

/// Queue observations for one channel
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ChannelStats {
    /// Stream or message bytes that have not been transmitted
    pub unsent_bytes: usize,
    /// Reliable stream bytes transmitted but not acknowledged
    pub unacked_bytes: usize,
    /// Age since application submission of the oldest retained message
    pub oldest_queued: Option<Duration>,
    /// Gross-rate estimate without competing queues or retransmissions, never delivery credit
    pub send_delay: Option<Duration>,
}

/// Connection statistics, see `Client::stats` and `Server::stats`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Stats {
    /// Smoothed round-trip time, `None` before the first acknowledgement.
    pub rtt: Option<Duration>,
    /// The lowest round-trip time of the last 10 s: the path without queueing.
    pub min_rtt: Option<Duration>,
    /// Mean deviation of the round-trip time.
    pub rtt_var: Duration,
    /// Standing round-trip delay above the recent minimum, including reverse-path congestion
    pub queue_delay: Duration,
    /// The congestion controller's send rate in bytes per second, see `gross_send_budget`.
    pub send_rate: u64,
    /// Bytes per second the peer received recently.
    pub delivery_rate: u64,
    /// Smoothed fraction of the sent packets that were lost.
    pub packet_loss: f32,
    /// Why the send rate is limited, if it is.
    pub congestion: Option<Congestion>,
    /// Bytes waiting to be sent, plus reliable bytes waiting for an acknowledgement.
    pub queued_bytes: usize,
    /// Unreliable messages dropped because they waited longer than `unreliable_max_age`.
    pub expired_messages: u64,
}
