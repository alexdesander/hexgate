// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{rc::Rc, time::Instant};

use crate::common::{
    channel::{scheduler::ChannelConfiguration, Channels},
    congestion::{CongestionConfiguration, CongestionController},
    crypto::Crypto,
    stats::ProbeLoss,
};

/// This struct just holds state. The logic resides in the thread module.
pub struct Connection {
    pub crypto: Crypto,
    pub last_latency_discovery_response: u32,
    pub probe_loss: ProbeLoss,
    pub last_received: Instant,
    pub last_sent: Instant,

    pub channels: Channels,
    pub congestion: CongestionController,
    /// Reason of a graceful disconnect in progress.
    pub closing: Option<Rc<[u8]>>,
}

impl Connection {
    pub fn new(
        crypto: Crypto,
        channel_config: &ChannelConfiguration,
        congestion_config: CongestionConfiguration,
        max_recv_msg_size: usize,
    ) -> Self {
        Self {
            crypto,
            last_latency_discovery_response: 0,
            probe_loss: ProbeLoss::default(),
            last_received: Instant::now(),
            last_sent: Instant::now(),

            channels: Channels::new(channel_config, max_recv_msg_size),
            congestion: CongestionController::new(congestion_config),
            closing: None,
        }
    }
}
