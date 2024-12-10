// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::time::Instant;

use crate::common::{
    channel::{scheduler::ChannelConfiguration, Channels},
    congestion::CongestionController,
    crypto::Crypto,
};

/// This struct just holds state. The logic resides in the thread module.
pub struct Connection {
    pub crypto: Crypto,
    pub last_latency_discovery_response: u32,
    pub last_received: Instant,
    pub last_sent: Instant,

    pub channels: Channels,
    pub congestion: CongestionController,
}

impl Connection {
    pub fn new(crypto: Crypto, channel_config: &ChannelConfiguration) -> Self {
        let congestion = CongestionController::new();
        Self {
            crypto,
            last_latency_discovery_response: 0,
            last_received: Instant::now(),
            last_sent: Instant::now(),

            channels: Channels::new(&congestion, channel_config),
            congestion,
        }
    }
}
