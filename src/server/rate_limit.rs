// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{
    net::{IpAddr, Ipv6Addr},
    time::{Duration, Instant},
};

use ahash::HashMap;

/// A token bucket per IPv4 address or IPv6 /64 network.
pub(crate) struct RateLimiter {
    per_second: f64,
    burst: f64,
    buckets: HashMap<IpAddr, (f64, Instant)>,
}

impl RateLimiter {
    pub fn new(per_second: f64, burst: f64) -> Self {
        Self {
            per_second,
            burst,
            buckets: HashMap::default(),
        }
    }

    pub fn allow(&mut self, ip: IpAddr, now: Instant) -> bool {
        let (tokens, last) = self.buckets.entry(network(ip)).or_insert((self.burst, now));
        let refill = self.per_second * now.saturating_duration_since(*last).as_secs_f64();
        *tokens = (*tokens + refill).min(self.burst);
        *last = now;
        if *tokens < 1.0 {
            return false;
        }
        *tokens -= 1.0;
        true
    }

    /// Forgets networks whose bucket has refilled completely.
    pub fn prune(&mut self, now: Instant) {
        let refill_time = Duration::from_secs_f64(self.burst / self.per_second);
        self.buckets
            .retain(|_, (_, last)| now.saturating_duration_since(*last) < refill_time);
    }
}

fn network(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(ip) => IpAddr::V6(Ipv6Addr::from(u128::from(ip) & !u128::from(u64::MAX))),
        ipv4 => ipv4,
    }
}
