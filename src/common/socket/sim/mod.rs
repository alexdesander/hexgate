// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Network simulation for testing a game under bad connections.
//!
//! A [`Simulator`] decides the fate of every packet a client or server sends or receives: it
//! can drop, delay, corrupt or duplicate it. [`Link`] emulates one direction of a real path
//! (rate-limited bottleneck with a buffer, delay and jitter, bursty loss, spikes, stalls,
//! outages), and [`Profile`] has presets from perfect to terrible:
//!
//! ```no_run
//! # fn run(client: hexgate::Client) {
//! use hexgate::sim::Profile;
//!
//! // Both directions, simulated at the client.
//! let _ = client.set_simulator(Profile::bad().client(1));
//! # }
//! ```
//!
//! The simulation runs on the network thread, in real time. Delayed packets are released when
//! the thread wakes up, which can be up to ~1 ms late. Packets still delayed when the client or
//! server stops are delivered by a short-lived thread.

use std::{cmp::Ordering, collections::BinaryHeap, fmt, net::SocketAddr, time::Instant};

mod bottleneck;
mod link;
mod profile;

pub use bottleneck::{Bottleneck, CrossTraffic};
pub use link::{
    Duplicate, Episodes, Interval, Jitter, JitterDistribution, Link, LinkConfig, LinkStats, Loss,
    Reorder, Spikes,
};
pub use profile::Profile;

/// Decides what happens to each packet on one direction of a connection.
///
/// [`Link`] covers the usual conditions, implement this for anything else (e.g. dropping one
/// specific packet in a test).
pub trait NetworkSimulator: Send {
    /// The fate of `packet` to or from `peer`, handed to the network at `now`. It may be
    /// modified (corrupted).
    fn simulate(&mut self, now: Instant, peer: SocketAddr, packet: &mut [u8]) -> Fate;
}

/// What happens to a packet, see [`NetworkSimulator`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fate {
    /// The packet is lost.
    Drop,
    /// The packet arrives at this time (now or earlier: right away).
    Deliver(Instant),
    /// The packet arrives twice.
    Duplicate(Instant, Instant),
}

/// The simulators of both directions of a client or server, `Simulator::default()` simulates
/// nothing.
#[derive(Default)]
pub struct Simulator {
    /// Applied to the packets this end sends.
    pub send: Option<Box<dyn NetworkSimulator>>,
    /// Applied to the packets this end receives, before they are processed.
    pub recv: Option<Box<dyn NetworkSimulator>>,
}

impl Simulator {
    /// Simulates both directions.
    pub fn new(
        send: impl NetworkSimulator + 'static,
        recv: impl NetworkSimulator + 'static,
    ) -> Self {
        Self {
            send: Some(Box::new(send)),
            recv: Some(Box::new(recv)),
        }
    }

    /// Simulates only the sent packets.
    pub fn sending(send: impl NetworkSimulator + 'static) -> Self {
        Self {
            send: Some(Box::new(send)),
            recv: None,
        }
    }

    /// Simulates only the received packets.
    pub fn receiving(recv: impl NetworkSimulator + 'static) -> Self {
        Self {
            send: None,
            recv: Some(Box::new(recv)),
        }
    }
}

impl fmt::Debug for Simulator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Simulator")
            .field("send", &self.send.is_some())
            .field("recv", &self.recv.is_some())
            .finish()
    }
}

/// Packets waiting for their delivery time.
#[derive(Default)]
pub(crate) struct DelayQueue {
    pending: BinaryHeap<Pending>,
    pool: Vec<Vec<u8>>,
    seq: u64,
}

pub(crate) struct Pending {
    pub at: Instant,
    seq: u64,
    pub peer: SocketAddr,
    pub data: Vec<u8>,
}

impl PartialEq for Pending {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Pending {}

impl PartialOrd for Pending {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Pending {
    /// Earliest first in the max-heap, equal times in insertion order.
    fn cmp(&self, other: &Self) -> Ordering {
        (other.at, other.seq).cmp(&(self.at, self.seq))
    }
}

impl DelayQueue {
    /// A buffer holding `data`, reused from delivered packets.
    pub fn buffer(&mut self, data: &[u8]) -> Vec<u8> {
        let mut buf = self.pool.pop().unwrap_or_default();
        buf.extend_from_slice(data);
        buf
    }

    pub fn recycle(&mut self, mut buf: Vec<u8>) {
        buf.clear();
        self.pool.push(buf);
    }

    pub fn push(&mut self, at: Instant, peer: SocketAddr, data: Vec<u8>) {
        self.seq += 1;
        self.pending.push(Pending {
            at,
            seq: self.seq,
            peer,
            data,
        });
    }

    pub fn next_deadline(&self) -> Option<Instant> {
        self.pending.peek().map(|pending| pending.at)
    }

    pub fn pop_due(&mut self, now: Instant) -> Option<Pending> {
        self.pending
            .peek()
            .is_some_and(|pending| pending.at <= now)
            .then(|| self.pending.pop().unwrap())
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    pub fn into_sorted(self) -> impl Iterator<Item = Pending> {
        self.pending.into_sorted_vec().into_iter().rev()
    }
}
