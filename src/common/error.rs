// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::io;

use super::channel::Channel;

#[derive(Debug, thiserror::Error)]
pub enum RecvError {
    #[error("the network thread has stopped")]
    Stopped,
    /// The network thread stopped because of a fatal socket error.
    /// Returned once, later calls return `Stopped`.
    #[error("the network thread failed: {0}")]
    Io(#[from] io::Error),
}

/// The peer broke the protocol and was disconnected.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ProtocolViolation {
    #[error("received a message larger than max_recv_msg_size ({max} bytes)")]
    MessageTooLarge { max: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{size} bytes exceed the limit of {max} bytes")]
pub struct TooLarge {
    pub size: usize,
    pub max: usize,
}

impl TooLarge {
    pub(crate) fn check(size: usize, max: usize) -> Result<(), Self> {
        if size > max {
            return Err(Self { size, max });
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SendError {
    #[error("message too large: {0}")]
    MessageTooLarge(TooLarge),
    #[error("channel {0:?} is not configured")]
    UnknownChannel(Channel),
    #[error("the network thread has stopped")]
    Stopped,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("channel weights must be greater than zero")]
    ZeroChannelWeight,
    #[error("{0} channels of one kind configured, at most 256 are supported")]
    TooManyChannels(usize),
    #[error("info too large: {0}")]
    InfoTooLarge(TooLarge),
    #[error("congestion config needs 0 < min_bandwidth <= start_bandwidth <= max_bandwidth")]
    InvalidBandwidth,
}
