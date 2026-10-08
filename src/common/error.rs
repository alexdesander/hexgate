// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Errors of the client and server handles.

use std::{any::Any, io, net::SocketAddr};

use super::channel::Channel;

/// Returned by `next` and `try_next` once the network thread has stopped.
#[derive(Debug, thiserror::Error)]
pub enum RecvError {
    /// The thread stopped normally (disconnect, timeout, shutdown) or the reason was already
    /// returned.
    #[error("the network thread has stopped")]
    Stopped,
    /// The network thread stopped because of a fatal socket error.
    /// Returned once, later calls return `Stopped`.
    #[error("the network thread failed: {0}")]
    Io(#[from] io::Error),
    /// The network thread or the authenticator panicked, with this message.
    /// Returned once, later calls return `Stopped`.
    #[error("hexgate panicked: {0}")]
    Panicked(String),
}

impl RecvError {
    pub(crate) fn panicked(payload: Box<dyn Any + Send>) -> Self {
        let message = match payload.downcast::<String>() {
            Ok(message) => *message,
            Err(payload) => payload
                .downcast_ref::<&str>()
                .map_or_else(String::new, |message| message.to_string()),
        };
        Self::Panicked(message)
    }
}

/// The peer broke the protocol and was disconnected.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ProtocolViolation {
    /// A message exceeded `max_recv_msg_size`.
    #[error("received a message larger than max_recv_msg_size ({max} bytes)")]
    MessageTooLarge {
        /// `max_recv_msg_size`.
        max: usize,
    },
    /// A frame that no correct peer sends: inconsistent fragments, reliable data beyond the
    /// flow-control window.
    #[error("received a malformed frame")]
    Malformed,
}

/// Data longer than allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{size} bytes exceed the limit of {max} bytes")]
pub struct TooLarge {
    /// The data's size.
    pub size: usize,
    /// The limit.
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

/// Why a message couldn't be queued.
#[derive(Debug, thiserror::Error)]
pub enum SendError {
    /// The message exceeds `max_send_msg_size`.
    #[error("message too large: {0}")]
    MessageTooLarge(TooLarge),
    /// The channel id is beyond the channel configuration.
    #[error("channel {0:?} is not configured")]
    UnknownChannel(Channel),
    /// The client isn't connected (see `Server::connections`). A client disconnecting at the
    /// same time can still drop the message without this error.
    #[error("{0} is not connected")]
    NotConnected(SocketAddr),
    /// `next`/`try_next` report why.
    #[error("the network thread has stopped")]
    Stopped,
}

/// An invalid builder setting.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// A `ChannelConfiguration` weight is 0.
    #[error("channel weights must be greater than zero")]
    ZeroChannelWeight,
    /// More than 256 unreliable ordered or reliable channels.
    #[error("{0} channels of one kind configured, at most 256 are supported")]
    TooManyChannels(usize),
    /// The server info exceeds 256 bytes.
    #[error("info too large: {0}")]
    InfoTooLarge(TooLarge),
    /// The `CongestionConfig` rates are out of order or zero.
    #[error("congestion config needs 0 < min_rate <= initial_rate <= max_rate")]
    InvalidRate,
}
