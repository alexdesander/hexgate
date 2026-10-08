use std::{
    collections::HashMap,
    ops::Deref,
    sync::{Arc, Mutex, PoisonError},
    time::Instant,
};

use super::{
    channel::Channel,
    error::{ConfigError, SendError},
};

/// Bounds retained outgoing buffers, including commands awaiting the network thread
#[derive(Debug, Clone, Copy)]
pub struct SendQueueLimits {
    /// Buffer capacity retained per connection
    pub max_bytes: usize,
    /// Messages retained per connection, including empty messages
    pub max_messages: usize,
    /// Buffer capacity retained on any one channel
    pub max_channel_bytes: usize,
    /// Messages retained on any one channel
    pub max_channel_messages: usize,
}

impl Default for SendQueueLimits {
    fn default() -> Self {
        Self {
            max_bytes: 8 << 20,
            max_messages: 4096,
            max_channel_bytes: 4 << 20,
            max_channel_messages: 2048,
        }
    }
}

impl SendQueueLimits {
    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        if [
            self.max_bytes,
            self.max_messages,
            self.max_channel_bytes,
            self.max_channel_messages,
        ]
        .contains(&0)
        {
            return Err(ConfigError::InvalidQueueLimits);
        }
        Ok(())
    }
}

/// Optional freshness and acknowledgment feedback for one send
#[derive(Debug, Clone, Copy, Default)]
pub struct SendOptions {
    /// Unreliable messages expire at this instant, including time spent connecting
    pub deadline: Option<Instant>,
    /// Replace unsent unreliable messages on the same channel
    pub replace: bool,
    /// Application cookie returned with transport delivery feedback
    pub receipt: Option<u64>,
}

/// Transport acknowledgment feedback, independent of application processing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendOutcome {
    /// Every part of the message was acknowledged by the peer transport
    Acked,
    /// Confirmation is unavailable; the peer might still have received the message
    Dropped,
}

impl SendOptions {
    pub(crate) fn validate(self, channel: Channel) -> Result<(), SendError> {
        if matches!(channel, Channel::Reliable(_)) && (self.deadline.is_some() || self.replace) {
            return Err(SendError::InvalidOptions);
        }
        Ok(())
    }
}

#[derive(Default)]
struct Usage {
    bytes: usize,
    messages: usize,
}

#[derive(Default)]
struct State {
    total: Usage,
    channels: HashMap<Channel, Usage>,
}

pub(crate) struct Admission {
    limits: SendQueueLimits,
    state: Mutex<State>,
}

impl Admission {
    pub fn new(limits: SendQueueLimits) -> Arc<Self> {
        Arc::new(Self {
            limits,
            state: Mutex::new(State::default()),
        })
    }

    pub fn reserve(
        self: &Arc<Self>,
        channel: Channel,
        bytes: usize,
    ) -> Result<Arc<Reservation>, SendError> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let limit = self.limits;
        if bytes > limit.max_bytes.saturating_sub(state.total.bytes)
            || state.total.messages >= limit.max_messages
        {
            return Err(SendError::Backpressure);
        }
        let usage = state.channels.entry(channel).or_default();
        if bytes > limit.max_channel_bytes.saturating_sub(usage.bytes)
            || usage.messages >= limit.max_channel_messages
        {
            return Err(SendError::Backpressure);
        }
        usage.bytes += bytes;
        usage.messages += 1;
        state.total.bytes += bytes;
        state.total.messages += 1;
        Ok(Arc::new(Reservation {
            admission: self.clone(),
            channel,
            bytes,
        }))
    }
}

pub(crate) struct Reservation {
    admission: Arc<Admission>,
    channel: Channel,
    bytes: usize,
}

impl Reservation {
    pub fn admission(&self) -> &Arc<Admission> {
        &self.admission
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        let mut state = self
            .admission
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        state.total.bytes -= self.bytes;
        state.total.messages -= 1;
        let usage = state.channels.get_mut(&self.channel).unwrap();
        usage.bytes -= self.bytes;
        usage.messages -= 1;
        if usage.messages == 0 {
            state.channels.remove(&self.channel);
        }
    }
}

#[derive(Clone)]
pub(crate) struct Message {
    pub data: Arc<Vec<u8>>,
    pub submitted: Instant,
    pub options: SendOptions,
    pub reservation: Option<Arc<Reservation>>,
}

impl Message {
    #[cfg(any(test, feature = "bench", fuzzing))]
    pub fn untracked(data: std::rc::Rc<Vec<u8>>, submitted: Instant) -> Self {
        Self {
            data: Arc::new(std::rc::Rc::try_unwrap(data).unwrap_or_else(|data| (*data).clone())),
            submitted,
            options: SendOptions::default(),
            reservation: None,
        }
    }
}

impl Deref for Message {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

pub(crate) fn command_error<T>(error: crossbeam_channel::TrySendError<T>) -> SendError {
    match error {
        crossbeam_channel::TrySendError::Full(_) => SendError::Backpressure,
        crossbeam_channel::TrySendError::Disconnected(_) => SendError::Stopped,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reservations_bound_shared_producers_and_release_on_last_drop() {
        let admission = Admission::new(SendQueueLimits {
            max_bytes: 100,
            max_messages: 3,
            max_channel_bytes: 60,
            max_channel_messages: 2,
        });
        let first = admission.reserve(Channel::Reliable(0), 60).unwrap();
        let clone = first.clone();
        assert!(matches!(
            admission.reserve(Channel::Reliable(0), 1),
            Err(SendError::Backpressure)
        ));
        let second = admission.reserve(Channel::Unreliable, 40).unwrap();
        assert!(matches!(
            admission.reserve(Channel::Reliable(1), 1),
            Err(SendError::Backpressure)
        ));
        drop(first);
        assert!(admission.reserve(Channel::Reliable(0), 1).is_err());
        drop(clone);
        let empty = admission.reserve(Channel::Unreliable, 0).unwrap();
        assert!(admission.reserve(Channel::Unreliable, 0).is_err());
        drop((second, empty));
        assert!(admission.reserve(Channel::Reliable(0), 60).is_ok());
    }
}
