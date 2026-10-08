// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use crossbeam_channel::{Receiver, Sender, TryRecvError, unbounded};

use super::error::RecvError;

const MAX_QUEUED_BYTES: usize = 64 << 20;

pub(crate) struct DeliveryBudget {
    pub messages: usize,
    pub bytes: usize,
    pub work: usize,
}

impl DeliveryBudget {
    #[cfg(any(test, feature = "bench"))]
    pub fn unlimited() -> Self {
        Self {
            messages: usize::MAX,
            bytes: usize::MAX,
            work: usize::MAX,
        }
    }

    pub fn take(&mut self, bytes: usize) -> bool {
        if self.messages == 0 || bytes > self.bytes {
            return false;
        }
        self.messages -= 1;
        self.bytes -= bytes;
        true
    }
}

pub(crate) trait Payload {
    fn payload_len(&self) -> usize;
}

/// The network thread never blocks on the app: connection events are always queued, received
/// messages only while fewer than `max_events` events and 64 MiB (at least 4 messages of
/// `max_recv_msg_size`) of messages are queued (see `has_room`).
pub(crate) fn channel<E: Payload>(
    max_events: usize,
    max_recv_msg_size: usize,
) -> (EventSender<E>, EventReceiver<E>) {
    let (tx, rx) = unbounded();
    let bytes = Arc::new(AtomicUsize::new(0));
    let sender = EventSender {
        tx,
        bytes: bytes.clone(),
        max_events,
        max_bytes: MAX_QUEUED_BYTES.max(max_recv_msg_size.saturating_mul(4)),
    };
    (sender, EventReceiver { rx, bytes })
}

pub(crate) struct EventSender<E> {
    tx: Sender<Result<E, RecvError>>,
    bytes: Arc<AtomicUsize>,
    max_events: usize,
    max_bytes: usize,
}

impl<E> Clone for EventSender<E> {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
            bytes: self.bytes.clone(),
            max_events: self.max_events,
            max_bytes: self.max_bytes,
        }
    }
}

impl<E: Payload> EventSender<E> {
    pub fn send(&self, event: E) {
        self.bytes.fetch_add(event.payload_len(), Ordering::Relaxed);
        let _ = self.tx.send(Ok(event));
    }

    pub fn budget(&self) -> DeliveryBudget {
        DeliveryBudget {
            messages: self.max_events.saturating_sub(self.tx.len()).min(256),
            bytes: self
                .max_bytes
                .saturating_sub(self.bytes.load(Ordering::Relaxed)),
            work: 64 << 10,
        }
    }

    /// Reports why the network thread stopped.
    pub fn fail(&self, error: RecvError) {
        let _ = self.tx.send(Err(error));
    }
}

pub(crate) struct EventReceiver<E> {
    rx: Receiver<Result<E, RecvError>>,
    bytes: Arc<AtomicUsize>,
}

impl<E: Payload> EventReceiver<E> {
    pub fn next(&self) -> Result<E, RecvError> {
        self.rx
            .recv()
            .map_err(|_| RecvError::Stopped)?
            .inspect(|event| self.dequeued(event))
    }

    pub fn try_next(&self) -> Result<Option<E>, RecvError> {
        match self.rx.try_recv() {
            Ok(event) => event.inspect(|event| self.dequeued(event)).map(Some),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(RecvError::Stopped),
        }
    }

    fn dequeued(&self, event: &E) {
        self.bytes.fetch_sub(event.payload_len(), Ordering::Relaxed);
    }
}
