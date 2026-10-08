// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crossbeam::channel::{unbounded, Receiver, Sender, TryRecvError};

use super::error::RecvError;

/// The network thread never blocks on the app: connection events are always queued, received
/// messages only while fewer than `max_events` events are queued (see `has_room`).
pub(crate) fn channel<E>(max_events: usize) -> (EventSender<E>, EventReceiver<E>) {
    let (tx, rx) = unbounded();
    (EventSender { tx, max_events }, EventReceiver { rx })
}

pub(crate) struct EventSender<E> {
    tx: Sender<Result<E, RecvError>>,
    max_events: usize,
}

impl<E> EventSender<E> {
    pub fn send(&self, event: E) {
        let _ = self.tx.send(Ok(event));
    }

    /// When false, incoming payload packets are dropped: unreliable messages are lost, reliable
    /// packets stay unacknowledged and are retransmitted by the peer.
    pub fn has_room(&self) -> bool {
        self.tx.len() < self.max_events
    }

    /// Reports why the network thread stopped.
    pub fn fail(&self, error: RecvError) {
        let _ = self.tx.send(Err(error));
    }
}

pub(crate) struct EventReceiver<E> {
    rx: Receiver<Result<E, RecvError>>,
}

impl<E> EventReceiver<E> {
    pub fn next(&self) -> Result<E, RecvError> {
        self.rx.recv().map_err(|_| RecvError::Stopped)?
    }

    pub fn try_next(&self) -> Result<Option<E>, RecvError> {
        match self.rx.try_recv() {
            Ok(event) => event.map(Some),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(RecvError::Stopped),
        }
    }
}
