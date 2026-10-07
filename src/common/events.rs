// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::io;

use crossbeam::channel::{bounded, Receiver, Sender, TryRecvError};

use super::error::RecvError;

pub(crate) fn channel<E>(max_events: usize) -> (EventSender<E>, EventReceiver<E>) {
    let (tx, rx) = bounded(max_events);
    (EventSender { tx }, EventReceiver { rx })
}

pub(crate) struct EventSender<E> {
    tx: Sender<Result<E, io::Error>>,
}

impl<E> EventSender<E> {
    pub fn send(&self, event: E) {
        let _ = self.tx.send(Ok(event));
    }

    /// Reports the fatal error that stopped the network thread.
    pub fn fail(&self, error: io::Error) {
        let _ = self.tx.send(Err(error));
    }
}

pub(crate) struct EventReceiver<E> {
    rx: Receiver<Result<E, io::Error>>,
}

impl<E> EventReceiver<E> {
    pub fn next(&self) -> Result<E, RecvError> {
        self.rx
            .recv()
            .map_err(|_| RecvError::Stopped)?
            .map_err(RecvError::Io)
    }

    pub fn try_next(&self) -> Result<Option<E>, RecvError> {
        match self.rx.try_recv() {
            Ok(event) => event.map(Some).map_err(RecvError::Io),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(RecvError::Stopped),
        }
    }
}
