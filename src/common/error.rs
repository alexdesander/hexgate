// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::io;

#[derive(Debug, thiserror::Error)]
pub enum RecvError {
    #[error("the network thread has stopped")]
    Stopped,
    /// The network thread stopped because of a fatal socket error.
    /// Returned once, later calls return `Stopped`.
    #[error("the network thread failed: {0}")]
    Io(#[from] io::Error),
}
