// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{net::SocketAddr, sync::Arc};

use crossbeam::channel::{Receiver, Sender};
use mio::Waker;

use super::thread::Cmd;
use crate::common::packets::login_response::MAX_FAILURE_DATA_SIZE;

pub trait AuthResult: Send + 'static {}
impl<T> AuthResult for T where T: Send + 'static {}

/// Runs on its own thread, one login at a time.
///
/// Every login attempt needs a key exchange, and the server allows at most 10 per second (burst
/// 20) per IPv4 address or IPv6 /64. Limit failed attempts per account here when `auth_data` is
/// a password.
pub trait Authenticator<R: AuthResult>: Send + 'static {
    /// Authenticate the client with the given authentication data.
    /// The error value is sent to the client if the authentication fails.
    /// NOTE: The error vec is truncated to 1181 bytes.
    fn authenticate(&mut self, from: SocketAddr, auth_data: Vec<u8>) -> Result<R, Vec<u8>>;
}

/// Login attempts are identified by the client address and the handshake salt.
pub(crate) type LoginAttempt = (SocketAddr, [u8; 4]);

pub(crate) enum AuthCmd {
    Authenticate(LoginAttempt, Vec<u8>),
}

pub(crate) struct AuthThreadState<A: Authenticator<R>, R: AuthResult> {
    pub phantom: std::marker::PhantomData<R>,
    pub authenticator: A,
    pub main_cmds: Sender<Cmd<R>>,
    pub cmds: Receiver<AuthCmd>,
    pub waker: Arc<Waker>,
}

impl<R: AuthResult, A: Authenticator<R>> Drop for AuthThreadState<A, R> {
    fn drop(&mut self) {
        let _ = self.main_cmds.send(Cmd::Shutdown(vec![]));
        let _ = self.waker.wake();
    }
}

pub(crate) fn auth_thread<R: AuthResult, A: Authenticator<R>>(mut state: AuthThreadState<A, R>) {
    while let Ok(cmd) = state.cmds.recv() {
        match cmd {
            AuthCmd::Authenticate(attempt, auth_data) => {
                match state.authenticator.authenticate(attempt.0, auth_data) {
                    Ok(auth_result) => {
                        if state
                            .main_cmds
                            .send(Cmd::AuthSuccess(attempt, auth_result))
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(mut e) => {
                        e.truncate(MAX_FAILURE_DATA_SIZE);
                        if state.main_cmds.send(Cmd::AuthFailed(attempt, e)).is_err() {
                            break;
                        }
                    }
                }
            }
        }
        let _ = state.waker.wake();
    }
}
