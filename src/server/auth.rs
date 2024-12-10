// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{net::SocketAddr, sync::Arc};

use crossbeam::channel::{Receiver, Sender};
use mio::Waker;

use super::thread::Cmd;

pub trait AuthResult: Send + 'static {}
impl<T> AuthResult for T where T: Send + 'static {}

pub trait Authenticator<R: AuthResult>: Send + 'static {
    /// Authenticate the client with the given authentication data.
    /// The error value is sent to the client if the authentication fails.
    /// NOTE: The error vec can have a max len of 1181 bytes.
    fn authenticate(&mut self, from: SocketAddr, auth_data: Vec<u8>) -> Result<R, Vec<u8>>;
}

pub(crate) enum AuthCmd {
    Authenticate(SocketAddr, Vec<u8>),
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
            AuthCmd::Authenticate(from, auth_data) => {
                match state.authenticator.authenticate(from, auth_data) {
                    Ok(auth_result) => {
                        if state
                            .main_cmds
                            .send(Cmd::AuthSuccess(from, auth_result))
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(e) => {
                        if state.main_cmds.send(Cmd::AuthFailed(from, e)).is_err() {
                            break;
                        }
                    }
                }
            }
        }
        let _ = state.waker.wake();
    }
}
