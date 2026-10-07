// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

mod common;

use common::{client, server, TIMEOUT};

#[test]
fn connect_repeatedly() {
    for _ in 0..10 {
        let server = server(TIMEOUT);
        let _client = client(server.local_addr(), TIMEOUT);
    }
}
