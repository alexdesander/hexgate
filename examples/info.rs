// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket},
    sync::mpsc::channel,
    time::Duration,
};

use hexgate::{
    client::request_infos,
    common::channel::scheduler::ChannelConfiguration,
    server::{auth::Authenticator, Server},
};

const SERVER_ADDR: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 44444));

struct MockAuthenticator;
impl Authenticator<()> for MockAuthenticator {
    fn authenticate(&mut self, _: std::net::SocketAddr, _: Vec<u8>) -> Result<(), Vec<u8>> {
        Ok(())
    }
}

fn main() {
    let _server = Server::prepare()
        .bind_addr(SERVER_ADDR)
        .info(b"Hello, world! This is a placeholder server info! It could be anything serializable to a Vec<u8>!".to_vec())
        .allowed_client_versions(|_| Ok(()))
        .secret_key([0u8; 32])
        .auth_salt([0u8; 16])
        .authenticator(MockAuthenticator)
        .channel_config(ChannelConfiguration { weight_unreliable: 10, weights_unreliable_ordered: vec![10], weights_reliable: vec![10] })
        .run()
        .unwrap();

    let mut tmp_socket = UdpSocket::bind("0.0.0.0:0").unwrap();
    let (infos_tx, infos_rx) = channel();
    request_infos(
        &mut tmp_socket,
        Duration::from_secs(2),
        &[SERVER_ADDR],
        infos_tx,
    )
    .unwrap();
    println!(
        "Received server Info: {:?}",
        String::from_utf8(infos_rx.recv().unwrap().1).unwrap()
    );
}
