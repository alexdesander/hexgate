use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

use hexgate::{
    Authenticator, Channel, ChannelConfiguration, Client, ClientVersion, SendOptions, Server,
    ServerKey, client, error::SendError, server,
};

struct Accept;
impl Authenticator<()> for Accept {
    fn authenticate(&mut self, _: SocketAddr, _: Vec<u8>) -> Result<(), Vec<u8>> {
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = rand::random();
    let channels = ChannelConfiguration {
        weights_reliable: vec![1, 1],
        ..ChannelConfiguration::default()
    };
    let server = Server::prepare()
        .bind_addr("127.0.0.1:0".parse()?)
        .secret_key(key)
        .auth_salt(rand::random())
        .authenticator(Accept)
        .info(vec![])
        .allowed_client_versions(|_| Ok(()))
        .channel_config(channels.clone())
        .run()?;
    let client = Client::prepare()
        .server_socket_addr(server.local_addr())
        .server_key(ServerKey::Pinned(server::public_key(&key)))
        .client_version(ClientVersion::ZERO)
        .auth_data(vec![])
        .hash_auth_data(false)
        .channel_config(channels)
        .connect()?;
    client.set_priority(Channel::UnreliableOrdered(0), 1)?;
    client.set_priority(Channel::Reliable(1), -1)?;
    client.send(Channel::Reliable(1), vec![7; 96 << 10])?;

    let tick = Duration::from_micros(16_667);
    for frame in 0..180u32 {
        let started = Instant::now();
        while let Some(event) = server.try_next()? {
            if let server::Event::Received(peer, Channel::UnreliableOrdered(0), input) = event {
                if let Err(error) = server.send(peer, Channel::UnreliableOrdered(0), input) {
                    if !matches!(error, SendError::Backpressure) {
                        return Err(error.into());
                    }
                }
            }
        }
        while let Some(event) = client.try_next()? {
            if let client::Event::Received(channel, snapshot) = event {
                println!("{channel:?}: {} bytes", snapshot.len());
            }
        }
        let result = client.send_with(
            Channel::UnreliableOrdered(0),
            frame.to_le_bytes().to_vec(),
            SendOptions {
                deadline: Some(started + tick * 3),
                replace: true,
                ..SendOptions::default()
            },
        );
        if let Err(error) = result {
            if !matches!(error, SendError::Backpressure) {
                return Err(error.into());
            }
        }
        if frame == 60 {
            client.reset_channel(1)?;
            client.send(Channel::Reliable(1), vec![8; 96 << 10])?;
        }
        client.flush()?;
        server.flush()?;
        std::thread::sleep(tick.saturating_sub(started.elapsed()));
    }
    Ok(())
}
