// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

mod common;

use std::time::{Duration, Instant};

use common::{connected, Network, BAD, OKAY, TERRIBLE, TIMEOUT};
use hexgate::{server::Event, Channel};

/// All messages arrive, in order.
fn reliable_transfer(network: Option<Network>, amount: u32, timeout_dur: Duration) {
    let (server, client) = connected(network, timeout_dur);
    for i in 0..amount {
        client
            .send(Channel::Reliable(0), i.to_string().into_bytes())
            .unwrap();
    }
    let mut next = 0;
    while next < amount {
        match server.next().unwrap() {
            Event::Connected(..) => {}
            Event::Received(_, message) => {
                assert_eq!(message, next.to_string().as_bytes());
                next += 1;
            }
            event => panic!("unexpected event {event:?}"),
        }
    }
}

/// Messages arrive in order, late ones are dropped, the newest state gets through: one of
/// the last `newest` messages. Returns how many arrived.
fn unreliable_ordered_transfer(network: Option<Network>, amount: u32, newest: u32) -> u32 {
    const QUIET: Duration = Duration::from_secs(2);
    let (server, client) = connected(network, TIMEOUT);
    for i in 0..amount {
        client
            .send(Channel::UnreliableOrdered(0), i.to_string().into_bytes())
            .unwrap();
    }
    let mut last = None;
    let mut received = 0;
    let mut last_received = Instant::now();
    while last != Some(amount - 1) && last_received.elapsed() < QUIET {
        match server.try_next().unwrap() {
            Some(Event::Connected(..)) => {}
            Some(Event::Received(_, message)) => {
                let id: u32 = String::from_utf8(message).unwrap().parse().unwrap();
                assert!(last.is_none_or(|last| id > last), "{id} after {last:?}");
                last = Some(id);
                received += 1;
                last_received = Instant::now();
            }
            Some(event) => panic!("unexpected event {event:?}"),
            None => std::thread::sleep(Duration::from_millis(1)),
        }
    }
    assert!(
        last.is_some_and(|last| last >= amount - newest),
        "newest: {last:?}"
    );
    received
}

/// Fragmented messages are delivered whole and unmixed (each one's length and fill byte encode
/// its index) or not at all. Returns the received indices.
fn fragmented_transfer(channel: Channel, network: Network) -> Vec<u32> {
    const QUIET: Duration = Duration::from_secs(2);
    let size = |i: u32| 3000 + 7 * i as usize;
    let (server, client) = connected(Some(network), TIMEOUT);
    for i in 0..200 {
        client.send(channel, vec![i as u8; size(i)]).unwrap();
    }
    let mut received = Vec::new();
    let mut last_received = Instant::now();
    while last_received.elapsed() < QUIET {
        match server.try_next().unwrap() {
            Some(Event::Connected(..)) => {}
            Some(Event::Received(_, message)) => {
                let i = ((message.len() - 3000) / 7) as u32;
                assert_eq!(message, vec![i as u8; size(i)]);
                received.push(i);
                last_received = Instant::now();
            }
            Some(event) => panic!("unexpected event {event:?}"),
            None => std::thread::sleep(Duration::from_millis(1)),
        }
    }
    assert!(!received.is_empty());
    received
}

#[test]
fn unreliable_fragments_survive_loss_and_reordering() {
    fragmented_transfer(Channel::Unreliable, BAD);
}

#[test]
fn unreliable_ordered_fragments_survive_loss_and_reordering() {
    let received = fragmented_transfer(Channel::UnreliableOrdered(1), BAD);
    assert!(
        received.windows(2).all(|pair| pair[0] < pair[1]),
        "{received:?}"
    );
}

#[test]
fn reliable_no_simulator() {
    reliable_transfer(None, 50_000, TIMEOUT);
}

#[test]
fn reliable_okay_network() {
    reliable_transfer(Some(OKAY), 50_000, TIMEOUT);
}

#[test]
fn reliable_bad_network() {
    reliable_transfer(Some(BAD), 25_000, TIMEOUT);
}

/// At 70 % loss each way, the tail of a transfer can go longer than the default timeout
/// without a single packet getting through.
#[test]
fn reliable_terrible_network() {
    reliable_transfer(Some(TERRIBLE), 1_000, Duration::from_secs(60));
}

/// A few messages may be dropped when parallel tests starve the receiver (full socket buffer or
/// event queue).
#[test]
fn unreliable_ordered_no_simulator() {
    let amount = 50_000;
    let received = unreliable_ordered_transfer(None, amount, 50);
    assert!(received >= amount * 9 / 10, "{received}/{amount}");
}

#[test]
fn unreliable_ordered_okay_network() {
    unreliable_ordered_transfer(Some(OKAY), 50_000, 50);
}

#[test]
fn unreliable_ordered_bad_network() {
    unreliable_ordered_transfer(Some(BAD), 50_000, 50);
}

#[test]
fn unreliable_ordered_terrible_network() {
    // About 150 of these small messages share a packet, and 70 % of the packets are lost.
    unreliable_ordered_transfer(Some(TERRIBLE), 50_000, 5_000);
}
