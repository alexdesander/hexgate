// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

mod common;

use std::time::{Duration, Instant};

use common::{connected, Network, BAD, OKAY, TERRIBLE, TIMEOUT};
use hexgate::{common::channel::Channel, server::Event};

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

/// Messages arrive in order, late ones are dropped, the newest state gets through.
/// Returns how many arrived.
fn unreliable_ordered_transfer(network: Option<Network>, amount: u32) -> u32 {
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
        last.is_some_and(|last| last >= amount - 50),
        "newest: {last:?}"
    );
    received
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
    let received = unreliable_ordered_transfer(None, amount);
    assert!(received >= amount * 9 / 10, "{received}/{amount}");
}

#[test]
fn unreliable_ordered_okay_network() {
    unreliable_ordered_transfer(Some(OKAY), 50_000);
}

#[test]
fn unreliable_ordered_bad_network() {
    unreliable_ordered_transfer(Some(BAD), 50_000);
}

#[test]
fn unreliable_ordered_terrible_network() {
    unreliable_ordered_transfer(Some(TERRIBLE), 50_000);
}
