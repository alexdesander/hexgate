#![cfg(feature = "bench")]

use hexgate::{
    Channel, ChannelConfiguration, CongestionConfig, SendOptions, SendOutcome,
    bench::{Delivery, Pairs, Side},
    sim::{Link, LinkConfig},
};
use std::time::Duration;

#[test]
fn flush_keeps_previous_batch_eligible() {
    let mut pairs = Pairs::new();
    pairs.add(
        ChannelConfiguration::default(),
        CongestionConfig::default(),
        None,
        None,
    );
    let now = pairs.now();
    pairs.send(0, Side::Client, Channel::Reliable(0), vec![1]);
    pairs.flush(0, Side::Client);
    pairs.send(0, Side::Client, Channel::Reliable(0), vec![2]);
    let mut received = Vec::new();
    pairs.run(now + Duration::from_millis(1), &mut |_, _, _, d| {
        if let Delivery::Message(m) = d {
            received.push(m);
        }
    });
    assert_eq!(received, [vec![1]]);
    pairs.flush(0, Side::Client);
    pairs.run(now + Duration::from_millis(10), &mut |_, _, _, d| {
        if let Delivery::Message(m) = d {
            received.push(m);
        }
    });
    assert_eq!(received, [vec![1], vec![2]]);
}

#[test]
fn snapshot_receipts_cover_fragment_acknowledgments_replacement_and_deadlines() {
    let mut pairs = Pairs::new();
    pairs.add(
        ChannelConfiguration::default(),
        CongestionConfig::default(),
        None,
        None,
    );
    let now = pairs.now();
    for (cookie, message, replace, deadline) in [
        (1, vec![1], false, None),
        (2, vec![2; 3000], true, None),
        (3, vec![3], false, Some(now)),
    ] {
        pairs.send_with(
            0,
            Side::Client,
            Channel::Unreliable,
            message,
            SendOptions {
                receipt: Some(cookie),
                replace,
                deadline,
            },
        );
    }
    let mut received = Vec::new();
    let mut results = Vec::new();
    pairs.run(
        now + Duration::from_secs(1),
        &mut |_, side, _, delivery| match delivery {
            Delivery::Message(message) => {
                assert_eq!(side, Side::Server);
                received.push(message);
            }
            Delivery::SendResult(cookie, outcome) => {
                assert_eq!(side, Side::Client);
                results.push((cookie, outcome));
            }
            _ => panic!("{delivery:?}"),
        },
    );
    results.sort_by_key(|&(cookie, _)| cookie);
    assert_eq!(received, [vec![2; 3000]]);
    assert_eq!(
        results,
        [
            (1, SendOutcome::Dropped),
            (2, SendOutcome::Acked),
            (3, SendOutcome::Dropped)
        ]
    );
}

#[test]
fn channel_reset_cancels_a_partial_transfer_and_delivers_its_successor() {
    let mut pairs = Pairs::new();
    let link = LinkConfig {
        delay: Duration::from_millis(20),
        ..LinkConfig::default()
    };
    pairs.add(
        ChannelConfiguration::default(),
        CongestionConfig::default(),
        Some(Box::new(Link::new(link.clone(), 1))),
        Some(Box::new(Link::new(link, 2))),
    );
    let now = pairs.now();
    pairs.send_with(
        0,
        Side::Client,
        Channel::Reliable(0),
        vec![1; 1 << 20],
        SendOptions {
            receipt: Some(1),
            ..SendOptions::default()
        },
    );
    pairs.run(now + Duration::from_millis(5), &mut |_, _, _, delivery| {
        panic!("{delivery:?}")
    });
    pairs.reset_channel(0, Side::Client, Channel::Reliable(0));
    pairs.send_with(
        0,
        Side::Client,
        Channel::Reliable(0),
        vec![9],
        SendOptions {
            receipt: Some(2),
            ..SendOptions::default()
        },
    );
    let mut received = Vec::new();
    let mut results = Vec::new();
    pairs.run(
        now + Duration::from_secs(2),
        &mut |_, _, _, delivery| match delivery {
            Delivery::Message(message) => received.push(message),
            Delivery::SendResult(cookie, outcome) => results.push((cookie, outcome)),
            _ => panic!("{delivery:?}"),
        },
    );
    assert_eq!(received, [vec![9]]);
    assert_eq!(
        results,
        [(1, SendOutcome::Dropped), (2, SendOutcome::Acked)]
    );
    assert_eq!(pairs.stats(0, Side::Client).queued_bytes, 0);
}
