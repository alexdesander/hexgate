// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::*;

fn path(now: Instant) -> Rtt {
    let mut rtt = Rtt::default();
    rtt.update(now, Duration::from_millis(40), Duration::ZERO);
    rtt
}

#[test]
fn fixed_rate_has_bounded_feedback_state_with_loss_and_reordering() {
    let now = Instant::now();
    let mut cc = Controller::new(
        CongestionConfig {
            min_rate: 100_000,
            initial_rate: 100_000,
            max_rate: 100_000,
            ..CongestionConfig::default()
        },
        now,
    );
    let rtt = path(now);
    for pn in 0..10_000 {
        let info = cc.on_sent(now, 100, true, true);
        cc.on_timestamp(now, 100, 10_000 - pn);
        if pn % 3 == 0 {
            cc.on_lost(info);
        } else {
            cc.on_acked(info);
        }
        cc.on_ack_end(now, &rtt);
        assert!(cc.samples.len() <= MAX_RATE_SAMPLES);
        assert_eq!(cc.rate(), 100_000.0);
    }
    cc.maintain(now + Duration::from_secs(1));
    assert!(cc.samples.is_empty());
}

#[test]
fn sparse_loss_accumulates_and_ages_without_samples_disappearing() {
    let now = Instant::now();
    let mut cc = Controller::new(CongestionConfig::default(), now);
    let rtt = path(now);
    for i in 0..100 {
        cc.on_acked(SentInfo::default());
        cc.on_lost(SentInfo::default());
        cc.on_ack_end(now + Duration::from_millis(i * 10), &rtt);
    }
    assert!(cc.loss() > 0.49);
    cc.acked_packets = 1;
    cc.lost_packets = 1;
    cc.loss_since = now;
    cc.on_ack_end(now + LOSS_MAX_AGE, &rtt);
    assert_eq!(cc.acked_packets + cc.lost_packets, 0);
}

#[test]
fn loss_reduces_once_per_rtt_and_clean_feedback_releases_the_hold() {
    let now = Instant::now();
    let mut cc = Controller::new(CongestionConfig::default(), now);
    let rtt = path(now);
    let before = cc.window;
    for offset in [0, 1] {
        cc.acked_packets = 7;
        cc.lost_packets = 3;
        cc.on_ack_end(now + Duration::from_millis(offset), &rtt);
        assert_eq!(cc.window, before * 0.7);
    }
    cc.acked_bytes = 1200;
    cc.demand_bytes = 1200;
    cc.acked_packets = 10;
    cc.on_ack_end(now + Duration::from_secs(1), &rtt);
    assert!(cc.window > before * 0.7);
}

#[test]
fn random_loss_pairs_within_a_window_of_packets_do_not_cut() {
    let now = Instant::now();
    let mut cc = Controller::new(CongestionConfig::default(), now);
    let rtt = path(now);
    cc.window = 150.0 * MTU;
    cc.slow_start = false;
    let before = cc.window;
    for i in 0..20 {
        cc.acked_packets = 148;
        cc.lost_packets = 2;
        cc.on_ack_end(now + Duration::from_millis(i * 40), &rtt);
    }
    assert!(cc.window >= before, "{} < {before}", cc.window);
    assert!((cc.loss() - 2.0 / 150.0).abs() < 0.002, "{}", cc.loss());
    cc.acked_packets = 130;
    cc.lost_packets = 20;
    cc.on_ack_end(now + Duration::from_secs(1), &rtt);
    assert!(cc.window < before);
}

#[test]
fn idle_feedback_does_not_accumulate_velocity_for_the_next_transfer() {
    let now = Instant::now();
    let mut cc = Controller::new(CongestionConfig::default(), now);
    let rtt = path(now);
    cc.slow_start = false;
    let before = cc.window;
    for i in 0..100 {
        let at = now + Duration::from_millis(i * 100);
        cc.on_rtt(at, rtt.smoothed());
        cc.on_acked(SentInfo {
            bytes: 100,
            app_limited: true,
            first: true,
        });
        cc.on_ack_end(at, &rtt);
    }
    assert_eq!(cc.velocity, 1.0);
    assert_eq!(cc.window, before);
    cc.on_acked(SentInfo {
        bytes: 1200,
        app_limited: false,
        first: true,
    });
    cc.on_ack_end(now + Duration::from_secs(10), &rtt);
    assert!(cc.window - before <= MTU);
}

#[test]
fn delay_baseline_relearns_a_changed_route() {
    let now = Instant::now();
    let mut cc = Controller::new(CongestionConfig::default(), now);
    cc.on_rtt(now, Duration::from_millis(40));
    for second in 1..30 {
        cc.on_rtt(
            now + Duration::from_secs(second),
            Duration::from_millis(140),
        );
    }
    assert_eq!(cc.min_rtt(), Some(Duration::from_millis(140)));
    assert_eq!(cc.queue_delay(), Duration::ZERO);
}

#[test]
fn delivery_rate_counts_actual_interval_bytes_despite_ack_order() {
    let now = Instant::now();
    for sizes in [[1200, 100], [100, 1200]] {
        for reverse in [false, true] {
            let mut cc = Controller::new(CongestionConfig::default(), now);
            for index in if reverse { [1, 0] } else { [0, 1] } {
                let received = sizes[..=index].iter().sum::<usize>() as u64 * 10;
                cc.on_timestamp(now, sizes[index], received);
            }
            assert_eq!(cc.delivery_rate(), 100_000.0);
        }
    }
}

#[test]
fn receiver_timestamps_cannot_affect_delay_control_or_overflow() {
    let now = Instant::now();
    let mut cc = Controller::new(CongestionConfig::default(), now);
    for received in [0, i64::MAX as u64, u64::MAX] {
        cc.on_timestamp(now, 1200, received);
    }
    assert!(cc.delivery_rate().is_finite());
    assert_eq!(cc.queue_delay(), Duration::ZERO);
}

#[test]
fn pacing_respects_the_configured_maximum_and_fixed_rate() {
    let now = Instant::now();
    let mut cc = Controller::new(CongestionConfig::default(), now);
    cc.rate = f64::from(cc.config.max_rate);
    assert_eq!(cc.pacing_rate(), cc.rate);
    cc.config.min_rate = cc.config.max_rate;
    assert_eq!(cc.pacing_rate(), cc.rate);
}
