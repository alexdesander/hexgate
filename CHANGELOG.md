# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- The congestion controller tolerates path jitter: the standing RTT is the minimum over two base RTTs, queueing
  delay up to four times the measured packet-to-packet RTT variation (at most 4 ms) is not treated as queue, and
  growth is paced by what the short filter can catch. A download on a jittery 25 Mbit/s link gets 3× the
  bandwidth, on a 100 Mbit/s link 2.5×, at unchanged realtime latency.
- Loss is judged over at least a window of packets, so random loss pairs no longer cut the window; realtime tails
  and expired messages on lossy links improved.
