# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.2] - 2026-10-08

Rewrite of the whole crate; protocol version 1 is not compatible with 0.0.1.

### Changed

- New transport: encrypted DATA packets carrying frames, selective acknowledgments, loss recovery and a paced,
  delay-based congestion controller shared by all channels.
- New handshake: the client pins the server's ed25519 key, signed x25519 key exchange, stateless cookies, per-IP
  rate limits and no traffic amplification.
- New API: `Server`/`Client` builders, blocking and polling event queues, non-blocking `start()`, broadcast, kick,
  connection limits, send receipts, flush per tick and connection statistics.
- Channels: Unreliable, UnreliableOrdered, Reliable and ReliableUnordered with weighted priorities, flow control,
  deadlines, replacement and reset.
- The congestion controller tolerates path jitter: the standing RTT is the minimum over two base RTTs, queueing
  delay up to four times the measured packet-to-packet RTT variation (at most 4 ms) is not treated as queue, and
  growth is paced by what the short filter can catch. A download on a jittery 25 Mbit/s link gets 3× the
  bandwidth, on a 100 Mbit/s link 2.5×, at unchanged realtime latency.
- Loss is judged over at least a window of packets, so random loss pairs no longer cut the window; realtime tails
  and expired messages on lossy links improved.
