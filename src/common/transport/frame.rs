// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Frames inside DATA packets. Data frames carry their length unless they fill the rest of
//! the packet (QUIC's `LEN` bit).
//!
//! ```text
//! PING        0x01
//! ACK         0x02 largest, ack_delay_us, range_count, first_range, (gap, len)*,
//!                  ts_count, [largest - pn, recv_us, (pn gap - 1, zigzag recv_us delta)*]
//! CLOSE       0x03 len, reason
//! UNRELIABLE  0x08 | LEN 0x01 | ORDERED 0x02 | FRAG 0x04:
//!                  [channel if ORDERED] [msg_id if ORDERED or FRAG] [offset, total if FRAG]
//!                  [len if LEN] data
//! RELIABLE    0x10 | LEN 0x01: channel, offset, [len if LEN] data
//! ```
//!
//! ACK ranges follow QUIC: the first covers `largest - first_range..=largest`, each further
//! range ends `gap + 2` below the previous start and spans `len + 1` packets. Receive
//! timestamps are µs on the receiver's clock; the sender only uses differences.

use std::ops::RangeInclusive;

use crate::common::{
    codec::{varint_len, Reader, Writer},
    packets::PacketError,
};

const PING: u8 = 0x01;
const ACK: u8 = 0x02;
const CLOSE: u8 = 0x03;
const CREDIT: u8 = 0x04;
const RESET: u8 = 0x05;
const UNRELIABLE: u8 = 0x08;
const RELIABLE: u8 = 0x10;
const LEN: u8 = 0x01;
const ORDERED: u8 = 0x02;
const FRAG: u8 = 0x04;
const MAX_RANGES: u64 = 256;
const MAX_TIMESTAMPS: u64 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fragment {
    pub offset: u64,
    pub total: u64,
}

pub enum Frame<'a> {
    Ping,
    Credit {
        channel: u8,
        limit: u64,
    },
    Reset {
        channel: u8,
        offset: u64,
    },
    Ack(AckFrame<'a>),
    Close(&'a [u8]),
    Unreliable {
        /// `None` for `Channel::Unreliable`.
        channel: Option<u8>,
        msg_id: u64,
        fragment: Option<Fragment>,
        data: &'a [u8],
    },
    Reliable {
        channel: u8,
        offset: u64,
        data: &'a [u8],
    },
}

pub struct AckFrame<'a> {
    pub largest: u64,
    pub delay_us: u64,
    first_range: u64,
    range_count: u64,
    ranges: &'a [u8],
    timestamp_count: u64,
    timestamps: &'a [u8],
}

impl<'a> AckFrame<'a> {
    /// Acknowledged packet numbers, newest first.
    pub fn ranges(&self) -> impl Iterator<Item = RangeInclusive<u64>> + 'a {
        let mut reader = Reader::new(self.ranges);
        let mut next = Some(self.largest - self.first_range..=self.largest);
        let mut left = self.range_count;
        std::iter::from_fn(move || {
            let range = next.take()?;
            if left > 0 {
                left -= 1;
                let (gap, len) = (reader.varint()?, reader.varint()?);
                let high = range.start().checked_sub(gap.checked_add(2)?)?;
                next = Some(high.checked_sub(len)?..=high);
            }
            Some(range)
        })
    }

    /// Packet numbers and their receive times (µs on the receiver's clock), newest first.
    pub fn timestamps(&self) -> impl Iterator<Item = (u64, u64)> + 'a {
        let mut reader = Reader::new(self.timestamps);
        let mut previous: Option<(u64, u64)> = None;
        let mut left = self.timestamp_count;
        let largest = self.largest;
        std::iter::from_fn(move || {
            if left == 0 {
                return None;
            }
            left -= 1;
            let next = next_timestamp(&mut reader, largest, previous)?;
            previous = Some(next);
            Some(next)
        })
    }
}

fn next_timestamp(
    reader: &mut Reader,
    largest: u64,
    previous: Option<(u64, u64)>,
) -> Option<(u64, u64)> {
    match previous {
        None => Some((largest.checked_sub(reader.varint()?)?, reader.varint()?)),
        Some((pn, recv_us)) => {
            let pn = pn.checked_sub(reader.varint()?.checked_add(1)?)?;
            let recv_us = i128::from(recv_us) - i128::from(unzigzag(reader.varint()?));
            Some((pn, u64::try_from(recv_us).ok()?))
        }
    }
}

fn zigzag(value: i64) -> u64 {
    ((value << 1) ^ (value >> 63)) as u64
}

fn unzigzag(value: u64) -> i64 {
    (value >> 1) as i64 ^ -((value & 1) as i64)
}

fn malformed<T>(value: Option<T>) -> Result<T, PacketError> {
    value.ok_or(PacketError::Malformed)
}

/// The next frame, `None` at the end of the packet.
pub fn parse<'a>(r: &mut Reader<'a>) -> Result<Option<Frame<'a>>, PacketError> {
    let Some(kind) = r.u8() else {
        return Ok(None);
    };
    let data = |r: &mut Reader<'a>, len: bool| match len {
        true => malformed(r.varint().and_then(|len| r.bytes(len))),
        false => Ok(r.rest()),
    };
    let frame = match kind {
        PING => Frame::Ping,
        CREDIT => Frame::Credit {
            channel: malformed(r.u8())?,
            limit: malformed(r.varint())?,
        },
        RESET => Frame::Reset {
            channel: malformed(r.u8())?,
            offset: malformed(r.varint())?,
        },
        ACK => Frame::Ack(parse_ack(r)?),
        CLOSE => Frame::Close(data(r, true)?),
        kind if kind & !(LEN | ORDERED | FRAG) == UNRELIABLE => {
            let channel = match kind & ORDERED {
                0 => None,
                _ => Some(malformed(r.u8())?),
            };
            let msg_id = match kind & (ORDERED | FRAG) {
                0 => 0,
                _ => malformed(r.varint())?,
            };
            let fragment = match kind & FRAG {
                0 => None,
                _ => Some(Fragment {
                    offset: malformed(r.varint())?,
                    total: malformed(r.varint())?,
                }),
            };
            Frame::Unreliable {
                channel,
                msg_id,
                fragment,
                data: data(r, kind & LEN != 0)?,
            }
        }
        kind if kind & !LEN == RELIABLE => Frame::Reliable {
            channel: malformed(r.u8())?,
            offset: malformed(r.varint())?,
            data: data(r, kind & LEN != 0)?,
        },
        _ => return Err(PacketError::Malformed),
    };
    Ok(Some(frame))
}

/// Validates the whole frame, so the iterators of `AckFrame` can't fail.
fn parse_ack<'a>(r: &mut Reader<'a>) -> Result<AckFrame<'a>, PacketError> {
    let largest = malformed(
        r.varint()
            .filter(|&pn| pn <= super::packet::MAX_PACKET_NUMBER),
    )?;
    let delay_us = malformed(r.varint())?;
    let range_count = malformed(r.varint().filter(|&count| count <= MAX_RANGES))?;
    let first_range = malformed(r.varint().filter(|&first| first <= largest))?;
    let ranges = r.remaining();
    let mut low = largest - first_range;
    for _ in 0..range_count {
        let (gap, len) = (malformed(r.varint())?, malformed(r.varint())?);
        let high = malformed(gap.checked_add(2).and_then(|gap| low.checked_sub(gap)))?;
        low = malformed(high.checked_sub(len))?;
    }
    let ranges = &ranges[..ranges.len() - r.remaining().len()];
    let timestamp_count = malformed(r.varint().filter(|&count| count <= MAX_TIMESTAMPS))?;
    let timestamps = r.remaining();
    let mut previous = None;
    for _ in 0..timestamp_count {
        previous = Some(malformed(next_timestamp(r, largest, previous))?);
    }
    let timestamps = &timestamps[..timestamps.len() - r.remaining().len()];
    Ok(AckFrame {
        largest,
        delay_us,
        first_range,
        range_count,
        ranges,
        timestamp_count,
        timestamps,
    })
}

/// Writes an ACK frame with as many of `ranges` (`(low, high)`, newest first, the first one
/// ending at the largest received packet) and `timestamps` (`(pn, recv_us)`, newest first) as
/// fit. Returns false if not even the newest range fits.
pub fn write_ack(
    w: &mut Writer,
    delay_us: u64,
    ranges: &[(u64, u64)],
    timestamps: &[(u64, u64)],
) -> bool {
    let Some(&(first_low, largest)) = ranges.first() else {
        return false;
    };
    let gaps = || {
        ranges.windows(2).map(|pair| {
            let (previous_low, (low, high)) = (pair[0].0, pair[1]);
            (previous_low - high - 2, high - low)
        })
    };
    let fixed =
        1 + varint_len(largest) + varint_len(delay_us) + varint_len(largest - first_low) + 1;
    let mut size = fixed + varint_len(0);
    let mut range_count = 0;
    for (gap, len) in gaps() {
        let more = varint_len(gap) + varint_len(len) + varint_len(range_count as u64 + 1)
            - varint_len(range_count as u64);
        if size + more > w.remaining() {
            break;
        }
        size += more;
        range_count += 1;
    }
    if size > w.remaining() {
        return false;
    }
    let mut timestamp_count = 0;
    let mut previous: Option<(u64, u64)> = None;
    for &(pn, recv_us) in timestamps.iter().filter(|(pn, _)| *pn <= largest) {
        let entry = match previous {
            None => varint_len(largest - pn) + varint_len(recv_us),
            Some((previous_pn, previous_us)) => {
                varint_len(previous_pn - pn - 1)
                    + varint_len(zigzag(previous_us as i64 - recv_us as i64))
            }
        };
        let more =
            entry + varint_len(timestamp_count as u64 + 1) - varint_len(timestamp_count as u64);
        if timestamp_count == MAX_TIMESTAMPS as usize || size + more > w.remaining() {
            break;
        }
        size += more;
        timestamp_count += 1;
        previous = Some((pn, recv_us));
    }

    w.u8(ACK);
    w.varint(largest);
    w.varint(delay_us);
    w.varint(range_count as u64);
    w.varint(largest - first_low);
    for (gap, len) in gaps().take(range_count) {
        w.varint(gap);
        w.varint(len);
    }
    w.varint(timestamp_count as u64);
    let mut previous: Option<(u64, u64)> = None;
    for &(pn, recv_us) in timestamps
        .iter()
        .filter(|(pn, _)| *pn <= largest)
        .take(timestamp_count)
    {
        match previous {
            None => {
                w.varint(largest - pn);
                w.varint(recv_us);
            }
            Some((previous_pn, previous_us)) => {
                w.varint(previous_pn - pn - 1);
                w.varint(zigzag(previous_us as i64 - recv_us as i64));
            }
        }
        previous = Some((pn, recv_us));
    }
    true
}

/// How many of `available` data bytes a frame with a `header` (without `LEN`) can carry in
/// `room` bytes: all of them, with a length field unless they fill the room exactly, or as many
/// as the room holds.
pub fn fit(header: usize, available: usize, room: usize) -> usize {
    let Some(room) = room.checked_sub(header) else {
        return 0;
    };
    if available == room || available + varint_len(available as u64) <= room {
        available
    } else if available > room {
        room
    } else {
        room - varint_len(room as u64)
    }
}

/// The header size of an unreliable frame without `LEN`.
pub fn unreliable_header(channel: Option<u8>, msg_id: u64, fragment: Option<Fragment>) -> usize {
    let msg_id = if channel.is_some() || fragment.is_some() {
        varint_len(msg_id)
    } else {
        0
    };
    1 + usize::from(channel.is_some())
        + msg_id
        + fragment.map_or(0, |f| varint_len(f.offset) + varint_len(f.total))
}

/// Writes an unreliable frame with all of `data`, which must fit.
pub fn write_unreliable(
    w: &mut Writer,
    channel: Option<u8>,
    msg_id: u64,
    fragment: Option<Fragment>,
    data: &[u8],
) {
    let with_len = unreliable_header(channel, msg_id, fragment) + data.len() < w.remaining();
    let kind = UNRELIABLE
        | if with_len { LEN } else { 0 }
        | channel.map_or(0, |_| ORDERED)
        | fragment.map_or(0, |_| FRAG);
    w.u8(kind);
    if let Some(channel) = channel {
        w.u8(channel);
    }
    if channel.is_some() || fragment.is_some() {
        w.varint(msg_id);
    }
    if let Some(fragment) = fragment {
        w.varint(fragment.offset);
        w.varint(fragment.total);
    }
    if with_len {
        w.varint(data.len() as u64);
    }
    w.bytes(data);
}

/// The header size of a reliable frame without `LEN`.
pub fn reliable_header(offset: u64) -> usize {
    2 + varint_len(offset)
}

/// Writes a reliable frame header for `len` data bytes, the caller writes the data.
pub fn write_reliable_header(w: &mut Writer, channel: u8, offset: u64, len: usize) {
    let with_len = reliable_header(offset) + len < w.remaining();
    w.u8(RELIABLE | if with_len { LEN } else { 0 });
    w.u8(channel);
    w.varint(offset);
    if with_len {
        w.varint(len as u64);
    }
}

pub fn write_credit(w: &mut Writer, channel: u8, limit: u64) -> bool {
    if w.remaining() < 2 + varint_len(limit) {
        return false;
    }
    w.u8(CREDIT);
    w.u8(channel);
    w.varint(limit);
    true
}

pub fn write_reset(w: &mut Writer, channel: u8, offset: u64) -> bool {
    if w.remaining() < 2 + varint_len(offset) {
        return false;
    }
    w.u8(RESET);
    w.u8(channel);
    w.varint(offset);
    true
}

pub fn write_ping(w: &mut Writer) {
    w.u8(PING);
}

pub fn write_close(w: &mut Writer, reason: &[u8]) {
    w.u8(CLOSE);
    w.varint(reason.len() as u64);
    w.bytes(reason);
}

/// Bytes a CLOSE frame with `reason` takes.
pub fn close_len(reason: &[u8]) -> usize {
    1 + varint_len(reason.len() as u64) + reason.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_all(buf: &[u8]) -> Vec<Frame<'_>> {
        let mut r = Reader::new(buf);
        std::iter::from_fn(|| parse(&mut r).unwrap()).collect()
    }

    #[test]
    fn ack_round_trip() {
        let ranges = [(95, 100), (80, 90), (3, 3), (0, 1)];
        let timestamps = [(100, 5000), (99, 4990), (96, 5010), (85, 4000)];
        let mut buf = [0u8; 200];
        let mut w = Writer::new(&mut buf);
        assert!(write_ack(&mut w, 1234, &ranges, &timestamps));
        let len = w.len();
        let frames = parse_all(&buf[..len]);
        let [Frame::Ack(ack)] = &frames[..] else {
            panic!("not one ACK frame");
        };
        assert_eq!(ack.largest, 100);
        assert_eq!(ack.delay_us, 1234);
        let parsed: Vec<_> = ack.ranges().map(|r| (*r.start(), *r.end())).collect();
        assert_eq!(parsed, ranges);
        assert_eq!(ack.timestamps().collect::<Vec<_>>(), timestamps);
    }

    #[test]
    fn ack_shrinks_to_fit() {
        let ranges: Vec<(u64, u64)> = (0..30).rev().map(|i| (i * 10, i * 10 + 5)).collect();
        let timestamps: Vec<(u64, u64)> = (0..6).rev().map(|i| (290 + i, 1000 + i)).collect();
        let mut buf = [0u8; 20];
        let mut w = Writer::new(&mut buf);
        assert!(write_ack(&mut w, 0, &ranges, &timestamps));
        let len = w.len();
        assert!(len <= 20);
        let frames = parse_all(&buf[..len]);
        let [Frame::Ack(ack)] = &frames[..] else {
            panic!("not one ACK frame");
        };
        assert_eq!(ack.ranges().next(), Some(290..=295));
        let mut tiny = [0u8; 3];
        assert!(!write_ack(
            &mut Writer::new(&mut tiny),
            0,
            &ranges,
            &timestamps
        ));
    }

    #[test]
    fn data_frames_round_trip() {
        let mut buf = [0u8; 100];
        let mut w = Writer::new(&mut buf);
        let fragment = Some(Fragment {
            offset: 300,
            total: 5000,
        });
        write_unreliable(&mut w, Some(3), 77, fragment, b"abc");
        write_reliable_header(&mut w, 1, 1 << 20, 2);
        w.bytes(b"xy");
        write_ping(&mut w);
        let rest = w.remaining();
        write_unreliable(&mut w, None, 0, None, &vec![9; rest - 1]);
        assert_eq!(w.remaining(), 0);
        let frames = parse_all(&buf);
        assert!(matches!(
            frames[0],
            Frame::Unreliable { channel: Some(3), msg_id: 77, fragment: f, data: b"abc" } if f == fragment
        ));
        assert!(matches!(
            frames[1],
            Frame::Reliable {
                channel: 1,
                offset: 1048576,
                data: b"xy"
            }
        ));
        assert!(matches!(frames[2], Frame::Ping));
        assert!(matches!(
            frames[3],
            Frame::Unreliable { channel: None, fragment: None, data, .. } if data.len() == rest - 1
        ));
    }
}
