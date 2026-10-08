// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! `[Data | DataAckNow][pn: varint][frames, encrypted][tag: 16]`. The AEAD nonce is the packet
//! number (big-endian, zero-padded), so it never repeats and never meets the fixed handshake
//! nonces (which begin with 0xff). The header is authenticated as associated data.

use crate::common::{
    codec::{read_varint, varint_len, write_varint},
    crypto::Crypto,
    packets::{PacketError, PacketIdentifier},
};

pub const MAX_DATAGRAM: usize = 1200;
pub const TAG_LEN: usize = 16;
pub const MAX_PACKET_NUMBER: u64 = (1 << 62) - 1;

pub struct Header {
    pub pn: u64,
    /// The sender asks for an immediate acknowledgement (last packet of a burst).
    pub ack_now: bool,
    pub len: usize,
}

/// Room for frames in a packet with this packet number.
pub fn capacity(pn: u64) -> usize {
    MAX_DATAGRAM - 1 - varint_len(pn) - TAG_LEN
}

/// Writes the header, returns its length.
pub fn write_header(buf: &mut [u8], pn: u64, ack_now: bool) -> usize {
    buf[0] = if ack_now {
        PacketIdentifier::DataAckNow
    } else {
        PacketIdentifier::Data
    } as u8;
    1 + write_varint(&mut buf[1..], pn)
}

fn nonce(pn: u64) -> [u8; 12] {
    let mut nonce = [0; 12];
    nonce[4..].copy_from_slice(&pn.to_be_bytes());
    nonce
}

/// Encrypts the frames in `buf[header_len..end]` and appends the tag, returns the packet size.
pub fn seal(crypto: &Crypto, pn: u64, buf: &mut [u8], header_len: usize, end: usize) -> usize {
    let (header, payload) = buf.split_at_mut(header_len);
    let tag = crypto.encrypt(&nonce(pn), header, &mut payload[..end - header_len]);
    buf[end..end + TAG_LEN].copy_from_slice(&tag);
    end + TAG_LEN
}

pub fn parse_header(buf: &[u8]) -> Result<Header, PacketError> {
    let ack_now = match PacketIdentifier::try_from(*buf.first().ok_or(PacketError::Size)?)? {
        PacketIdentifier::Data => false,
        PacketIdentifier::DataAckNow => true,
        _ => return Err(PacketError::Identifier),
    };
    let (pn, pn_len) = read_varint(&buf[1..]).ok_or(PacketError::Malformed)?;
    if pn > MAX_PACKET_NUMBER {
        return Err(PacketError::Malformed);
    }
    let len = 1 + pn_len;
    if buf.len() < len + TAG_LEN {
        return Err(PacketError::Size);
    }
    Ok(Header { pn, ack_now, len })
}

/// Decrypts the frames in place.
pub fn open<'a>(
    crypto: &Crypto,
    header: &Header,
    buf: &'a mut [u8],
) -> Result<&'a [u8], PacketError> {
    let tag_at = buf.len() - TAG_LEN;
    let (head, rest) = buf.split_at_mut(header.len);
    let (payload, tag) = rest.split_at_mut(tag_at - header.len);
    crypto.decrypt(
        &nonce(header.pn),
        head,
        payload,
        (&*tag).try_into().unwrap(),
    )?;
    Ok(payload)
}
