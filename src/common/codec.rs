// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! LEB128 varints and bounds-checked cursors for the post-handshake wire format.

/// Bytes `value` takes as a varint.
pub fn varint_len(value: u64) -> usize {
    (64 - (value | 1).leading_zeros() as usize).div_ceil(7)
}

/// Encodes `value` into `buf`, which must have room for `varint_len(value)` bytes.
pub fn write_varint(buf: &mut [u8], mut value: u64) -> usize {
    let mut i = 0;
    while value >= 0x80 {
        buf[i] = value as u8 | 0x80;
        value >>= 7;
        i += 1;
    }
    buf[i] = value as u8;
    i + 1
}

/// Decodes a varint, rejecting truncated, overlong and overflowing encodings.
pub fn read_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0u64;
    for (i, &byte) in buf.iter().enumerate().take(10) {
        let bits = u64::from(byte & 0x7f);
        if i == 9 && bits > 1 {
            return None;
        }
        value |= bits << (7 * i);
        if byte & 0x80 == 0 {
            return (i == 0 || byte != 0).then_some((value, i + 1));
        }
    }
    None
}

pub struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    /// The bytes not read yet, without consuming them.
    pub fn remaining(&self) -> &'a [u8] {
        self.buf
    }

    pub fn u8(&mut self) -> Option<u8> {
        let (&first, rest) = self.buf.split_first()?;
        self.buf = rest;
        Some(first)
    }

    pub fn varint(&mut self) -> Option<u64> {
        let (value, len) = read_varint(self.buf)?;
        self.buf = &self.buf[len..];
        Some(value)
    }

    pub fn bytes(&mut self, len: u64) -> Option<&'a [u8]> {
        let len = usize::try_from(len)
            .ok()
            .filter(|&len| len <= self.buf.len())?;
        let (bytes, rest) = self.buf.split_at(len);
        self.buf = rest;
        Some(bytes)
    }

    pub fn rest(&mut self) -> &'a [u8] {
        std::mem::take(&mut self.buf)
    }
}

pub struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> Writer<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn len(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn u8(&mut self, value: u8) {
        self.buf[self.pos] = value;
        self.pos += 1;
    }

    pub fn varint(&mut self, value: u64) {
        self.pos += write_varint(&mut self.buf[self.pos..], value);
    }

    pub fn bytes(&mut self, bytes: &[u8]) {
        self.buf[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
        self.pos += bytes.len();
    }

    /// The next `len` bytes, to be filled by the caller.
    pub fn space(&mut self, len: usize) -> &mut [u8] {
        let space = &mut self.buf[self.pos..self.pos + len];
        self.pos += len;
        space
    }
}
