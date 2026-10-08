// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Generating and storing keys: the server's `secret_key` and `auth_salt`, or a server key a
//! client pins after the first connection. Key files hold lowercase hex digits.

use std::{
    fmt::Write as _,
    fs::{self, OpenOptions},
    io::{self, Write as _},
    path::Path,
};

use rand::{rngs::OsRng, RngCore};

#[derive(Debug, thiserror::Error)]
pub enum KeyFileError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("the key file does not hold {expected} hex digits")]
    Malformed { expected: usize },
}

/// Random bytes from the operating system, e.g. a `secret_key` or `auth_salt`.
pub fn generate<const N: usize>() -> [u8; N] {
    let mut key = [0u8; N];
    OsRng.fill_bytes(&mut key);
    key
}

/// Reads a key file, `None` if it doesn't exist.
pub fn load<const N: usize>(path: impl AsRef<Path>) -> Result<Option<[u8; N]>, KeyFileError> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let malformed = KeyFileError::Malformed { expected: 2 * N };
    let text = text.trim().as_bytes();
    if text.len() != 2 * N {
        return Err(malformed);
    }
    let digit = |d: u8| char::from(d).to_digit(16);
    let mut key = [0u8; N];
    for (byte, pair) in key.iter_mut().zip(text.chunks_exact(2)) {
        *byte = match (digit(pair[0]), digit(pair[1])) {
            (Some(high), Some(low)) => (high * 16 + low) as u8,
            _ => return Err(malformed),
        };
    }
    Ok(Some(key))
}

/// Writes a new key file, readable only by the owner on Unix. Fails if the file exists.
pub fn save(path: impl AsRef<Path>, key: &[u8]) -> Result<(), KeyFileError> {
    let mut text = String::with_capacity(2 * key.len() + 1);
    for byte in key {
        let _ = write!(text, "{byte:02x}");
    }
    text.push('\n');
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)?.write_all(text.as_bytes())?;
    Ok(())
}

/// Reads a key file, or generates the key and saves it on the first run.
pub fn load_or_generate<const N: usize>(path: impl AsRef<Path>) -> Result<[u8; N], KeyFileError> {
    let path = path.as_ref();
    if let Some(key) = load(path)? {
        return Ok(key);
    }
    let key = generate();
    save(path, &key)?;
    Ok(key)
}
