// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use ahash::HashSet;

/// Reassembles one fragmented message at a time: fragments of older messages are dropped, a
/// fragment of a newer message discards the incomplete one.
pub(crate) struct FragmentAssembler {
    fragment_size: usize,
    message_id: u32,
    // TODO: Use a more efficient data structure
    fragments: HashSet<u32>,
    needed_fragments: u32,
    buffer: Vec<u8>,
}

impl FragmentAssembler {
    pub fn new(fragment_size: usize) -> Self {
        Self {
            fragment_size,
            message_id: 0,
            fragments: HashSet::default(),
            needed_fragments: u32::MAX,
            buffer: Vec::new(),
        }
    }

    pub fn handle(
        &mut self,
        message_id: u32,
        fragment_id: u32,
        is_last: bool,
        payload: &[u8],
    ) -> Option<Vec<u8>> {
        if message_id < self.message_id {
            return None;
        }
        if message_id > self.message_id {
            self.reset(message_id);
        }
        let offset = (fragment_id as usize).checked_mul(self.fragment_size)?;
        let end = offset + payload.len();
        // Only the last fragment may be short, and no fragment may lie beyond it.
        let fits = if is_last {
            end >= self.buffer.len()
        } else {
            payload.len() == self.fragment_size
        };
        if !fits || fragment_id >= self.needed_fragments || !self.fragments.insert(fragment_id) {
            return None;
        }
        if is_last {
            self.needed_fragments = fragment_id + 1;
        }
        if end > self.buffer.len() {
            self.buffer.resize(end, 0);
        }
        self.buffer[offset..end].copy_from_slice(payload);
        if self.fragments.len() < self.needed_fragments as usize {
            return None;
        }
        let message = std::mem::take(&mut self.buffer);
        self.reset(message_id.saturating_add(1));
        Some(message)
    }

    fn reset(&mut self, message_id: u32) {
        self.message_id = message_id;
        self.fragments.clear();
        self.needed_fragments = u32::MAX;
        self.buffer.clear();
    }
}
