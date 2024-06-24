// Copyright 2018-2024 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

use super::{
    super::nonce::{Nonce, NONCE_LEN},
    ffi::Counter,
    Block, BLOCK_LEN,
};

// `Counter` is `ffi::Counter` as its representation is dictated by its use in
// the FFI.
impl Counter {
    pub fn one(nonce: Nonce) -> Self {
        let mut value = [0u8; BLOCK_LEN];
        value[..NONCE_LEN].copy_from_slice(nonce.as_ref());
        value[BLOCK_LEN - 1] = 1;
        Self(value)
    }

    pub fn increment(&mut self) -> Iv {
        let iv = Iv(self.0);
        self.increment_by_less_safe(1);
        iv
    }

    pub(super) fn increment_by_less_safe(&mut self, increment_by: u32) {
        let [.., c0, c1, c2, c3] = &mut self.0;
        let old_value: u32 = u32::from_be_bytes([*c0, *c1, *c2, *c3]);
        let new_value = old_value + increment_by;
        [*c0, *c1, *c2, *c3] = u32::to_be_bytes(new_value);
    }
}

/// The IV for a single block encryption.
///
/// Intentionally not `Clone` to ensure each is used only once.
pub struct Iv(Block);

impl Iv {
    pub(super) fn new_less_safe(value: Block) -> Self {
        Self(value)
    }

    pub(super) fn into_block_less_safe(self) -> Block {
        self.0
    }
}

impl From<Counter> for Iv {
    fn from(counter: Counter) -> Self {
        Self(counter.0)
    }
}
