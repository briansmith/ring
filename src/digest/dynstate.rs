// Copyright 2015-2019 Brian Smith.
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

use super::{format_output, sha1, sha2, Output};
use core::num::NonZeroUsize;

// Invariant: When constructed with `new32` (resp. `new64`), `As32` (resp.
// `As64`) is the active variant.
// Invariant: The active variant never changes after initialization.
#[derive(Clone)]
pub(super) enum DynState {
    As64(sha2::State64),
    As32(sha2::State32),
}

impl DynState {
    pub const fn new32(initial_state: sha2::State32) -> Self {
        Self::As32(initial_state)
    }

    pub const fn new64(initial_state: sha2::State64) -> Self {
        Self::As64(initial_state)
    }
}

pub(super) unsafe fn sha1_block_data_order(
    state: &mut DynState,
    data: *const u8,
    num: NonZeroUsize,
) {
    let state = match state {
        DynState::As32(state) => state,
        _ => {
            unreachable!();
        }
    };

    // SAFETY: The caller guarantees that this is called with data pointing to `num`
    // `sha1::BLOCK_LEN`-long blocks.
    sha1::sha1_block_data_order(state, data, num);
}

pub(super) unsafe fn sha256_block_data_order(
    state: &mut DynState,
    data: *const u8,
    num: NonZeroUsize,
) {
    let state = match state {
        DynState::As32(state) => state,
        _ => {
            unreachable!();
        }
    };

    // SAFETY: The caller guarantees that this is called with data pointing to `num`
    // `SHA256_BLOCK_LEN`-long blocks.
    sha2::sha256_block_data_order(state, data, num);
}

pub(super) unsafe fn sha512_block_data_order(
    state: &mut DynState,
    data: *const u8,
    num: NonZeroUsize,
) {
    let state = match state {
        DynState::As64(state) => state,
        _ => {
            unreachable!();
        }
    };

    // SAFETY: The caller guarantees that this is called with data pointing to `num`
    // `SHA512_BLOCK_LEN`-long blocks.
    sha2::sha512_block_data_order(state, data, num);
}

pub(super) fn sha256_format_output(state: DynState) -> Output {
    let state = match state {
        DynState::As32(state) => state,
        _ => {
            unreachable!();
        }
    };
    format_output::<_, _, { core::mem::size_of::<u32>() }>(state, u32::to_be_bytes)
}

pub(super) fn sha512_format_output(state: DynState) -> Output {
    let state = match state {
        DynState::As64(state) => state,
        _ => {
            unreachable!();
        }
    };
    format_output::<_, _, { core::mem::size_of::<u64>() }>(state, u64::to_be_bytes)
}
