// Copyright 2015-2019 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

#[allow(unused_imports)]
use crate::polyfill::prelude::*;

use super::{format_output, sha1, sha2, Algorithm, Output};
use crate::cpu;
use core::mem::size_of;

pub(super) enum DynInitialState {
    As64(sha2::State64),
    As32(sha2::State32),
}

impl DynInitialState {
    pub const fn new32(state: sha2::State32) -> Self {
        Self::As32(state)
    }

    pub const fn new64(state: sha2::State64) -> Self {
        Self::As64(state)
    }
}

// `algorithm` is stored "redundantly" in each variant so that the tag will be
// stored in its niche.
//
// Invariant: The active variant never changes after initialization.
#[derive(Clone)]
pub(super) enum DynState {
    As64 {
        state: sha2::State64,
        algorithm: &'static Algorithm,
    },
    As32 {
        state: sha2::State32,
        algorithm: &'static Algorithm,
    },
}

impl DynState {
    pub fn new(algorithm: &'static Algorithm) -> Self {
        match &algorithm.initial_state {
            DynInitialState::As32(state) => Self::As32 {
                state: *state,
                algorithm,
            },
            DynInitialState::As64(state) => Self::As64 {
                state: *state,
                algorithm,
            },
        }
    }

    #[inline(always)]
    pub fn algorithm(&self) -> &'static Algorithm {
        match self {
            DynState::As64 { algorithm, .. } | DynState::As32 { algorithm, .. } => algorithm,
        }
    }

    pub fn format_output(self) -> Output {
        match self {
            Self::As64 { state, .. } => {
                format_output::<_, _, { size_of::<u64>() }>(state, u64::to_be_bytes)
            }
            Self::As32 { state, .. } => {
                format_output::<_, _, { size_of::<u32>() }>(state, u32::to_be_bytes)
            }
        }
    }
}

pub(super) fn sha1_block_data_order<'d>(
    state: &mut DynState,
    data: &'d [u8],
    _cpu_features: cpu::Features,
) -> (usize, &'d [u8]) {
    let state = match state {
        DynState::As32 { state, .. } => state,
        _ => {
            unreachable!();
        }
    };

    let (full_blocks, leftover) = data.as_chunks_();
    sha1::sha1_block_data_order(state, full_blocks);
    (full_blocks.as_flattened().len(), leftover)
}

pub(super) fn sha256_block_data_order<'d>(
    state: &mut DynState,
    data: &'d [u8],
    cpu_features: cpu::Features,
) -> (usize, &'d [u8]) {
    let state = match state {
        DynState::As32 { state, .. } => state,
        _ => {
            unreachable!();
        }
    };

    let (full_blocks, leftover) = data.as_chunks_();
    sha2::block_data_order_32(state, full_blocks, cpu_features);
    (full_blocks.len() * sha2::SHA256_BLOCK_LEN.into(), leftover)
}

pub(super) fn sha512_block_data_order<'d>(
    state: &mut DynState,
    data: &'d [u8],
    cpu_features: cpu::Features,
) -> (usize, &'d [u8]) {
    let state = match state {
        DynState::As64 { state, .. } => state,
        _ => {
            unreachable!();
        }
    };

    let (full_blocks, leftover) = data.as_chunks_();
    sha2::block_data_order_64(state, full_blocks, cpu_features);
    (full_blocks.len() * sha2::SHA512_BLOCK_LEN.into(), leftover)
}
