// Copyright 2015-2025 Brian Smith.
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

#![cfg(all(target_arch = "aarch64", target_endian = "little"))]

#[allow(unused_imports)]
use crate::polyfill::prelude::*;

use super::{aes, gcm, Counter, Overlapping, BLOCK_LEN};
use crate::{bits::BitLength, polyfill::u64_from_usize};
use core::num::NonZeroU64;

pub(super) fn seal_whole(
    aes_key: &aes::hw::Key,
    auth: &mut gcm::Context<gcm::clmul_aarch64::Key>,
    ctr: &mut Counter,
    in_out: &mut [[u8; BLOCK_LEN]],
) {
    prefixed_extern! {
        fn aes_gcm_enc_kernel(
            input: *const [u8; BLOCK_LEN],
            in_bits: BitLength<NonZeroU64>,
            output: *mut [u8; BLOCK_LEN],
            Xi: &mut gcm::Xi,
            ivec: &mut Counter,
            rd_keys: *const aes::RdKey,
            Htable: &gcm::clmul_aarch64::Key,
            rounds: aes::Rounds) -> u64;
    }

    let whole_block_bits = auth.in_out_whole_block_bits();
    if let Ok(whole_block_bits) = whole_block_bits.try_into() {
        let (htable, xi) = auth.inner();
        let in_out_len_bytes = in_out.as_flattened().len();
        let in_out = in_out.as_mut_ptr();
        let (rd_keys, rounds) = aes_key.rd_keys_and_rounds();
        let processed_bytes = unsafe {
            aes_gcm_enc_kernel(
                in_out.cast_const(),
                whole_block_bits,
                in_out,
                xi,
                ctr,
                rd_keys,
                htable,
                rounds,
            )
        };
        debug_assert_eq!(u64_from_usize(in_out_len_bytes), processed_bytes);
    }
}

pub(super) fn open_whole(
    aes_key: &aes::hw::Key,
    auth: &mut gcm::Context<gcm::clmul_aarch64::Key>,
    in_out: Overlapping,
    ctr: &mut Counter,
) {
    prefixed_extern! {
        fn aes_gcm_dec_kernel(
            input: *const u8,
            in_bits: BitLength<NonZeroU64>,
            output: *mut u8,
            Xi: &mut gcm::Xi,
            ivec: &mut Counter,
            key: *const aes::RdKey,
            Htable: &gcm::clmul_aarch64::Key,
            rounds: aes::Rounds) -> u64;
    }

    // Precondition. TODO: Create an overlapping::AsChunks for this.
    assert_eq!(in_out.len() % BLOCK_LEN, 0);

    in_out.with_input_output_len(|input, output, in_out_len_bytes| {
        let whole_block_bits = auth.in_out_whole_block_bits();
        if let Ok(whole_block_bits) = whole_block_bits.try_into() {
            let (htable, xi) = auth.inner();
            let (rd_keys, rounds) = aes_key.rd_keys_and_rounds();
            let processed_bytes = unsafe {
                aes_gcm_dec_kernel(
                    input,
                    whole_block_bits,
                    output,
                    xi,
                    ctr,
                    rd_keys,
                    htable,
                    rounds,
                )
            };
            debug_assert_eq!(u64_from_usize(in_out_len_bytes), processed_bytes);
        }
    })
}
