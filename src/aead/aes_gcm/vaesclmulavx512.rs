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

#![cfg(target_arch = "x86_64")]
#![cfg_attr(any(target_os = "macos", target_vendor = "apple"), allow(dead_code))]

use super::{aes, gcm, Counter, Overlapping, BLOCK_LEN};
use crate::{c, polyfill::slice::AsChunksMut};
use core::num::{NonZeroU32, NonZeroUsize};

pub(super) fn seal_whole(
    aes_key: &aes::hw::Key,
    auth: &mut gcm::Context<gcm::vclmulavx512::Key>,
    ctr: &mut Counter,
    mut in_out: AsChunksMut<u8, BLOCK_LEN>,
) {
    prefixed_extern! {
        fn aes_gcm_enc_update_vaes_avx512(
            input: *const u8,
            output: *mut u8,
            len: c::NonZero_size_t, // TODO? zero OK?
            key: &aes::hw::Key,
            ivec: &Counter,
            Htable: &gcm::vclmulavx512::Key,
            Xi: &mut gcm::Xi);
    }

    let in_out = in_out.as_flattened_mut();

    // Precondition: Since we have a `gcm::Context` then the number of blocks
    // must fit in `u32`.
    let blocks = u32::try_from(in_out.len() / BLOCK_LEN).unwrap();

    if let Some(len) = NonZeroUsize::new(in_out.len()) {
        let (htable, xi) = auth.inner();
        let input = in_out.as_ptr();
        let output = in_out.as_mut_ptr();
        unsafe { aes_gcm_enc_update_vaes_avx512(input, output, len, aes_key, ctr, htable, xi) };
        let blocks = NonZeroU32::new(blocks).unwrap_or_else(|| {
            unreachable!() // Due to previous checks.
        });
        ctr.increment_by_less_safe(blocks);
    }
}

pub(super) fn open_whole(
    aes_key: &aes::hw::Key,
    auth: &mut gcm::Context<gcm::vclmulavx512::Key>,
    in_out: Overlapping,
    ctr: &mut Counter,
) {
    prefixed_extern! {
        fn aes_gcm_dec_update_vaes_avx512(
            input: *const u8,
            output: *mut u8,
            len: c::NonZero_size_t, // TODO? zero OK?
            key: &aes::hw::Key,
            ivec: &mut Counter,
            Htable: &gcm::vclmulavx512::Key,
            Xi: &mut gcm::Xi);
    }

    // Precondition. TODO: Create an overlapping::AsChunks for this.
    assert_eq!(in_out.len() % BLOCK_LEN, 0);
    // Precondition: Since we have a `gcm::Context` then the number of blocks
    // must fit in `u32`.
    let blocks = u32::try_from(in_out.len() / BLOCK_LEN).unwrap();

    in_out.with_input_output_len(|input, output, len| {
        if let Some(len) = NonZeroUsize::new(len) {
            let (htable, xi) = auth.inner();
            unsafe { aes_gcm_dec_update_vaes_avx512(input, output, len, aes_key, ctr, htable, xi) };
            let blocks = NonZeroU32::new(blocks).unwrap_or_else(|| {
                unreachable!() // Due to previous checks.
            });
            ctr.increment_by_less_safe(blocks);
        }
    })
}
