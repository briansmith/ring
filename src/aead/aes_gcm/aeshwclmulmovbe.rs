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

#[allow(unused_imports)]
use crate::polyfill::prelude::*;

use super::{
    super::overlapping::IndexError,
    aes::{self, Counter, EncryptCtr32, OverlappingPartialBlock},
    gcm, open_whole_partial_tail, Aad, Overlapping, Tag, BLOCK_LEN,
};
use crate::{c, error::InputTooLongError};

const STRIDE_LEN: usize = 6 * BLOCK_LEN;

#[inline(never)]
pub(super) fn seal(
    aes_key: &aes::hw::Key,
    gcm_key: &gcm::clmulavxmovbe::Key,
    mut ctr: Counter,
    tag_iv: aes::Iv,
    aad: Aad<&[u8]>,
    in_out: &mut [u8],
) -> Result<Tag, InputTooLongError> {
    prefixed_extern! {
        // Requires `len % STRIDE_LEN == 0 && len >= 3 * STRIDE_LEN`.
        //
        // The upstream version has a different calling convention where it
        // accepts any `len` and returns the number of bytes processed
        // according to the above.
        fn aesni_gcm_encrypt(
            input: *const u8,
            output: *mut u8,
            len: c::size_t,
            key: &aes::hw::Key,
            ivec: &mut Counter,
            Htable: &gcm::clmulavxmovbe::Key,
            Xi: &mut gcm::Xi);
    }

    let in_out_len = in_out.len();
    let mut auth = gcm::Context::new(gcm_key, aad, in_out_len)?;

    let remainder = if in_out_len >= 3 * STRIDE_LEN {
        let leftover = in_out_len % STRIDE_LEN;
        let (integrated, remainder) = in_out
            .split_at_mut_checked(in_out_len - leftover)
            .unwrap_or_else(|| {
                // Since `leftover <= in_out_len`
                unreachable!()
            });
        debug_assert!(integrated.len() >= 3 * STRIDE_LEN);
        let (htable, xi) = auth.inner();
        let integrated_len = integrated.len();
        let integrated = integrated.as_mut_ptr();
        unsafe {
            aesni_gcm_encrypt(
                integrated.cast_const(),
                integrated,
                integrated_len,
                aes_key,
                &mut ctr,
                htable,
                xi,
            )
        };
        remainder
    } else {
        in_out
    };

    let (whole, remainder) = remainder.as_chunks_mut();
    aes_key.ctr32_encrypt_within(whole.as_flattened_mut().into(), &mut ctr);
    auth.update_blocks(whole.as_ref());
    let remainder = OverlappingPartialBlock::new(remainder.into())
        .unwrap_or_else(|InputTooLongError { .. }| unreachable!());

    Ok(super::seal_finish(aes_key, auth, remainder, ctr, tag_iv))
}

#[inline(never)]
pub(super) fn open(
    aes_key: &aes::hw::Key,
    gcm_key: &gcm::clmulavxmovbe::Key,
    mut ctr: Counter,
    tag_iv: aes::Iv,
    aad: Aad<&[u8]>,
    in_out: Overlapping<'_>,
) -> Result<Tag, InputTooLongError> {
    prefixed_extern! {
        // Requires `len % STRIDE_LEN == 0 && len != 0`.
        //
        // The upstream version has a different calling convention where it
        // accepts any `len` and returns the number of bytes processed
        // according to the above.
        fn aesni_gcm_decrypt(
            input: *const u8,
            output: *mut u8,
            len: c::size_t,
            key: &aes::hw::Key,
            ivec: &mut Counter,
            Htable: &gcm::clmulavxmovbe::Key,
            Xi: &mut gcm::Xi);
    }

    let in_out_len = in_out.len();
    let mut auth = gcm::Context::new(gcm_key, aad, in_out_len)?;

    let in_out = if in_out_len >= STRIDE_LEN {
        let leftover = in_out_len % STRIDE_LEN;
        in_out
            .split_at(in_out_len - leftover, |strides| {
                debug_assert!(strides.len() >= STRIDE_LEN);
                debug_assert_eq!(strides.len() % STRIDE_LEN, 0);
                strides.with_input_output_len(|input, output, len| {
                    let (htable, xi) = auth.inner();
                    unsafe { aesni_gcm_decrypt(input, output, len, aes_key, &mut ctr, htable, xi) }
                })
            })
            .unwrap_or_else(|IndexError { .. }| unreachable!())
    } else {
        in_out
    };

    Ok(open_whole_partial_tail(
        aes_key,
        auth,
        in_out,
        ctr,
        tag_iv,
        |aes_key, auth, whole, ctr| {
            let (whole_input, _) = whole.input().as_chunks();
            auth.update_blocks(whole_input);
            aes_key.ctr32_encrypt_within(whole, ctr);
        },
    ))
}
