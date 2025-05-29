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

use super::{
    super::overlapping::IndexError,
    aes::{self, Counter, EncryptCtr32, Overlapping, OverlappingPartialBlock},
    gcm, open_whole_partial_tail, Aad, Tag,
};
use crate::{c, error::InputTooLongError, polyfill::slice};

const STRIDE_LEN: usize = 96;

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
        // `HTable` and `Xi` should be 128-bit aligned. TODO: Can we shrink `HTable`? The
        // assembly says it needs just nine values in that array.
        fn aesni_gcm_encrypt(
            input: *const u8,
            output: *mut u8,
            len: c::size_t,
            key: &aes::AES_KEY,
            ivec: &mut Counter,
            Htable: &gcm::HTable,
            Xi: &mut gcm::Xi) -> c::size_t;
    }

    let mut auth = gcm::Context::new(gcm_key, aad, in_out.len())?;
    let (htable, xi) = auth.inner();

    let processed = unsafe {
        aesni_gcm_encrypt(
            in_out.as_ptr(),
            in_out.as_mut_ptr(),
            in_out.len(),
            aes_key.inner_less_safe(),
            &mut ctr,
            htable,
            xi,
        )
    };

    let remaining = match in_out.get_mut(processed..) {
        Some(remaining) => remaining,
        None => {
            // This can't happen. If it did, then the assembly already
            // caused a buffer overflow.
            unreachable!()
        }
    };
    let (mut whole, remainder) = slice::as_chunks_mut(remaining);
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
        //
        // `HTable` and `Xi` should be 128-bit aligned. TODO: Can we shrink `HTable`? The
        // assembly says it needs just nine values in that array.
        fn aesni_gcm_decrypt(
            input: *const u8,
            output: *mut u8,
            len: c::size_t,
            key: &aes::AES_KEY,
            ivec: &mut Counter,
            Htable: &gcm::HTable,
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
                    unsafe {
                        aesni_gcm_decrypt(
                            input,
                            output,
                            len,
                            aes_key.inner_less_safe(),
                            &mut ctr,
                            htable,
                            xi,
                        )
                    }
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
            let (whole_input, _) = slice::as_chunks(whole.input());
            auth.update_blocks(whole_input);
            aes_key.ctr32_encrypt_within(whole, ctr);
        },
    ))
}
