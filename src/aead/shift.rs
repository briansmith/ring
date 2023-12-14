// Copyright 2018 Brian Smith.
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

#![cfg(target_arch = "x86")]

use super::{
    block::{Block, BLOCK_LEN},
    InOut,
};
use crate::{error, polyfill};

pub fn shift_full_blocks<'o>(
    mut in_out: InOut<'_, 'o>,
    mut transform: impl for<'a> FnMut(&'a [u8; BLOCK_LEN]) -> Block,
) -> Result<&'o mut [u8], error::Unspecified> {
    let result_ptr = in_out.output_ptr_less_safe();
    let result_len = in_out.len();

    while in_out.len() > 0 {
        in_out.advance_after(BLOCK_LEN, |chunk| {
            let input = <&[u8; BLOCK_LEN]>::try_from(chunk.input()).unwrap();
            let block = transform(input);
            let input: *const u8 = block.as_ref().as_ptr();
            let output: *mut u8 = chunk.into_output_ptr().cast();
            unsafe {
                core::ptr::copy_nonoverlapping(input, output, BLOCK_LEN);
            }
        })?;
    }

    let output = unsafe {
        polyfill::maybeuninit::slice_assume_init_mut(core::slice::from_raw_parts_mut(
            result_ptr, result_len,
        ))
    };
    Ok(output)
}
