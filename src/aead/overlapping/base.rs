// Copyright 2024 Brian Smith.
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

use crate::error;
use core::ops::RangeFrom;

pub struct Overlapping<'o, T> {
    in_out: &'o mut [T],
    src: RangeFrom<usize>,
}

impl<'o, T> Overlapping<'o, T> {
    pub fn in_place(in_out: &'o mut [T]) -> Self {
        Self { in_out, src: 0.. }
    }

    pub fn new(in_out: &'o mut [T], src: RangeFrom<usize>) -> Result<Self, SrcIndexError> {
        match in_out.get(src.clone()) {
            Some(_) => Ok(Self { in_out, src }),
            None => Err(SrcIndexError::new(src)),
        }
    }

    #[cfg(any(target_arch = "arm", target_arch = "x86"))]
    pub fn into_slice_src_mut(self) -> (&'o mut [T], RangeFrom<usize>) {
        (self.in_out, self.src)
    }
}

impl<T> Overlapping<'_, T> {
    pub fn len(&self) -> usize {
        self.in_out[self.src.clone()].len()
    }
    pub fn into_input_output_len(self) -> (*const T, *mut T, usize) {
        let len = self.len();
        let output = self.in_out.as_mut_ptr();
        // TODO: MSRV(1.65): use `output.cast_const()`
        let output_const: *const T = output;
        // SAFETY: The constructor ensures that `src` is a valid range.
        // Equivalent to `self.in_out[src.clone()].as_ptr()` but without
        // worries about compatibility with the stacked borrows model.
        let input = unsafe { output_const.add(self.src.start) };
        (input, output, len)
    }
}

pub struct SrcIndexError(#[allow(dead_code)] RangeFrom<usize>);

impl SrcIndexError {
    #[cold]
    fn new(src: RangeFrom<usize>) -> Self {
        Self(src)
    }
}

impl From<SrcIndexError> for error::Unspecified {
    fn from(_: SrcIndexError) -> Self {
        Self
    }
}
