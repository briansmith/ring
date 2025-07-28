// Copyright 2024 Brian Smith.
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

pub use self::index_error::IndexError;
use super::Array;
use crate::error::LenMismatchError;
use core::{mem, ops::RangeFrom};

pub struct Overlapping<'o, T> {
    // Invariant: self.src.start <= in_out.len().
    in_out: &'o mut [T],
    src: RangeFrom<usize>,
}

impl<'o, T> From<&'o mut [T]> for Overlapping<'o, T> {
    fn from(in_out: &'o mut [T]) -> Self {
        Self { in_out, src: 0.. }
    }
}

impl<'o, T> Overlapping<'o, T> {
    pub fn new(in_out: &'o mut [T], src: RangeFrom<usize>) -> Result<Self, IndexError> {
        match in_out.get(src.clone()) {
            Some(_) => Ok(Self { in_out, src }),
            None => Err(IndexError::new(src.start)),
        }
    }

    #[cfg(any(
        all(target_arch = "arm", target_endian = "little"),
        target_arch = "x86"
    ))]
    pub fn copy_within(self) -> &'o mut [T]
    where
        T: Copy,
    {
        if self.src.start == 0 {
            self.in_out
        } else {
            let len = self.len();
            self.in_out.copy_within(self.src, 0);
            &mut self.in_out[..len]
        }
    }

    pub fn assume_entire_output_written_on_success<R, E>(
        self,
        f: impl for<'b> FnOnce(Overlapping<'b, T>) -> Result<R, E>,
    ) -> Result<(&'o mut [T], R), E> {
        let len = self.len();
        let reborrowed = Overlapping {
            in_out: &mut self.in_out[..],
            src: self.src.clone(),
        };
        let r = f(reborrowed)?;
        Ok((&mut self.in_out[..len], r))
    }

    pub fn into_unwritten_output(self) -> &'o mut [T] {
        let len = self.len();
        self.in_out.get_mut(..len).unwrap_or_else(|| {
            // The invariant ensures this succeeds.
            unreachable!()
        })
    }
}

impl<T> Overlapping<'_, T> {
    pub fn len(&self) -> usize {
        self.input().len()
    }

    pub fn input(&self) -> &[T] {
        self.in_out.get(self.src.clone()).unwrap_or_else(|| {
            // Ensured by invariant.
            unreachable!()
        })
    }

    pub fn with_input_output_len<R>(self, f: impl FnOnce(*const T, *mut T, usize) -> R) -> R {
        let len = self.len();
        let output = self.in_out.as_mut_ptr();
        // SAFETY: The constructor ensures that `src` is a valid range.
        // Equivalent to `self.in_out[src.clone()].as_ptr()` but without
        // worries about compatibility with the stacked borrows model.
        // TODO(MSRV-1.80, probably): Avoid special casing 0; see
        // https://github.com/rust-lang/rust/pull/117329
        // https://github.com/rust-lang/rustc_codegen_gcc/issues/516
        let input = if self.src.start == 0 {
            output.cast_const()
        } else {
            unsafe { output.cast_const().add(self.src.start) }
        };
        f(input, output, len)
    }

    // Perhaps unlike `slice::split_first_chunk_mut`, this is biased,
    // performance-wise, against the case where `N > self.len()`, so callers
    // should be structured to avoid that.
    //
    // If the result is `Err` then nothing was written to `self`; if anything
    // was written then the result will not be `Err`.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn split_first_chunk<const N: usize>(
        self,
        f: impl for<'a> FnOnce(Array<'a, T, N>),
    ) -> Result<Self, IndexError> {
        self.split_at(N, |first| {
            let first = Array::new(first).unwrap_or_else(|LenMismatchError { .. }| unreachable!());
            f(first);
        })
    }

    pub fn split_at(
        mut self,
        mid: usize,
        f: impl for<'a> FnOnce(Overlapping<'a, T>),
    ) -> Result<Self, IndexError> {
        let src = self.src.clone();
        let end = self
            .src
            .start
            .checked_add(mid)
            .ok_or_else(|| IndexError::new(mid))?;
        let before = self
            .in_out
            .get_mut(..end)
            .ok_or_else(|| IndexError::new(mid))?;
        let before = Overlapping::new(before, src).unwrap_or_else(|IndexError { .. }| {
            // Since `end == src.start + mid`.
            unreachable!()
        });
        // Once we call `f`, we must return `Ok` because `f` may have written
        // over (part of) the input.
        Ok({
            f(before);
            let tail = mem::take(&mut self.in_out)
                .get_mut(mid..)
                .unwrap_or_else(|| {
                    // There are at least `N` elements since `end == src.start + mid`.
                    unreachable!()
                });
            Self::new(tail, self.src).unwrap_or_else(|IndexError { .. }| {
                // Follows from `end == src.start + mid`.
                unreachable!()
            })
        })
    }
}

cold_exhaustive_error! {
    struct index_error::IndexError { index: usize }
}
