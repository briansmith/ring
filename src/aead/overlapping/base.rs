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
use super::{arrays::BlocksError, Array, Blocks, PartialBlock};
use crate::error::{InputTooLongError, LenMismatchError};
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

    pub fn into_unwritten_output(self) -> &'o mut [T] {
        let len = self.len();
        self.in_out.get_mut(..len).unwrap_or_else(|| {
            // The invariant ensures this succeeds.
            unreachable!()
        })
    }
}

impl<T> Overlapping<'_, T> {
    pub fn is_empty(&self) -> bool {
        self.input().is_empty()
    }

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
        // TODO: MSRV(1.65): use `output.cast_const()`
        let output_const: *const T = output;
        // SAFETY: The constructor ensures that `src` is a valid range.
        // Equivalent to `self.in_out[src.clone()].as_ptr()` but without
        // worries about compatibility with the stacked borrows model.
        // TODO(MSRV-1.80, probably): Avoid special casing 0; see
        // https://github.com/rust-lang/rust/pull/117329
        // https://github.com/rust-lang/rustc_codegen_gcc/issues/516
        let input = if self.src.start == 0 {
            output_const
        } else {
            unsafe { output_const.add(self.src.start) }
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

impl<'o, T> Overlapping<'o, T> {
    pub fn split_whole_blocks<Len: TryFrom<usize>, const BLOCK_LEN: usize>(
        self,
        f: impl for<'a> FnOnce(Blocks<'a, T, Len, BLOCK_LEN>),
    ) -> Result<PartialBlock<'o, T, BLOCK_LEN>, InputTooLongError> {
        let in_out_len = self.len();
        let checked_remainder_len = Blocks::<'o, T, Len, BLOCK_LEN>::checked_remainder(in_out_len)?;
        let whole_len = in_out_len - checked_remainder_len;
        let remainder = self
            .split_at(whole_len, |whole| {
                let blocks = Blocks::try_from(whole).unwrap_or_else(|err| match err {
                    BlocksError::InputTooLong(_) => {
                        let _impossible_because = checked_remainder_len;
                        unreachable!();
                    }
                    BlocksError::NotAMultipleOfBlockLen(_) => {
                        let _impossible_because = checked_remainder_len;
                        unreachable!();
                    }
                });
                f(blocks);
            })
            .unwrap_or_else(|IndexError { .. }| {
                let _impossible_because = whole_len;
                unreachable!();
            });
        Ok(
            PartialBlock::new(remainder).unwrap_or_else(|InputTooLongError { .. }| {
                let _impossible_because = checked_remainder_len;
                unreachable!()
            }),
        )
    }
}

cold_exhaustive_error! {
    struct index_error::IndexError { index: usize }
}
