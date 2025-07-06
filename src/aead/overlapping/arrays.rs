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

#![cfg_attr(not(test), allow(dead_code))]

pub(crate) use self::error::BlocksError;
use super::{Array, IndexError, Overlapping};
use crate::error::InputTooLongError;
use crate::polyfill::slice::AsChunksMut;
use core::marker::PhantomData;
use core::num::NonZeroU32;
use untrusted::Input;

pub struct Blocks<'o, T, NumBlocks, const BLOCK_LEN: usize> {
    // Invariant: BLOCK_LEN != 0.
    // Invariant: `self.in_out.len() % BLOCK_LEN == 0`.
    // Invariant: `NumBlocks::try_from(self.in_out.len() / BLOCK_LEN).is_ok()`.
    in_out: Overlapping<'o, T>,
    _num_blocks: PhantomData<NumBlocks>,
}

impl<'o, T, const BLOCK_LEN: usize> From<AsChunksMut<'o, T, BLOCK_LEN>>
    for Blocks<'o, T, u32, BLOCK_LEN>
where
    Overlapping<'o, T>: From<&'o mut [T]>,
{
    fn from(in_out: AsChunksMut<'o, T, BLOCK_LEN>) -> Self {
        Self {
            in_out: Overlapping::from(in_out.as_flattened_mut()),
            _num_blocks: PhantomData,
        }
    }
}

impl<'o, T, const BLOCK_LEN: usize> From<&'o mut [T; BLOCK_LEN]> for Blocks<'o, T, u32, BLOCK_LEN>
where
    Overlapping<'o, T>: From<&'o mut [T]>,
{
    fn from(value: &'o mut [T; BLOCK_LEN]) -> Self {
        Self {
            in_out: Overlapping::from(value.as_mut()),
            _num_blocks: PhantomData,
        }
    }
}

impl<'o, T, NumBlocks: TryFrom<usize>, const BLOCK_LEN: usize> TryFrom<Overlapping<'o, T>>
    for Blocks<'o, T, NumBlocks, BLOCK_LEN>
{
    type Error = BlocksError;

    fn try_from(in_out: Overlapping<'o, T>) -> Result<Self, Self::Error> {
        assert_ne!(BLOCK_LEN, 0);
        let len = in_out.len();
        let remainder =
            Self::check_num_blocks(in_out.len()).map_err(BlocksError::input_too_long)?;
        if remainder != 0 {
            return Err(BlocksError::not_a_multiple_of_block_len(remainder));
        }
        Ok(Self {
            in_out,
            _num_blocks: PhantomData,
        })
    }
}

impl<'o, T, NumBlocks: TryFrom<usize>, const BLOCK_LEN: usize> Blocks<'o, T, NumBlocks, BLOCK_LEN> {
    pub(super) fn checked_remainder(len: usize) -> Result<usize, InputTooLongError> {
        let blocks = len / BLOCK_LEN;
        let leftover = len % BLOCK_LEN;
        if NumBlocks::try_from(blocks).is_err() {
            return Err(InputTooLongError::new(blocks));
        }
        Ok(leftover)
    }
}

impl<'o, T, const BLOCK_LEN: usize> Blocks<'o, T, u32, BLOCK_LEN> {
    pub fn with_input_output_blocks<R>(
        self,
        f: impl FnOnce(*const [T; BLOCK_LEN], *mut [T; BLOCK_LEN], u32) -> R,
    ) -> R {
        self.in_out.with_input_output_len(|input, output, len| {
            let nun_blocks = len / BLOCK_LEN;
            #[allow(clippy::cast_possible_truncation)] // lossless due to invariant.
            let num_blocks = nun_blocks as u32;
            f(
                input.cast::<[T; BLOCK_LEN]>(),
                output.cast::<[T; BLOCK_LEN]>(),
                num_blocks,
            )
        })
    }

    // TODO: `IndexError` is perhaps not the best error to return
    pub fn split_first_block(
        self,
        f: impl for<'a> FnOnce(Array<'a, T, BLOCK_LEN>),
    ) -> Result<Self, IndexError> {
        self.in_out
            .split_first_chunk::<BLOCK_LEN>(f)
            .map(|in_out| Self {
                in_out,
                _num_blocks: PhantomData,
            })
    }

    pub fn num_blocks(&self) -> u32 {
        let num_blocks = self.in_out.len() / BLOCK_LEN;
        #[allow(clippy::cast_possible_truncation)] // lossless due to invariant.
        let num_blocks = num_blocks as u32;
        num_blocks
    }
}

cold_exhaustive_error! {
    enum error::BlocksError {
        input_too_long => InputTooLong(InputTooLongError),
        not_a_multiple_of_block_len => NotAMultipleOfBlockLen(usize),
    }
}
