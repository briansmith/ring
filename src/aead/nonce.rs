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

//! Encapsulates the progression from (key, nonce) -> counter -> IV, ensuring
//! unique IVs for a given (key, nonce). Currently the caller is required to
//! ensure that each nonce is unique and that counters don't overlap.
//!
//! To use:
//!
//! 1. Construct a `Nonce`.
//! 2. Construct a `Counter` from the `Nonce`.
//! 3. For each block encrypted, increment the counter. Each time the counter
//!    is incremented, the current value is returned.

use super::Block;
use crate::{endian::*, error, polyfill::convert::*};
use core::marker::PhantomData;

/// A nonce for a single AEAD opening or sealing operation.
///
/// The user must ensure, for a particular key, that each nonce is unique.
///
/// `Nonce` intentionally doesn't implement `Clone` to ensure that each one is
/// consumed at most once.
pub struct Nonce([u8; NONCE_LEN]);

impl Nonce {
    /// Constructs a `Nonce` with the given value, assuming that the value is
    /// unique for the lifetime of the key it is being used with.
    ///
    /// Fails if `value` isn't `NONCE_LEN` bytes long.
    #[inline]
    pub fn try_assume_unique_for_key(value: &[u8]) -> Result<Self, error::Unspecified> {
        let value: &[u8; NONCE_LEN] = value.try_into_()?;
        Ok(Self::assume_unique_for_key(*value))
    }

    /// Constructs a `Nonce` with the given value, assuming that the value is
    /// unique for the lifetime of the key it is being used with.
    #[inline]
    pub fn assume_unique_for_key(value: [u8; NONCE_LEN]) -> Self { Nonce(value) }
}

impl AsRef<[u8; NONCE_LEN]> for Nonce {
    fn as_ref(&self) -> &[u8; NONCE_LEN] { &self.0 }
}

/// All the AEADs we support use 96-bit nonces.
pub const NONCE_LEN: usize = 96 / 8;

/// A generator of a monotonically increasing series of `Iv`s.
///
/// Intentionally not `Clone` to ensure counters aren't forked.
#[repr(C)]
pub union Counter<U32: Layout<u32>>
where
    u32: From<U32>,
{
    block: Block,
    u32s: [U32; 4],
    encoding: PhantomData<U32>,
}

impl<U32: Layout<u32>> Counter<U32>
where
    u32: From<U32>,
{
    pub fn zero(nonce: Nonce) -> Self { Self::new(nonce, 0) }
    pub fn one(nonce: Nonce) -> Self { Self::new(nonce, 1) }

    // Used by `zero()` and by the tests.
    #[cfg(test)]
    pub fn from_test_vector(nonce: &[u8], initial_counter: u32) -> Self {
        Self::new(
            Nonce::try_assume_unique_for_key(nonce).unwrap(),
            initial_counter,
        )
    }

    fn new(Nonce(nonce): Nonce, initial_counter: u32) -> Self {
        let mut r = Self {
            block: Block::zero(),
        };
        let block = unsafe { &mut r.block };
        block.as_mut()[U32::NONCE_BYTE_INDEX..][..NONCE_LEN].copy_from_slice(nonce.as_ref());
        r.increment_by_less_safe(initial_counter);

        r
    }

    #[inline]
    pub fn increment(&mut self) -> Iv {
        let block = unsafe { &self.block };
        let r = Iv(block.clone());

        self.increment_by_less_safe(1);

        r
    }

    #[inline]
    pub fn increment_by_less_safe(&mut self, increment_by: u32) {
        let u32s = unsafe { &mut self.u32s };
        let value = &mut u32s[U32::COUNTER_U32_INDEX];
        *value = (u32::from(*value) + increment_by).into();
    }
}

/// The IV for a single block encryption.
///
/// Intentionally not `Clone` to ensure each is used only once.
#[repr(C)]
pub struct Iv(Block);

impl<U32: Layout<u32>> From<Counter<U32>> for Iv
where
    u32: From<U32>,
{
    fn from(counter: Counter<U32>) -> Self { Iv(unsafe { counter.block }) }
}

impl Iv {
    #[inline]
    pub fn assume_unique_for_key(a: Block) -> Self { Iv(a) }

    #[inline]
    pub fn into_block_less_safe(self) -> Block { self.0 }
}

pub trait Layout<T>: Encoding<T>
where
    T: From<Self>,
{
    const COUNTER_U32_INDEX: usize;
    const NONCE_BYTE_INDEX: usize;
}

impl<T> Layout<T> for BigEndian<T>
where
    BigEndian<T>: Encoding<T>,
    T: Copy + From<Self>,
{
    const COUNTER_U32_INDEX: usize = 3;
    const NONCE_BYTE_INDEX: usize = 0;
}

impl<T> Layout<T> for LittleEndian<T>
where
    LittleEndian<T>: Encoding<T>,
    T: Copy + From<Self>,
{
    const COUNTER_U32_INDEX: usize = 0;
    const NONCE_BYTE_INDEX: usize = 4;
}
