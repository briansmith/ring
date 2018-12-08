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
//! 1. Construct a `NonceRef`.
//! 2. Construct a `Counter` from the `NonceRef`.
//! 3. For each block encrypted, increment the counter. Each time the counter
//!    is incremented, the current value is returned.

use super::Block;
use crate::{endian::*, error, polyfill::convert::*};

/// A nonce.
///
/// The user must ensure, for a particular key, that each nonce is unique.
///
/// Intentionally doesn't implement `Clone` to ensure that each one is consumed
/// at most once.
#[repr(transparent)]
pub struct NonceRef<'a>(&'a [u8; NONCE_LEN]);

impl<'a> NonceRef<'a> {
    pub fn try_from(value: &'a [u8]) -> Result<Self, error::Unspecified> {
        Ok(NonceRef(value.try_into_()?))
    }
}

// All the AEADs we support use 96-bit nonces.
pub const NONCE_LEN: usize = 96 / 8;

/// A generator of a monotonically increasing series of `Iv`s.
///
/// Intentionally not `Clone` to ensure counters aren't forked.
#[repr(C)]
pub union Counter {
    block: Block,
    u32s: [LittleEndian<u32>; 4],
}

impl Counter {
    pub fn zero(nonce: NonceRef) -> Self { Self::new(nonce, 0) }

    // Used by `zero()` and by the tests.
    #[cfg(test)]
    pub fn from_test_vector(nonce: &[u8], initial_counter: u32) -> Self {
        Self::new(NonceRef::try_from(nonce).unwrap(), initial_counter)
    }

    fn new(NonceRef(nonce): NonceRef, initial_counter: u32) -> Self {
        let mut r = Self {
            block: Block::zero(),
        };
        let block = unsafe { &mut r.block };
        block.as_mut()[4..].copy_from_slice(nonce);
        let u32s = unsafe { &mut r.u32s };
        u32s[0] = initial_counter.into();
        r
    }

    /// XXX: The caller is responsible for ensuring that the counter doesn't
    /// wrap around to zero.
    pub fn increment(&mut self) -> Iv {
        let block = unsafe { &self.block };
        let r = Iv(block.clone());

        let ctr = unsafe { &mut self.u32s[0] };
        let new_value = u32::from(*ctr) + 1;
        *ctr = new_value.into();

        r
    }
}

impl Into<Iv> for Counter {
    fn into(self) -> Iv { Iv(unsafe { self.block }) }
}

/// The IV for a single block encryption.
///
/// Intentionally not `Clone` to ensure each is used only once.
#[repr(C)]
pub struct Iv(Block);
