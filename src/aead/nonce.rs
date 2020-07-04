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

use crate::{endian::*, error};
use core::convert::TryInto;

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
        let value: &[u8; NONCE_LEN] = value.try_into()?;
        Ok(Self::assume_unique_for_key(*value))
    }

    /// Constructs a `Nonce` with the given value, assuming that the value is
    /// unique for the lifetime of the key it is being used with.
    #[inline]
    pub fn assume_unique_for_key(value: [u8; NONCE_LEN]) -> Self {
        Self(value)
    }
}

impl AsRef<[u8; NONCE_LEN]> for Nonce {
    fn as_ref(&self) -> &[u8; NONCE_LEN] {
        &self.0
    }
}

/// All the AEADs we support use 96-bit nonces.
pub const NONCE_LEN: usize = 96 / 8;

/// A generator of a monotonically increasing series of `Iv`s.
///
/// Intentionally not `Clone` to ensure counters aren't forked.
#[repr(C)]
pub struct Counter<U32> {
    u32s: [U32; 4],
}

impl<U32> Counter<U32>
where
    U32: Copy,
    U32: Encoding<u32>,
    U32: From<[u8; 4]>,
    U32: Layout,
{
    pub fn zero(nonce: Nonce) -> Self {
        Self::new(nonce, 0)
    }
    pub fn one(nonce: Nonce) -> Self {
        Self::new(nonce, 1)
    }

    #[cfg(test)]
    pub fn from_test_vector(nonce: &[u8], initial_counter: u32) -> Self {
        Self::new(
            Nonce::try_assume_unique_for_key(nonce).unwrap(),
            initial_counter,
        )
    }

    fn new(Nonce(nonce): Nonce, initial_counter: u32) -> Self {
        let mut r = Self {
            u32s: [U32::ZERO; 4],
        };
        let nonce_index = (U32::COUNTER_INDEX + 1) % r.u32s.len();
        (&mut r.u32s[nonce_index..][..3])
            .iter_mut()
            .zip(nonce.chunks_exact(4))
            .for_each(|(initial, nonce)| {
                let nonce: &[u8; 4] = nonce.try_into().unwrap();
                *initial = U32::from(*nonce);
            });
        r.u32s[U32::COUNTER_INDEX] = U32::from(initial_counter);
        r
    }

    #[inline]
    pub fn increment(&mut self) -> Iv {
        let r = Iv::from_counter_less_safe(Self { u32s: self.u32s });
        self.increment_by_less_safe(1);

        r
    }

    #[inline]
    pub fn increment_by_less_safe(&mut self, increment_by: u32) {
        let counter = &mut self.u32s[U32::COUNTER_INDEX];
        let old_value: u32 = (*counter).into();
        *counter = U32::from(old_value + increment_by);
    }
}

/// The IV for a single block encryption.
///
/// Intentionally not `Clone` to ensure each is used only once.
#[repr(C)]
pub struct Iv([u8; IV_LEN]);

const IV_LEN: usize = 16;

impl Iv {
    #[inline]
    pub(super) fn from_counter_less_safe<U32>(counter: Counter<U32>) -> Self
    where
        U32: Encoding<u32>,
    {
        let bytes: &[u8; 16] = as_bytes(&counter.u32s).try_into().unwrap();
        Self(*bytes)
    }

    #[inline]
    pub fn assume_unique_for_key(a: [u8; IV_LEN]) -> Self {
        Self(a)
    }

    #[inline]
    pub fn into_bytes_less_safe(self) -> [u8; IV_LEN] {
        self.0
    }
}

pub trait Layout {
    const COUNTER_INDEX: usize;
}

impl Layout for BigEndian<u32> {
    const COUNTER_INDEX: usize = 3;
}

impl Layout for LittleEndian<u32> {
    const COUNTER_INDEX: usize = 0;
}
