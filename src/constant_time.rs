// Copyright 2015-2016 Brian Smith.
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

//! Constant-time operations.

use crate::error;

/// Returns `Ok(())` if `a == b` and `Err(error::Unspecified)` otherwise.
/// The comparison of `a` and `b` is done in constant time with respect to the
/// contents of each, but NOT in constant time with respect to the lengths of
/// `a` and `b`.
pub fn verify_slices_are_equal(a: &[u8], b: &[u8]) -> Result<(), error::Unspecified> {
    verify_equal(a.iter().copied(), b.iter().copied())
}

/// Types that have a zero value.
pub(crate) trait Zero {
    /// The zero value.
    fn zero() -> Self;
}

/// All operations in the supertraits are assumed to be constant time.
pub(crate) trait CryptoValue:
    Zero
    + Into<CryptoWord>
    + core::ops::BitXor<Self, Output = Self>
    + core::ops::BitOr<Self, Output = Self>
{
}

impl Zero for u8 {
    fn zero() -> Self {
        0
    }
}

impl CryptoValue for u8 {}

// TODO: Use this in internal callers, in favor of `verify_slices_are_equal`.
#[inline]
pub(crate) fn verify_equal<T>(
    a: impl ExactSizeIterator<Item = T>,
    b: impl ExactSizeIterator<Item = T>,
) -> Result<(), error::Unspecified>
where
    T: CryptoValue,
{
    if a.len() != b.len() {
        return Err(error::Unspecified);
    }
    let zero_if_equal = a.zip(b).fold(T::zero(), |accum, (a, b)| accum | (a ^ b));
    let zero_if_equal = unsafe { CONSTANT_TIME_value_barrier_w(zero_if_equal.into()) };
    match zero_if_equal {
        0 => Ok(()),
        _ => Err(error::Unspecified),
    }
}

/// The integer type that's the "natural" unsigned machine word size.
pub type CryptoWord = CryptoWord_;

// Keep in sync with `crypto_word` in crypto/internal.h.
#[cfg(target_pointer_width = "32")]
type CryptoWord_ = u32;
#[cfg(target_pointer_width = "64")]
type CryptoWord_ = u64;

prefixed_extern! {
    fn CONSTANT_TIME_value_barrier_w(a: CryptoWord) -> CryptoWord;
}

#[cfg(test)]
mod tests {
    use crate::{bssl, error};

    #[test]
    fn test_constant_time() -> Result<(), error::Unspecified> {
        prefixed_extern! {
            fn bssl_constant_time_test_main() -> bssl::Result;
        }
        Result::from(unsafe { bssl_constant_time_test_main() })
    }
}
