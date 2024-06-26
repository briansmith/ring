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

#[cfg(target_pointer_width = "64")]
pub(crate) type Word = u64;

#[cfg(target_pointer_width = "32")]
pub(crate) type Word = u32;

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
    Zero + Into<Word> + core::ops::BitXor<Self, Output = Self> + core::ops::BitOr<Self, Output = Self>
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
    let zero_if_equal = unsafe { RING_value_barrier_w(zero_if_equal.into()) };
    match zero_if_equal {
        0 => Ok(()),
        _ => Err(error::Unspecified),
    }
}

/// The integer type that's the "natural" unsigned machine word size.
pub(crate) type Word = CryptoWord;

// Keep in sync with `crypto_word_t` in crypto/internal.h.
#[cfg(target_pointer_width = "32")]
type CryptoWord = u32;
#[cfg(target_pointer_width = "64")]
type CryptoWord = u64;

prefixed_extern! {
    fn RING_value_barrier_w(a: CryptoWord) -> CryptoWord;
}

pub(crate) fn xor_16(a: [u8; 16], b: [u8; 16]) -> [u8; 16] {
    let a = u128::from_ne_bytes(a);
    let b = u128::from_ne_bytes(b);
    let r = a ^ b;
    r.to_ne_bytes()
}

/// XORs the first N bytes of `b` into `a`, where N is
/// `core::cmp::min(a.len(), b.len())`.
#[inline(always)]
pub(crate) fn xor_assign_at_start<'a>(
    a: impl IntoIterator<Item = &'a mut u8>,
    b: impl IntoIterator<Item = &'a u8>,
) {
    a.into_iter().zip(b).for_each(|(a, b)| *a ^= *b);
}

#[cfg(test)]
mod tests {
    use crate::{bssl, constant_time::xor_assign_at_start, error, limb::LimbMask, rand};

    #[test]
    fn test_constant_time() -> Result<(), error::Unspecified> {
        prefixed_extern! {
            fn bssl_constant_time_test_main() -> bssl::Result;
        }
        Result::from(unsafe { bssl_constant_time_test_main() })
    }

    #[test]
    fn constant_time_conditional_memcpy() -> Result<(), error::Unspecified> {
        let rng = rand::SystemRandom::new();
        for _ in 0..100 {
            let mut out = rand::generate::<[u8; 256]>(&rng)?.expose();
            let input = rand::generate::<[u8; 256]>(&rng)?.expose();

            // Mask to 16 bits to make zero more likely than it would otherwise be.
            let b = (rand::generate::<[u8; 1]>(&rng)?.expose()[0] & 0x0f) == 0;

            let ref_in = input;
            let ref_out = if b { input } else { out };

            prefixed_extern! {
                fn bssl_constant_time_test_conditional_memcpy(dst: &mut [u8; 256], src: &[u8; 256], b: LimbMask);
            }
            unsafe {
                bssl_constant_time_test_conditional_memcpy(
                    &mut out,
                    &input,
                    if b { LimbMask::True } else { LimbMask::False },
                )
            }
            assert_eq!(ref_in, input);
            assert_eq!(ref_out, out);
        }

        Ok(())
    }

    #[test]
    fn constant_time_conditional_memxor() -> Result<(), error::Unspecified> {
        let rng = rand::SystemRandom::new();
        for _ in 0..256 {
            let mut out = rand::generate::<[u8; 256]>(&rng)?.expose();
            let input = rand::generate::<[u8; 256]>(&rng)?.expose();

            // Mask to 16 bits to make zero more likely than it would otherwise be.
            let b = (rand::generate::<[u8; 1]>(&rng)?.expose()[0] & 0x0f) != 0;

            let ref_in = input;
            let mut ref_out = out;
            if b {
                xor_assign_at_start(&mut ref_out, &ref_in)
            };

            prefixed_extern! {
                fn bssl_constant_time_test_conditional_memxor(dst: &mut [u8; 256], src: &[u8; 256], b: LimbMask);
            }
            unsafe {
                bssl_constant_time_test_conditional_memxor(
                    &mut out,
                    &input,
                    if b { LimbMask::True } else { LimbMask::False },
                );
            }

            assert_eq!(ref_in, input);
            assert_eq!(ref_out, out);
        }

        Ok(())
    }
}
