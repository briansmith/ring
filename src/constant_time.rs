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
    verify_all_bytes_are_equal(a.iter().copied(), b.iter().copied())
}

// TODO: Use this in internal callers, in favor of `verify_slices_are_equal`.
#[inline]
pub(crate) fn verify_all_bytes_are_equal(
    a: impl ExactSizeIterator<Item = u8>,
    b: impl ExactSizeIterator<Item = u8>,
) -> Result<(), error::Unspecified> {
    if a.len() != b.len() {
        return Err(error::Unspecified);
    }
    let zero_if_equal = a.zip(b).fold(0, |accum, (a, b)| accum | (a ^ b));
    let zero_if_equal = unsafe { RING_value_barrier_w(Word::from(zero_if_equal)) };
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

#[cfg(test)]
mod tests {
    use crate::limb::LimbMask;
    use crate::{bssl, error, rand};

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
                ref_out
                    .iter_mut()
                    .zip(ref_in.iter())
                    .for_each(|(out, input)| {
                        *out ^= input;
                    });
            }

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
