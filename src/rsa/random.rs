// Copyright 2016 David Judd.
// Copyright 2016 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

//! Generation of random field elements, in particular field elements in GFn
//! where *n* is an RSA public modulus.

use {rand, error, rsa};
use limb::*;

/// Sets `out` to a *uniformly* random value in the range [1, `max_exclusive`).
pub fn set_to_rand_mod(out: &mut [Limb], max_exclusive: &[Limb],
                       rng: &rand::SecureRandom)
                       -> Result<(), error::Unspecified> {
    assert_eq!(out.len(), max_exclusive.len());
    assert!(out.len() >= 1);
    assert!(out.len() <= rsa::PRIVATE_KEY_PUBLIC_MODULUS_MAX_LIMBS);
    assert!(max_exclusive.len() >= 1);
    assert!(max_exclusive.len() <= rsa::PRIVATE_KEY_PUBLIC_MODULUS_MAX_LIMBS);

    let sampling_params = select_sampling_params(max_exclusive);

    // Make copies of `out` and `max_exclusive` that are padded on the most
    // significant end by at least one zero limb. This is needed to handle the
    // `sampling_params.extend_limbs_by_one` case.
    let mut tmp_out = [0; rsa::PRIVATE_KEY_PUBLIC_MODULUS_MAX_LIMBS + 1];
    tmp_out[..out.len()].copy_from_slice(&out);
    let mut tmp_max = [0; rsa::PRIVATE_KEY_PUBLIC_MODULUS_MAX_LIMBS + 1];
    tmp_max[..max_exclusive.len()].copy_from_slice(&max_exclusive);
    let extra_limb = if sampling_params.extend_limbs_by_one { 1 } else { 0 };

    let range = Range {
        max_exclusive: &tmp_max[..(max_exclusive.len() + extra_limb)],
        sampling_params: &sampling_params,
    };
    range.sample_into_limbs(&mut tmp_out[..out.len() + extra_limb], rng)?;

    let dest_len = out.len();
    out.copy_from_slice(&tmp_out[..dest_len]);

    Ok(())
}

/// References a positive integer range `[1..max_exclusive)`. `max_exclusive`
/// is assumed to be public, not secret.
//
// TODO(djudd) Part of this code can potentially be pulled back into
// `super::limb` and shared with EC key generation, without unnecessarily
// complicating that, once specialization is stabilized.
struct Range<'a> {
    max_exclusive: &'a [Limb],
    sampling_params: &'a SamplingParams,
}

impl <'a> Range<'a> {
    /// Checks that `limbs` are in the range. If `limbs` is in range then it
    /// runs in constant time with respect to its value.
    fn are_limbs_within(&self, limbs: &[Limb]) -> bool {
        assert_eq!(self.max_exclusive.len(), limbs.len());

        // The caller calls this in a sequence where it makes more sense to
        // check for too-large values first and return early.
        if limbs_less_than_limbs_consttime(limbs, self.max_exclusive) !=
                LimbMask::True {
            return false;
        }

        limbs_are_zero_constant_time(limbs) == LimbMask::False
    }

    /// Chooses a positive integer within the range and stores it into `out`.
    ///
    /// This function is intended to be suitable for generating private keys.
    fn sample_into_limbs(&self, out: &mut [Limb], rng: &rand::SecureRandom)
                         -> Result<(), error::Unspecified> {
        // Loosely based on [NSA Suite B Implementer's Guide to ECDSA]
        // Appendix A.1.2, and
        // [NSA Suite B Implementer's Guide to NIST SP 800-56A] Appendix B.2,
        // "Key Pair Generation by Testing Candidates".
        //
        // [NSA Suite B Implementer's Guide to ECDSA]: doc/ecdsa.pdf.
        // [NSA Suite B Implementer's Guide to NIST SP 800-56A]: doc/ecdh.pdf.

        assert_eq!(self.max_exclusive.len(), out.len());

        // XXX: The value 100 was chosen to match OpenSSL due to uncertainty of
        // what specific value would be better, but it seems bad to try 100
        // times.
        for _ in 0..100 {
            {
                let mut dest_as_bytes = limbs_as_bytes_mut(out);
                rng.fill(&mut dest_as_bytes)?;
            }

            // Mask off unwanted bits.
            let mask = self.sampling_params.most_sig_limb_mask;
            out[self.max_exclusive.len() - 1] &= mask;

            if self.are_limbs_within(&out) {
                return Ok(());
            }

            if self.sampling_params.reduce_when_over_bound {
                limbs_reduce_once_constant_time(out, self.max_exclusive);
                if self.are_limbs_within(&out) {
                    // `out` started out in (max, 2*max).
                    return Ok(());
                }

                limbs_reduce_once_constant_time(out, self.max_exclusive);
                if self.are_limbs_within(&out) {
                    // `out` started out in (2*max, 3*max).
                    return Ok(());
                }

                // `out` started out in [3*max, 2**(n+1)) or congruent to
                // 0 mod max (0, max, or 2*max), so we can't fix it. Loop and
                // generate a new random value.
            }
        }

        Err(error::Unspecified)
    }
}

/// Params which specify the implementation strategy for random sampling from
/// an interval (0, max).
struct SamplingParams {
    // We generate random data to fill a slice of limbs, so if we want a number
    // of bits which isn't a multiple of LIMB_BITS, we need to mask off some
    // of the bits in the most significant limb.
    most_sig_limb_mask: Limb,

    // Assume `x` is of the form `0b100...`. This means:
    //
    //    x < 2**n - 2**(n-2) - 2**(n-3).
    //
    // This means that `3*x < 2**(n+1)`. Proof:
    //
    //  3*x < 3*(2**n - 2**(n-2) - 2**(n-3))
    //      < (2 + 1)*(2**n - 2**(n-2) - 2**(n-3))
    //      < 2*(2**n - 2**(n-2) - 2**(n-3)) + 2**n - 2**(n-2) - 2**(n-3)
    //      < 2**(n+1) - 2**(n-1) - 2**(n-2) + 2**n - 2**(n-2) - 2**(n-3)
    //      < 2**(n+1) + 2**n - 2**(n-1) - 2**(n-2) - 2**(n-2) - 2**(n-3)
    //      < 2**(n+1) + 2**n - 2**(n-1) - 2*(2**(n-2)) - 2**(n-3)
    //      < 2**(n+1) + 2**n - 2**(n-1) - 2**(n-1) - 2**(n-3)
    //      < 2**(n+1) + 2**n - 2*(2**(n-1)) - 2**(n-3)
    //      < 2**(n+1) + 2**n - 2**n - 2**(n-3)
    //      < 2**(n+1) - 2**(n-3)
    //
    // Then clearly 2**(n+1) - 2**(n-3) < 2**(n+1) since n is positive.
    //
    // This means that when `max` is of the form `0b100...`, we can generate a
    // value in the range [0, 2**(n+1)), which would fall into one of four
    // sub-intervals:
    //
    //    [0, max)          => Return the value as-is.
    //    [max, 2*max)      => Return `value - max`.
    //    [2*max, 3*max)    => Return `value - max - max`.
    //    [3*max, 2**(n+1)) => Generate a new random value and try again.
    //
    // This avoids biasing the result towards small values, which is what
    // reducing the random value (mod max) would do, while reducing the
    // probability that a new random value will be needed.
    //
    // Microbenchmarking suggests this can provide a ~33% speedup.
    reduce_when_over_bound: bool,

    // In order to carry about the `max == 0b100...` optimization described
    // above, we need to generate one random bit more than we want to keep.
    //
    // When the number of bits we want to keep is a multiple of LIMB_BITS,
    // that means we need to allocate space for an extra limb to store the
    // extra bit.
    extend_limbs_by_one: bool,
}

/// Decide implementation strategy for random sampling.
//
// We support a special case performance optimization for bounds of the form
// `0b100...` - see comment in `SamplingParams`.
//
// However, for simplicity, we only support this for the case when the number
// of bits in the bound (/ public key modulus) is a multiple of LIMB_BITS,
// or one less, which we expect to be the case in performance-sensitive
// applications, where, e.g., the 2048 or 2047-bit modulus will be the product
// of two 1024-bit integers.
fn select_sampling_params(max_exclusive: &[Limb]) -> SamplingParams {
    let most_sig = max_exclusive.last().unwrap();

    if most_sig >> (LIMB_BITS - 3) == 0b100 {
        SamplingParams {
            // This is effectively a carry into a new, more-significant limb.
            most_sig_limb_mask: 1,
            reduce_when_over_bound: true,
            extend_limbs_by_one: true,
        }
    } else if most_sig >> (LIMB_BITS - 4) == 0b0100 {
        SamplingParams {
            most_sig_limb_mask: Limb::max_value(),
            reduce_when_over_bound: true,
            extend_limbs_by_one: false,
        }
    } else {
        SamplingParams {
            most_sig_limb_mask: Limb::max_value() >> most_sig.leading_zeros(),
            reduce_when_over_bound: false,
            extend_limbs_by_one: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use {core, rand, test};
    use limb::*;

    #[test]
    fn test_select_sampling_params() {
        use super::select_sampling_params;

        let starting_with_0b100 = &[
            1 << (LIMB_BITS - 1),
            1 << (LIMB_BITS - 1) | 1,
            (1 << (LIMB_BITS - 1)) | (1 << LIMB_BITS - 4),
            (1 << (LIMB_BITS - 1)) | (Limb::max_value() >> 3),
        ];

        for l in starting_with_0b100 {
            for x in [
                &[*l][..],
                &[0, *l][..],
                &[Limb::max_value(), *l][..],
            ].iter() {
                let p = select_sampling_params(x);
                assert!(p.extend_limbs_by_one);
                assert!(p.reduce_when_over_bound);
                assert_eq!(1, p.most_sig_limb_mask);
            }
        }

        let starting_with_0b0100 = &[
            1 << (LIMB_BITS - 2),
            1 << (LIMB_BITS - 2) | 1,
            (1 << (LIMB_BITS - 2)) | (1 << LIMB_BITS - 5),
            (1 << (LIMB_BITS - 2)) | (Limb::max_value() >> 4),
        ];

        for l in starting_with_0b0100 {
            for x in [
                &[*l][..],
                &[0, *l][..],
                &[Limb::max_value(), *l][..],
            ].iter() {
                let p = select_sampling_params(x);
                assert!(!p.extend_limbs_by_one);
                assert!(p.reduce_when_over_bound);
                assert_eq!(Limb::max_value(), p.most_sig_limb_mask);
            }
        }

        macro_rules! assert_normal {
            ($i:expr, $l:expr) => {
                {
                    let x = [$l];
                    let p = select_sampling_params(&x[..]);
                    let mask = Limb::max_value() >> (LIMB_BITS - 1 - $i);
                    assert!(!p.extend_limbs_by_one);
                    assert!(!p.reduce_when_over_bound);
                    assert_eq!(mask, p.most_sig_limb_mask);
                }
            }
        }

        // Of `0b(0*)100` values, only the first two should send us into the
        // special-case optimization.
        for i in 0..(LIMB_BITS - 2) {
            let l = 1 << i;

            assert_normal!(i, l);
        }

        // `0b11` and `0b101` values should never send us into the `0b100`
        // case.
        for i in 0..LIMB_BITS {
            let l = 1 << i;

            assert_normal!(i, l | l >> 1);
            assert_normal!(i, l | l >> 2);
        }
    }

    #[test]
    fn test_limbs_in_range() {
        use super::{SamplingParams,Range};

        let params = SamplingParams {
            most_sig_limb_mask: Limb::max_value(),
            reduce_when_over_bound: false,
            extend_limbs_by_one: false,
        };

        let limbs = &[Limb::max_value(), Limb::max_value()];
        let range = Range { max_exclusive: limbs, sampling_params: &params };
        assert!(!range.are_limbs_within(&[Limb::max_value(),
                                          Limb::max_value()]));
        assert!(range.are_limbs_within(&[Limb::max_value(),
                                         Limb::max_value() - 1]));
        assert!(range.are_limbs_within(&[Limb::max_value() - 1,
                                         Limb::max_value()]));
        assert!(!range.are_limbs_within(&[0, 0]));
        assert!(range.are_limbs_within(&[1, 0]));
        assert!(range.are_limbs_within(&[0, 1]));

        let limbs = &[0x12345678, 0xdeadbeef];
        let range = Range { max_exclusive: limbs, sampling_params: &params };
        assert!(!range.are_limbs_within(&[0x12345678, 0xdeadbeef]));
        assert!(range.are_limbs_within(&[0x12345678 - 1, 0xdeadbeef]));
        assert!(range.are_limbs_within(&[0x12345678, 0xdeadbeef - 1]));
        assert!(!range.are_limbs_within(&[0x12345678 + 0x10, 0xdeadbeef]));
        assert!(!range.are_limbs_within(&[0x12345678, 0xdeadbeef + 0x10]));

        let limbs = &[0, 1];
        let range = Range { max_exclusive: limbs, sampling_params: &params };
        assert!(!range.are_limbs_within(&[0, 0]));
        assert!(range.are_limbs_within(&[1, 0]));
        assert!(!range.are_limbs_within(&[0, 1]));
        assert!(range.are_limbs_within(&[Limb::max_value(), 0]));

        let limbs = &[2];
        let range = Range { max_exclusive: limbs, sampling_params: &params };
        assert!(!range.are_limbs_within(&[0]));
        assert!(range.are_limbs_within(&[1]));
        assert!(!range.are_limbs_within(&[2]));
    }

    #[test]
    fn test_set_to_rand_mod() {
        use super::set_to_rand_mod;

        let rng = rand::SystemRandom::new();

        macro_rules! generate_and_assert_success {
            ($limbs:expr, $num_limbs:expr) => { {
                let limbs: [Limb; $num_limbs] = $limbs;
                let mut out: [Limb; $num_limbs] = [0; $num_limbs];
                assert!(set_to_rand_mod(&mut out, &limbs, &rng).is_ok());
                assert!(out.iter().any( |b| *b > 0 ));
                out
            } }
        };

        let _ = generate_and_assert_success!([0xdeadbeef, 0xdeadbeef], 2);

        let out = generate_and_assert_success!([2], 1);
        assert_eq!([1], out);

        let _ = generate_and_assert_success!([1 << (LIMB_BITS - 1)], 1);
        let _ = generate_and_assert_success!([Limb::max_value()], 1);

        let out = generate_and_assert_success!([0, 1], 2);
        assert_eq!(0, out[1]);

        let _ = generate_and_assert_success!([1, 1], 2);
        let _ = generate_and_assert_success!([1 << (LIMB_BITS - 1), 1], 2);
        let _ = generate_and_assert_success!([Limb::max_value(), 1], 2);
        let _ = generate_and_assert_success!([0, 1 << (LIMB_BITS - 1)], 2);
        let _ = generate_and_assert_success!([1, 1 << (LIMB_BITS - 1)], 2);
        let _ = generate_and_assert_success!(
                    [1 << (LIMB_BITS - 1), 1 << (LIMB_BITS - 1)], 2);
        let _ = generate_and_assert_success!(
                    [Limb::max_value(), 1 << (LIMB_BITS - 1)], 2);
        let _ = generate_and_assert_success!([0, Limb::max_value()], 2);
        let _ = generate_and_assert_success!([1, Limb::max_value()], 2);
        let _ = generate_and_assert_success!(
                    [1 << (LIMB_BITS - 1), Limb::max_value()], 2);
        let _ = generate_and_assert_success!(
                    [Limb::max_value(), Limb::max_value()], 2);
    }

    #[test]
    fn test_random_generation_retries() {
        use super::{SamplingParams, Range};

        // Generates a string of bytes 0x00...00, which will always result in
        // a scalar value of zero.
        let random_00 = test::rand::FixedByteRandom { byte: 0x00 };

        // Generates a string of bytes 0xFF...FF, which will be larger than the
        // group order of any curve that is supported.
        let random_ff = test::rand::FixedByteRandom { byte: 0xff };

        let max_exclusive = [Limb::max_value(), Limb::max_value() >> 1];

        let sampling_params = SamplingParams {
            most_sig_limb_mask: Limb::max_value(),
            reduce_when_over_bound: false,
            extend_limbs_by_one: false,
        };

        let range = Range {
            max_exclusive: &max_exclusive,
            sampling_params: &sampling_params,
        };

        // Test that a generated zero is rejected and that `sample_into_limbs`
        // gives up after a while of only getting zeros.
        {
            let mut result = [0, 0];
            assert!(range.sample_into_limbs(&mut result, &random_00).is_err());
        }

        // Test that a generated value larger than `max_exclusive` is rejected
        // and that `sample_into_limbs` gives up after a while of only getting
        // values larger than the group order.
        {
            let mut result = [0, 0];
            assert!(range.sample_into_limbs(&mut result, &random_ff).is_err());
        }

        // Test that a generated value exactly equal `max_exclusive` is
        // rejected and that `generate` gives up after a while of only getting
        // that value from the PRNG.
        let max_exclusive_bytes = limbs_as_bytes(&max_exclusive);
        {
            let rng = test::rand::FixedSliceRandom {
                bytes: &max_exclusive_bytes
            };
            let mut result = [0, 0];
            assert!(range.sample_into_limbs(&mut result, &rng).is_err());
        }

        let max_exclusive_minus_1 = [max_exclusive[0] - 1, max_exclusive[1]];

        // Test that a generated value exactly equal to `mex_exclusive - 1` is
        // accepted.
        let max_exclusive_minus_1_bytes =
            limbs_as_bytes(&max_exclusive_minus_1);
        {
            let rng = test::rand::FixedSliceRandom {
                bytes: max_exclusive_minus_1_bytes
            };
            let mut result = [0, 0];
            range.sample_into_limbs(&mut result, &rng).unwrap();
            assert_eq!(&max_exclusive_minus_1, &result);
        }

        // Test recovery from initial RNG failure.
        {
            let bytes = [
                &max_exclusive_bytes[..],
                &[0u8; 2 * LIMB_BYTES],
                &max_exclusive_minus_1_bytes[..],
            ];
            let rng = test::rand::FixedSliceSequenceRandom {
                bytes: &bytes,
                current: core::cell::UnsafeCell::new(0),
            };
            let mut result = [0, 0];
            range.sample_into_limbs(&mut result, &rng).unwrap();
            assert_eq!(&max_exclusive_minus_1, &result);
        }
    }
}

#[cfg(feature = "internal_benches")]
mod bench {
    use {bench, rand, rsa};
    use limb::*;
    use super::{Range, SamplingParams};

    const MAX_LIMBS: usize = rsa::RSA_PUBLIC_KEY_MODULUS_MAX_LIMBS;

    // Baseline with which to compare the effect of the `0b100...` optimization
    #[bench]
    fn bench_sample_into_limbs_no_reduce(b: &mut bench::Bencher) {
        let mut out: [Limb; MAX_LIMBS] = [0; MAX_LIMBS];
        let rng = rand::SystemRandom::new();

        let params = SamplingParams {
            most_sig_limb_mask: Limb::max_value(),
            reduce_when_over_bound: false,
            extend_limbs_by_one: false,
        };
        let range = Range {
            max_exclusive: &max_sized_0b100_bound(),
            sampling_params: &params,
        };

        b.iter(|| {
            range.sample_into_limbs(&mut out, &rng)
        });
    }

    // Demonstrate that the `0b100` optimization is worth the added complexity
    #[bench]
    fn bench_sample_into_limbs_with_reduce(b: &mut bench::Bencher) {
        let mut out: [Limb; MAX_LIMBS] = [0; MAX_LIMBS];
        let rng = rand::SystemRandom::new();

        let params = SamplingParams {
            most_sig_limb_mask: Limb::max_value(),
            reduce_when_over_bound: true,
            extend_limbs_by_one: false,
        };
        let range = Range {
            max_exclusive: &max_sized_0b100_bound(),
            sampling_params: &params,
        };

        b.iter(|| {
            range.sample_into_limbs(&mut out, &rng)
        });
    }

    fn max_sized_0b100_bound() -> [Limb; MAX_LIMBS] {
        let mut max: [Limb; MAX_LIMBS] = [0; MAX_LIMBS];
        max[MAX_LIMBS - 1] = 1 << (LIMB_BITS - 1);
        assert_eq!(max[MAX_LIMBS - 1] >> (LIMB_BITS - 3), 0b100);
        max
    }
}
