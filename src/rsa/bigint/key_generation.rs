// Copyright 2018 est31 <MTest31@outlook.com>
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

//! RSA key generation

use crate::rsa::small_primes::SMALL_PRIMES;
use core::marker::PhantomData;

use crate::{
    error, rand,
    rsa::bigint,
    limb::LIMB_BITS,
};

/// Performs the Miller-Rabin primality test
///
/// Implementation of the algorithm as it
/// is described in FIPS 186-4 C.3.1
fn miller_rabin_test(
    w: &bigint::Nonnegative,
    iterations: u32,
    rng: &rand::SecureRandom,
) -> Result<bool, error::Unspecified> {
    // Step 1.
    let w_m1 = w.odd_sub_one();
    let a = w.trailing_zeros();

    // Step 2.
    let m = w.shift_right(a);

    // Step 3 not needed.

    // preparation
    let w_modulus = bigint::Modulus::from_nonnegative_with_bit_length(w.clone())?.0;
    let boxed_m = bigint::BoxedLimbs::<()>::minimal_width_from_unpadded(&m.limbs);
    let m_exponent = bigint::PrivateExponent {
        limbs: boxed_m,
    };
    let two = bigint::Nonnegative::from_u32(2);
    let w_m1_elem = w_m1.to_elem(&w_modulus)?;
    let w_m1_elem_rr = bigint::elem_mul(w_modulus.oneRR().as_ref(), w_m1_elem, &w_modulus);
    let one_elem = bigint::Nonnegative::from_u32(1).to_elem(&w_modulus)?;
    let one_r = bigint::elem_mul(w_modulus.oneRR().as_ref(), one_elem, &w_modulus);

    // Step 4.
    for _ in 0 .. iterations {
        let mut b;
        loop {
            // Step 4.1
            b = bigint::Nonnegative::random(rng, w.limbs.len())?;
            // Step 4.2
            if bigint::greater_than(&b, &two) && bigint::greater_than(&w_m1, &b) {
                break;
            }
        }
        // Step 4.3
        // TODO: figure out hot to get this work
        //let b_elem = b.to_elem(&w_modulus)?;
        let boxed_b = bigint::BoxedLimbs::minimal_width_from_unpadded(&b.limbs);
        let b_elem = bigint::Elem {
            limbs: boxed_b,
            encoding: PhantomData,
        };
        let z_elem_u = bigint::elem_exp_consttime(b_elem, &m_exponent, &w_modulus)? ;
        let mut z_elem = bigint::elem_mul(w_modulus.oneRR().as_ref(), z_elem_u, &w_modulus);

        // Step 4.4
        let is_one = bigint::elem_verify_equal_consttime(&z_elem, &one_r).is_ok();
        let is_m1 = bigint::elem_verify_equal_consttime(&z_elem, &w_m1_elem_rr).is_ok();
        if is_one || is_m1 {
            continue;
        }
        // Step 4.5
        for _ in 1 .. a {
            // Step 4.5.1
            z_elem = bigint::elem_squared(z_elem, &w_modulus.as_partial());
            // Step 4.5.2
            if bigint::elem_verify_equal_consttime(&z_elem, &w_m1_elem_rr).is_ok() {
                continue;
            }
            // Step 4.5.1
            if bigint::elem_verify_equal_consttime(&z_elem, &one_r).is_ok() {
                return Ok(false);
            }
        }
    }

    // Step 5.
    return Ok(true);
}

/// Checks whether a given number is prime
///
/// The test used is the Miller-Rabin primality test together
/// with prior checking for divisibility by small primes
pub fn probable_primality_test(
    w: &bigint::Nonnegative,
    iterations: u32,
    rng: &rand::SecureRandom,
) -> Result<bool, error::Unspecified> {

    // 1 and 0 are no primes.
    if w.is_zero() || w.equal_to_u32(1) {
        return Ok(false);
    }

    // Check whether we are divisible by small primes
    let divisble = SMALL_PRIMES.iter().find(|prime| w.mod_u16_consttime(**prime) == 0);
    if let Some(prime) = divisble {
        return Ok(w.equal_to_u32((*prime).into()));
    }

    return miller_rabin_test(w, iterations, rng);
}

/// Returns the number of M-R iterations for a given bit count
///
/// Uses values inside FIPS 186-4 Table C.3 plus 1.
#[inline]
fn mr_iterations_for_bit_count(bit_count: u32) -> Result<u32, error::Unspecified> {
    match bit_count {
        1024 => Ok(6),
        1536 => Ok(5),
        // Unsupported bit count
        _ => Err(error::Unspecified),
    }
}

/// Generate (p,q) prime pair
///
/// Implementation of FIPS 186-4 section B.3.3
///
/// We imply e = 65537.
pub fn generate_pq(
    nlen: u32,
    rng: &rand::SecureRandom,
) -> Result<(bigint::Nonnegative, bigint::Nonnegative), error::Unspecified> {
    // Step 1.
    if nlen != 2048 && nlen != 3072 {
        return Err(error::Unspecified);
    }
    // Step 2 not needed.
    //let e = 65537;
    let iterations = mr_iterations_for_bit_count(nlen / 2)?;
    let limb_count = (nlen / 2) as usize / LIMB_BITS;
    // Step 3 not needed.
    // Step 4.
    // Step 4.1
    let mut i = 0;
    let mut p;
    loop {
        // Step 4.2
        p = bigint::Nonnegative::random(rng, limb_count)?;
        // Step 4.3
        if !p.is_odd() {
            p = p.even_add_one();
        }
        // Step 4.4
        // TODO
        // Step 4.5
        // TODO this doesn't work, as e == u16_max + 2
        // We could use bn_is_relatively_prime here though.
        //if p.odd_sub_one().mod_u16_consttime(e) != 0 {
        if true {
            // Step 4.5.1
            if probable_primality_test(&p, iterations, rng)? {
                // Step 4.5.2
                break;
            }
        }
        // Step 4.6
        i += 1;
        // Step 4.7
        if i >= 5 * (nlen / 2) {
            return Err(error::Unspecified);
        }
    }
    // Step 5.
    // Step 5.1
    let mut i = 0;
    loop {
        // Step 5.2
        let mut q = bigint::Nonnegative::random(rng, limb_count)?;
        // Step 5.3
        if !q.is_odd() {
            q = q.even_add_one();
        }
        // Step 5.4
        // TODO
        // Step 5.5
        // TODO
        // Step 5.6
        // TODO this doesn't work, as e == u16_max + 2
        // We could use bn_is_relatively_prime here though.
        //if q.odd_sub_one().mod_u16_consttime(e) != 0 {
        if true {
            // Step 5.6.1
            if probable_primality_test(&q, iterations, rng)? {
                // Step 5.6.2
                return Ok((p, q));
            }
        }
        // Step 5.7
        i += 1;
        // Step 5.8
        if i >= 5 * (nlen / 2) {
            return Err(error::Unspecified);
        }
    }

    // Unreachable location.
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::tests::*;
    use crate::test;

    #[test]
    fn check_probable_primes_small() {
        fn ptest(v: u32) -> Result<bool, error::Unspecified> {
            let rng = rand::SystemRandom::new();
            probable_primality_test(&bigint::Nonnegative::from_u32(v), 10, &rng)
        }
        assert_eq!(ptest(0), Ok(false));
        assert_eq!(ptest(1), Ok(false));
        assert_eq!(ptest(2), Ok(true));
        assert_eq!(ptest(3), Ok(true));
        assert_eq!(ptest(4), Ok(false));
        assert_eq!(ptest(5), Ok(true));
        assert_eq!(ptest(6), Ok(false));
        assert_eq!(ptest(7), Ok(true));
        assert_eq!(ptest(8), Ok(false));
        assert_eq!(ptest(9), Ok(false));
        assert_eq!(ptest(10), Ok(false));
        assert_eq!(ptest(11), Ok(true));
        assert_eq!(ptest(12), Ok(false));
        assert_eq!(ptest(13), Ok(true));
        assert_eq!(ptest(14), Ok(false));
        assert_eq!(ptest(15), Ok(false));
    }

    #[test]
    fn check_probable_primes_big() {
        test::from_file(
            "src/rsa/bigint/primes_tests.txt",
            |section, test_case| {
                assert_eq!(section, "");

                let is_prime = test_case.consume_bool("Prime");
                let n = consume_nonnegative(test_case, "N");
                let rng = rand::SystemRandom::new();
                assert_eq!(probable_primality_test(&n, 10, &rng).unwrap(), is_prime);

                Ok(())
            },
        )
    }
}
