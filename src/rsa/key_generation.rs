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

//! RSA key generation

use super::small_primes::SMALL_PRIMES;
use core::marker::PhantomData;
use std::vec::Vec;

use crate::{
    limb::{self, LimbMask},
    error, rand,
    rsa::bigint,
};

/// Performs the Miller-Rabin primality test
///
/// Implementation of the algorithm as it
/// is described in FIPS 186-4 C.3.1
fn miller_rabin_test(
    w: &[u64],
    iterations: u32,
    rng: &rand::SecureRandom,
) -> Result<bool, error::Unspecified> {
    // Step 1.
    let mut w_m1 = vec![0; w.len()];
    limb::limbs_sub_limb(&mut w_m1, w, 1);
    let a = limb::limbs_count_low_zero_bits(&w_m1);

    // Step 2.
    let mut m = vec![0; w_m1.len()];
    limb::limbs_copy(&mut m, &w_m1);
    limb::limbs_rshift(&mut m, a);

    // Step 3 not needed.

    // preparation
    let boxed_w = bigint::BoxedLimbs::<()>::minimal_width_from_unpadded(&w);
    let w_modulus = bigint::Modulus::from_boxed_limbs(boxed_w)?.0;
    let boxed_m = bigint::BoxedLimbs::<()>::minimal_width_from_unpadded(&m);
    let m_exponent = bigint::PrivateExponent {
        limbs: boxed_m,
    };
    // Step 4.
    let mut b: Vec<limb::Limb> = vec![0; w.len()];
    for _ in 0 .. iterations {
        loop {
            // Step 4.1
            unsafe {
                let b_mut_ptr = (&mut b[..]).as_mut_ptr() as * mut u8;
                let b_mut_slice = core::slice::from_raw_parts_mut(b_mut_ptr, b.len() * 8);
                rng.fill(b_mut_slice)?;
            }
            // Step 4.2
            if limb::limbs_less_than_limb_constant_time(&b, 2) == LimbMask::False
                    && limb::limbs_less_than_limbs_consttime(&b, &w_m1) == LimbMask::True
            {
                break;
            }
        }
        // Step 4.3
        let boxed_b = bigint::BoxedLimbs::minimal_width_from_unpadded(&b);
        let b_elem = bigint::Elem {
            limbs: boxed_b,
            encoding: PhantomData,
        };
        let mut z_elem = bigint::elem_exp_consttime(b_elem, &m_exponent, &w_modulus)?;
        // Step 4.4
        if z_elem.is_one() || limb::limbs_equal_limbs_consttime(&z_elem.limbs, &w_m1) == LimbMask::True {
            continue;
        }
        // Step 4.5
        for _ in 1 .. a {
            // Step 4.5.1
            // TODO figure out how to make this compile
            //z_elem = bigint::elem_squared(z_elem, &w_modulus.as_partial());
            // Step 4.5.2
            if limb::limbs_equal_limbs_consttime(&z_elem.limbs, &w_m1) == LimbMask::True {
                continue;
            }
            // Step 4.5.1
            if z_elem.is_one() {
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
    w: &[u64],
    iterations: u32,
    rng: &rand::SecureRandom,
) -> Result<bool, error::Unspecified> {

    // 1 and 0 are no primes.
    if limb::limbs_are_zero_constant_time(w) == LimbMask::True {
        return Ok(false);
    }
    if limb::limbs_equal_limb_constant_time(w, 1) == LimbMask::True {
        return Ok(false);
    }

    // Check whether we are divisible by small primes
    let divisble = SMALL_PRIMES.iter().find(|prime| limb::mod_u16_consttime(w, **prime) == 0);
    if let Some(prime) = divisble {
        return Ok(limb::limbs_equal_limb_constant_time(w, (*prime).into()) == LimbMask::True);
    }

    return miller_rabin_test(w, iterations, rng);
}

#[cfg(test)]
#[test]
fn check_probable_primes() {
    let rng = rand::SystemRandom::new();
    assert_eq!(probable_primality_test(&[0], 10, &rng), Ok(false));
    assert_eq!(probable_primality_test(&[1], 10, &rng), Ok(false));
    assert_eq!(probable_primality_test(&[2], 10, &rng), Ok(true));
    assert_eq!(probable_primality_test(&[3], 10, &rng), Ok(true));
    assert_eq!(probable_primality_test(&[4], 10, &rng), Ok(false));
    assert_eq!(probable_primality_test(&[5], 10, &rng), Ok(true));
    assert_eq!(probable_primality_test(&[6], 10, &rng), Ok(false));
    assert_eq!(probable_primality_test(&[7], 10, &rng), Ok(true));
    assert_eq!(probable_primality_test(&[8], 10, &rng), Ok(false));
    assert_eq!(probable_primality_test(&[9], 10, &rng), Ok(false));
    assert_eq!(probable_primality_test(&[10], 10, &rng), Ok(false));
    assert_eq!(probable_primality_test(&[11], 10, &rng), Ok(true));
    assert_eq!(probable_primality_test(&[12], 10, &rng), Ok(false));
}
