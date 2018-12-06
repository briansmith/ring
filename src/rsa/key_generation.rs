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

use crate::{
    limb::{self, LimbMask},
    error, //rand,
};

/// Performs the Miller-Rabin primality test
///
/// Implementation of the algorithm as it
/// is described in FIPS 186-4 C.3.1
fn miller_rabin_test(
    _w: &[u64],
    _iterations: u32,
    //rng: &rand::SecureRandom,
) -> Result<bool, error::Unspecified> {
    // TODO
    unimplemented!()
}

/// Checks whether a given number is prime
///
/// The test used is the Miller-Rabin primality test together
/// with prior checking for divisibility by small primes
pub fn probable_primality_test(
    w: &[u64],
    iterations: u32,
    //rng: &rand::SecureRandom,
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

    return miller_rabin_test(w, iterations);
}

#[test]
fn check_probable_primes() {
    assert_eq!(probable_primality_test(&[0], 10), Ok(false));
    assert_eq!(probable_primality_test(&[1], 10), Ok(false));
    assert_eq!(probable_primality_test(&[2], 10), Ok(true));
    assert_eq!(probable_primality_test(&[3], 10), Ok(true));
    assert_eq!(probable_primality_test(&[4], 10), Ok(false));
    assert_eq!(probable_primality_test(&[5], 10), Ok(true));
    assert_eq!(probable_primality_test(&[6], 10), Ok(false));
    assert_eq!(probable_primality_test(&[7], 10), Ok(true));
    assert_eq!(probable_primality_test(&[8], 10), Ok(false));
    assert_eq!(probable_primality_test(&[9], 10), Ok(false));
    assert_eq!(probable_primality_test(&[10], 10), Ok(false));
    assert_eq!(probable_primality_test(&[11], 10), Ok(true));
    assert_eq!(probable_primality_test(&[12], 10), Ok(false));
}
