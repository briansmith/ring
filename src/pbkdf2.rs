// Copyright 2015 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

//! PBKDF2 derivation and verification.
//!
//! Use `derive` to derive PBKDF2 outputs. Use `verify` to verify secret
//! against previously-derived outputs.
//!
//! PBKDF2 is specified in
//! [RFC 2898 Section 5.2](https://tools.ietf.org/html/rfc2898#section-5.2)
//! with test vectors given in [RFC 6070](https://tools.ietf.org/html/rfc6070).
//! See also [NIST Special Publication
//! 800-132](http://csrc.nist.gov/publications/nistpubs/800-132/nist-sp800-132.pdf).

use super::{digest, ffi, hmac};

/// Fills `out` with the key derived using PBKDF2 with the given inputs,
/// using HMAC with the given digest algorithm as the PRF.
///
/// Do not use `derive` as part of verifying a secret; use `verify` instead, to
/// minimize the effectiveness of timing attacks.
///
/// `out.len()` must be no larger than the output length of the digest function
/// used in the PRF algorithm. This limit is more strict than what the
/// specification requires. As noted at https://github.com/ctz/fastpbkdf2,
/// "PBKDF2 is mis-designed and you should avoid asking for more than your hash
/// function's output length."
///
/// | Parameter   | RFC 2898 Section 5.2 Term
/// |-------------|---------------------------------------
/// | prf         | PRF
/// | secret      | P (password)
/// | salt        | S (salt)
/// | iterations  | c (iteration count)
/// | out         | dk (derived key)
/// | out.len()   | dkLen (derived key length)
///
/// C analog: `PKCS5_PBKDF2_HMAC`
///
/// # Panics
///
/// `derive` panics if `iterations < 1`.
///
/// `derive` panics if `out.len()` is larger than the output length of the
/// digest function used by the PRF algorithm.
pub fn derive(prf: &'static PRF, iterations: usize, secret: &[u8], salt: &[u8],
              out: &mut [u8]) {
    assert!(iterations >= 1);
    assert!(out.len() <= prf.digest_alg.digest_len);

    // This implementation's performance is asymptotically optimal as described
    // in https://jbp.io/2015/08/11/pbkdf2-performance-matters/. However, it
    // hasn't been optimized to the same extent as fastpbkdf2. In particular,
    // this implementation is probably doing a lot of unnecessary copying.

    let secret = hmac::SigningKey::new(prf.digest_alg, secret);

    // Clear |out|.
    for i in 0..out.len() {
        out[i] = 0;
    }

    let mut ctx = hmac::SigningContext::with_key(&secret);
    ctx.update(salt);
    ctx.update(&[0, 0, 0, 1]);
    let mut u = ctx.sign();

    let mut remaining = iterations;
    loop {
        for i in 0..out.len() {
            out[i] ^= u.as_ref()[i];
        }

        if remaining == 1 {
            break;
        }
        remaining -= 1;

        u = hmac::sign(&secret, u.as_ref());
    }
}

/// Verifies that a previously-derived (e.g., using `derive`) PBKDF2 value
/// matches the PBKDF2 value derived from the other inputs.
///
/// The comparison is done in constant time to prevent timing attacks.
///
/// | Parameter                | RFC 2898 Section 5.2 Term
/// |--------------------------|---------------------------------------
/// | prf                      | PRF
/// | secret                   | P (password)
/// | salt                     | S (salt)
/// | iterations               | c (iteration count)
/// | previously_derived       | dk (derived key)
/// | previously_derived.len() | dkLen (derived key length)
///
/// C analog: `PKCS5_PBKDF2_HMAC` + `CRYPTO_memcmp`
///
/// # Panics
///
/// `verify` panics if `iterations < 1`.
///
/// `verify` panics if `out.len()` is larger than the output length of the
/// digest function used by the PRF algorithm.
pub fn verify(prf: &'static PRF, iterations: usize, secret: &[u8], salt: &[u8],
              previously_derived: &[u8]) -> Result<(), ()> {
    let mut derived_buf = [0u8; digest::MAX_DIGEST_LEN];
    if previously_derived.len() > derived_buf.len() {
        return Err(());
    }
    let derived = &mut derived_buf[0..previously_derived.len()];
    derive(prf, iterations, secret, salt, derived);
    ffi::verify_slices_are_equal_ct(derived, previously_derived)
}

/// A PRF algorithm for use with `derive` and `verify`.
pub struct PRF {
    digest_alg: &'static digest::Algorithm,
}

/// HMAC-SHA256.
pub static HMAC_SHA256: PRF  = PRF {
    digest_alg: &digest::SHA256,
};

/// HMAC-SHA512.
pub static HMAC_SHA512: PRF  = PRF {
    digest_alg: &digest::SHA512,
};

/// HMAC-SHA1. *Deprecated*.
///
/// SHA-1 is deprecated in *ring* and its implementation in *ring* will be more
/// optimized more for size than for speed on some platforms. Since PBKDF2
/// requires an implementation highly optimized for speed, the size-for-speed
/// trade-off does not work well for PBKDF2.
///
pub static HMAC_SHA1: PRF = PRF {
    digest_alg: &digest::SHA1,
};

#[cfg(test)]
mod tests {
    use super::super::{digest, file_test, pbkdf2};

    #[test]
    pub fn pkbdf2_tests() {
        fn test_case(test_case: &mut file_test::TestCase) {
            let digest_alg = test_case.consume_digest_alg("Hash").unwrap();
            let iterations = test_case.consume_usize("c");
            let secret = test_case.consume_bytes("P");
            let salt = test_case.consume_bytes("S");
            let dk = test_case.consume_bytes("DK");

            let prf = if digest_alg.nid == digest::SHA1.nid {
                &pbkdf2::HMAC_SHA1
            } else if digest_alg.nid == digest::SHA256.nid {
                &pbkdf2::HMAC_SHA256
            } else if digest_alg.nid == digest::SHA512.nid {
                &pbkdf2::HMAC_SHA512
            } else {
                unimplemented!();
            };

            let mut out = vec![0u8; dk.len()];
            pbkdf2::derive(prf, iterations, &secret, &salt, &mut out);
            assert_eq!(dk, out);
            assert!(pbkdf2::verify(prf, iterations, &secret, &salt,&out).is_ok());
        }

        file_test::run("src/pbkdf2_tests.txt", test_case);
    }
}
