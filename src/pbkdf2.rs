// Copyright 2015 Brian Smith.
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

//! PBKDF2 derivation and verification.
//!
//! Use `derive` to derive PBKDF2 outputs. Use `verify` to verify secret
//! against previously-derived outputs.
//!
//! PBKDF2 is specified in [RFC 2898 Section 5.2] with test vectors given in
//! [RFC 6070]. See also [NIST Special Publication 800-132].
//!
//! [RFC 2898 Section 5.2]: https://tools.ietf.org/html/rfc2898#section-5.2
//! [RFC 6070]: https://tools.ietf.org/html/rfc6070
//! [NIST Special Publication 800-132]:
//!    http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf
//!
//! # Examples
//!
//! ## Password Database Example
//!
//! ```
//! use ring::pbkdf2;
//! use std::collections::HashMap;
//!
//! static PBKDF2_PRF: &'static pbkdf2::PRF = &pbkdf2::HMAC_SHA256;
//! const CREDENTIAL_LEN: usize = 32; // digest::SHA256.output_len()
//! pub type Credential = [u8; CREDENTIAL_LEN];
//!
//! enum Error {
//!     WrongUsernameOrPassword
//! }
//!
//! struct PasswordDatabase {
//!     pbkdf2_iterations: usize,
//!     db_salt_component: [u8; 16],
//!
//!     // Normally this would be a persistent database.
//!     storage: HashMap<String, Credential>,
//! }
//!
//! impl PasswordDatabase {
//!     pub fn store_password(&mut self, username: &str, password: &str) {
//!         let salt = self.salt(username);
//!         let mut to_store: Credential = [0u8; CREDENTIAL_LEN];
//!         pbkdf2::derive(PBKDF2_PRF, self.pbkdf2_iterations, &salt,
//!                        password.as_bytes(), &mut to_store);
//!         self.storage.insert(String::from(username), to_store);
//!     }
//!
//!     pub fn verify_password(&self, username: &str, attempted_password: &str)
//!                            -> Result<(), Error> {
//!         match self.storage.get(username) {
//!            Some(actual_password) => {
//!                let salt = self.salt(username);
//!                pbkdf2::verify(PBKDF2_PRF, self.pbkdf2_iterations, &salt,
//!                               attempted_password.as_bytes(),
//!                               actual_password)
//!                     .map_err(|_| Error::WrongUsernameOrPassword)
//!            },
//!
//!            None => Err(Error::WrongUsernameOrPassword)
//!         }
//!     }
//!
//!     // The salt should have a user-specific component so that an attacker
//!     // cannot crack one password for multiple users in the database. It
//!     // should have a database-unique component so that an attacker cannot
//!     // crack the same user's password across databases in the unfortunate
//!     // but common case that the user has used the same password for
//!     // multiple systems.
//!     fn salt(&self, username: &str) -> Vec<u8> {
//!         let mut salt = Vec::with_capacity(self.db_salt_component.len() +
//!                                           username.as_bytes().len());
//!         salt.extend(self.db_salt_component.as_ref());
//!         salt.extend(username.as_bytes());
//!         salt
//!     }
//! }
//!
//! fn main() {
//!     // Normally these parameters would be loaded from a configuration file.
//!     let mut db = PasswordDatabase {
//!         pbkdf2_iterations: 100_000,
//!         db_salt_component: [
//!             // This value was generated from a secure PRNG.
//!             0xd6, 0x26, 0x98, 0xda, 0xf4, 0xdc, 0x50, 0x52,
//!             0x24, 0xf2, 0x27, 0xd1, 0xfe, 0x39, 0x01, 0x8a
//!         ],
//!         storage: HashMap::new(),
//!     };
//!
//!     db.store_password("alice", "@74d7]404j|W}6u");
//!
//!     // An attempt to log in with the wrong password fails.
//!     assert!(db.verify_password("alice", "wrong password").is_err());
//!
//!     // Normally there should be an expoentially-increasing delay between
//!     // attempts to further protect against online attacks.
//!
//!     // An attempt to log in with the right password succeeds.
//!     assert!(db.verify_password("alice", "@74d7]404j|W}6u").is_ok());
//! }

use {constant_time, digest, error, hmac, polyfill};

/// Fills `out` with the key derived using PBKDF2 with the given inputs.
///
/// Do not use `derive` as part of verifying a secret; use `verify` instead, to
/// minimize the effectiveness of timing attacks.
///
/// `out.len()` must be no larger than the output length of the digest function
/// used in the PRF algorithm * (2**32 - 1), per the PBKDF2 specification.
///
/// | Parameter   | RFC 2898 Section 5.2 Term
/// |-------------|---------------------------------------
/// | prf         | PRF
/// | iterations  | c (iteration count)
/// | salt        | S (salt)
/// | secret      | P (password)
/// | out         | dk (derived key)
/// | out.len()   | dkLen (derived key length)
///
/// C analog: `PKCS5_PBKDF2_HMAC`
///
/// # Panics
///
/// `derive` panics if `iterations < 1`.
///
/// `derive` panics if `out.len()` is larger than (2**32 - 1) * the PRF digest
/// length, per the PBKDF2 specification.
pub fn derive(prf: &'static PRF, iterations: usize, salt: &[u8], secret: &[u8],
              out: &mut [u8]) {
    assert!(iterations >= 1);

    let output_len = prf.digest_alg.output_len;

    // This implementation's performance is asymptotically optimal as described
    // in https://jbp.io/2015/08/11/pbkdf2-performance-matters/. However, it
    // hasn't been optimized to the same extent as fastpbkdf2. In particular,
    // this implementation is probably doing a lot of unnecessary copying.

    let secret = hmac::SigningKey::new(prf.digest_alg, secret);

    // Clear |out|.
    polyfill::slice::fill(out, 0);

    let mut idx: u32 = 0;

    for chunk in out.chunks_mut(output_len) {
        idx = idx.checked_add(1).expect("derived key too long");
        derive_block(&secret, iterations, salt, idx, chunk);
    }
}

fn derive_block(
        secret: &hmac::SigningKey,
        iterations: usize,
        salt: &[u8],
        idx: u32,
        out: &mut [u8]) {
    let mut ctx = hmac::SigningContext::with_key(&secret);
    ctx.update(salt);
    ctx.update(&polyfill::slice::be_u8_from_u32(idx));

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
/// The comparison is done in constant time to prevent timing attacks. The
/// comparison will fail if `previously_derived` is empty (has a length of
/// zero).
///
/// | Parameter                | RFC 2898 Section 5.2 Term
/// |--------------------------|---------------------------------------
/// | prf                      | PRF
/// | iterations               | c (iteration count)
/// | salt                     | S (salt)
/// | secret                   | P (password)
/// | previously_derived       | dk (derived key)
/// | previously_derived.len() | dkLen (derived key length)
///
/// C analog: `PKCS5_PBKDF2_HMAC` + `CRYPTO_memcmp`
///
/// # Panics
///
/// `verify` panics if `iterations < 1`.
///
/// `derive` panics if `out.len()` is larger than (2**32 - 1) * the PRF digest
/// length, per the PBKDF2 specification.
pub fn verify(prf: &'static PRF, iterations: usize, salt: &[u8], secret: &[u8],
              previously_derived: &[u8]) -> Result<(), error::Unspecified> {
    if previously_derived.len() == 0 {
        return Err(error::Unspecified);
    }

    let mut derived_buf = [0u8; digest::MAX_OUTPUT_LEN];

    let output_len = prf.digest_alg.output_len;
    let secret = hmac::SigningKey::new(prf.digest_alg, secret);
    let mut idx: u32 = 0;

    let mut matches = 1;

    for previously_derived_chunk in previously_derived.chunks(output_len) {
        idx = idx.checked_add(1).expect("derived key too long");

        let derived_chunk = &mut derived_buf[..previously_derived_chunk.len()];
        polyfill::slice::fill(derived_chunk, 0);

        derive_block(&secret, iterations, salt, idx, derived_chunk);

        // XXX: This isn't fully constant-time-safe. TODO: Fix that.
        let current_block_matches =
            if constant_time::verify_slices_are_equal(
                    derived_chunk, previously_derived_chunk).is_ok() {
                1
            } else {
                0
            };

        matches = matches & current_block_matches;
    }

    if matches == 0 {
        return Err(error::Unspecified);
    }

    Ok(())
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

#[cfg(test)]
mod tests {
    use {error, pbkdf2, test};

    #[test]
    pub fn pkbdf2_tests() {
        test::from_file("src/pbkdf2_tests.txt", |section, test_case| {
            assert_eq!(section, "");
            let prf_digest_alg = &test_case.consume_string("Hash");
            let prf = match prf_digest_alg.as_ref() {
                "SHA256" => &pbkdf2::HMAC_SHA256,
                "SHA512" => &pbkdf2::HMAC_SHA512,
                _ => panic!("Unexpected digest algorithm in PBKDF2 test"),
            };
            let iterations = test_case.consume_usize("c");
            let secret = test_case.consume_bytes("P");
            let salt = test_case.consume_bytes("S");
            let dk = test_case.consume_bytes("DK");
            let verify_expected_result = test_case.consume_string("Verify");
            let verify_expected_result = match verify_expected_result.as_str() {
                "OK" => Ok(()),
                "Err" => Err(error::Unspecified),
                _ => panic!("Unsupported value of \"Verify\"")
            };

            {
                let mut out = vec![0u8; dk.len()];
                pbkdf2::derive(prf, iterations, &salt, &secret, &mut out);
                assert_eq!(dk == out,
                           verify_expected_result.is_ok() || dk.len() == 0);
            }

            assert_eq!(pbkdf2::verify(prf, iterations, &salt, &secret, &dk),
                       verify_expected_result);

            Ok(())
        });
    }
}
