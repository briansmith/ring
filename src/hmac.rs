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

//! HMAC is specified in [RFC 2104](https://tools.ietf.org/html/rfc2104).
//!
//! Although HMAC keys are symmetric, a given peer in a multi-peer
//! communication should usually only use a key for either authenticating a
//! peer's messages or for signing its own messages, but usually not both. To
//! better facilitate the use of separate keys for signing and verification,
//! the API is split into groups: `SigningKey`, `SigningContext`, and `sign`;
//! and `VerificationKey` and `verify`. When HMAC is being used for a purpose
//! other than signing & authenticating messages, such as when implementing
//! HMAC-based PRFs, the signing operations should be used.
//!
//! Usually an HMAC key is used for multiple signing operations or multiple
//! verification operations. After a `SigningKey` or `VerificationKey` is
//! constructed, it can be used for multiple signing or verification operations.
//! Separating the construction of the key from the rest of the HMAC operation
//! allows the per-key precomputation to be done only once, instead of it being
//! done in every HMAC operation.
//!
//! Frequently all the data to be signed in a message is available in a single
//! contiguous piece. In that case, the module-level `sign` function can be
//! used. Otherwise, if the input is in multiple parts, `SigningContext` should
//! be used.
//!
//! The `verify` function should be used for verifying HMAC signatures.
//! `verify` compares the computed HMAC signature to the expected HMAC
//! signature in constant time to prevent timing attacks. There is no
//! multi-step "`VerificationContext`" interface. Such a streaming interface
//! would be dangerous as generally one must verify the HMAC signature of the
//! entire input before processing any part of the input.
//!
//! # Examples:
//!
//! ## Using the one-shot API:
//!
//! ```
//! use ring::{digest, hmac, rand};
//!
//! # fn main_with_result() -> Result<(), ()> {
//! let msg = "hello, world";
//!
//! let mut key_value = [0u8; 32];
//! try!(rand::fill_secure_random(&mut key_value));
//!
//! let s_key = hmac::SigningKey::new(&digest::SHA256, key_value.as_ref());
//! let signature = hmac::sign(&s_key, msg.as_bytes());
//!
//! let v_key = hmac::VerificationKey::new(&digest::SHA256, key_value.as_ref());
//! try!(hmac::verify(&v_key, msg.as_bytes(), signature.as_ref()));
//! #
//! # Ok(())
//! # }
//! #
//! # fn main() { main_with_result().unwrap() }
//! ```
//!
//! ## Using the multi-part API:
//! ```
//! use ring::{digest, hmac, rand};
//!
//! # fn main_with_result() -> Result<(), ()> {
//! let parts = ["hello", ", ", "world"];
//!
//! let mut key_value = [0u8; 48];
//! try!(rand::fill_secure_random(&mut key_value));
//!
//! let s_key = hmac::SigningKey::new(&digest::SHA384, key_value.as_ref());
//! let mut s_ctx = hmac::SigningContext::with_key(&s_key);
//! for part in &parts {
//!     s_ctx.update(part.as_bytes());
//! }
//! let signature = s_ctx.sign();
//!
//! let v_key = hmac::VerificationKey::new(&digest::SHA384, key_value.as_ref());
//! let mut msg = Vec::<u8>::new();
//! for part in &parts {
//!     msg.extend(part.as_bytes());
//! }
//! try!(hmac::verify(&v_key, &msg.as_ref(), signature.as_ref()));
//! #
//! # Ok(())
//! # }
//! #
//! # fn main() { main_with_result().unwrap() }
//! ```

use super::{constant_time, digest};

/// A key to use for HMAC signing.
pub struct SigningKey {
    ctx_prototype: SigningContext,
}

impl SigningKey {
    /// Construct an HMAC signing key using the given digest algorithm and key
    /// value.
    ///
    /// As specified in RFC 2104, if `key_value` is shorter than the digest
    /// algorithm's block length (as returned by `digest::Algorithm::block_len`,
    /// not the digest length returned by `digest::Algorithm::digest_len`) then
    /// it will be padded with zeros. Similarly, if it is longer than the block
    /// length then it will be compressed using the digest algorithm.
    pub fn new(digest_alg: &'static digest::Algorithm, key_value: &[u8])
               -> SigningKey {
        let mut key = SigningKey {
            ctx_prototype: SigningContext {
                inner: digest::Context::new(digest_alg),
                outer: digest::Context::new(digest_alg)
            },
        };

        let key_hash;
        let key_value = if key_value.len() <= digest_alg.block_len {
            key_value
        } else {
            key_hash = digest::digest(digest_alg, key_value);
            key_hash.as_ref()
        };

        const IPAD: u8 = 0x36;
        const OPAD: u8 = 0x5C;

        for b in key_value {
            key.ctx_prototype.inner.update(&[IPAD ^ b]);
            key.ctx_prototype.outer.update(&[OPAD ^ b]);
        }

        // If the key is shorter than one block then act as though the key is
        // padded with zeros.
        for _ in key_value.len()..digest_alg.block_len {
            key.ctx_prototype.inner.update(&[IPAD]);
            key.ctx_prototype.outer.update(&[OPAD]);
        }

        key
    }

    pub fn digest_algorithm(&self) -> &'static digest::Algorithm {
        self.ctx_prototype.inner.algorithm()
    }
}

/// A context for multi-step (Init-Update-Finish) HMAC signing.
///
/// Use `sign` for single-step HMAC signing.
///
/// C analog: `HMAC_CTX`.
pub struct SigningContext {
    inner: digest::Context,
    outer: digest::Context,
}

impl SigningContext {
    /// Constructs a new HMAC signing context using the given digest algorithm
    /// and key.
    ///
    /// C analog: `HMAC_CTX_init`
    pub fn with_key(signing_key: &SigningKey) -> SigningContext {
        SigningContext {
            inner: signing_key.ctx_prototype.inner.clone(),
            outer: signing_key.ctx_prototype.outer.clone(),
        }
    }

    /// Updates the HMAC with all the data in `data`. `update` may be called
    /// zero or more times until `finish` is called.
    ///
    /// C analog: `HMAC_Update`
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalizes the HMAC calculation and returns the HMAC value. `sign`
    /// consumes the context so it cannot be (mis-)used after `sign` has been
    /// called.
    ///
    /// It is generally not safe to implement HMAC verification by comparing
    // the return value of `sign` to a signature. Use `verify` for verification
    // instead.
    ///
    /// C analog: `HMAC_Final`
    pub fn sign(mut self) -> digest::Digest {
        self.outer.update(self.inner.finish().as_ref());
        self.outer.finish()
    }
}

/// Calculates the HMAC of `data` using the key `key` in one step.
///
/// Use `SignignContext` to calculate HMACs where the input is in multiple
/// parts.
///
/// It is generally not safe to implement HMAC verification by comparing the
/// return value of `sign` to a signature. Use `verify` for verification
/// instead.
///
/// C analog: `HMAC_CTX_init` + `HMAC_Update` + `HMAC_Final`.
pub fn sign(key: &SigningKey, data: &[u8]) -> digest::Digest {
    let mut ctx = SigningContext::with_key(key);
    ctx.update(data);
    ctx.sign()
}

/// A key to use for HMAC authentication.
pub struct VerificationKey {
    wrapped: SigningKey
}

impl VerificationKey {
    /// Construct an HMAC verification key using the given digest algorithm and
    /// key value.
    ///
    /// As specified in RFC 2104, if `key_value` is shorter than the digest
    /// algorithm's block length (as returned by `digest::Algorithm::block_len`,
    /// not the digest length returned by `digest::Algorithm::digest_len`) then
    /// it will be padded with zeros. Similarly, if it is longer than the block
    /// length then it will be compressed using the digest algorithm.
    #[inline(always)]
    pub fn new(digest_alg: &'static digest::Algorithm, key_value: &[u8])
               -> VerificationKey {
        VerificationKey { wrapped: SigningKey::new(digest_alg, key_value) }
    }
}

/// Calculates the HMAC of `data` using the key `key`, and verifies whether the
/// resultant value equals `expected_value`, in one step.
///
/// The verification will be done in constant time to prevent timing attacks.
///
/// C analog: `HMAC_Init` + `HMAC_Update` + `HMAC_Final` + `CRYPTO_memcmp`
pub fn verify(key: &VerificationKey, data: &[u8], expected_value: &[u8])
              -> Result<(), ()> {
    let mut ctx = SigningContext::with_key(&key.wrapped);
    ctx.update(data);
    let actual_value = ctx.sign();
    constant_time::verify_slices_are_equal(actual_value.as_ref(),
                                           expected_value)
}

#[cfg(test)]
mod tests {
    use super::super::{digest, file_test, hmac};

    #[test]
    pub fn hmac_tests() {
        file_test::run("src/hmac_tests.txt", hmac_test_case);
    }

    fn hmac_test_case(test_case: &mut file_test::TestCase) {
        let digest_alg = test_case.consume_digest_alg("HMAC");
        let key_value = test_case.consume_bytes("Key");
        let mut input = test_case.consume_bytes("Input");
        let output = test_case.consume_bytes("Output");

        let digest_alg = match digest_alg {
            Some(digest_alg) => digest_alg,
            None => { return; } // Unsupported digest algorithm
        };

        hmac_test_case_inner(digest_alg, &key_value[..], &input[..],
                             &output[..], true);

        // Tamper with the input and check that verification fails.
        if input.len() == 0 {
            input.push(0);
        } else {
            input[0] ^= 1;
        }

        hmac_test_case_inner(digest_alg, &key_value[..], &input[..],
                             &output[..], false);
    }

    fn hmac_test_case_inner(digest_alg: &'static digest::Algorithm,
                            key_value: &[u8], input: &[u8], output: &[u8],
                            is_ok: bool) {

        let s_key = hmac::SigningKey::new(digest_alg, key_value);
        let v_key = hmac::VerificationKey::new(digest_alg, key_value);

        // One-shot API.
        {
            let signature = hmac::sign(&s_key, input);
            assert_eq!(is_ok, signature.as_ref() == output);
            assert_eq!(is_ok, hmac::verify(&v_key, input, output).is_ok());
        }

        // Multi-part API, one single part.
        {
            let mut s_ctx = hmac::SigningContext::with_key(&s_key);
            s_ctx.update(input);
            let signature = s_ctx.sign();
            assert_eq!(is_ok, signature.as_ref() == output);
        }

        // Multi-part API, byte by byte.
        {
            let mut s_ctx = hmac::SigningContext::with_key(&s_key);
            for b in input {
                s_ctx.update(&[*b]);
            }
            let signature = s_ctx.sign();
            assert_eq!(is_ok, signature.as_ref() == output);
        }
    }
}
