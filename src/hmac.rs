// Copyright 2015-2016 Brian Smith.
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
//! After a `SigningKey` or `VerificationKey` is constructed, it can be used
//! for multiple signing or verification operations. Separating the
//! construction of the key from the rest of the HMAC operation allows the
//! per-key precomputation to be done only once, instead of it being done in
//! every HMAC operation.
//!
//! Frequently all the data to be signed in a message is available in a single
//! contiguous piece. In that case, the module-level `sign` function can be
//! used. Otherwise, if the input is in multiple parts, `SigningContext` should
//! be used.
//!
//! # Use Case: Multi-party Communication
//!
//! Examples: TLS, SSH, and IPSEC record/packet authentication.
//!
//! The key that is used to sign messages to send to other parties should be a
//! `SigningKey`; `SigningContext` or `sign` should be used for the signing.
//! Each key that is used to authenticate messages received from peers should
//! be a `VerificationKey`; `verify` should be used for the authentication. All
//! of the keys should have distinct, independent, values.
//!
//! # Use Case: One-party Anti-tampering Protection
//!
//! Examples: Signed cookies, stateless CSRF protection.
//!
//! The key that is used to sign the data should be a `SigningKey`;
//! `SigningContext` or `sign` should be used for the signing. Use
//! `verify_with_own_key` to verify the signature using the signing key; this
//! is equivalent to, but more efficient than, constructing a `VerificationKey`
//! with the same value as the signing key and then calling `verify`.
//!
//! # Use Case: Key Derivation and Password Hashing
//!
//! Examples: HKDF, PBKDF2, the TLS PRF.
//!
//! All keys used during the key derivation should be `SigningKey`s;
//! `SigningContext` should usually be used for the HMAC calculations. The
//! [code for
//! `ring::pbkdf2`](https://github.com/briansmith/ring/blob/master/src/pbkdf2.rs)
//! and the [code for
//! `ring::hkdf`](https://github.com/briansmith/ring/blob/master/src/hkdf.rs)
//! are good examples of how to use `ring::hmac` efficiently for key derivation.
//!
//! # Examples:
//!
//! ## Signing a value and verifying it wasn't tampered with
//!
//! ```
//! use ring::{digest, hmac};
//!
//! # fn main_with_result() -> Result<(), ()> {
//! let key = try!(hmac::SigningKey::generate(&digest::SHA256));
//!
//! let msg = "hello, world";
//!
//! let signature = hmac::sign(&key, msg.as_bytes());
//!
//! // [We give access to the message to an untrusted party, and they give it
//! // back to us. We need to verify they didn't tamper with it.]
//!
//! try!(hmac::verify_with_own_key(&key, msg.as_bytes(), signature.as_ref()));
//! #
//! # Ok(())
//! # }
//! #
//! # fn main() { main_with_result().unwrap() }
//! ```
//!
//! ## Using the one-shot API:
//!
//! ```
//! use ring::{digest, hmac, rand};
//!
//! # fn main_with_result() -> Result<(), ()> {
//! let msg = "hello, world";
//!
//! // The sender generates a secure key value and signs the message with it.
//! // Note that it is better to use `SigningKey::generate` to generate the key
//! // when practical.
//! let mut key_value = [0u8; 32];
//! try!(rand::fill_secure_random(&mut key_value));
//!
//! let s_key = hmac::SigningKey::new(&digest::SHA256, key_value.as_ref());
//! let signature = hmac::sign(&s_key, msg.as_bytes());
//!
//! // The receiver (somehow!) knows the key value, and uses it to verify the
//! // integrity of the message.
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
//! // The sender generates a secure key value and signs the message with it.
//! // Note that it is better to use `SigningKey::generate` to generate the key
//! // when practical.
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
//! // The receiver (somehow!) knows the key value, and uses it to verify the
//! // integrity of the message.
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

use super::{constant_time, digest, rand};

/// A key to use for HMAC signing.
pub struct SigningKey {
    ctx_prototype: SigningContext,
}

impl SigningKey {
    /// Generate an HMAC signing key for the given digest algorithm using
    /// |ring::rand|. The key will be `digest_alg.chaining_len` bytes long. The
    /// key size choice is based on the recommendation of
    /// [NIST SP 800-107, Section 5.3.4: Security Effect of the HMAC
    /// Key](http://csrc.nist.gov/publications/nistpubs/800-107-rev1/sp800-107-rev1.pdf)
    /// and is consistent with the key lengths chosen for TLS as described in
    /// [RFC 5246, Appendix C](https://tools.ietf.org/html/rfc5246#appendix-C).
    pub fn generate(digest_alg: &'static digest::Algorithm)
                    -> Result<SigningKey, ()> {
        // XXX: There should probably be a `digest::MAX_CHAINING_LEN`, but for
        // now `digest::MAX_OUTPUT_LEN` is good enough.
        let mut key_data = [0u8; digest::MAX_OUTPUT_LEN];
        let key_data = &mut key_data[0..digest_alg.output_len];
        try!(rand::fill_secure_random(key_data));
        Ok(SigningKey::new(digest_alg, key_data))
    }

    /// Construct an HMAC signing key using the given digest algorithm and key
    /// value.
    ///
    /// As specified in RFC 2104, if `key_value` is shorter than the digest
    /// algorithm's block length (as returned by `digest::Algorithm::block_len`,
    /// not the digest length returned by `digest::Algorithm::output_len`) then
    /// it will be padded with zeros. Similarly, if it is longer than the block
    /// length then it will be compressed using the digest algorithm.
    ///
    /// You should not use keys larger than the `digest_alg.block_len` because
    /// the truncation described above reduces their strength to only
    /// `digest_alg.output_len * 8` bits. Support for such keys is likely to be
    /// removed in a future version of *ring*.
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

    /// The digest algorithm for the key.
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
    /// not the digest length returned by `digest::Algorithm::output_len`) then
    /// it will be padded with zeros. Similarly, if it is longer than the block
    /// length then it will be compressed using the digest algorithm.
    #[inline(always)]
    pub fn new(digest_alg: &'static digest::Algorithm, key_value: &[u8])
               -> VerificationKey {
        VerificationKey { wrapped: SigningKey::new(digest_alg, key_value) }
    }
}

/// Calculates the HMAC of `data` using the key `key`, and verifies whether the
/// resultant value equals `signature`, in one step.
///
/// The verification will be done in constant time to prevent timing attacks.
///
/// C analog: `HMAC_Init` + `HMAC_Update` + `HMAC_Final` + `CRYPTO_memcmp`
#[inline(always)]
pub fn verify(key: &VerificationKey, data: &[u8], signature: &[u8])
              -> Result<(), ()> {
    verify_with_own_key(&key.wrapped, data, signature)
}

/// Calculates the HMAC of `data` using the signing key `key`, and verifies
/// whether the resultant value equals `signature`, in one step.
///
/// This is logically equivalent to, but more efficient than, constructing a
/// `VerificationKey` with the same value as `key` and then using `verify`.
///
/// The verification will be done in constant time to prevent timing attacks.
///
/// C analog: `HMAC_Init` + `HMAC_Update` + `HMAC_Final` + `CRYPTO_memcmp`
pub fn verify_with_own_key(key: &SigningKey, data: &[u8], signature: &[u8])
                           -> Result<(), ()> {
    constant_time::verify_slices_are_equal(sign(&key, data).as_ref(), signature)
}

#[cfg(test)]
mod tests {
    use super::super::{digest, file_test, hmac};

    // Make sure that `SigningKey::generate` and `verify_with_own_key` aren't
    // completely wacky.
    #[test]
    pub fn hmac_signing_key_coverage() {
        const HELLO_WORLD_GOOD: &'static [u8] = b"hello, world";
        const HELLO_WORLD_BAD:  &'static [u8] = b"hello, worle";

        for d in &digest::test_util::ALL_ALGORITHMS {
            let key = hmac::SigningKey::generate(d).unwrap();
            let signature = hmac::sign(&key, HELLO_WORLD_GOOD);
            assert!(hmac::verify_with_own_key(&key, HELLO_WORLD_GOOD,
                                              signature.as_ref()).is_ok());
            assert!(hmac::verify_with_own_key(&key, HELLO_WORLD_BAD,
                                              signature.as_ref()).is_err())
        }
    }

    #[test]
    pub fn hmac_tests() {
        file_test::run("src/hmac_tests.txt", |section, test_case| {
            assert_eq!(section, "");
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
        });
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
