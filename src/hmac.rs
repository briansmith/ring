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

//! HMAC is specified in [RFC 2104].
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
//! [code for `ring::pbkdf2`] and the [code for `ring::hkdf`] are good
//! examples of how to use `ring::hmac` efficiently for key derivation.
//!
//!
//! # Examples:
//!
//! ## Signing a value and verifying it wasn't tampered with
//!
//! ```
//! use ring::{digest, hmac, rand};
//!
//! # fn main_with_result() -> Result<(), ring::error::Unspecified> {
//! let rng = rand::SystemRandom::new();
//! let key = hmac::SigningKey::generate(&digest::SHA256, &rng)?;
//!
//! let msg = "hello, world";
//!
//! let signature = hmac::sign(&key, msg.as_bytes());
//!
//! // [We give access to the message to an untrusted party, and they give it
//! // back to us. We need to verify they didn't tamper with it.]
//!
//! hmac::verify_with_own_key(&key, msg.as_bytes(), signature.as_ref())?;
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
//! use ring::rand::SecureRandom;
//!
//! # fn main_with_result() -> Result<(), ring::error::Unspecified> {
//! let msg = "hello, world";
//!
//! // The sender generates a secure key value and signs the message with it.
//! // Note that in a real protocol, a key agreement protocol would be used to
//! // derive `key_value`.
//! let mut key_value = [0u8; 32];
//! let rng = rand::SystemRandom::new();
//! rng.fill(&mut key_value)?;
//!
//! let s_key = hmac::SigningKey::new(&digest::SHA256, key_value.as_ref());
//! let signature = hmac::sign(&s_key, msg.as_bytes());
//!
//! // The receiver (somehow!) knows the key value, and uses it to verify the
//! // integrity of the message.
//! let v_key = hmac::VerificationKey::new(&digest::SHA256, key_value.as_ref());
//! hmac::verify(&v_key, msg.as_bytes(), signature.as_ref())?;
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
//! use ring::rand::SecureRandom;
//!
//! # fn main_with_result() -> Result<(), ring::error::Unspecified> {
//! let parts = ["hello", ", ", "world"];
//!
//! // The sender generates a secure key value and signs the message with it.
//! // Note that in a real protocol, a key agreement protocol would be used to
//! // derive `key_value`.
//! let mut key_value = [0u8; 48];
//! let rng = rand::SystemRandom::new();
//! rng.fill(&mut key_value)?;
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
//! hmac::verify(&v_key, &msg.as_ref(), signature.as_ref())?;
//! #
//! # Ok(())
//! # }
//! #
//! # fn main() { main_with_result().unwrap() }
//! ```
//!
//! [RFC 2104]: https://tools.ietf.org/html/rfc2104
//! [code for `ring::pbkdf2`]:
//!     https://github.com/briansmith/ring/blob/master/src/pbkdf2.rs
//! [code for `ring::hkdf`]:
//!     https://github.com/briansmith/ring/blob/master/src/hkdf.rs

use crate::{constant_time, digest, error, rand};

/// An HMAC signature.
///
/// For a given signature `s`, use `s.as_ref()` to get the signature value as
/// a byte slice.
#[derive(Clone, Copy, Debug)]
pub struct Signature(digest::Digest);

/// A key to use for HMAC signing.
pub struct SigningKey {
    ctx_prototype: SigningContext,
}

impl core::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("SigningKey")
            .field("algorithm", self.digest_algorithm())
            .finish()
    }
}

impl AsRef<[u8]> for Signature {
    #[inline]
    fn as_ref(&self) -> &[u8] { self.0.as_ref() }
}

impl SigningKey {
    /// Generate an HMAC signing key using the given digest algorithm with a
    /// random value generated from `rng`.
    ///
    /// The key will be `recommended_key_len(digest_alg)` bytes long.
    pub fn generate(
        digest_alg: &'static digest::Algorithm, rng: &rand::SecureRandom,
    ) -> Result<SigningKey, error::Unspecified> {
        // XXX: There should probably be a `digest::MAX_CHAINING_LEN`, but for
        // now `digest::MAX_OUTPUT_LEN` is good enough.
        let mut key_bytes = [0u8; digest::MAX_OUTPUT_LEN];
        let key_bytes = &mut key_bytes[..recommended_key_len(digest_alg)];
        Self::generate_serializable(digest_alg, rng, key_bytes)
    }

    /// Generate an HMAC signing key using the given digest algorithm with a
    /// random value generated from `rng`, and puts the raw key value in
    /// `key_bytes`.
    ///
    /// The key will be `recommended_key_len(digest_alg)` bytes long. The raw
    /// value of the random key is put in `key_bytes` so that it can be
    /// serialized for later use, so `key_bytes` must be exactly
    /// `recommended_key_len(digest_alg)`. This serialized value can be
    /// deserialized with `SigningKey::new()`.
    pub fn generate_serializable(
        digest_alg: &'static digest::Algorithm, rng: &rand::SecureRandom, key_bytes: &mut [u8],
    ) -> Result<SigningKey, error::Unspecified> {
        if key_bytes.len() != recommended_key_len(digest_alg) {
            return Err(error::Unspecified);
        }
        rng.fill(key_bytes)?;
        Ok(SigningKey::new(digest_alg, key_bytes))
    }

    /// Construct an HMAC signing key using the given digest algorithm and key
    /// value.
    ///
    /// `key_value` should be a value generated using a secure random number
    /// generator (e.g. the `key_value` output by
    /// `SealingKey::generate_serializable()`) or derived from a random key by
    /// a key derivation function (e.g. `ring::hkdf`). In particular,
    /// `key_value` shouldn't be a password.
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
    pub fn new(digest_alg: &'static digest::Algorithm, key_value: &[u8]) -> SigningKey {
        let mut key = SigningKey {
            ctx_prototype: SigningContext {
                inner: digest::Context::new(digest_alg),
                outer: digest::Context::new(digest_alg),
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

        let mut padded_key = [IPAD; digest::MAX_BLOCK_LEN];
        let padded_key = &mut padded_key[..digest_alg.block_len];

        // If the key is shorter than one block then we're supposed to act like
        // it is padded with zero bytes up to the block length. `x ^ 0 == x` so
        // we can just leave the trailing bytes of `padded_key` untouched.
        for (padded_key, key_value) in padded_key.iter_mut().zip(key_value.iter()) {
            *padded_key ^= *key_value;
        }
        key.ctx_prototype.inner.update(&padded_key);

        const OPAD: u8 = 0x5C;

        // Remove the `IPAD` masking, leaving the unmasked padded key, then
        // mask with `OPAD`, all in one step.
        for b in padded_key.iter_mut() {
            *b ^= IPAD ^ OPAD;
        }
        key.ctx_prototype.outer.update(&padded_key);

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
#[derive(Clone)]
pub struct SigningContext {
    inner: digest::Context,
    outer: digest::Context,
}

impl core::fmt::Debug for SigningContext {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("SigningContext")
            .field("algorithm", self.inner.algorithm())
            .finish()
    }
}

impl SigningContext {
    /// Constructs a new HMAC signing context using the given digest algorithm
    /// and key.
    pub fn with_key(signing_key: &SigningKey) -> SigningContext {
        SigningContext {
            inner: signing_key.ctx_prototype.inner.clone(),
            outer: signing_key.ctx_prototype.outer.clone(),
        }
    }

    /// Updates the HMAC with all the data in `data`. `update` may be called
    /// zero or more times until `finish` is called.
    pub fn update(&mut self, data: &[u8]) { self.inner.update(data); }

    /// Finalizes the HMAC calculation and returns the HMAC value. `sign`
    /// consumes the context so it cannot be (mis-)used after `sign` has been
    /// called.
    ///
    /// It is generally not safe to implement HMAC verification by comparing
    // the return value of `sign` to a signature. Use `verify` for verification
    // instead.
    pub fn sign(mut self) -> Signature {
        self.outer.update(self.inner.finish().as_ref());
        Signature(self.outer.finish())
    }
}

/// Calculates the HMAC of `data` using the key `key` in one step.
///
/// Use `SigningContext` to calculate HMACs where the input is in multiple
/// parts.
///
/// It is generally not safe to implement HMAC verification by comparing the
/// return value of `sign` to a signature. Use `verify` for verification
/// instead.
pub fn sign(key: &SigningKey, data: &[u8]) -> Signature {
    let mut ctx = SigningContext::with_key(key);
    ctx.update(data);
    ctx.sign()
}

/// A key to use for HMAC authentication.
pub struct VerificationKey {
    wrapped: SigningKey,
}

impl core::fmt::Debug for VerificationKey {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("VerificationKey")
            .field("algorithm", self.digest_algorithm())
            .finish()
    }
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
    pub fn new(digest_alg: &'static digest::Algorithm, key_value: &[u8]) -> VerificationKey {
        VerificationKey {
            wrapped: SigningKey::new(digest_alg, key_value),
        }
    }

    /// The digest algorithm for the key.
    #[inline]
    pub fn digest_algorithm(&self) -> &'static digest::Algorithm { self.wrapped.digest_algorithm() }
}

/// Calculates the HMAC of `data` using the key `key`, and verifies whether the
/// resultant value equals `signature`, in one step.
///
/// The verification will be done in constant time to prevent timing attacks.
#[inline(always)]
pub fn verify(
    key: &VerificationKey, data: &[u8], signature: &[u8],
) -> Result<(), error::Unspecified> {
    verify_with_own_key(&key.wrapped, data, signature)
}

/// Calculates the HMAC of `data` using the signing key `key`, and verifies
/// whether the resultant value equals `signature`, in one step.
///
/// This is logically equivalent to, but more efficient than, constructing a
/// `VerificationKey` with the same value as `key` and then using `verify`.
///
/// The verification will be done in constant time to prevent timing attacks.
pub fn verify_with_own_key(
    key: &SigningKey, data: &[u8], signature: &[u8],
) -> Result<(), error::Unspecified> {
    constant_time::verify_slices_are_equal(sign(key, data).as_ref(), signature)
}

/// Returns the recommended key length for HMAC using the given digest
/// algorithm.
///
/// The value returned is the chaining length of the digest function,
/// `digest_alg.chaining_len`. This is 32 bytes (256 bits) for SHA-256, and
/// 64 bytes (512 bits) for SHA-384 and SHA-512.
///
/// This recommendation is based on [NIST SP 800-107], Section 5.3.4: Security
/// Effect of the HMAC Key. The chaining length of the digest algorithm,
/// instead of its block length, is used to be consistent with the key lengths
/// chosen for TLS for SHA-256 (see [RFC 5246, Appendix C]) and most other
/// protocols.
///
/// [NIST SP 800-107]:
///     http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-107r1.pdf
/// [RFC 5246, Appendix C]:
///     https://tools.ietf.org/html/rfc5246#appendix-C
#[inline]
pub fn recommended_key_len(digest_alg: &digest::Algorithm) -> usize { digest_alg.chaining_len }

#[cfg(test)]
mod tests {
    use crate::{digest, hmac, rand, test};

    // Make sure that `SigningKey::generate` and `verify_with_own_key` aren't
    // completely wacky.
    #[test]
    pub fn hmac_signing_key_coverage() {
        let mut rng = rand::SystemRandom::new();

        const HELLO_WORLD_GOOD: &[u8] = b"hello, world";
        const HELLO_WORLD_BAD: &[u8] = b"hello, worle";

        for d in &digest::test_util::ALL_ALGORITHMS {
            {
                let key = hmac::SigningKey::generate(d, &mut rng).unwrap();
                let signature = hmac::sign(&key, HELLO_WORLD_GOOD);
                assert!(
                    hmac::verify_with_own_key(&key, HELLO_WORLD_GOOD, signature.as_ref()).is_ok()
                );
                assert!(
                    hmac::verify_with_own_key(&key, HELLO_WORLD_BAD, signature.as_ref()).is_err()
                )
            }

            {
                let mut key_bytes = vec![0; d.chaining_len];
                let key =
                    hmac::SigningKey::generate_serializable(d, &mut rng, &mut key_bytes).unwrap();
                let signature = hmac::sign(&key, HELLO_WORLD_GOOD);
                assert!(
                    hmac::verify_with_own_key(&key, HELLO_WORLD_GOOD, signature.as_ref()).is_ok()
                );
                assert!(
                    hmac::verify_with_own_key(&key, HELLO_WORLD_BAD, signature.as_ref()).is_err()
                )
            }

            // Attempt with a `key_bytes` parameter that wrongly uses the
            // output length instead of the chaining length, when those two
            // values differ.
            if d.chaining_len != d.output_len {
                let mut key_bytes = vec![0; d.output_len];
                assert!(
                    hmac::SigningKey::generate_serializable(d, &mut rng, &mut key_bytes).is_err()
                );
            }

            // Attempt with a too-small `key_bytes`.
            {
                let mut key_bytes = vec![0; d.chaining_len - 1];
                assert!(
                    hmac::SigningKey::generate_serializable(d, &mut rng, &mut key_bytes).is_err()
                );
            }

            // Attempt with a too-large `key_bytes`.
            {
                let mut key_bytes = vec![0; d.chaining_len + 1];
                assert!(
                    hmac::SigningKey::generate_serializable(d, &mut rng, &mut key_bytes).is_err()
                );
            }
        }
    }

    // Test that `generate_serializable()` generates a key from the RNG, and
    // that the generated key fills the entire `key_bytes` parameter.
    #[test]
    pub fn generate_serializable_tests() {
        test::run(
            test_file!("hmac_generate_serializable_tests.txt"),
            |section, test_case| {
                assert_eq!(section, "");
                let digest_alg = test_case.consume_digest_alg("HMAC").unwrap();
                let key_value_in = test_case.consume_bytes("Key");

                let rng = test::rand::FixedSliceRandom {
                    bytes: &key_value_in,
                };
                let mut key_value_out = vec![0; digest_alg.chaining_len];
                let _ =
                    hmac::SigningKey::generate_serializable(digest_alg, &rng, &mut key_value_out)
                        .unwrap();
                assert_eq!(&key_value_in, &key_value_out);

                Ok(())
            },
        )
    }
}
