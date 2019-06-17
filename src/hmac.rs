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
//! After a `Key` is constructed, it can be used for multiple signing or
//! verification operations. Separating the construction of the key from the
//! rest of the HMAC operation allows the per-key precomputation to be done
//! only once, instead of it being done in every HMAC operation.
//!
//! Frequently all the data to be signed in a message is available in a single
//! contiguous piece. In that case, the method [`Key::sign`] can be used. If the
//! input is in multiple parts the complementary [`Key::sign_parts`] provides
//! the signature in a single step. If not all parts of the data are available
//! immediately, [`Context`] should be used to compute the signature
//! incrementally.
//!
//! The verification of a signature is performed with the related methods
//! [`Key::verify`] and [`Key::verify_parts`].
//!
//! # Examples:
//!
//! ## Signing a value and verifying it wasn't tampered with
//!
//! ```
//! use ring::{hmac, rand};
//!
//! let rng = rand::SystemRandom::new();
//! let key = hmac::Key::generate(hmac::HMAC_SHA256, &rng)?;
//!
//! let msg = "hello, world";
//!
//! let tag = key.sign(msg.as_bytes());
//!
//! // [We give access to the message to an untrusted party, and they give it
//! // back to us. We need to verify they didn't tamper with it.]
//!
//! key.verify(msg.as_bytes(), tag.as_ref())?;
//!
//! # Ok::<(), ring::error::Unspecified>(())
//! ```
//!
//! ## Using the one-shot API:
//!
//! ```
//! use ring::{digest, hmac, rand};
//! use ring::rand::SecureRandom;
//!
//! let msg = b"hello, world";
//!
//! // The sender generates a secure key value and signs the message with it.
//! // Note that in a real protocol, a key agreement protocol would be used to
//! // derive `key_value`.
//! let rng = rand::SystemRandom::new();
//! let key_value: [u8; digest::SHA256_OUTPUT_LEN] = rand::generate(&rng)?.expose();
//!
//! let s_key = hmac::Key::new(hmac::HMAC_SHA256, key_value.as_ref());
//! let tag = s_key.sign(msg);
//!
//! // The receiver (somehow!) knows the key value, and uses it to verify the
//! // integrity of the message.
//! let v_key = hmac::Key::new(&digest::SHA256, key_value.as_ref());
//! v_key.verify(msg, tag.as_ref())?;
//!
//! # Ok::<(), ring::error::Unspecified>(())
//! ```
//!
//! ## Using the multi-part API:
//! ```
//! use ring::{digest, hmac, rand};
//! use ring::rand::SecureRandom;
//!
//! let parts: [&[u8]; 3] = [b"hello", b", ", b"world"];
//!
//! // The sender generates a secure key value and signs the message with it.
//! // Note that in a real protocol, a key agreement protocol would be used to
//! // derive `key_value`.
//! let rng = rand::SystemRandom::new();
//! let mut key_value: [u8; digest::SHA384_OUTPUT_LEN] = rand::generate(&rng)?.expose();
//!
//! let s_key = hmac::Key::new(hmac::HMAC_SHA384, key_value.as_ref());
//! let tag = s_key.sign_parts(parts.iter().cloned());
//!
//! // The receiver (somehow!) knows the key value, and uses it to verify the
//! // integrity of the message.
//! let v_key = hmac::Key::new(&digest::SHA384, key_value.as_ref());
//! v_key.verify_parts(parts.iter().cloned(), tag.as_ref())?;
//!
//! # Ok::<(), ring::error::Unspecified>(())
//! ```
//!
//! ## Using the Context API
//! ```
//! use ring::{digest, hmac, rand};
//! use ring::rand::SecureRandom;
//!
//! let parts: [&[u8]; 3] = [b"hello", b", ", b"world"];
//!
//! // The sender generates a secure key value and signs the message with it.
//! // Note that in a real protocol, a key agreement protocol would be used to
//! // derive `key_value`.
//! let rng = rand::SystemRandom::new();
//! let mut key_value: [u8; digest::SHA384_OUTPUT_LEN] = rand::generate(&rng)?.expose();
//!
//! let s_key = hmac::Key::new(hmac::HMAC_SHA384, key_value.as_ref());
//! let mut s_ctx = hmac::Context::with_key(&s_key);
//! for part in &parts {
//!     // The Context can consume parts one after another.
//!     s_ctx.update(part.as_bytes());
//! }
//! let tag = s_ctx.sign();
//!
//! // The receiver (somehow!) knows the key value, and uses it to verify the
//! // integrity of the message.
//! let v_key = hmac::Key::new(hmac::HMAC_SHA384, key_value.as_ref());
//! v_key.verify_parts(parts.iter().cloned(), tag.as_ref())?;
//! hmac::verify(&v_key, &msg.as_ref(), tag.as_ref())?;
//!
//! # Ok::<(), ring::error::Unspecified>(())
//! ```
//!
//! [RFC 2104]: https://tools.ietf.org/html/rfc2104
//! [code for `ring::pbkdf2`]:
//!     https://github.com/briansmith/ring/blob/master/src/pbkdf2.rs
//! [code for `ring::hkdf`]:
//!     https://github.com/briansmith/ring/blob/master/src/hkdf.rs
//! [`Context`]: struct.Context.html
//! [`Key::sign`]: struct.Key.html#method.sign
//! [`Key::sign_parts`]: struct.Key.html#method.sign_parts
//! [`Key::verify`]: struct.Key.html#method.verify
//! [`Key::verify_party`]: struct.Key.html#method.verify_parts
//!
use crate::{constant_time, digest, error, hkdf, rand};

/// An HMAC algorithm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Algorithm(&'static digest::Algorithm);

impl Algorithm {
    /// The digest algorithm this HMAC algorithm is based on.
    #[inline]
    pub fn digest_algorithm(&self) -> &'static digest::Algorithm {
        self.0
    }
}

/// HMAC using SHA-1. Obsolete.
pub static HMAC_SHA1_FOR_LEGACY_USE_ONLY: Algorithm = Algorithm(&digest::SHA1_FOR_LEGACY_USE_ONLY);

/// HMAC using SHA-256.
pub static HMAC_SHA256: Algorithm = Algorithm(&digest::SHA256);

/// HMAC using SHA-384.
pub static HMAC_SHA384: Algorithm = Algorithm(&digest::SHA384);

/// HMAC using SHA-512.
pub static HMAC_SHA512: Algorithm = Algorithm(&digest::SHA512);

/// A deprecated alias for `Tag`.
#[deprecated(note = "`Signature` was renamed to `Tag`. This alias will be removed soon.")]
pub type Signature = Tag;

/// An HMAC tag.
///
/// For a given tag `t`, use `t.as_ref()` to get the tag value as a byte slice.
#[derive(Clone, Copy, Debug)]
pub struct Tag(digest::Digest);

impl AsRef<[u8]> for Tag {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// A key to use for HMAC signing.
#[derive(Clone)]
pub struct Key {
    inner: digest::BlockContext,
    outer: digest::BlockContext,
}

/// `hmac::SigningKey` was renamed to `hmac::Key`.
#[deprecated(note = "Renamed to `hmac::Key`.")]
pub type SigningKey = Key;

/// `hmac::VerificationKey` was merged into `hmac::Key`.
#[deprecated(
    note = "The distinction between verification & signing keys was removed. Use `hmac::Key`."
)]
pub type VerificationKey = Key;

impl core::fmt::Debug for Key {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("Key")
            .field("algorithm", self.algorithm().digest_algorithm())
            .finish()
    }
}

impl Key {
    /// Generate an HMAC signing key using the given digest algorithm with a
    /// random value generated from `rng`.
    ///
    /// The key will be `digest_alg.output_len` bytes long, based on the
    /// recommendation in https://tools.ietf.org/html/rfc2104#section-3.
    pub fn generate(
        algorithm: Algorithm,
        rng: &dyn rand::SecureRandom,
    ) -> Result<Self, error::Unspecified> {
        Self::construct(algorithm, |buf| rng.fill(buf))
    }

    fn construct<F>(algorithm: Algorithm, fill: F) -> Result<Self, error::Unspecified>
    where
        F: FnOnce(&mut [u8]) -> Result<(), error::Unspecified>,
    {
        let mut key_bytes = [0; digest::MAX_OUTPUT_LEN];
        let key_bytes = &mut key_bytes[..algorithm.0.output_len];
        fill(key_bytes)?;
        Ok(Self::new(algorithm, key_bytes))
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
    pub fn new(algorithm: Algorithm, key_value: &[u8]) -> Self {
        let digest_alg = algorithm.0;
        let mut key = Self {
            inner: digest::BlockContext::new(digest_alg),
            outer: digest::BlockContext::new(digest_alg),
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
        key.inner.update(&padded_key);

        const OPAD: u8 = 0x5C;

        // Remove the `IPAD` masking, leaving the unmasked padded key, then
        // mask with `OPAD`, all in one step.
        for b in padded_key.iter_mut() {
            *b ^= IPAD ^ OPAD;
        }
        key.outer.update(&padded_key);

        key
    }

    /// The digest algorithm for the key.
    #[inline]
    pub fn algorithm(&self) -> Algorithm {
        Algorithm(self.inner.algorithm)
    }

    /// Calculates the HMAC of `data` using the key in one step.
    ///
    /// Use [`sign_parts`] if the data is not in a contiguous memory region. In
    /// more involved cases, use [`Context`] to calculate HMACs where the input
    /// is not available at once.
    ///
    /// It is generally not safe to implement HMAC verification by comparing the
    /// return value of `sign` to a tag. Use [`verify`] for verification instead.
    ///
    /// [`sign_parts`]: #method.sign_parts
    /// [`verify`]: #method.verify
    /// [`Context`]: ./struct.Context.html
    pub fn sign(&self, data: &[u8]) -> Tag {
        self.sign_parts(Some(data))
    }

    /// Verifies that the HACM of `data` with key equal `tag`.
    ///
    /// Use [`verify_parts`] if the data is not in a contiguous memory region.
    ///
    /// This will calculates the HMAC of `data` using the signing key, and
    /// verify whether the resultant value equals `tag`, in one step and without
    /// making the resulting tag available.  The comparison will be done in
    /// constant time to prevent timing attacks.
    ///
    /// [`verify_parts`]: #method.verify_parts
    pub fn verify(&self, data: &[u8], tag: &[u8]) -> Result<(), error::Unspecified> {
        self.verify_parts(Some(data), tag)
    }

    /// Sign data distributed in multiple memory regions.
    ///
    /// This is effectively the same as if signing the concatenation of all byte
    /// slices returned by the iterator. Use [`Context`] to calculate HMACs
    /// where the input is not available at once.
    ///
    /// It is generally not safe to implement HMAC verification by comparing the
    /// return value of `sign` to a tag. Use [`verify_parts`] for verification
    /// instead.
    ///
    /// [`verify_parts`]: #method.verify_parts
    /// [`Context`]: ./struct.Context.html
    pub fn sign_parts<'a>(&self, parts: impl IntoIterator<Item=&'a [u8]>) -> Tag {
        let mut ctx = Context::with_key(self);
        for part in parts {
            ctx.update(part);
        }
        ctx.sign()
    }

    /// Verify data distributed in multiple memory regions.
    ///
    /// This is effectively the same as if verifying the concatenation of all
    /// byte slices returned by the iterator.
    ///
    /// It is not possible to create verification context that does not verify
    /// the tag in one step after gather all inputs. This avoid accidentally
    /// processing parts of the input while under the *wrong* impression that
    /// they were already verified.
    ///
    /// This will calculates the HMAC of `data` using the signing key, and
    /// verify whether the resultant value equals `tag`, in one step and without
    /// making the resulting tag available.  The comparison will be done in
    /// constant time to prevent timing attacks.
    pub fn verify_parts<'a>(&self, parts: impl IntoIterator<Item=&'a [u8]>, tag: &[u8])
        -> Result<(), error::Unspecified>
    {
        let signature = self.sign_parts(parts);
        constant_time::verify_slices_are_equal(tag.as_ref(), signature.as_ref())
    }
}

impl hkdf::KeyType for Algorithm {
    fn len(&self) -> usize {
        self.digest_algorithm().output_len
    }
}

impl From<hkdf::Okm<'_, Algorithm>> for Key {
    fn from(okm: hkdf::Okm<Algorithm>) -> Self {
        Key::construct(*okm.len(), |buf| okm.fill(buf)).unwrap()
    }
}

/// A context for multi-step (Init-Update-Finish) HMAC signing.
///
/// Prefer [`Key::sign`] for single-step HMAC signing and [`Key::sign_parts`] for signle step
/// signing of data that is not in a contiguous memory region. Note that [`Context`] has no
/// verification parallel to [`sign`] to avoid misusing data that is not already verified.
///
/// [`Key::sign`]: struct.Key.html#method.sign
/// [`Key::sign_parts`]: struct.Key.html#method.sign_parts
/// [`Context`]: struct.Context.html
/// [`sign`]: #method.sign
// Note: No verify. This is to require all data to be verified and discourage processing parts of
// the data without being verified. A previous commit (12596a32f9e8cb15dbe7f84d062a9a8c6207a7e8)
// removed such an interface, so don't add it.
#[derive(Clone)]
pub struct Context {
    inner: digest::Context,
    outer: digest::BlockContext,
}

/// `hmac::SigningContext` was renamed to `hmac::Context`.
#[deprecated(note = "Renamed to `hmac::Context`.")]
pub type SigningContext = Context;

impl core::fmt::Debug for Context {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("Context")
            .field("algorithm", self.inner.algorithm())
            .finish()
    }
}

impl Context {
    /// Constructs a new HMAC signing context using the given digest algorithm
    /// and key.
    pub fn with_key(signing_key: &Key) -> Self {
        Self {
            inner: digest::Context::clone_from(&signing_key.inner),
            outer: signing_key.outer.clone(),
        }
    }

    /// Updates the HMAC with all the data in `data`. `update` may be called
    /// zero or more times until [`sign`] is called.
    ///
    /// [`sign`]: #method.sign
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalizes the HMAC calculation and returns the HMAC value. `sign`
    /// consumes the context so it cannot be (mis-)used after `sign` has been
    /// called.
    ///
    /// It is generally not safe to implement HMAC verification by comparing
    /// the return value of `sign` to a tag. Use the methods [`Key::verify`] and
    /// [`Key::verify_parts`] for verification instead.
    ///
    /// [`Key::verify`]: struct.Key.html#method.verify
    /// [`Key::verify_parts`]: struct.Key.html#method.verify_parts
    /// instead.
    pub fn sign(self) -> Tag {
        let algorithm = self.inner.algorithm();
        let mut pending = [0u8; digest::MAX_BLOCK_LEN];
        let pending = &mut pending[..algorithm.block_len];
        let num_pending = algorithm.output_len;
        pending[..num_pending].copy_from_slice(self.inner.finish().as_ref());
        Tag(self.outer.finish(pending, num_pending))
    }

    // Note: no verify. See note on `Context` itself.
}

/// Calculates the HMAC of `data` using the key `key` in one step.
///
/// Use `Context` to calculate HMACs where the input is in multiple parts.
///
/// It is generally not safe to implement HMAC verification by comparing the
/// return value of `sign` to a tag. Use `verify` for verification instead.
#[deprecated(note = "Moved to `hmac::Key::sign`.")]
pub fn sign(key: &Key, data: &[u8]) -> Tag {
    key.sign(data)
}

/// Calculates the HMAC of `data` using the signing key `key`, and verifies
/// whether the resultant value equals `tag`, in one step.
///
/// This is logically equivalent to, but more efficient than, constructing a
/// `Key` with the same value as `key` and then using `verify`.
///
/// The verification will be done in constant time to prevent timing attacks.
#[deprecated(note = "Moved to `hmac::Key::verify`.")]
pub fn verify(key: &Key, data: &[u8], tag: &[u8]) -> Result<(), error::Unspecified> {
    key.verify(data, tag)
}

#[cfg(test)]
mod tests {
    use crate::{hmac, rand};

    // Make sure that `Key::generate` and `verify_with_own_key` aren't
    // completely wacky.
    #[test]
    pub fn hmac_signing_key_coverage() {
        let mut rng = rand::SystemRandom::new();

        const HELLO_WORLD_GOOD: &[u8] = b"hello, world";
        const HELLO_WORLD_BAD: &[u8] = b"hello, worle";

        for algorithm in &[
            hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            hmac::HMAC_SHA256,
            hmac::HMAC_SHA384,
            hmac::HMAC_SHA512,
        ] {
            let key = hmac::Key::generate(*algorithm, &mut rng).unwrap();
            let tag = key.sign(HELLO_WORLD_GOOD);
            assert!(key.verify(HELLO_WORLD_GOOD, tag.as_ref()).is_ok());
            assert!(key.verify(HELLO_WORLD_BAD, tag.as_ref()).is_err())
        }
    }
}
