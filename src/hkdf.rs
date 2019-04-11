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

//! HMAC-based Extract-and-Expand Key Derivation Function.
//!
//! HKDF is specified in [RFC 5869].
//! ```
//! use ring::{aead, digest, error, hkdf};
//!
//! fn derive_opening_key(
//!     key_algorithm: &'static aead::Algorithm, salt: [u8; 32], ikm: [u8; 32], info: &[u8],
//! ) -> Result<aead::OpeningKey, error::Unspecified> {
//!     let salt = hkdf::Salt::new(&digest::SHA512, &salt);
//!     let prk = salt.extract(&ikm);
//!     let mut key_bytes = vec![0; key_algorithm.key_len()];
//!     let out = prk.expand(info).fill(&mut key_bytes)?;
//!     aead::OpeningKey::new(key_algorithm, &key_bytes)
//! }
//! ```
//!
//! [RFC 5869]: https://tools.ietf.org/html/rfc5869

use crate::{digest, error, hmac};

/// A salt for HKDF operations.
#[derive(Debug)]
pub struct Salt(hmac::Key);

impl Salt {
    /// Constructs a new `Salt` with the given value based on the given digest
    /// algorithm.
    ///
    /// Constructing a `Salt` is relatively expensive so it is good to reuse a
    /// `Salt` object instead of re-constructing `Salt`s with the same value.
    pub fn new(digest_algorithm: &'static digest::Algorithm, value: &[u8]) -> Self {
        Salt(hmac::Key::new(digest_algorithm, value))
    }

    /// The [HKDF-Extract] operation.
    ///
    /// [HKDF-Extract]: https://tools.ietf.org/html/rfc5869#section-2.2
    pub fn extract(&self, secret: &[u8]) -> Prk {
        // The spec says that if no salt is provided then a key of
        // `digest_alg.output_len` bytes of zeros is used. But, HMAC keys are
        // already zero-padded to the block length, which is larger than the output
        // length of the extract step (the length of the digest). Consequently the
        // `Key` constructor will automatically do the right thing for a
        // zero-length string.
        let salt = &self.0;
        let prk = hmac::sign(salt, secret);
        Prk(hmac::Key::new(salt.digest_algorithm(), prk.as_ref()))
    }
}

/// A HKDF PRK (pseudorandom key).
#[derive(Debug)]
pub struct Prk(hmac::Key);

impl Prk {
    /// The [HKDF-Expand] operation.
    ///
    /// [HKDF-Expand]: https://tools.ietf.org/html/rfc5869#section-2.3
    #[inline]
    pub fn expand<'a>(&'a self, info: &'a [u8]) -> Okm<'a> {
        Okm { prk: self, info }
    }
}

/// An HKDF OKM (Output Keying Material)
///
/// Intentionally not `Clone` or `Copy` as an OKM is generally only safe to
/// use once.
#[derive(Debug)]
pub struct Okm<'a> {
    prk: &'a Prk,
    info: &'a [u8],
}

impl Okm<'_> {
    /// Fills `out` with the output of the HKDF-Expand operation for the given
    /// inputs.
    ///
    /// Fails if (and only if) the requested output length is larger than 255
    /// times the size of the digest algorithm's output. (This is the limit
    /// imposed by the HKDF specification due to the way HKDF's counter is
    /// constructed.)
    pub fn fill(self, out: &mut [u8]) -> Result<(), error::Unspecified> {
        let digest_alg = self.prk.0.digest_algorithm();
        assert!(digest_alg.block_len >= digest_alg.output_len);

        let mut ctx = hmac::Context::with_key(&self.prk.0);

        let mut n = 1u8;
        let mut out = out;
        loop {
            ctx.update(self.info);
            ctx.update(&[n]);

            let t = ctx.sign();
            let t = t.as_ref();

            // Append `t` to the output.
            out = if out.len() < digest_alg.output_len {
                let len = out.len();
                out.copy_from_slice(&t[..len]);
                &mut []
            } else {
                let (this_chunk, rest) = out.split_at_mut(digest_alg.output_len);
                this_chunk.copy_from_slice(t);
                rest
            };

            if out.is_empty() {
                return Ok(());
            }

            ctx = hmac::Context::with_key(&self.prk.0);
            ctx.update(t);
            n = n.checked_add(1).ok_or(error::Unspecified)?;
        }
    }
}

/// Deprecated shortcut for
/// `salt.extract(secret).expand(info).fill(out).unwrap()`.
#[deprecated(note = "Will be removed in the next release.")]
pub fn extract_and_expand(salt: &Salt, secret: &[u8], info: &[u8], out: &mut [u8]) {
    salt.extract(secret).expand(info).fill(out).unwrap()
}
