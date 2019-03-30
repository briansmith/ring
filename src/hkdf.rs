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
//!
//! In most situations, it is best to use `extract_and_expand` to do both the
//! HKDF-Extract and HKDF-Expand as one atomic operation. It is only necessary
//! to use the separate `expand` and `extract` functions if a single derived
//! `PRK` (defined in RFC 5869) is used more than once.
//!
//! [RFC 5869]: https://tools.ietf.org/html/rfc5869

use crate::{digest, error, hmac};

/// A salt for HKDF operations.
///
/// Constructing a `Salt` is relatively expensive so it is good to reuse a
/// `Salt` object instead of re-constructing `Salt`s with the same value.
#[derive(Debug)]
pub struct Salt(hmac::SigningKey);

impl Salt {
    /// Constructs a new `Salt` with the given value.
    pub fn new(digest_algorithm: &'static digest::Algorithm, value: &[u8]) -> Self {
        Salt(hmac::SigningKey::new(digest_algorithm, value))
    }

    /// The HKDF-Extract operation.
    ///
    /// | Parameter                 | RFC 5869 Term
    /// |---------------------------|--------------
    /// | `salt.digest_algorithm()` | Hash
    /// | `secret`                  | IKM (Input Keying Material)
    /// | [return value]            | PRK
    pub fn extract(&self, secret: &[u8]) -> Prk {
        // The spec says that if no salt is provided then a key of
        // `digest_alg.output_len` bytes of zeros is used. But, HMAC keys are
        // already zero-padded to the block length, which is larger than the output
        // length of the extract step (the length of the digest). Consequently, the
        // `SigningKey` constructor will automatically do the right thing for a
        // zero-length string.
        let salt = &self.0;
        let prk = hmac::sign(salt, secret);
        Prk(hmac::SigningKey::new(salt.digest_algorithm(), prk.as_ref()))
    }
}

/// A HKDF PRK (pseudorandom key).
#[derive(Debug)]
pub struct Prk(hmac::SigningKey);

impl Prk {
    /// `prk` should be the return value of an earlier call to `extract`.
    ///
    /// | Parameter  | RFC 5869 Term
    /// |------------|--------------
    /// | prk        | PRK
    /// | info       | info
    /// | out        | OKM (Output Keying Material)
    /// | out.len()  | L (Length of output keying material in bytes)
    #[inline]
    pub fn expand<'a>(&'a self, info: &'a [u8]) -> Okm<'a> { Okm { prk: self, info } }
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

        let mut ctx = hmac::SigningContext::with_key(&self.prk.0);

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

            ctx = hmac::SigningContext::with_key(&self.prk.0);
            ctx.update(t);
            n = n.checked_add(1).ok_or(error::Unspecified)?;
        }
    }
}

/// Deprecated shortcut for `salt.extract(secret).expand(info,
/// out).fill(out).unwrap()`.
#[deprecated(note = "Use `salt.extract(secret).expand(info).fill(out)`.
                     Will be removed in the next release.")]
pub fn extract_and_expand(salt: &Salt, secret: &[u8], info: &[u8], out: &mut [u8]) {
    salt.extract(secret).expand(info).fill(out).unwrap()
}
