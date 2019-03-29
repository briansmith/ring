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

use crate::{digest, hmac};

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
pub struct Prk(hmac::SigningKey);

impl Prk {
    /// Fills `out` with the output of the HKDF-Expand operation for the given
    /// inputs.
    ///
    /// `prk` should be the return value of an earlier call to `extract`.
    ///
    /// | Parameter  | RFC 5869 Term
    /// |------------|--------------
    /// | prk        | PRK
    /// | info       | info
    /// | out        | OKM (Output Keying Material)
    /// | out.len()  | L (Length of output keying material in bytes)
    ///
    /// # Panics
    ///
    /// `expand` panics if the requested output length is larger than 255 times
    /// the size of the digest algorithm, i.e. if
    /// `out.len() > 255 * salt.digest_algorithm().output_len`. This is the
    /// limit imposed by the HKDF specification, and is necessary to prevent
    /// overflow of the 8-bit iteration counter in the expansion step.
    pub fn expand(&self, info: &[u8], out: &mut [u8]) {
        let prk = &self.0;
        let digest_alg = prk.digest_algorithm();
        assert!(out.len() <= 255 * digest_alg.output_len);
        assert!(digest_alg.block_len >= digest_alg.output_len);

        let mut ctx = hmac::SigningContext::with_key(prk);

        let mut n = 1u8;
        let mut pos = 0;
        loop {
            ctx.update(info);
            ctx.update(&[n]);

            let t = ctx.sign();

            // Append `t` to the output.
            let to_copy = if out.len() - pos < digest_alg.output_len {
                out.len() - pos
            } else {
                digest_alg.output_len
            };
            let t_bytes = t.as_ref();
            for i in 0..to_copy {
                out[pos + i] = t_bytes[i];
            }
            if to_copy < digest_alg.output_len {
                break;
            }
            pos += digest_alg.output_len;

            ctx = hmac::SigningContext::with_key(prk);
            ctx.update(t_bytes);
            n += 1;
        }
    }
}

/// Deprecated shortcut for `salt.extract(secret).expand(info, out)`.
#[deprecated(note = "Use `salt.extract(secret).expand(info, out)`.
                     Will be removed in the next release.")]
pub fn extract_and_expand(salt: &Salt, secret: &[u8], info: &[u8], out: &mut [u8]) {
    salt.extract(secret).expand(info, out)
}
