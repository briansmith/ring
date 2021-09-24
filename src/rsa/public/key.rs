// Copyright 2015-2021 Brian Smith.
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

use super::{Exponent, Modulus};
use crate::{
    bits, error,
    io::{self, der, der_writer},
};
use alloc::boxed::Box;

/// An RSA Public Key.
#[derive(Clone)]
pub struct Key {
    n: Modulus,
    e: Exponent,
    serialized: Box<[u8]>,
}

derive_debug_self_as_ref_hex_bytes!(Key);

impl Key {
    pub(in super::super) fn from_modulus_and_exponent(
        n: untrusted::Input,
        e: untrusted::Input,
        n_min_bits: bits::BitLength,
        n_max_bits: bits::BitLength,
        e_min_value: Exponent,
    ) -> Result<Self, error::KeyRejected> {
        let n_bytes = n;
        let e_bytes = e;

        // This is an incomplete implementation of NIST SP800-56Br1 Section
        // 6.4.2.2, "Partial Public-Key Validation for RSA." That spec defers
        // to NIST SP800-89 Section 5.3.3, "(Explicit) Partial Public Key
        // Validation for RSA," "with the caveat that the length of the modulus
        // shall be a length that is specified in this Recommendation." In
        // SP800-89, two different sets of steps are given, one set numbered,
        // and one set lettered. TODO: Document this in the end-user
        // documentation for RSA keys.

        let n = Modulus::from_be_bytes(n, n_min_bits..=n_max_bits)?;

        let e = Exponent::from_be_bytes(e, e_min_value)?;

        // If `n` is less than `e` then somebody has probably accidentally swapped
        // them. The largest acceptable `e` is smaller than the smallest acceptable
        // `n`, so no additional checks need to be done.

        // XXX: Steps 4 & 5 / Steps d, e, & f are not implemented. This is also the
        // case in most other commonly-used crypto libraries.

        // TODO: Remove this re-parsing, and stop allocating this here.
        // Instead we should serialize on demand without allocation, from
        // `Modulus::be_bytes()` and `Exponent::be_bytes()`.
        let n_bytes = io::Positive::from_be_bytes(n_bytes)
            .map_err(|_: error::Unspecified| error::KeyRejected::unexpected_error())?;
        let e_bytes = io::Positive::from_be_bytes(e_bytes)
            .map_err(|_: error::Unspecified| error::KeyRejected::unexpected_error())?;
        let serialized = der_writer::write_all(der::Tag::Sequence, &|output| {
            der_writer::write_positive_integer(output, &n_bytes);
            der_writer::write_positive_integer(output, &e_bytes);
        });

        Ok(Self { n, e, serialized })
    }

    /// The public modulus.
    #[inline]
    pub fn n(&self) -> &Modulus {
        &self.n
    }

    /// The public exponent.
    #[inline]
    pub fn e(&self) -> Exponent {
        self.e
    }
}

// XXX: Refactor `signature::KeyPair` to get rid of this.
impl AsRef<[u8]> for Key {
    fn as_ref(&self) -> &[u8] {
        &self.serialized
    }
}
