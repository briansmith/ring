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

//! EdDSA Signatures.

use super::super::ops::*;
use core;
use crate::{error, private, signature};
use untrusted;

use super::digest::*;

/// Parameters for EdDSA signing and verification.
pub struct EdDSAParameters;

impl core::fmt::Debug for EdDSAParameters {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        write!(f, "ring::signature::ED25519")
    }
}

/// Verification of [Ed25519] signatures.
///
/// Ed25519 uses SHA-512 as the digest algorithm.
///
/// [Ed25519]: https://ed25519.cr.yp.to/
pub static ED25519: EdDSAParameters = EdDSAParameters {};

impl signature::VerificationAlgorithm for EdDSAParameters {
    fn verify(
        &self, public_key: untrusted::Input, msg: untrusted::Input, signature: untrusted::Input,
    ) -> Result<(), error::Unspecified> {
        let public_key = public_key.as_slice_less_safe();
        let public_key = slice_as_array_ref!(public_key, ELEM_LEN)?;

        let (signature_r, signature_s) = signature.read_all(error::Unspecified, |input| {
            let r = input.skip_and_get_input(ELEM_LEN)?;
            let r = r.as_slice_less_safe();
            // `r` is only used as a slice, so don't convert it to an array ref.

            let s = input.skip_and_get_input(SCALAR_LEN)?;
            let s = s.as_slice_less_safe();
            let s = slice_as_array_ref!(s, SCALAR_LEN).unwrap();

            Ok((r, s))
        })?;

        // Ensure `s` is not too large.
        if (signature_s[SCALAR_LEN - 1] & 0b11100000) != 0 {
            return Err(error::Unspecified);
        }

        let mut a = ExtPoint::from_encoded_point_vartime(public_key)?;
        a.invert_vartime();

        let h_digest = eddsa_digest(signature_r, public_key, msg.as_slice_less_safe());
        let h = digest_scalar(h_digest);

        let mut r = Point::new_at_infinity();
        unsafe { GFp_x25519_ge_double_scalarmult_vartime(&mut r, &h, &a, &signature_s) };
        let r_check = r.into_encoded_point();
        if signature_r != r_check {
            return Err(error::Unspecified);
        }
        Ok(())
    }
}

impl private::Sealed for EdDSAParameters {}

extern "C" {
    fn GFp_x25519_ge_double_scalarmult_vartime(
        r: &mut Point, a_coeff: &Scalar, a: &ExtPoint, b_coeff: &Scalar,
    );
}
