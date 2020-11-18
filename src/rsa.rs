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

// *R* and *r* in Montgomery math refer to different things, so we always use
// `R` to refer to *R* to avoid confusion, even when that's against the normal
// naming conventions. Also the standard camelCase names are used for `KeyPair`
// components.

//! Low-level RSA primitives.

use crate::{
    arithmetic::bigint,
    bits, error,
    io::{self, der},
    limb,
};

mod bounds;
pub(crate) mod padding;

// Maximum RSA modulus size supported for signature verification (in bytes).
const PUBLIC_KEY_PUBLIC_MODULUS_MAX_LEN: usize = bigint::MODULUS_MAX_LIMBS * limb::LIMB_BYTES;

/// Parameters for RSA verification.
#[derive(Debug)]
pub struct RsaParameters {
    padding_alg: &'static dyn padding::Verification,
    min_bits: bits::BitLength,
}

impl Bounds for RsaParameters {
    fn n_min_bits(&self) -> bits::BitLength {
        self.min_bits
    }

    fn n_max_bits(&self) -> bits::BitLength {
        bits::BitLength::from_usize_bytes(PUBLIC_KEY_PUBLIC_MODULUS_MAX_LEN).unwrap()
    }

    fn e_min_value(&self) -> u64 {
        3
    }
}

fn parse_public_key(
    input: untrusted::Input,
) -> Result<(io::Positive, io::Positive), error::Unspecified> {
    input.read_all(error::Unspecified, |input| {
        der::nested(input, der::Tag::Sequence, error::Unspecified, |input| {
            let n = der::positive_integer(input)?;
            let e = der::positive_integer(input)?;
            Ok((n, e))
        })
    })
}

// Type-level representation of an RSA public modulus *n*. See
// `super::bigint`'s modulue-level documentation.
#[derive(Copy, Clone)]
enum N {}

unsafe impl bigint::PublicModulus for N {}

pub(crate) mod keypair;
pub(crate) mod public;

pub(crate) mod verification;

pub use self::{
    bounds::Bounds,
    keypair::{Components as RsaKeyPairComponents, RsaKeyPair},
    padding::{
        OaepEncoding, RSA_OAEP_2048_8192_SHA1_FOR_LEGACY_USE_ONLY, RSA_OAEP_2048_8192_SHA256,
    },
    public::{Components as RsaPublicKeyComponents, Key as RsaPublicKey},
};
