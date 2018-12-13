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

//! X25519 Key agreement.

use super::ops;
use crate::{agreement, constant_time, ec, error, polyfill::convert::*, rand};
use untrusted;

static CURVE25519: ec::Curve = ec::Curve {
    public_key_len: PUBLIC_KEY_LEN,
    elem_and_scalar_len: ELEM_AND_SCALAR_LEN,
    id: ec::CurveID::Curve25519,
    check_private_key_bytes: x25519_check_private_key_bytes,
    generate_private_key: x25519_generate_private_key,
    public_from_private: x25519_public_from_private,
};

/// X25519 (ECDH using Curve25519) as described in [RFC 7748].
///
/// Everything is as described in RFC 7748. Key agreement will fail if the
/// result of the X25519 operation is zero; see the notes on the
/// "all-zero value" in [RFC 7748 section 6.1].
///
/// [RFC 7748]: https://tools.ietf.org/html/rfc7748
/// [RFC 7748 section 6.1]: https://tools.ietf.org/html/rfc7748#section-6.1
pub static X25519: agreement::Algorithm = agreement::Algorithm {
    curve: &CURVE25519,
    ecdh: x25519_ecdh,
};

fn x25519_check_private_key_bytes(bytes: &[u8]) -> Result<(), error::Unspecified> {
    debug_assert_eq!(bytes.len(), PRIVATE_KEY_LEN);
    Ok(())
}

fn x25519_generate_private_key(
    rng: &rand::SecureRandom,
) -> Result<ec::PrivateKey, error::Unspecified> {
    let mut result = ec::PrivateKey {
        bytes: [0; ec::SCALAR_MAX_BYTES],
    };
    rng.fill(&mut result.bytes[..PRIVATE_KEY_LEN])?;
    Ok(result)
}

fn x25519_public_from_private(
    public_out: &mut [u8; ec::PUBLIC_KEY_MAX_LEN], private_key: &ec::PrivateKey,
) -> Result<(), error::Unspecified> {
    let (public_out, _) = public_out.into_();
    let (private_key, _) = (&private_key.bytes).into_();
    unsafe {
        GFp_x25519_public_from_private(public_out, private_key);
    }
    Ok(())
}

fn x25519_ecdh(
    out: &mut [u8], my_private_key: &ec::PrivateKey, peer_public_key: untrusted::Input,
) -> Result<(), error::Unspecified> {
    // XXX: This shouldn't require dynamic checks, but rustc can't slice an
    // array reference to a shorter array reference. TODO(perf): Fix this.
    let my_private_key = (&my_private_key.bytes[..PRIVATE_KEY_LEN]).try_into_()?;
    let peer_public_key: &[u8; PUBLIC_KEY_LEN] =
        peer_public_key.as_slice_less_safe().try_into_()?;

    unsafe {
        GFp_x25519_scalar_mult(out.try_into_()?, my_private_key, peer_public_key);
    }

    let zeros: SharedSecret = [0; SHARED_SECRET_LEN];
    if constant_time::verify_slices_are_equal(out, &zeros).is_ok() {
        // All-zero output results when the input is a point of small order.
        return Err(error::Unspecified);
    }

    Ok(())
}

const ELEM_AND_SCALAR_LEN: usize = ops::ELEM_LEN;

// An X25519 private key as an unmasked scalar.
type PrivateKey = [u8; PRIVATE_KEY_LEN];
const PRIVATE_KEY_LEN: usize = ELEM_AND_SCALAR_LEN;

// An X25519 public key as an encoded Curve25519 point.
type PublicKey = [u8; PUBLIC_KEY_LEN];
const PUBLIC_KEY_LEN: usize = ELEM_AND_SCALAR_LEN;

// An X25519 shared secret as an encoded Curve25519 point.
type SharedSecret = [u8; SHARED_SECRET_LEN];
const SHARED_SECRET_LEN: usize = ELEM_AND_SCALAR_LEN;

extern "C" {
    fn GFp_x25519_public_from_private(public_key_out: &mut PublicKey, private_key: &PrivateKey);
    fn GFp_x25519_scalar_mult(
        out: &mut ops::EncodedPoint, scalar: &ops::Scalar, point: &ops::EncodedPoint,
    );
}

impl_array_split!(u8, PUBLIC_KEY_LEN, ec::PUBLIC_KEY_MAX_LEN - PUBLIC_KEY_LEN);
