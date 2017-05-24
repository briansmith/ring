// Copyright 2016 Brian Smith.
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

//! Functionality shared by operations on private keys (ECC keygen and
//! ECDSA signing).

use {ec, error, rand};
use super::ops::*;
use super::verify_affine_point_is_on_the_curve;
use untrusted;

pub fn generate_private_key(ops: &PrivateKeyOps, rng: &rand::SecureRandom)
                            -> Result<ec::PrivateKey, error::Unspecified> {
    // [NSA Suite B Implementer's Guide to ECDSA] Appendix A.1.2, and
    // [NSA Suite B Implementer's Guide to NIST SP 800-56A] Appendix B.2,
    // "Key Pair Generation by Testing Candidates".
    //
    // [NSA Suite B Implementer's Guide to ECDSA]: doc/ecdsa.pdf.
    // [NSA Suite B Implementer's Guide to NIST SP 800-56A]: doc/ecdh.pdf.

    // TODO: The NSA guide also suggests, in appendix B.1, another mechanism
    // that would avoid the need to use `rng.fill()` more than once. It works
    // by generating an extra 64 bits of random bytes and then reducing the
    // output (mod n). Supposedly, this removes enough of the bias towards
    // small values from the modular reduction, but it isn't obvious that it is
    // sufficient. TODO: Figure out what we can do to mitigate the bias issue
    // and switch to the other mechanism.

    let num_limbs = ops.common.num_limbs;

    // XXX: The value 100 was chosen to match OpenSSL due to uncertainty of
    // what specific value would be better, but it seems bad to try 100 times.
    for _ in 0..100 {
        let mut candidate = [0; ec::SCALAR_MAX_BYTES];

        {
            // NSA Guide Steps 1, 2, and 3.
            //
            // Since we calculate the length ourselves, it is pointless to check
            // it, since we can only check it by doing the same calculation.
            let candidate = &mut candidate[..(num_limbs * LIMB_BYTES)];

            // NSA Guide Step 4.
            //
            // The requirement that the random number generator has the
            // requested security strength is delegated to `rng`.
            rng.fill(candidate)?;

            // NSA Guide Steps 5, 6, and 7.
            if check_scalar_big_endian_bytes(ops, candidate).is_err() {
                continue;
            }
        }

        // NSA Guide Step 8 is done in `public_from_private()`.

        // NSA Guide Step 9.
        return Ok(ec::PrivateKey {
            bytes: candidate,
        });
    }

    Err(error::Unspecified)
}


// The underlying X25519 and Ed25519 code uses an [u8; 32] to store the private
// key. To make the ECDH and ECDSA code similar to that, we also store the
// private key that way, which means we have to convert it to a Scalar whenever
// we need to use it.
#[inline]
pub fn private_key_as_scalar(ops: &PrivateKeyOps,
                             private_key: &ec::PrivateKey) -> Scalar {
    // This cannot fail because we know the private key is valid.
    scalar_from_big_endian_bytes(
        ops, &private_key.bytes[..(ops.common.num_limbs * LIMB_BYTES)]).unwrap()
}

pub fn check_scalar_big_endian_bytes(ops: &PrivateKeyOps, bytes: &[u8])
                                     -> Result<(), error::Unspecified> {
    debug_assert_eq!(bytes.len(), ops.common.num_limbs * LIMB_BYTES);
    scalar_from_big_endian_bytes(ops, bytes).map(|_| ())
}

// Parses a fixed-length (zero-padded) big-endian-encoded scalar in the range
// [1, n). This is constant-time with respect to the actual value *only if* the
// value is actually in range. In other words, this won't leak anything about a
// valid value, but it might leak small amounts of information about an invalid
// value (which constraint it failed).
pub fn scalar_from_big_endian_bytes(ops: &PrivateKeyOps, bytes: &[u8])
                                    -> Result<Scalar, error::Unspecified> {
    // [NSA Suite B Implementer's Guide to ECDSA] Appendix A.1.2, and
    // [NSA Suite B Implementer's Guide to NIST SP 800-56A] Appendix B.2,
    // "Key Pair Generation by Testing Candidates".
    //
    // [NSA Suite B Implementer's Guide to ECDSA]: doc/ecdsa.pdf.
    // [NSA Suite B Implementer's Guide to NIST SP 800-56A]: doc/ecdh.pdf.
    //
    // Steps 5, 6, and 7.
    //
    // XXX: The NSA guide says that we should verify that the random scalar is
    // in the range [0, n - 1) and then add one to it so that it is in the range
    // [1, n). Instead, we verify that the scalar is in the range [1, n). This
    // way, we avoid needing to compute or store the value (n - 1), we avoid the
    // need to implement a function to add one to a scalar, and we avoid needing
    // to convert the scalar back into an array of bytes.
    scalar_parse_big_endian_fixed_consttime(
        ops.common, untrusted::Input::from(bytes))
}

pub fn public_from_private(ops: &PrivateKeyOps, public_out: &mut [u8],
                           my_private_key: &ec::PrivateKey)
                           -> Result<(), error::Unspecified> {
    let elem_and_scalar_bytes = ops.common.num_limbs * LIMB_BYTES;
    debug_assert_eq!(public_out.len(), 1 + (2 * elem_and_scalar_bytes));
    let my_private_key = private_key_as_scalar(ops, my_private_key);
    let my_public_key = ops.point_mul_base(&my_private_key);
    public_out[0] = 4; // Uncompressed encoding.
    let (x_out, y_out) =
        (&mut public_out[1..]).split_at_mut(elem_and_scalar_bytes);

    // `big_endian_affine_from_jacobian` verifies that the point is not at
    // infinity and is on the curve.
    big_endian_affine_from_jacobian(ops, Some(x_out), Some(y_out),
                                    &my_public_key)
}

pub fn big_endian_affine_from_jacobian(ops: &PrivateKeyOps,
                                       x_out: Option<&mut [u8]>,
                                       y_out: Option<&mut [u8]>, p: &Point)
                                       -> Result<(), error::Unspecified> {
    let z = ops.common.point_z(p);

    // Since we restrict our private key to the range [1, n), the curve has
    // prime order, and we verify that the peer's point is on the curve,
    // there's no way that the result can be at infinity. But, use `assert!`
    // instead of `debug_assert!` anyway
    assert!(ops.common.elem_verify_is_not_zero(&z).is_ok());

    let x = ops.common.point_x(p);
    let y = ops.common.point_y(p);

    let zz_inv = ops.elem_inverse_squared(&z);

    let x_aff = ops.common.elem_product(&x, &zz_inv);

    // `y_aff` is needed to validate the point is on the curve. It is also
    // needed in the non-ECDH case where we need to output it.
    let y_aff = {
        let zzzz_inv = ops.common.elem_squared(&zz_inv);
        let zzz_inv = ops.common.elem_product(&z, &zzzz_inv);
        ops.common.elem_product(&y, &zzz_inv)
    };

    // If we validated our inputs correctly and then computed (x, y, z), then
    // (x, y, z) will be on the curve. See
    // `verify_affine_point_is_on_the_curve_scaled` for the motivation.
    verify_affine_point_is_on_the_curve(ops.common, (&x_aff, &y_aff))?;

    let num_limbs = ops.common.num_limbs;
    if let Some(x_out) = x_out {
        let x = ops.common.elem_unencoded(&x_aff);
        big_endian_from_limbs_padded(&x.limbs[..num_limbs], x_out);
    }
    if let Some(y_out) = y_out {
        let y = ops.common.elem_unencoded(&y_aff);
        big_endian_from_limbs_padded(&y.limbs[..num_limbs], y_out);
    }

    Ok(())
}
