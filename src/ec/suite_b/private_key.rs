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

#[allow(unsafe_code)]
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
        let mut candidate_private_key = ec::PrivateKey {
            bytes: [0; ec::SCALAR_MAX_BYTES],
        };

        // NSA Guide Steps 1, 2, and 3.
        //
        // Since we calculate the length ourselves, it is pointless to check
        // it, since we can only check it by doing the same calculation.
        let num_bytes = num_limbs * LIMB_BYTES;

        // NSA Guide Step 4.
        //
        // The requirement that the random number generator has the requested
        // security strength is delegated to `rng`.
        try!(rng.fill(&mut candidate_private_key.bytes[..num_bytes]));

        // NSA Guide Steps 5, 6, and 7.
        //
        // XXX: The NSA guide says that we should verify that the random scalar
        // is in the range [0, n - 1) and then add one to it so that it is in
        // the range [1, n). Instead, we verify that the scalar is in the range
        // [1, n) like BoringSSL (et al.) does. This way, we avoid needing to
        // compute or store the value (n - 1), we avoid the need to implement
        // a function to add one to a scalar, and we avoid needing to convert
        // the scalar back into an array of bytes. TODO: Is there any security
        // advantage to the way the NSA suggests? There doesn't seem to be,
        // other than being less error prone w.r.t. accidentally generating
        // zero-valued keys.
        let scalar = private_key_as_scalar_(ops, &candidate_private_key);
        if !scalar_is_in_range(ops.common, &scalar) {
            continue;
        }

        // NSA Guide Step 8 is done in `public_from_private()`.

        // NSA Guide Step 9.
        return Ok(candidate_private_key);
    }

    Err(error::Unspecified)
}


// The underlying X25519 and Ed25519 code uses an [u8; 32] to store the private
// key. To make the ECDH and ECDSA code similar to that, we also store the
// private key that way, which means we have to convert it to a Scalar whenever
// we need to use it.
#[inline]
pub fn private_key_as_scalar(ops: &PrivateKeyOps, private_key: &ec::PrivateKey)
                             -> Scalar {
    let r = private_key_as_scalar_(ops, private_key);
    assert!(scalar_is_in_range(&ops.common, &r));
    r
}

// Like `private_key_as_scalar`, but without the assertions about the range of
// the value.
fn private_key_as_scalar_(ops: &PrivateKeyOps, private_key: &ec::PrivateKey)
                          -> Scalar {
    let num_limbs = ops.common.num_limbs;
    let bytes = &private_key.bytes;
    let mut limbs = [0; MAX_LIMBS];
    for i in 0..num_limbs {
        let mut limb = 0;
        for j in 0..LIMB_BYTES {
            limb = (limb << 8) |
                    (bytes[((num_limbs - i - 1) * LIMB_BYTES) + j] as Limb);
        }
        limbs[i] = limb;
    }
    Scalar::from_limbs_unchecked(&limbs)
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
    let z = ops.common.point_z(&p);

    // Since we restrict our private key to the range [1, n), the curve has
    // prime order, and we verify that the peer's point is on the curve,
    // there's no way that the result can be at infinity. But, use `assert!`
    // instead of `debug_assert!` anyway
    assert!(ops.common.elem_verify_is_not_zero(&z).is_ok());

    let x = ops.common.point_x(&p);
    let y = ops.common.point_y(&p);

    let z_inv = ops.elem_inverse(&z);
    let zz_inv = ops.common.elem_squared(&z_inv);
    let zzz_inv = ops.common.elem_product(&z_inv, &zz_inv);

    let x_aff = ops.common.elem_product(&x, &zz_inv);
    let y_aff = ops.common.elem_product(&y, &zzz_inv);

    // If we validated our inputs correctly and then computed (x, y, z), then
    // (x, y, z) will be on the curve. See
    // `verify_affine_point_is_on_the_curve_scaled` for the motivation.
    try!(verify_affine_point_is_on_the_curve(ops.common, (&x_aff, &y_aff)));

    let num_limbs = ops.common.num_limbs;
    if let Some(x_out) = x_out {
        let x_decoded = ops.common.elem_decoded(&x_aff);
        big_endian_from_limbs(x_out, &x_decoded.limbs[..num_limbs]);
    }
    if let Some(y_out) = y_out {
        let y_decoded = ops.common.elem_decoded(&y_aff);
        big_endian_from_limbs(y_out, &y_decoded.limbs[..num_limbs]);
    }

    Ok(())
}

fn big_endian_from_limbs(out: &mut [u8], limbs: &[Limb]) {
    let num_limbs = limbs.len();
    debug_assert_eq!(out.len(), num_limbs * LIMB_BYTES);
    for i in 0..num_limbs {
        let mut limb = limbs[i];
        for j in 0..LIMB_BYTES {
            out[((num_limbs - i - 1) * LIMB_BYTES) + (LIMB_BYTES - j - 1)]
                = (limb & 0xff) as u8;
            limb >>= 8;
        }
    }
}

fn scalar_is_in_range(ops: &CommonOps, candidate_scalar: &Scalar) -> bool {
    let range = Range::from_max_exclusive(&ops.n.limbs[..ops.num_limbs]);
    range.are_limbs_within(&candidate_scalar.limbs[..ops.num_limbs])
}

#[cfg(test)]
pub mod test_util {
    use super::super::ops::Limb;

    pub fn big_endian_from_limbs(out: &mut [u8], limbs: &[Limb]) {
        super::big_endian_from_limbs(out, limbs)
    }
}
