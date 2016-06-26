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

use ec;
use super::ops::*;

// The underlying X25519 and Ed25519 code uses an [u8; 32] to store the private
// key. To make the ECDH and ECDSA code similar to that, we also store the
// private key that way, which means we have to convert it to a Scalar whenever
// we need to use it.
pub fn private_key_as_scalar(ops: &PrivateKeyOps, private_key: &ec::PrivateKey)
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
    //TODO:
    //debug_assert!(limbs_less_than_limbs(&limbs[..num_limbs],
    //                                    &ops.common.n.limbs[..num_limbs]))
    Scalar::from_limbs_unchecked(&limbs)
}

pub fn public_from_private(ops: &PrivateKeyOps, public_out: &mut [u8],
                            my_private_key: &ec::PrivateKey)
                            -> Result<(), ()> {
    let elem_and_scalar_bytes = ops.common.num_limbs * LIMB_BYTES;
    debug_assert_eq!(public_out.len(), 1 + (2 * elem_and_scalar_bytes));
    let my_private_key = private_key_as_scalar(ops, my_private_key);
    // TODO: what does the spec call this?
    let my_public_key = try!(ops.base_point_mult(&my_private_key));

    // XXX: Is this needed?
    // try!(ops.common.elem_verify_is_not_zero(&z));

    public_out[0] = 4; // Uncompressed encoding.
    let (x_out, y_out) =
        (&mut public_out[1..]).split_at_mut(elem_and_scalar_bytes);
    big_endian_affine_from_jacobian(ops, Some(x_out), Some(y_out),
                                    &my_public_key);

    Ok(())
}

pub fn big_endian_affine_from_jacobian(ops: &PrivateKeyOps,
                                       x_out: Option<&mut [u8]>,
                                       y_out: Option<&mut [u8]>,
                                       &(ref x, ref y, ref z):
                                            &(Elem, Elem, Elem)) {
    debug_assert!(ops.common.elem_verify_is_not_zero(z).is_ok());

    let z_inv = ops.elem_inverse(&z);
    let zz_inv = ops.common.elem_sqr(&z_inv);

    // Instead of converting `x` from Montgomery encoding and then
    // (separately) converting the `y` coordinate from Montgomery encoding,
    // convert the common factor `zz_inv` once now, saving one reduction.
    let zz_inv = ops.common.elem_decoded(&zz_inv);

    let num_limbs = ops.common.num_limbs;

    if let Some(x_out) = x_out {
        let x_decoded = ops.common.elem_mul_mixed(x, &zz_inv);
        big_endian_from_limbs(x_out, &x_decoded.limbs[..num_limbs]);
    }

    if let Some(y_out) = y_out {
        let zzz_inv = ops.common.elem_mul_mixed(&z_inv, &zz_inv);
        let y_decoded = ops.common.elem_mul_mixed(y, &zzz_inv);
        big_endian_from_limbs(y_out, &y_decoded.limbs[..num_limbs]);
    }
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
