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

use super::*;
use super::{Mont, elem_sqr_mul, elem_sqr_mul_acc};

macro_rules! p256_limbs {
    [$limb_7:expr, $limb_6:expr, $limb_5:expr, $limb_4:expr,
     $limb_3:expr, $limb_2:expr, $limb_1:expr, $limb_0:expr] => {
        limbs![0, 0, 0, 0,
               $limb_7, $limb_6, $limb_5, $limb_4,
               $limb_3, $limb_2, $limb_1, $limb_0]
    };
}


pub static COMMON_OPS: CommonOps = CommonOps {
    num_limbs: 256 / LIMB_BITS,

    q: Mont {
        p: p256_limbs![0xffffffff, 0x00000001, 0x00000000, 0x00000000,
                       0x00000000, 0xffffffff, 0xffffffff, 0xffffffff],
        rr: p256_limbs![0x00000004, 0xfffffffd, 0xffffffff, 0xfffffffe,
                        0xfffffffb, 0xffffffff, 0x00000000, 0x00000003],
    },

    n: ElemDecoded {
        limbs: p256_limbs![0xffffffff, 0x00000000, 0xffffffff, 0xffffffff,
                           0xbce6faad, 0xa7179e84, 0xf3b9cac2, 0xfc632551],
    },

    a: Elem {
        limbs: p256_limbs![0xfffffffc, 0x00000004, 0x00000000, 0x00000000,
                           0x00000003, 0xffffffff, 0xffffffff, 0xfffffffc],
    },
    b: Elem {
        limbs: p256_limbs![0xdc30061d, 0x04874834, 0xe5a220ab, 0xf7212ed6,
                           0xacf005cd, 0x78843090, 0xd89cdf62, 0x29c4bddf],
    },

    elem_add_impl: ecp_nistz256_add,
    elem_mul_mont: ecp_nistz256_mul_mont,
    elem_sqr_mont: ecp_nistz256_sqr_mont,

    ec_group: &EC_GROUP_P256,
};


pub static PRIVATE_KEY_OPS: PrivateKeyOps = PrivateKeyOps {
    common: &COMMON_OPS,
    elem_inv: p256_elem_inv,
    point_mul_base_impl: p256_point_mul_base_impl,
    point_mul_impl: p256_point_mul_impl,
};

fn p256_elem_inv(a: &Elem) -> Elem {
    // Calculate the modular inverse of field element |a| using Fermat's Little
    // Theorem:
    //
    //    a**-1 (mod q) == a**(q - 2) (mod q)
    //
    // The exponent (q - 2) is:
    //
    //    0xffffffff00000001000000000000000000000000fffffffffffffffffffffffd

    #[inline]
    fn sqr_mul(a: &Elem, squarings: usize, b: &Elem) -> Elem {
        elem_sqr_mul(&COMMON_OPS, a, squarings, b)
    }

    #[inline]
    fn sqr_mul_acc(a: &mut Elem, squarings: usize, b: &Elem) {
        elem_sqr_mul_acc(&COMMON_OPS, a, squarings, b)
    }

    let b_1 = &a;
    let b_11     = sqr_mul(&b_1,  0 +  1, &b_1);
    let f        = sqr_mul(&b_11, 0 +  2, &b_11);
    let ff       = sqr_mul(&f,    0 +  4, &f);
    let ffff     = sqr_mul(&ff,   0 +  8, &ff);
    let ffffffff = sqr_mul(&ffff, 0 + 16, &ffff);

    // ffffffff00000001
    let mut acc = sqr_mul(&ffffffff, 31 + 1, &b_1);

    // ffffffff00000001000000000000000000000000ffffffff
    sqr_mul_acc(&mut acc, 96 + 32, &ffffffff);

    // ffffffff00000001000000000000000000000000ffffffffffffffff
    sqr_mul_acc(&mut acc, 0 + 32, &ffffffff);

    // ffffffff00000001000000000000000000000000ffffffffffffffffffff
    sqr_mul_acc(&mut acc, 0 + 16, &ffff);

    // ffffffff00000001000000000000000000000000ffffffffffffffffffffff
    sqr_mul_acc(&mut acc, 0 + 8, &ff);

    // ffffffff00000001000000000000000000000000fffffffffffffffffffffff
    sqr_mul_acc(&mut acc, 0 + 4, &f);

    // ffffffff00000001000000000000000000000000fffffffffffffffffffffffd
    sqr_mul_acc(&mut acc, 0 + 2, &b_11);
    sqr_mul(&acc, 1 + 1, &b_1)
}

fn p256_point_mul_base_impl(g_scalar: &Scalar) -> Result<Point, ()> {
    let mut r = Point::new_at_infinity();
    unsafe {
        ecp_nistz256_point_mul_base(r.xyz.as_mut_ptr(),
                                    g_scalar.limbs.as_ptr());
    }
    Ok(r)
}

fn p256_point_mul_impl(p_scalar: &Scalar, &(ref p_x, ref p_y): &(Elem, Elem))
                       -> Result<Point, ()> {
    let mut r = Point::new_at_infinity();
    unsafe {
        ecp_nistz256_point_mul(r.xyz.as_mut_ptr(), p_scalar.limbs.as_ptr(),
                               p_x.limbs.as_ptr(), p_y.limbs.as_ptr());
    }
    Ok(r)
}


pub static PUBLIC_KEY_OPS: PublicKeyOps = PublicKeyOps {
    common: &COMMON_OPS,
};


pub static PUBLIC_SCALAR_OPS: PublicScalarOps = PublicScalarOps {
    public_key_ops: &PUBLIC_KEY_OPS,

    q_minus_n: ElemDecoded {
        limbs: p256_limbs![0, 0, 0, 0,
                           0x43190553, 0x58e8617b, 0x0c46353d, 0x039cdaae],
    },

    scalar_inv_to_mont_impl: GFp_p256_scalar_inv_to_mont,
    scalar_mul_mont: GFp_p256_scalar_mul_mont,
};


extern {
    fn ecp_nistz256_add(r: *mut Limb/*[COMMON_OPS.num_limbs]*/,
                        a: *const Limb/*[COMMON_OPS.num_limbs]*/,
                        b: *const Limb/*[COMMON_OPS.num_limbs]*/);
    fn ecp_nistz256_mul_mont(r: *mut Limb/*[COMMON_OPS.num_limbs]*/,
                             a: *const Limb/*[COMMON_OPS.num_limbs]*/,
                             b: *const Limb/*[COMMON_OPS.num_limbs]*/);
    fn ecp_nistz256_sqr_mont(r: *mut Limb/*[COMMON_OPS.num_limbs]*/,
                             a: *const Limb/*[COMMON_OPS.num_limbs]*/);

    fn ecp_nistz256_point_mul(r: *mut Limb/*[3][COMMON_OPS.num_limbs]*/,
                              p_scalar: *const Limb/*[COMMON_OPS.num_limbs]*/,
                              p_x: *const Limb/*[COMMON_OPS.num_limbs]*/,
                              p_y: *const Limb/*[COMMON_OPS.num_limbs]*/);
    fn ecp_nistz256_point_mul_base(r: *mut Limb/*[3][COMMON_OPS.num_limbs]*/,
                                   g_scalar: *const Limb/*[COMMON_OPS.num_limbs]*/);

    fn GFp_p256_scalar_inv_to_mont(r: *mut Limb/*[COMMON_OPS.num_limbs]*/,
                                   a: *const Limb/*[COMMON_OPS.num_limbs]*/);
    fn GFp_p256_scalar_mul_mont(r: *mut Limb/*[COMMON_OPS.num_limbs]*/,
                                a: *const Limb/*[COMMON_OPS.num_limbs]*/,
                                b: *const Limb/*[COMMON_OPS.num_limbs]*/);

    static EC_GROUP_P256: EC_GROUP;
}


#[cfg(feature = "internal_benches")]
mod internal_benches {
    use super::*;
    use super::super::internal_benches::*;

    bench_curve!(&[
        Scalar { limbs: LIMBS_1 },
        Scalar { limbs: LIMBS_ALTERNATING_10, },
        Scalar { // n - 1
            limbs: p256_limbs![0xffffffff, 0x00000000, 0xffffffff, 0xffffffff,
                               0xbce6faad, 0xa7179e84, 0xf3b9cac2,
                               0xfc632551 - 1],
        },
    ]);
}
