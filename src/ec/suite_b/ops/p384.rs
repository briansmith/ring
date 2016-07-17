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

use bssl;
use core;
use super::*;
use super::{GFp_suite_b_public_twin_mult, elem_sqr_mul, elem_sqr_mul_acc,
            Mont, ab_assign, rab};


macro_rules! p384_limbs {
    [$limb_b:expr, $limb_a:expr, $limb_9:expr, $limb_8:expr,
     $limb_7:expr, $limb_6:expr, $limb_5:expr, $limb_4:expr,
     $limb_3:expr, $limb_2:expr, $limb_1:expr, $limb_0:expr] => {
        limbs![$limb_b, $limb_a, $limb_9, $limb_8,
               $limb_7, $limb_6, $limb_5, $limb_4,
               $limb_3, $limb_2, $limb_1, $limb_0]
    };
}


pub static COMMON_OPS: CommonOps = CommonOps {
    num_limbs: 384 / LIMB_BITS,

    q: Mont {
        p: p384_limbs![0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
                       0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe,
                       0xffffffff, 0x00000000, 0x00000000, 0xffffffff],
        rr: limbs![0, 0, 0, 1, 2, 0, 0xfffffffe, 0, 2, 0, 0xfffffffe, 1 ],
    },

    n: ElemDecoded {
        limbs: p384_limbs![0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
                           0xffffffff, 0xffffffff, 0xc7634d81, 0xf4372ddf,
                           0x581a0db2, 0x48b0a77a, 0xecec196a, 0xccc52973],
    },

    a: Elem {
        limbs: p384_limbs![0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
                           0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffb,
                           0xfffffffc, 0x00000000, 0x00000003, 0xfffffffc],
    },
    b: Elem {
        limbs: p384_limbs![0xcd08114b, 0x604fbff9, 0xb62b21f4, 0x1f022094,
                           0xe3374bee, 0x94938ae2, 0x77f2209b, 0x1920022e,
                           0xf729add8, 0x7a4c32ec, 0x08118871, 0x9d412dcc],
    },

    elem_add_impl: GFp_p384_elem_add,
    elem_mul_mont: GFp_p384_elem_mul_mont,
    elem_sqr_mont: GFp_p384_elem_sqr_mont,

    ec_group: &EC_GROUP_P384,
};


pub static PRIVATE_KEY_OPS: PrivateKeyOps = PrivateKeyOps {
    common: &COMMON_OPS,
    elem_inv: p384_elem_inv,
    point_mul_base_impl: p384_point_mul_base_impl,
    point_mul_impl: p384_point_mul_impl,
};

fn p384_elem_inv(a: &Elem) -> Elem {
    // Calculate the modular inverse of field element |a| using Fermat's Little
    // Theorem:
    //
    //    a**-1 (mod q) == a**(q - 2) (mod q)
    //
    // The exponent (q - 2) is:
    //
    //    0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe\
    //      ffffffff0000000000000000fffffffd

    #[inline]
    fn sqr_mul(a: &Elem, squarings: usize, b: &Elem) -> Elem {
        elem_sqr_mul(&COMMON_OPS, a, squarings, b)
    }

    #[inline]
    fn sqr_mul_acc(a: &mut Elem, squarings: usize, b: &Elem) {
        elem_sqr_mul_acc(&COMMON_OPS, a, squarings, b)
    }

    let b_1 = &a;
    let b_11    = sqr_mul(&b_1,    0 + 1, &b_1);
    let f       = sqr_mul(&b_11,   0 + 2, &b_11);
    let ff      = sqr_mul(&f,      0 + 4, &f);
    let ffff    = sqr_mul(&ff,     0 + 8, &ff);
    let ffffff  = sqr_mul(&ffff,   0 + 8, &ff);
    let fffffff = sqr_mul(&ffffff, 0 + 4, &f);

    let b_1 = &a;

    let ffffffffffffff = sqr_mul(&fffffff, 0 + 28, &fffffff);

    let ffffffffffffffffffffffffffff =
        sqr_mul(&ffffffffffffff, 0 + 56, &ffffffffffffff);

    // ffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    let mut acc = sqr_mul(&ffffffffffffffffffffffffffff, 0 + 112,
                          &ffffffffffffffffffffffffffff);

    // fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff */
    sqr_mul_acc(&mut acc, 0 + 28, &fffffff);

    // fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff[11]
    sqr_mul_acc(&mut acc, 0 + 2, &b_11);

    // fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff[111]
    sqr_mul_acc(&mut acc, 0 + 1, &b_1);

    // fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffff
    sqr_mul_acc(&mut acc, 1 + 28, &fffffff);

    // fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff
    sqr_mul_acc(&mut acc, 0 + 4, &f);

    // fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff
    // 0000000000000000fffffff
    sqr_mul_acc(&mut acc, 64 + 28, &fffffff);

    // fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff
    // 0000000000000000fffffffd
    sqr_mul_acc(&mut acc, 0 + 2, &b_11);
    sqr_mul(&acc, 1 + 1, &b_1)
}


fn p384_point_mul_base_impl(a: &Scalar) -> Result<Point, ()> {
    // XXX: GFp_suite_b_public_twin_mult isn't always constant time and
    // shouldn't be used for this. TODO: Replace use of this with the use
    // of an always-constant-time implementation.
    let mut p = Point::new_at_infinity();
    try!(bssl::map_result(unsafe {
        GFp_suite_b_public_twin_mult(COMMON_OPS.ec_group,
                                     p.xyz.as_mut_ptr(),
                                     a.limbs.as_ptr(), // g_scalar
                                     core::ptr::null(), // p_scalar
                                     core::ptr::null(), // p_x
                                     core::ptr::null()) // p_y
    }));
    Ok(p)
}

pub fn p384_point_mul_impl(s: &Scalar, &(ref x, ref y): &(Elem, Elem))
                           -> Result<Point, ()> {
    // XXX: GFp_suite_b_public_twin_mult isn't always constant time and
    // shouldn't be used for this. TODO: Replace use of this with the use of an
    // always-constant-time implementation.
    let mut p = Point::new_at_infinity();
    try!(bssl::map_result(unsafe {
        GFp_suite_b_public_twin_mult(COMMON_OPS.ec_group, p.xyz.as_mut_ptr(),
                                     core::ptr::null(), s.limbs.as_ptr(),
                                     x.limbs.as_ptr(), y.limbs.as_ptr())
    }));
    Ok(p)
}


pub static PUBLIC_KEY_OPS: PublicKeyOps = PublicKeyOps {
    common: &COMMON_OPS,
};


pub static PUBLIC_SCALAR_OPS: PublicScalarOps = PublicScalarOps {
    public_key_ops: &PUBLIC_KEY_OPS,

    q_minus_n: ElemDecoded {
        limbs: p384_limbs![0, 0, 0, 0,
                           0, 0, 0x389cb27e, 0x0bc8d21f,
                           0x1313e696, 0x333ad68c, 0xa7e5f24c, 0xb74f5885],
    },

    scalar_inv_to_mont_impl: p384_scalar_inv_to_mont,
    scalar_mul_mont: GFp_p384_scalar_mul_mont,
};

fn p384_scalar_inv_to_mont(a: &Scalar) -> ScalarMont {
    // Calculate the modular inverse of scalar |a| using Fermat's Little
    // Theorem:
    //
    //   a**-1 (mod n) == a**(n - 2) (mod n)
    //
    // The exponent (n - 2) is:
    //
    //     0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf\
    //       581a0db248b0a77aecec196accc52971.

    // XXX(perf): This hasn't been optimized at all. TODO: optimize.

    fn mul(a: &ScalarMont, b: &ScalarMont) -> ScalarMont {
        ScalarMont { limbs: rab(GFp_p384_scalar_mul_mont, &a.limbs, &b.limbs) }
    }

    fn sqr(a: &ScalarMont) -> ScalarMont {
        ScalarMont { limbs: rab(GFp_p384_scalar_mul_mont, &a.limbs, &a.limbs) }
    }

    fn sqr_mut(a: &mut ScalarMont) {
        unsafe {
            GFp_p384_scalar_mul_mont(a.limbs.as_mut_ptr(), a.limbs.as_ptr(),
                                     a.limbs.as_ptr())
        }
    }

    // Returns (`a` squared `squarings` times) * `b`.
    fn sqr_mul(a: &ScalarMont, squarings: usize, b: &ScalarMont)
               -> ScalarMont {
        debug_assert!(squarings >= 1);
        let mut tmp = sqr(a);
        for _ in 1..squarings {
            sqr_mut(&mut tmp);
        }
        mul(&tmp, b)
    }

    // Sets `acc` = (`acc` squared `squarings` times) * `b`.
    fn sqr_mul_acc(acc: &mut ScalarMont, squarings: usize, b: &ScalarMont) {
        debug_assert!(squarings >= 1);
        for _ in 0..squarings {
            sqr_mut(acc);
        }
        ab_assign(GFp_p384_scalar_mul_mont, &mut acc.limbs, &b.limbs)
    }

    fn to_mont(a: &Scalar) -> ScalarMont {
        static N_RR: [Limb; MAX_LIMBS] =
            p384_limbs![0x0c84ee01, 0x2b39bf21, 0x3fb05b7a, 0x28266895,
                        0xd40d4917, 0x4aab1cc5, 0xbc3e483a, 0xfcb82947,
                        0xff3d81e5, 0xdf1aa419, 0x2d319b24, 0x19b409a9];
        ScalarMont { limbs: rab(GFp_p384_scalar_mul_mont, &a.limbs, &N_RR) }
    }

    // Indexes into `d`.
    const B_1: usize = 0;
    const B_10: usize = 1;
    const B_11: usize = 2;
    const B_101: usize = 3;
    const B_111: usize = 4;
    const B_1111: usize = 5;
    const DIGIT_COUNT: usize = 6;

    let mut d = [ScalarMont { limbs: [0; MAX_LIMBS] }; DIGIT_COUNT];

    d[B_1]    = to_mont(a);
    d[B_10]   = sqr    (&d[B_1]);
    d[B_11]   = mul    (&d[B_10],         &d[B_1]);
    d[B_101]  = sqr_mul(&d[B_10],  0 + 1, &d[B_1]);
    d[B_111]  = mul    (&d[B_101],        &d[B_10]);
    d[B_1111] = sqr_mul(&d[B_111], 0 + 1, &d[B_1]);

    let ff       = sqr_mul(&d[B_1111], 0 +  4, &d[B_1111]);
    let ffff     = sqr_mul(&ff,        0 +  8, &ff);
    let ffffffff = sqr_mul(&ffff,      0 + 16, &ffff);

    let ffffffffffffffff = sqr_mul(&ffffffff, 0 + 32, &ffffffff);

    let ffffffffffffffffffffffff =
        sqr_mul(&ffffffffffffffff, 0 + 32, &ffffffff);

    // ffffffffffffffffffffffffffffffffffffffffffffffff
    let mut acc =
        sqr_mul(&ffffffffffffffffffffffff, 0 + 96, &ffffffffffffffffffffffff);

    // The rest of the exponent, in binary, is:
    //
    //    1100011101100011010011011000000111110100001101110010110111011111
    //    0101100000011010000011011011001001001000101100001010011101111010
    //    1110110011101100000110010110101011001100110001010010100101110001

    static REMAINING_WINDOWS: [(u8, u8); 48] = [
        (    2, B_11 as u8),
        (3 + 3, B_111 as u8),
        (1 + 2, B_11 as u8),
        (3 + 2, B_11 as u8),
        (1 + 1, B_1 as u8),
        (2 + 2, B_11 as u8),
        (1 + 2, B_11 as u8),
        (6 + 4, B_1111 as u8),
        (    3, B_101 as u8),
        (4 + 2, B_11 as u8),
        (1 + 3, B_111 as u8),
        (2 + 3, B_101 as u8),
        (    1, B_1 as u8),
        (1 + 3, B_111 as u8),
        (1 + 4, B_1111 as u8),
        (    3, B_101 as u8),
        (1 + 2, B_11 as u8),
        (6 + 2, B_11 as u8),
        (1 + 1, B_1 as u8),
        (5 + 2, B_11 as u8),
        (1 + 2, B_11 as u8),
        (1 + 2, B_11 as u8),
        (2 + 1, B_1 as u8),
        (2 + 1, B_1 as u8),
        (2 + 1, B_1 as u8),
        (3 + 1, B_1 as u8),
        (1 + 2, B_11 as u8),
        (4 + 1, B_1 as u8),
        (1 + 1, B_1 as u8),
        (2 + 3, B_111 as u8),
        (1 + 4, B_1111 as u8),
        (1 + 1, B_1 as u8),
        (1 + 3, B_111 as u8),
        (1 + 2, B_11 as u8),
        (2 + 3, B_111 as u8),
        (1 + 2, B_11 as u8),
        (5 + 2, B_11 as u8),
        (2 + 1, B_1 as u8),
        (1 + 2, B_11 as u8),
        (1 + 3, B_101 as u8),
        (1 + 2, B_11 as u8),
        (2 + 2, B_11 as u8),
        (2 + 2, B_11 as u8),
        (3 + 3, B_101 as u8),
        (2 + 3, B_101 as u8),
        (2 + 1, B_1 as u8),
        (1 + 3, B_111 as u8),
        (3 + 1, B_1 as u8),
    ];

    for &(squarings, digit) in &REMAINING_WINDOWS[..] {
        sqr_mul_acc(&mut acc, squarings as usize, &d[digit as usize]);
    }

    acc
}


#[allow(non_snake_case)]
unsafe extern fn GFp_p384_elem_sqr_mont(
        r: *mut Limb/*[COMMON_OPS.num_limbs]*/,
        a: *const Limb/*[COMMON_OPS.num_limbs]*/) {
  // XXX: Inefficient. TODO: Make a dedicated squaring routine.
  GFp_p384_elem_mul_mont(r, a, a);
}


extern {
    fn GFp_p384_elem_add(r: *mut Limb/*[COMMON_OPS.num_limbs]*/,
                         a: *const Limb/*[COMMON_OPS.num_limbs]*/,
                         b: *const Limb/*[COMMON_OPS.num_limbs]*/);
    fn GFp_p384_elem_mul_mont(r: *mut Limb/*[COMMON_OPS.num_limbs]*/,
                              a: *const Limb/*[COMMON_OPS.num_limbs]*/,
                              b: *const Limb/*[COMMON_OPS.num_limbs]*/);

    fn GFp_p384_scalar_mul_mont(r: *mut Limb/*[COMMON_OPS.num_limbs]*/,
                                a: *const Limb/*[COMMON_OPS.num_limbs]*/,
                                b: *const Limb/*[COMMON_OPS.num_limbs]*/);

    static EC_GROUP_P384: EC_GROUP;
}


#[cfg(feature = "internal_benches")]
mod internal_benches {
    use super::*;
    use super::super::internal_benches::*;

    bench_curve!(&[
        Scalar { limbs: LIMBS_1 },
        Scalar { limbs: LIMBS_ALTERNATING_10, },
        Scalar { // n - 1
            limbs: p384_limbs![0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
                               0xffffffff, 0xffffffff, 0xc7634d81, 0xf4372ddf,
                               0x581a0db2, 0x48b0a77a, 0xecec196a,
                               0xccc52973 - 1],
        },
    ]);
}
