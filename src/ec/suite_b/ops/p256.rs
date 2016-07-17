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

use c;
use super::*;
use super::{Mont, elem_sqr_mul, elem_sqr_mul_acc, ab_assign, ra,
            rab};

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

    scalar_inv_to_mont_impl: p256_scalar_inv_to_mont,
    scalar_mul_mont: GFp_p256_scalar_mul_mont,
};

fn p256_scalar_inv_to_mont(a: &Scalar) -> ScalarMont {
    // Calculate the modular inverse of scalar |a| using Fermat's Little
    // Theorem:
    //
    //    a**-1 (mod n) == a**(n - 2) (mod n)
    //
    // The exponent (n - 2) is:
    //
    //    0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254f

    #[inline]
    fn mul(a: &ScalarMont, b: &ScalarMont) -> ScalarMont {
        ScalarMont { limbs: rab(GFp_p256_scalar_mul_mont, &a.limbs, &b.limbs) }
    }

    #[inline]
    fn sqr(a: &ScalarMont) -> ScalarMont {
        ScalarMont { limbs: ra(GFp_p256_scalar_sqr_mont, &a.limbs) }
    }

    // Returns (`a` squared `squarings` times) * `b`.
    fn sqr_mul(a: &ScalarMont, squarings: c::int, b: &ScalarMont)
               -> ScalarMont {
        debug_assert!(squarings >= 1);
        let mut tmp = ScalarMont { limbs: [0; MAX_LIMBS] };
        unsafe {
            GFp_p256_scalar_sqr_rep_mont(tmp.limbs.as_mut_ptr(),
                                         a.limbs.as_ptr(), squarings)
        }
        mul(&tmp, &b)
    }

    // Sets `acc` = (`acc` squared `squarings` times) * `b`.
    fn sqr_mul_acc(acc: &mut ScalarMont, squarings: c::int, b: &ScalarMont) {
        debug_assert!(squarings >= 1);
        unsafe {
            GFp_p256_scalar_sqr_rep_mont(acc.limbs.as_mut_ptr(),
                                         acc.limbs.as_ptr(), squarings)
        }
        ab_assign(GFp_p256_scalar_mul_mont, &mut acc.limbs, &b.limbs);
    }

    fn to_mont(a: &Scalar) -> ScalarMont {
        static N_RR: [Limb; MAX_LIMBS] =
            p256_limbs![0x66e12d94, 0xf3d95620, 0x2845b239, 0x2b6bec59,
                        0x4699799c, 0x49bd6fa6, 0x83244c95, 0xbe79eea2];
        ScalarMont { limbs: rab(GFp_p256_scalar_mul_mont, &a.limbs, &N_RR) }
    }

    // Indexes into `d`.
    const B_1: usize = 0;
    const B_10: usize = 1;
    const B_11: usize = 2;
    const B_101: usize = 3;
    const B_111: usize = 4;
    const B_1010: usize = 5;
    const B_1111: usize = 6;
    const B_10101: usize = 7;
    const B_101111: usize = 8;
    const DIGIT_COUNT: usize = 9;

    let mut d = [ScalarMont { limbs: [0; MAX_LIMBS] }; DIGIT_COUNT];

    d[B_1]    = to_mont(a);
    d[B_10]   = sqr(&d[B_1]);
    d[B_11]   = mul(&d[B_10],   &d[B_1]);
    d[B_101]  = sqr_mul(&d[B_10], 0 + 1, &d[B_1]);
    d[B_111]  = mul(&d[B_101],  &d[B_10]);
    d[B_1010] = sqr(&d[B_101]);
    d[B_1111] = mul(&d[B_1010], &d[B_101]);

    // These two fork off the main star chain.
    d[B_10101] =  sqr_mul(&d[B_1010],  0 + 1, &d[B_1]);
    d[B_101111] = sqr_mul(&d[B_10101], 0 + 1, &d[B_101]);

    let ff       = sqr_mul(&d[B_1111], 0 + 4,  &d[B_1111]);
    let ffff     = sqr_mul(&ff,        0 + 8,  &ff);
    let ffffffff = sqr_mul(&ffff,      0 + 16, &ffff);

    // ffffffff00000000ffffffff
    let mut acc = sqr_mul(&ffffffff, 32 + 32, &ffffffff);

    // ffffffff00000000ffffffffffffffff
    sqr_mul_acc(&mut acc, 0 + 32, &ffffffff);

    // The rest of the exponent, in binary, is:
    //
    //    1011110011100110111110101010110110100111000101111001111010000100
    //    1111001110111001110010101100001011111100011000110010010101001111

    static REMAINING_WINDOWS: [(u8, u8); 26] = [
        (    6, B_101111 as u8),
        (2 + 3, B_111 as u8),
        (2 + 2, B_11 as u8),
        (1 + 4, B_1111 as u8),
        (    5, B_10101 as u8),
        (1 + 3, B_101 as u8),
        (0 + 3, B_101 as u8),
        (0 + 3, B_101 as u8),
        (2 + 3, B_111 as u8),
        (3 + 6, B_101111 as u8),
        (2 + 4, B_1111 as u8),
        (1 + 1, B_1 as u8),
        (4 + 1, B_1 as u8),
        (2 + 4, B_1111 as u8),
        (2 + 3, B_111 as u8),
        (1 + 3, B_111 as u8),
        (2 + 3, B_111 as u8),
        (2 + 3, B_101 as u8),
        (1 + 2, B_11 as u8),
        (4 + 6, B_101111 as u8),
        (    2, B_11 as u8),
        (3 + 2, B_11 as u8),
        (3 + 2, B_11 as u8),
        (2 + 1, B_1 as u8),
        (2 + 5, B_10101 as u8),
        (2 + 4, B_1111 as u8),
    ];

    for &(squarings, digit) in &REMAINING_WINDOWS {
        sqr_mul_acc(&mut acc, squarings as c::int, &d[digit as usize]);
    }

    acc
}


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

    fn GFp_p256_scalar_mul_mont(r: *mut Limb/*[COMMON_OPS.num_limbs]*/,
                                a: *const Limb/*[COMMON_OPS.num_limbs]*/,
                                b: *const Limb/*[COMMON_OPS.num_limbs]*/);
    fn GFp_p256_scalar_sqr_mont(r: *mut Limb/*[COMMON_OPS.num_limbs]*/,
                                a: *const Limb/*[COMMON_OPS.num_limbs]*/);
    fn GFp_p256_scalar_sqr_rep_mont(r: *mut Limb/*[COMMON_OPS.num_limbs]*/,
                                    a: *const Limb/*[COMMON_OPS.num_limbs]*/,
                                    rep: c::int);

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
