// Copyright 2016-2023 Brian Smith.
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

use super::{
    elem::{binary_op, binary_op_assign},
    elem_sqr_mul, elem_sqr_mul_acc, Modulus, *,
};

pub static COMMON_OPS: CommonOps = CommonOps {
    num_limbs: 256 / LIMB_BITS,

    q: Modulus {
        p: limbs_from_hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"),
        rr: limbs_from_hex("4fffffffdfffffffffffffffefffffffbffffffff0000000000000003"),
    },
    n: Elem::from_hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),

    a: Elem::from_hex("fffffffc00000004000000000000000000000003fffffffffffffffffffffffc"),
    b: Elem::from_hex("dc30061d04874834e5a220abf7212ed6acf005cd78843090d89cdf6229c4bddf"),

    elem_mul_mont: p256_mul_mont,
    elem_sqr_mont: p256_sqr_mont,

    point_add_jacobian_impl: p256_point_add,
};

#[cfg(test)]
pub(super) static GENERATOR: (Elem<R>, Elem<R>) = (
    Elem::from_hex("18905f76a53755c679fb732b7762251075ba95fc5fedb60179e730d418a9143c"),
    Elem::from_hex("8571ff1825885d85d2e88688dd21f3258b4ab8e4ba19e45cddf25357ce95560a"),
);

pub static PRIVATE_KEY_OPS: PrivateKeyOps = PrivateKeyOps {
    common: &COMMON_OPS,
    elem_inv_squared: p256_elem_inv_squared,
    point_mul_base_impl: p256_point_mul_base_impl,
    point_mul_impl: p256_point_mul,
};

fn p256_elem_inv_squared(a: &Elem<R>) -> Elem<R> {
    // Calculate a**-2 (mod q) == a**(q - 3) (mod q)
    //
    // The exponent (q - 3) is:
    //
    //    0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc

    #[inline]
    fn sqr_mul(a: &Elem<R>, squarings: usize, b: &Elem<R>) -> Elem<R> {
        elem_sqr_mul(&COMMON_OPS, a, squarings, b)
    }

    #[inline]
    fn sqr_mul_acc(a: &mut Elem<R>, squarings: usize, b: &Elem<R>) {
        elem_sqr_mul_acc(&COMMON_OPS, a, squarings, b)
    }

    let b_1 = &a;
    let b_11 = sqr_mul(b_1, 1, b_1);
    let b_111 = sqr_mul(&b_11, 1, b_1);
    let f_11 = sqr_mul(&b_111, 3, &b_111);
    let fff = sqr_mul(&f_11, 6, &f_11);
    let fff_111 = sqr_mul(&fff, 3, &b_111);
    let fffffff_11 = sqr_mul(&fff_111, 15, &fff_111);
    let ffffffff = sqr_mul(&fffffff_11, 2, &b_11);

    // ffffffff00000001
    let mut acc = sqr_mul(&ffffffff, 31 + 1, b_1);

    // ffffffff00000001000000000000000000000000ffffffff
    sqr_mul_acc(&mut acc, 96 + 32, &ffffffff);

    // ffffffff00000001000000000000000000000000ffffffffffffffff
    sqr_mul_acc(&mut acc, 32, &ffffffff);

    // ffffffff00000001000000000000000000000000fffffffffffffffffffffff_11
    sqr_mul_acc(&mut acc, 30, &fffffff_11);

    // ffffffff00000001000000000000000000000000fffffffffffffffffffffffc
    COMMON_OPS.elem_square(&mut acc);
    COMMON_OPS.elem_square(&mut acc);

    acc
}

fn p256_point_mul_base_impl(g_scalar: &Scalar) -> Point {
    prefixed_extern! {
        fn p256_point_mul_base(
            r: *mut Limb,          // [3][COMMON_OPS.num_limbs]
            g_scalar: *const Limb, // [COMMON_OPS.num_limbs]
        );
    }

    let mut r = Point::new_at_infinity();
    unsafe {
        p256_point_mul_base(r.xyz.as_mut_ptr(), g_scalar.limbs.as_ptr());
    }
    r
}

pub static PUBLIC_KEY_OPS: PublicKeyOps = PublicKeyOps {
    common: &COMMON_OPS,
};

pub static SCALAR_OPS: ScalarOps = ScalarOps {
    common: &COMMON_OPS,
    scalar_mul_mont: p256_scalar_mul_mont,
};

pub static PUBLIC_SCALAR_OPS: PublicScalarOps = PublicScalarOps {
    scalar_ops: &SCALAR_OPS,
    public_key_ops: &PUBLIC_KEY_OPS,

    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    twin_mul: twin_mul_nistz256,

    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    twin_mul: |g_scalar, p_scalar, p_xy| {
        twin_mul_inefficient(&PRIVATE_KEY_OPS, g_scalar, p_scalar, p_xy)
    },

    q_minus_n: Elem::from_hex("4319055358e8617b0c46353d039cdaae"),

    // TODO: Use an optimized variable-time implementation.
    scalar_inv_to_mont_vartime: |s| PRIVATE_SCALAR_OPS.scalar_inv_to_mont(s),
};

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
fn twin_mul_nistz256(g_scalar: &Scalar, p_scalar: &Scalar, p_xy: &(Elem<R>, Elem<R>)) -> Point {
    let scaled_g = point_mul_base_vartime(g_scalar);
    let scaled_p = PRIVATE_KEY_OPS.point_mul(p_scalar, p_xy);
    PRIVATE_KEY_OPS.common.point_sum(&scaled_g, &scaled_p)
}

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
fn point_mul_base_vartime(g_scalar: &Scalar) -> Point {
    prefixed_extern! {
        fn p256_point_mul_base_vartime(r: *mut Limb,          // [3][COMMON_OPS.num_limbs]
                                       g_scalar: *const Limb, // [COMMON_OPS.num_limbs]
        );
    }
    let mut scaled_g = Point::new_at_infinity();
    unsafe {
        p256_point_mul_base_vartime(scaled_g.xyz.as_mut_ptr(), g_scalar.limbs.as_ptr());
    }
    scaled_g
}

pub static PRIVATE_SCALAR_OPS: PrivateScalarOps = PrivateScalarOps {
    scalar_ops: &SCALAR_OPS,

    oneRR_mod_n: Scalar::from_hex(
        "66e12d94f3d956202845b2392b6bec594699799c49bd6fa683244c95be79eea2",
    ),
    scalar_inv_to_mont: p256_scalar_inv_to_mont,
};

fn p256_scalar_inv_to_mont(a: Scalar<R>) -> Scalar<R> {
    // Calculate the modular inverse of scalar |a| using Fermat's Little
    // Theorem:
    //
    //    a**-1 (mod n) == a**(n - 2) (mod n)
    //
    // The exponent (n - 2) is:
    //
    //    0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254f

    #[inline]
    fn mul(a: &Scalar<R>, b: &Scalar<R>) -> Scalar<R> {
        binary_op(p256_scalar_mul_mont, a, b)
    }

    #[inline]
    fn sqr(a: &Scalar<R>) -> Scalar<R> {
        let mut tmp = Scalar::zero();
        unsafe { p256_scalar_sqr_rep_mont(tmp.limbs.as_mut_ptr(), a.limbs.as_ptr(), 1) }
        tmp
    }

    // Returns (`a` squared `squarings` times) * `b`.
    fn sqr_mul(a: &Scalar<R>, squarings: Limb, b: &Scalar<R>) -> Scalar<R> {
        debug_assert!(squarings >= 1);
        let mut tmp = Scalar::zero();
        unsafe { p256_scalar_sqr_rep_mont(tmp.limbs.as_mut_ptr(), a.limbs.as_ptr(), squarings) }
        mul(&tmp, b)
    }

    // Sets `acc` = (`acc` squared `squarings` times) * `b`.
    fn sqr_mul_acc(acc: &mut Scalar<R>, squarings: Limb, b: &Scalar<R>) {
        debug_assert!(squarings >= 1);
        unsafe { p256_scalar_sqr_rep_mont(acc.limbs.as_mut_ptr(), acc.limbs.as_ptr(), squarings) }
        binary_op_assign(p256_scalar_mul_mont, acc, b);
    }

    // Indexes into `d`.
    const B_1: usize = 0;
    const B_10: usize = 1;
    const B_11: usize = 2;
    const B_101: usize = 3;
    const B_111: usize = 4;
    const B_1111: usize = 5;
    const B_10101: usize = 6;
    const B_101111: usize = 7;
    const DIGIT_COUNT: usize = 8;

    let mut d = [Scalar::zero(); DIGIT_COUNT];

    d[B_1] = a;
    d[B_10] = sqr(&d[B_1]);
    d[B_11] = mul(&d[B_10], &d[B_1]);
    d[B_101] = mul(&d[B_10], &d[B_11]);
    d[B_111] = mul(&d[B_101], &d[B_10]);
    let b_1010 = sqr(&d[B_101]);
    d[B_1111] = mul(&b_1010, &d[B_101]);
    d[B_10101] = sqr_mul(&b_1010, 0 + 1, &d[B_1]);
    let b_101010 = sqr(&d[B_10101]);
    d[B_101111] = mul(&b_101010, &d[B_101]);
    let b_111111 = mul(&b_101010, &d[B_10101]);

    let ff = sqr_mul(&b_111111, 0 + 2, &d[B_11]);
    let ffff = sqr_mul(&ff, 0 + 8, &ff);
    let ffffffff = sqr_mul(&ffff, 0 + 16, &ffff);

    // ffffffff00000000ffffffff
    let mut acc = sqr_mul(&ffffffff, 32 + 32, &ffffffff);

    // ffffffff00000000ffffffffffffffff
    sqr_mul_acc(&mut acc, 0 + 32, &ffffffff);

    // The rest of the exponent, in binary, is:
    //
    //    1011110011100110111110101010110110100111000101111001111010000100
    //    1111001110111001110010101100001011111100011000110010010101001111

    #[allow(clippy::cast_possible_truncation)]
    static REMAINING_WINDOWS: [(u8, u8); 26] = [
        (6, B_101111 as u8),
        (2 + 3, B_111 as u8),
        (2 + 2, B_11 as u8),
        (1 + 4, B_1111 as u8),
        (5, B_10101 as u8),
        (1 + 3, B_101 as u8),
        (3, B_101 as u8),
        (3, B_101 as u8),
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
        (2, B_11 as u8),
        (3 + 2, B_11 as u8),
        (3 + 2, B_11 as u8),
        (2 + 1, B_1 as u8),
        (2 + 5, B_10101 as u8),
        (2 + 4, B_1111 as u8),
    ];

    for &(squarings, digit) in &REMAINING_WINDOWS {
        sqr_mul_acc(&mut acc, Limb::from(squarings), &d[usize::from(digit)]);
    }

    acc
}

prefixed_extern! {
    pub(super) fn p256_mul_mont(
        r: *mut Limb,   // [COMMON_OPS.num_limbs]
        a: *const Limb, // [COMMON_OPS.num_limbs]
        b: *const Limb, // [COMMON_OPS.num_limbs]
    );
    pub(super) fn p256_sqr_mont(
        r: *mut Limb,   // [COMMON_OPS.num_limbs]
        a: *const Limb, // [COMMON_OPS.num_limbs]
    );

    fn p256_point_add(
        r: *mut Limb,   // [3][COMMON_OPS.num_limbs]
        a: *const Limb, // [3][COMMON_OPS.num_limbs]
        b: *const Limb, // [3][COMMON_OPS.num_limbs]
    );
    fn p256_point_mul(
        r: *mut Limb,          // [3][COMMON_OPS.num_limbs]
        p_scalar: *const Limb, // [COMMON_OPS.num_limbs]
        p_x: *const Limb,      // [COMMON_OPS.num_limbs]
        p_y: *const Limb,      // [COMMON_OPS.num_limbs]
    );

    fn p256_scalar_mul_mont(
        r: *mut Limb,   // [COMMON_OPS.num_limbs]
        a: *const Limb, // [COMMON_OPS.num_limbs]
        b: *const Limb, // [COMMON_OPS.num_limbs]
    );
    fn p256_scalar_sqr_rep_mont(
        r: *mut Limb,   // [COMMON_OPS.num_limbs]
        a: *const Limb, // [COMMON_OPS.num_limbs]
        rep: Limb,
    );
}

#[cfg(test)]
mod tests {
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    #[test]
    fn p256_point_mul_base_vartime_test() {
        use super::{super::tests::point_mul_base_tests, *};
        point_mul_base_tests(
            &PRIVATE_KEY_OPS,
            point_mul_base_vartime,
            test_file!("p256_point_mul_base_tests.txt"),
        );
    }
}
