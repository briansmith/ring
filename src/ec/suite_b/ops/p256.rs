// Copyright 2016-2023 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

use super::{
    elem::{binary_op, binary_op_assign},
    elem_sqr_mul, elem_sqr_mul_acc, PublicModulus, *,
};
use cfg_if::cfg_if;

pub(super) const NUM_LIMBS: usize = 256 / LIMB_BITS;

pub static COMMON_OPS: CommonOps = CommonOps {
    num_limbs: elem::NumLimbs::P256,

    q: PublicModulus {
        p: limbs_from_hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"),
        rr: PublicElem::from_hex("4fffffffdfffffffffffffffefffffffbffffffff0000000000000003"),
    },
    n: PublicElem::from_hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),

    a: PublicElem::from_hex("fffffffc00000004000000000000000000000003fffffffffffffffffffffffc"),
    b: PublicElem::from_hex("dc30061d04874834e5a220abf7212ed6acf005cd78843090d89cdf6229c4bddf"),

    elem_mul_mont: p256_mul_mont,
    elem_sqr_mont: p256_sqr_mont,
};

#[cfg(test)]
pub(super) static GENERATOR: (PublicElem<R>, PublicElem<R>) = (
    PublicElem::from_hex("18905f76a53755c679fb732b7762251075ba95fc5fedb60179e730d418a9143c"),
    PublicElem::from_hex("8571ff1825885d85d2e88688dd21f3258b4ab8e4ba19e45cddf25357ce95560a"),
);

pub static PRIVATE_KEY_OPS: PrivateKeyOps = PrivateKeyOps {
    common: &COMMON_OPS,
    elem_inv_squared: p256_elem_inv_squared,
    point_mul_base_impl: p256_point_mul_base_impl,
    point_mul_impl: p256_point_mul,
    point_add_jacobian_impl: p256_point_add,
};

fn p256_elem_inv_squared(q: &Modulus<Q>, a: &Elem<R>) -> Elem<R> {
    // Calculate a**-2 (mod q) == a**(q - 3) (mod q)
    //
    // The exponent (q - 3) is:
    //
    //    0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc

    #[inline]
    fn sqr_mul(q: &Modulus<Q>, a: &Elem<R>, squarings: LeakyWord, b: &Elem<R>) -> Elem<R> {
        elem_sqr_mul(&COMMON_OPS, a, squarings, b, q.cpu())
    }

    #[inline]
    fn sqr_mul_acc(q: &Modulus<Q>, a: &mut Elem<R>, squarings: LeakyWord, b: &Elem<R>) {
        elem_sqr_mul_acc(&COMMON_OPS, a, squarings, b, q.cpu())
    }

    let b_1 = &a;
    let b_11 = sqr_mul(q, b_1, 1, b_1);
    let b_111 = sqr_mul(q, &b_11, 1, b_1);
    let f_11 = sqr_mul(q, &b_111, 3, &b_111);
    let fff = sqr_mul(q, &f_11, 6, &f_11);
    let fff_111 = sqr_mul(q, &fff, 3, &b_111);
    let fffffff_11 = sqr_mul(q, &fff_111, 15, &fff_111);
    let ffffffff = sqr_mul(q, &fffffff_11, 2, &b_11);

    // ffffffff00000001
    let mut acc = sqr_mul(q, &ffffffff, 31 + 1, b_1);

    // ffffffff00000001000000000000000000000000ffffffff
    sqr_mul_acc(q, &mut acc, 96 + 32, &ffffffff);

    // ffffffff00000001000000000000000000000000ffffffffffffffff
    sqr_mul_acc(q, &mut acc, 32, &ffffffff);

    // ffffffff00000001000000000000000000000000fffffffffffffffffffffff_11
    sqr_mul_acc(q, &mut acc, 30, &fffffff_11);

    // ffffffff00000001000000000000000000000000fffffffffffffffffffffffc
    q.elem_square(&mut acc);
    q.elem_square(&mut acc);

    acc
}

fn p256_point_mul_base_impl(g_scalar: &Scalar, _cpu: cpu::Features) -> Point {
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

    twin_mul,

    q_minus_n: PublicElem::from_hex("4319055358e8617b0c46353d039cdaae"),

    // TODO: Use an optimized variable-time implementation.
    scalar_inv_to_mont_vartime: |s, cpu| PRIVATE_SCALAR_OPS.scalar_inv_to_mont(s, cpu),
};

fn point_mul_base_vartime(g_scalar: &Scalar, cpu: cpu::Features) -> Point {
    cfg_if! {
        if #[cfg(any(all(target_arch = "aarch64", target_endian = "little"),
                         target_arch = "x86_64"))] {
            prefixed_extern! {
                fn p256_point_mul_base_vartime(
                    r: *mut Limb,          // [3][COMMON_OPS.num_limbs]
                    g_scalar: *const Limb, // [COMMON_OPS.num_limbs]
                );
            }
            let mut scaled_g = Point::new_at_infinity();
            let _ = cpu;
            unsafe {
                p256_point_mul_base_vartime(
                    scaled_g.xyz.as_mut_ptr(),
                    g_scalar.limbs.as_ptr());
            }
            scaled_g
        } else {
            p256_point_mul_base_impl(g_scalar, cpu)
        }
    }
}

fn twin_mul(
    g_scalar: &Scalar,
    p_scalar: &Scalar,
    p_xy: &(Elem<R>, Elem<R>),
    cpu: cpu::Features,
) -> Point {
    // XXX: This is inefficient for the same reason as `twin_mul_inefficient`
    // when we don't have `p256_point_mul_base_vartime`.
    let scaled_g = point_mul_base_vartime(g_scalar, cpu);
    let scaled_p = PRIVATE_KEY_OPS.point_mul(p_scalar, p_xy, cpu);
    PRIVATE_KEY_OPS.point_sum(&scaled_g, &scaled_p, cpu)
}

pub static PRIVATE_SCALAR_OPS: PrivateScalarOps = PrivateScalarOps {
    scalar_ops: &SCALAR_OPS,

    oneRR_mod_n: PublicScalar::from_hex(
        "66e12d94f3d956202845b2392b6bec594699799c49bd6fa683244c95be79eea2",
    ),
    scalar_inv_to_mont: p256_scalar_inv_to_mont,
};

#[allow(clippy::just_underscores_and_digits)]
fn p256_scalar_inv_to_mont(a: Scalar<R>, cpu: cpu::Features) -> Scalar<R> {
    // Calculate the modular inverse of scalar |a| using Fermat's Little
    // Theorem:
    //
    //    a**-1 (mod n) == a**(n - 2) (mod n)
    //
    // The exponent (n - 2) is:
    //
    //    0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254f

    #[inline]
    fn mul(a: &Scalar<R>, b: &Scalar<R>, _cpu: cpu::Features) -> Scalar<R> {
        binary_op(p256_scalar_mul_mont, a, b)
    }

    #[inline]
    fn sqr(a: &Scalar<R>, _cpu: cpu::Features) -> Scalar<R> {
        let mut tmp = Scalar::zero();
        unsafe { p256_scalar_sqr_rep_mont(tmp.limbs.as_mut_ptr(), a.limbs.as_ptr(), 1) }
        tmp
    }

    // Returns (`a` squared `squarings` times) * `b`.
    #[inline]
    fn sqr_mul(
        a: &Scalar<R>,
        squarings: LeakyWord,
        b: &Scalar<R>,
        cpu: cpu::Features,
    ) -> Scalar<R> {
        debug_assert!(squarings >= 1);
        let mut tmp = Scalar::zero();
        unsafe { p256_scalar_sqr_rep_mont(tmp.limbs.as_mut_ptr(), a.limbs.as_ptr(), squarings) }
        mul(&tmp, b, cpu)
    }

    // Sets `acc` = (`acc` squared `squarings` times) * `b`.
    #[inline]
    fn sqr_mul_acc(acc: &mut Scalar<R>, squarings: LeakyWord, b: &Scalar<R>, _cpu: cpu::Features) {
        debug_assert!(squarings >= 1);
        {
            let acc = acc.limbs.as_mut_ptr();
            unsafe { p256_scalar_sqr_rep_mont(acc, acc.cast_const(), squarings) }
        }
        binary_op_assign(p256_scalar_mul_mont, acc, b);
    }

    let _1 = &a;

    let _10 = sqr(_1, cpu); // 2
    let _100 = sqr(&_10, cpu); // 4
    let _101 = mul(&_100, _1, cpu); // 5
    let _111 = mul(&_101, &_10, cpu); // 7

    let _1000 = sqr(&_100, cpu); // 8
    let _10000 = sqr(&_1000, cpu); // 16
    let _100000 = sqr(&_10000, cpu); // 32

    let _100111 = mul(&_111, &_100000, cpu); // 39 = 7 + 32
    let _101011 = mul(&_100, &_100111, cpu); // 43 = 4 + 39
    let _101111 = mul(&_100, &_101011, cpu); // 47 = 4 + 39
    let _1001111 = mul(&_100000, &_101111, cpu); // 79 = 32 + 47
    let _86 = sqr(&_101011, cpu); // 86 = 43 * 2
    let _1011011 = mul(&_101, &_86, cpu); // 91 = 5 + 86
    let _92 = mul(_1, &_1011011, cpu); // 92 = 1 + 91
    let _1100011 = mul(&_111, &_92, cpu); // 99 = 7 + 92
    let _10111111 = mul(&_92, &_1100011, cpu); // 191 = 92 + 99
    let _11011111 = mul(&_100000, &_10111111, cpu); // 223 = 32 + 191

    let ff = mul(&_100000, &_11011111, cpu); // 255 = 32 + 223
    let ffff = sqr_mul(&ff, 0 + 8, &ff, cpu);
    let ffffffff = sqr_mul(&ffff, 0 + 16, &ffff, cpu);

    // ffffffff00000000ffffffff
    let mut acc = sqr_mul(&ffffffff, 32 + 32, &ffffffff, cpu);

    // ffffffff00000000ffffffffffffffff
    sqr_mul_acc(&mut acc, 0 + 32, &ffffffff, cpu);

    // The rest of the exponent, in binary, is:
    //
    //    1011110011100110111110101010110110100111000101111001111010000100
    //    1111001110111001110010101100001011111100011000110010010101001111

    sqr_mul_acc(&mut acc, 6, &_101111, cpu);
    sqr_mul_acc(&mut acc, 2 + 3, &_111, cpu);
    sqr_mul_acc(&mut acc, 2 + 8, &_11011111, cpu);
    sqr_mul_acc(&mut acc, 1 + 3, &_101, cpu);
    sqr_mul_acc(&mut acc, 1 + 7, &_1011011, cpu);
    sqr_mul_acc(&mut acc, 1 + 6, &_100111, cpu);
    sqr_mul_acc(&mut acc, 3 + 6, &_101111, cpu);
    sqr_mul_acc(&mut acc, 2 + 3, &_111, cpu);
    sqr_mul_acc(&mut acc, 3, &_101, cpu);
    sqr_mul_acc(&mut acc, 4 + 7, &_1001111, cpu);
    sqr_mul_acc(&mut acc, 2 + 3, &_111, cpu);
    sqr_mul_acc(&mut acc, 1 + 3, &_111, cpu);
    sqr_mul_acc(&mut acc, 2 + 3, &_111, cpu);
    sqr_mul_acc(&mut acc, 2 + 6, &_101011, cpu);
    sqr_mul_acc(&mut acc, 4 + 8, &_10111111, cpu);
    sqr_mul_acc(&mut acc, 3 + 7, &_1100011, cpu);
    sqr_mul_acc(&mut acc, 2 + 1, _1, cpu);
    sqr_mul_acc(&mut acc, 2 + 3, &_101, cpu);
    sqr_mul_acc(&mut acc, 1 + 7, &_1001111, cpu);

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
        rep: LeakyWord,
    );
}

#[cfg(test)]
mod tests {
    #[test]
    fn p256_point_mul_base_vartime_test() {
        use super::{super::tests::point_mul_base_tests, *};
        point_mul_base_tests(
            &PRIVATE_KEY_OPS,
            point_mul_base_vartime,
            test_vector_file!("p256_point_mul_base_tests.txt"),
        );
    }
}
