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
    PublicModulus,
    elem::{binary_op, binary_op_assign},
    elem_sqr_rep, *,
};

pub(super) const NUM_LIMBS: usize = 384 / LIMB_BITS;

pub static COMMON_OPS: CommonOps = CommonOps {
    num_limbs: elem::NumLimbs::P384,

    q: PublicModulus {
        p: limbs_from_hex(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
        ),
        rr: PublicElem::from_hex(
            "10000000200000000fffffffe000000000000000200000000fffffffe00000001",
        ),
    },
    n: PublicElem::from_hex(
        "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
    ),

    a: PublicElem::from_hex(
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffffffc0000000000000003fffffffc",
    ),
    b: PublicElem::from_hex(
        "cd08114b604fbff9b62b21f41f022094e3374bee94938ae277f2209b1920022ef729add87a4c32ec081188719d412dcc",
    ),

    elem_mul_mont: p384_elem_mul_mont,
    elem_sqr_mont: p384_elem_sqr_mont,
};

pub(super) static GENERATOR: (PublicElem<R>, PublicElem<R>) = (
    PublicElem::from_hex(
        "4d3aadc2299e1513812ff723614ede2b6454868459a30eff879c3afc541b4d6e20e378e2a0d6ce383dd0756649c0b528",
    ),
    PublicElem::from_hex(
        "2b78abc25a15c5e9dd8002263969a840c6c3521968f4ffd98bade7562e83b050a1bfa8bf7bb4a9ac23043dad4b03a4fe",
    ),
);

pub static PRIVATE_KEY_OPS: PrivateKeyOps = PrivateKeyOps {
    common: &COMMON_OPS,
    elem_inv_squared: p384_elem_inv_squared,
    point_mul_base_impl: p384_point_mul_base_impl,
    point_mul_impl: p384_point_mul,
    point_add_jacobian_impl: p384_point_add,
};

fn p384_elem_inv_squared(q: &Modulus<Q>, a: &Elem<R>) -> Elem<R> {
    // Calculate a**-2 (mod q) == a**(q - 3) (mod q)
    //
    // The exponent (q - 3) is:
    //
    //    0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe\
    //      ffffffff0000000000000000fffffffc

    #[inline]
    fn sqr_rep<const REP: LeakyWord>(q: &Modulus<Q>, a: &Elem<R>) -> Elem<R> {
        elem_sqr_rep(
            &COMMON_OPS,
            a,
            const { NonZero::new(REP).unwrap() },
            q.cpu(),
        )
    }

    #[inline]
    fn sqr_rep_acc<const REP: LeakyWord>(q: &Modulus<Q>, acc: &mut Elem<R>) {
        *acc = sqr_rep::<REP>(q, acc);
    }

    #[inline]
    fn sqr_mul<const REP: LeakyWord>(q: &Modulus<Q>, a: &Elem<R>, b: &Elem<R>) -> Elem<R> {
        q.elem_product(&sqr_rep::<REP>(q, a), b)
    }

    #[inline]
    fn sqr_mul_acc<const REP: LeakyWord>(q: &Modulus<Q>, acc: &mut Elem<R>, b: &Elem<R>) {
        sqr_rep_acc::<REP>(q, acc);
        q.elem_mul(acc, b)
    }

    let b_1 = &a;
    let b_11 = sqr_mul::<1>(q, b_1, b_1);
    let b_111 = sqr_mul::<1>(q, &b_11, b_1);
    let f_11 = sqr_mul::<3>(q, &b_111, &b_111);
    let fff = sqr_mul::<6>(q, &f_11, &f_11);
    let fff_111 = sqr_mul::<3>(q, &fff, &b_111);
    let fffffff_11 = sqr_mul::<15>(q, &fff_111, &fff_111);

    let fffffffffffffff = sqr_mul::<30>(q, &fffffff_11, &fffffff_11);

    let ffffffffffffffffffffffffffffff = sqr_mul::<60>(q, &fffffffffffffff, &fffffffffffffff);

    // ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    let mut acc = sqr_mul::<120>(
        q,
        &ffffffffffffffffffffffffffffff,
        &ffffffffffffffffffffffffffffff,
    );

    // fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_111
    sqr_mul_acc::<15>(q, &mut acc, &fff_111);

    // fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff
    sqr_mul_acc::<{ 1 + 30 }>(q, &mut acc, &fffffff_11);
    sqr_mul_acc::<2>(q, &mut acc, &b_11);

    // fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff
    // 0000000000000000fffffff_11
    sqr_mul_acc::<{ 64 + 30 }>(q, &mut acc, &fffffff_11);

    // fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff
    // 0000000000000000fffffffc
    q.elem_square(&mut acc);
    q.elem_square(&mut acc);

    acc
}

fn p384_point_mul_base_impl(a: &Scalar, cpu: cpu::Features) -> Point {
    // XXX: Not efficient. TODO: Precompute multiples of the generator.
    let generator = (Elem::from(&GENERATOR.0), Elem::from(&GENERATOR.1));
    PRIVATE_KEY_OPS.point_mul(a, &generator, cpu)
}

pub static PUBLIC_KEY_OPS: PublicKeyOps = PublicKeyOps {
    common: &COMMON_OPS,
};

pub static SCALAR_OPS: ScalarOps = ScalarOps {
    common: &COMMON_OPS,
    scalar_mul_mont: p384_scalar_mul_mont,
};

pub static PUBLIC_SCALAR_OPS: PublicScalarOps = PublicScalarOps {
    scalar_ops: &SCALAR_OPS,
    public_key_ops: &PUBLIC_KEY_OPS,
    twin_mul: |g_scalar, p_scalar, p_xy, cpu| {
        twin_mul_inefficient(&PRIVATE_KEY_OPS, g_scalar, p_scalar, p_xy, cpu)
    },

    q_minus_n: PublicElem::from_hex("389cb27e0bc8d21fa7e5f24cb74f58851313e696333ad68c"),

    // TODO: Use an optimized variable-time implementation.
    scalar_inv_to_mont_vartime: |s, cpu| PRIVATE_SCALAR_OPS.scalar_inv_to_mont(s, cpu),
};

pub static PRIVATE_SCALAR_OPS: PrivateScalarOps = PrivateScalarOps {
    scalar_ops: &SCALAR_OPS,

    oneRR_mod_n: PublicScalar::from_hex(
        "c84ee012b39bf213fb05b7a28266895d40d49174aab1cc5bc3e483afcb82947ff3d81e5df1aa4192d319b2419b409a9",
    ),
    scalar_inv_to_mont: p384_scalar_inv_to_mont,
};

fn p384_scalar_inv_to_mont(a: Scalar<R>, cpu: cpu::Features) -> Scalar<R> {
    // Calculate the modular inverse of scalar |a| using Fermat's Little
    // Theorem:
    //
    //    a**-1 (mod n) == a**(n - 2) (mod n)
    //
    // The exponent (n - 2) is:
    //
    //    0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf\
    //      581a0db248b0a77aecec196accc52971

    #[inline]
    fn mul(a: &Scalar<R>, b: &Scalar<R>, _cpu: cpu::Features) -> Scalar<R> {
        binary_op(p384_scalar_mul_mont, a, b)
    }

    #[inline]
    fn sqr(a: &Scalar<R>, cpu: cpu::Features) -> Scalar<R> {
        sqr_rep::<1>(a, cpu)
    }

    #[inline]
    fn sqr_rep<const REP: LeakyWord>(a: &Scalar<R>, cpu: cpu::Features) -> Scalar<R> {
        scalar_sqr_rep(a, const { NonZero::new(REP).unwrap() }, cpu)
    }

    #[inline]
    fn sqr_rep_acc<const REP: LeakyWord>(acc: &mut Scalar<R>, cpu: cpu::Features) {
        *acc = sqr_rep::<REP>(acc, cpu);
    }

    #[inline]
    fn sqr_mul<const REP: LeakyWord>(
        a: &Scalar<R>,
        b: &Scalar<R>,
        cpu: cpu::Features,
    ) -> Scalar<R> {
        mul(&sqr_rep::<REP>(a, cpu), b, cpu)
    }

    #[inline]
    fn sqr_mul_acc<const REP: LeakyWord>(acc: &mut Scalar<R>, b: &Scalar<R>, cpu: cpu::Features) {
        sqr_rep_acc::<REP>(acc, cpu);
        binary_op_assign(p384_scalar_mul_mont, acc, b)
    }

    let b_1 = &a;

    let b_10 = sqr(b_1, cpu); // 2
    let b_100 = sqr(&b_10, cpu); // 4
    let b_101 = mul(b_1, &b_100, cpu); // 5
    let b_111 = mul(&b_101, &b_10, cpu); // 7
    let b_1001 = mul(&b_111, &b_10, cpu); // 9
    let b_1011 = mul(&b_1001, &b_10, cpu); // 11
    let b_1101 = mul(&b_1011, &b_10, cpu); // 13
    let b_10110 = sqr(&b_1011, cpu); // 22
    let b_10111 = mul(&b_10110, b_1, cpu); // 23 = 22 + 1
    let b_11001 = mul(&b_10111, &b_10, cpu); // 25 = 23 + 2
    let b_11011 = mul(&b_11001, &b_10, cpu); // 27 = 25 + 2
    let b_110001 = mul(&b_11011, &b_10110, cpu); // 49

    // ffffffffffffffffffffffffffffffffffffffffffffffff
    let x6 = sqr_mul::<1>(&b_11001, &b_1101, cpu); // 63
    let x12 = sqr_mul::<6>(&x6, &x6, cpu);
    let x24 = sqr_mul::<12>(&x12, &x12, cpu);
    let x48 = sqr_mul::<24>(&x24, &x24, cpu);
    let x96 = sqr_mul::<48>(&x48, &x48, cpu);
    let mut acc = sqr_mul::<96>(&x96, &x96, cpu);

    // The rest of the exponent, in binary, is:
    //
    //    1100011101100011010011011000000111110100001101110010110111011111
    //    0101100000011010000011011011001001001000101100001010011101111010
    //    1110110011101100000110010110101011001100110001010010100101110001

    sqr_mul_acc::<{ 0 + 6 }>(&mut acc, &b_110001, cpu);
    sqr_mul_acc::<{ 0 + 5 }>(&mut acc, &b_11011, cpu);
    sqr_mul_acc::<{ 3 + 4 }>(&mut acc, &b_1101, cpu);
    sqr_mul_acc::<{ 2 + 5 }>(&mut acc, &b_11011, cpu);
    sqr_mul_acc::<{ 6 + 3 }>(&mut acc, &b_111, cpu);
    sqr_mul_acc::<4>(&mut acc, &b_1101, cpu);
    sqr_mul_acc::<{ 4 + 5 }>(&mut acc, &b_11011, cpu);
    sqr_mul_acc::<4>(&mut acc, &b_1001, cpu);
    sqr_mul_acc::<{ 1 + 5 }>(&mut acc, &b_11011, cpu);
    sqr_mul_acc::<4>(&mut acc, &b_1011, cpu);
    sqr_mul_acc::<3>(&mut acc, &b_111, cpu);
    sqr_mul_acc::<{ 1 + 4 }>(&mut acc, &b_1011, cpu);
    sqr_mul_acc::<{ 6 + 4 }>(&mut acc, &b_1101, cpu);
    sqr_mul_acc::<{ 5 + 5 }>(&mut acc, &b_11011, cpu);
    sqr_mul_acc::<{ 1 + 5 }>(&mut acc, &b_11001, cpu);
    sqr_mul_acc::<{ 2 + 4 }>(&mut acc, &b_1001, cpu);
    sqr_mul_acc::<{ 3 + 4 }>(&mut acc, &b_1011, cpu);
    sqr_mul_acc::<{ 4 + 3 }>(&mut acc, &b_101, cpu);
    sqr_mul_acc::<{ 2 + 3 }>(&mut acc, &b_111, cpu);
    sqr_mul_acc::<{ 1 + 3 }>(&mut acc, &b_111, cpu);
    sqr_mul_acc::<{ 0 + 3 }>(&mut acc, &b_101, cpu);
    sqr_mul_acc::<{ 1 + 3 }>(&mut acc, &b_111, cpu);
    sqr_mul_acc::<{ 1 + 5 }>(&mut acc, &b_11001, cpu);
    sqr_mul_acc::<{ 0 + 5 }>(&mut acc, &b_11011, cpu);
    sqr_mul_acc::<{ 5 + 5 }>(&mut acc, &b_11001, cpu);
    sqr_mul_acc::<{ 1 + 4 }>(&mut acc, &b_1101, cpu);
    sqr_mul_acc::<{ 1 + 4 }>(&mut acc, &b_1011, cpu);
    sqr_mul_acc::<{ 2 + 5 }>(&mut acc, &b_11001, cpu);
    sqr_mul_acc::<{ 0 + 1 }>(&mut acc, b_1, cpu);
    sqr_mul_acc::<{ 3 + 3 }>(&mut acc, &b_101, cpu);
    sqr_mul_acc::<{ 2 + 3 }>(&mut acc, &b_101, cpu);
    sqr_mul_acc::<{ 2 + 5 }>(&mut acc, &b_10111, cpu);
    sqr_mul_acc::<{ 3 + 1 }>(&mut acc, b_1, cpu);

    acc
}

// Returns `a` squared `rep` times.
fn scalar_sqr_rep(a: &Scalar<R>, rep: NonZero<LeakyWord>, _cpu: cpu::Features) -> Scalar<R> {
    let mut r = binary_op(p384_scalar_mul_mont, a, a);
    for _ in 1..rep.get() {
        unary_op_from_binary_op_assign(p384_scalar_mul_mont, &mut r);
    }
    r
}

unsafe extern "C" fn p384_elem_sqr_mont(
    r: *mut Limb,   // [COMMON_OPS.num_limbs]
    a: *const Limb, // [COMMON_OPS.num_limbs]
) {
    // XXX: Inefficient. TODO: Make a dedicated squaring routine.
    unsafe {
        p384_elem_mul_mont(r, a, a);
    }
}

prefixed_extern! {
    unsafe fn p384_elem_mul_mont(
        r: *mut Limb,   // [COMMON_OPS.num_limbs]
        a: *const Limb, // [COMMON_OPS.num_limbs]
        b: *const Limb, // [COMMON_OPS.num_limbs]
    );

    unsafe fn p384_point_add(
        r: *mut Limb,   // [3][COMMON_OPS.num_limbs]
        a: *const Limb, // [3][COMMON_OPS.num_limbs]
        b: *const Limb, // [3][COMMON_OPS.num_limbs]
    );
    unsafe fn p384_point_mul(
        r: *mut Limb,          // [3][COMMON_OPS.num_limbs]
        p_scalar: *const Limb, // [COMMON_OPS.num_limbs]
        p_x: *const Limb,      // [COMMON_OPS.num_limbs]
        p_y: *const Limb,      // [COMMON_OPS.num_limbs]
    );

    unsafe fn p384_scalar_mul_mont(
        r: *mut Limb,   // [COMMON_OPS.num_limbs]
        a: *const Limb, // [COMMON_OPS.num_limbs]
        b: *const Limb, // [COMMON_OPS.num_limbs]
    );
}
