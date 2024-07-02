# Copyright 2023 Brian Smith.
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND BRIAN SMITH AND THE AUTHORS DISCLAIM
# ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL BRIAN SMITH OR THE AUTHORS
# BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
# AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

# Usage: python lib/gfp_generate.py --outdir <dir>

from textwrap import wrap

rs_template = """
// Copyright 2016-2024 Brian Smith.
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
    num_limbs: (%(bits)d + LIMB_BITS - 1) / LIMB_BITS,
    order_bits: %(bits)d,

    q: Modulus {
        p: limbs_from_hex("%(q)x"),
        rr: limbs_from_hex(%(q_rr)s),
    },
    n: Elem::from_hex("%(n)x"),

    a: Elem::from_hex(%(a)s),
    b: Elem::from_hex(%(b)s),

    elem_mul_mont: p%(bits)s_elem_mul_mont,
    elem_sqr_mont: p%(bits)s_elem_sqr_mont,

    point_add_jacobian_impl: p%(bits)s_point_add,
};

pub(super) static GENERATOR: (Elem<R>, Elem<R>) = (
    Elem::from_hex(%(Gx)s),
    Elem::from_hex(%(Gy)s),
);

pub static PRIVATE_KEY_OPS: PrivateKeyOps = PrivateKeyOps {
    common: &COMMON_OPS,
    elem_inv_squared: p%(bits)s_elem_inv_squared,
    point_mul_base_impl: p%(bits)s_point_mul_base_impl,
    point_mul_impl: p%(bits)s_point_mul,
};

fn p%(bits)d_elem_inv_squared(a: &Elem<R>) -> Elem<R> {
    // Calculate a**-2 (mod q) == a**(q - 3) (mod q)
    //
    // The exponent (q - 3) is:
    //
    //    %(q_minus_3)s

    #[inline]
    fn sqr_mul(a: &Elem<R>, squarings: usize, b: &Elem<R>) -> Elem<R> {
        elem_sqr_mul(&COMMON_OPS, a, squarings, b)
    }

    #[inline]
    fn sqr_mul_acc(a: &mut Elem<R>, squarings: usize, b: &Elem<R>) {
        elem_sqr_mul_acc(&COMMON_OPS, a, squarings, b)
    }

    let b_1 = &a;

    todo!();

    acc
}

fn p%(bits)s_point_mul_base_impl(a: &Scalar) -> Point {
    // XXX: Not efficient. TODO: Precompute multiples of the generator.
    PRIVATE_KEY_OPS.point_mul(a, &GENERATOR)
}

pub static PUBLIC_KEY_OPS: PublicKeyOps = PublicKeyOps {
    common: &COMMON_OPS,
};

pub static SCALAR_OPS: ScalarOps = ScalarOps {
    common: &COMMON_OPS,
    scalar_mul_mont: p%(bits)s_scalar_mul_mont,
};

pub static PUBLIC_SCALAR_OPS: PublicScalarOps = PublicScalarOps {
    scalar_ops: &SCALAR_OPS,
    public_key_ops: &PUBLIC_KEY_OPS,
    twin_mul: |g_scalar, p_scalar, p_xy, cpu| {
        twin_mul_inefficient(&PRIVATE_KEY_OPS, g_scalar, p_scalar, p_xy, cpu)
    },

    q_minus_n: Elem::from_hex("%(q_minus_n)x"),

    // TODO: Use an optimized variable-time implementation.
    scalar_inv_to_mont_vartime: |s| PRIVATE_SCALAR_OPS.scalar_inv_to_mont(s),
};

pub static PRIVATE_SCALAR_OPS: PrivateScalarOps = PrivateScalarOps {
    scalar_ops: &SCALAR_OPS,

    oneRR_mod_n: Scalar::from_hex(%(oneRR_mod_n)s),
    scalar_inv_to_mont: p%(bits)s_scalar_inv_to_mont,
};

fn p%(bits)s_scalar_inv_to_mont(a: Scalar<R>) -> Scalar<R> {
    // Calculate the modular inverse of scalar |a| using Fermat's Little
    // Theorem:
    //
    //    a**-1 (mod n) == a**(n - 2) (mod n)
    //
    // The exponent (n - 2) is:
    //
    //    %(n_minus_2)s

    fn mul(a: &Scalar<R>, b: &Scalar<R>) -> Scalar<R> {
        binary_op(p%(bits)d_scalar_mul_mont, a, b)
    }

    fn sqr(a: &Scalar<R>) -> Scalar<R> {
        binary_op(p%(bits)d_scalar_mul_mont, a, a)
    }

    fn sqr_mut(a: &mut Scalar<R>) {
        unary_op_from_binary_op_assign(p%(bits)d_scalar_mul_mont, a);
    }

    // Returns (`a` squared `squarings` times) * `b`.
    fn sqr_mul(a: &Scalar<R>, squarings: usize, b: &Scalar<R>) -> Scalar<R> {
        debug_assert!(squarings >= 1);
        let mut tmp = sqr(a);
        for _ in 1..squarings {
            sqr_mut(&mut tmp);
        }
        mul(&tmp, b)
    }

    // Sets `acc` = (`acc` squared `squarings` times) * `b`.
    fn sqr_mul_acc(acc: &mut Scalar<R>, squarings: usize, b: &Scalar<R>) {
        debug_assert!(squarings >= 1);
        for _ in 0..squarings {
            sqr_mut(acc);
        }
        binary_op_assign(p%(bits)d_scalar_mul_mont, acc, b)
    }

    // Indexes into `d`.
    const B_1: usize = 0;
    todo!();
    const DIGIT_COUNT: usize = todo!();

    let mut d = [Scalar::zero(); DIGIT_COUNT];
    d[B_1] = a;
    let b_10 = sqr(&d[B_1]);
    for i in B_11..DIGIT_COUNT {
        d[i] = mul(&d[i - 1], &b_10);
    }

    todo!();

    // The rest of the exponent, in binary, is:
    //
    //    TODO

    static REMAINING_WINDOWS: [(u8, u8); 39] = [
        todo!()
    ];

    for &(squarings, digit) in &REMAINING_WINDOWS[..] {
        sqr_mul_acc(&mut acc, usize::from(squarings), &d[usize::from(digit)]);
    }

    acc
}

unsafe extern "C" fn p%(bits)s_elem_sqr_mont(
    r: *mut Limb,   // [COMMON_OPS.num_limbs]
    a: *const Limb, // [COMMON_OPS.num_limbs]
) {
    // XXX: Inefficient. TODO: Make a dedicated squaring routine.
    p%(bits)d_elem_mul_mont(r, a, a);
}

prefixed_extern! {
    fn p%(bits)s_elem_mul_mont(
        r: *mut Limb,   // [COMMON_OPS.num_limbs]
        a: *const Limb, // [COMMON_OPS.num_limbs]
        b: *const Limb, // [COMMON_OPS.num_limbs]
    );

    fn p%(bits)s_point_add(
        r: *mut Limb,   // [3][COMMON_OPS.num_limbs]
        a: *const Limb, // [3][COMMON_OPS.num_limbs]
        b: *const Limb, // [3][COMMON_OPS.num_limbs]
    );

    fn p%(bits)s_point_mul(
        r: *mut Limb,          // [3][COMMON_OPS.num_limbs]
        p_scalar: *const Limb, // [COMMON_OPS.num_limbs]
        p_x: *const Limb,      // [COMMON_OPS.num_limbs]
        p_y: *const Limb,      // [COMMON_OPS.num_limbs]
    );

    fn p%(bits)s_scalar_mul_mont(
        r: *mut Limb,   // [COMMON_OPS.num_limbs]
        a: *const Limb, // [COMMON_OPS.num_limbs]
        b: *const Limb, // [COMMON_OPS.num_limbs]
    );
}"""


import math
import random
import sys

def whole_bit_length(p, limb_bits):
    return (p.bit_length() + limb_bits - 1) // limb_bits * limb_bits

def to_montgomery_value(x, p, limb_bits):
    return (x * 2**whole_bit_length(p, limb_bits)) % p

def to_montgomery_(x, p, limb_bits):
    value = to_montgomery_value(x, p, limb_bits)
    return '"%x"' % value

def to_montgomery(x, p):
    mont64 = to_montgomery_(x, p, 64)
    mont32 = to_montgomery_(x, p, 32)
    if mont32 == mont64:
        value = mont64
    else:
        value = """
        if cfg!(target_pointer_width = "64") {
            %s
        } else {
            %s
        }""" % (mont64, mont32)
    return value

def rr(p):
    mont64 = to_montgomery_(2**whole_bit_length(p, 64), p, 64)
    mont32 = to_montgomery_(2**whole_bit_length(p, 32), p, 32)
    if mont32 == mont64:
        value = mont64
    else:
        value = """
        if cfg!(target_pointer_width = "64") {
            %s
        } else {
            %s
        }""" % (mont64, mont32)
    return value

# http://rosettacode.org/wiki/Modular_inverse#Python
def modinv(a, m):
    def extended_gcd(aa, bb):
        last_rem, rem = abs(aa), abs(bb)
        x, last_x, y, last_y = 0, 1, 1, 0
        while rem:
            last_rem, (quotient, rem) = rem, divmod(last_rem, rem)
            x, last_x = last_x - quotient * x, x
            y, last_y = last_y - quotient * y, y
        return (last_rem,
                last_x * (-1 if aa < 0 else 1),
                last_y * (-1 if bb < 0 else 1))

    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise ValueError
    return x % m

def format_curve_name(g):
    return "p%d" % g["q"].bit_length()

def generate_rs(g, out_dir):
    q = g["q"]
    n = g["n"]

    name = format_curve_name(g)

    q_minus_3 = "\\\n//      ".join(wrap(hex(q - 3), 66))
    n_minus_2 = "\\\n//      ".join(wrap(hex(n - 2), 66))

    output = rs_template % {
        "bits": g["q"].bit_length(),
        "name": name,
        "q" : q,
        "q_rr": rr(q),
        "q_minus_3": q_minus_3,
        "n" : n,
        "one" : to_montgomery(1, q),
        "a" : to_montgomery(g["a"], q),
        "b" : to_montgomery(g["b"], q),
        "Gx" : to_montgomery(g["Gx"], q),
        "Gy" : to_montgomery(g["Gy"], q),
        "q_minus_n" : q - n,
        "oneRR_mod_n": rr(n),
        "n_minus_2": n_minus_2,
    }

    out_path = os.path.join(out_dir, "%s.rs" % name)
    with open(out_path, "wb") as f:
        f.write(output.encode("utf-8"))
    subprocess.run(["rustfmt", out_path])

c_template = """
/* Copyright 2016-2023 Brian Smith.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include "../../limbs/limbs.h"
#include "../bn/internal.h"
#include "../../internal.h"

#include "../../limbs/limbs.inl"

#define BITS %(bits)d

#define P%(bits)d_LIMBS ((%(bits)d + LIMB_BITS - 1) / LIMB_BITS)

#define FE_LIMBS P%(bits)d_LIMBS

typedef Limb Elem[FE_LIMBS];
typedef Limb ScalarMont[FE_LIMBS];
typedef Limb Scalar[FE_LIMBS];

static const Elem Q = {
%(q)s
};

static const Elem N = {
%(n)s
};

static const Elem ONE = {
%(q_one)s
};

static const Elem Q_PLUS_1_SHR_1 = {
%(q_plus_1_shr_1)s
};

static const BN_ULONG Q_N0[] = {
  %(q_n0)s
};

static const BN_ULONG N_N0[] = {
  %(n_n0)s
};

/* XXX: MSVC for x86 warns when it fails to inline these functions it should
 * probably inline. */
#if defined(_MSC_VER) && !defined(__clang__) && defined(OPENSSL_X86)
#define INLINE_IF_POSSIBLE __forceinline
#else
#define INLINE_IF_POSSIBLE inline
#endif

/* Window values that are Ok for P384 (look at `ecp_nistz.h`): 2, 5, 6, 7 */
/* Window values that are Ok for P521 (look at `ecp_nistz.h`): 4 */
#define W_BITS %(w_bits)d

#include "ecp_nistz.inl"

"""

# Given a number |x|, return a generator of a sequence |a| such that
#
#     x == a[0] + a[1]*2**limb_bits + ...
#
def little_endian_limbs(x, limb_bits):
    if x < 0:
        raise ValueError("x must be positive");
    if x == 0:
        yield [0]
        return

    while x != 0:
        x, digit = divmod(x, 2**limb_bits)
        yield digit

def format_limb(x):
    if x < 10:
        return "%d" % x
    else:
        return "0x%x" % x

def format_big_int_(x, limb_count, limb_bits):
    num_limbs = limb_count(limb_bits)
    limbs = list(little_endian_limbs(x(limb_bits), limb_bits))
    limbs += (num_limbs - len(limbs)) * [0]
    return "\n  ".join(wrap(", ".join([format_limb(limb) for limb in limbs]), 80))

def format_big_int(x, limb_count):
    big = format_big_int_(x, limb_count, 64)
    small = format_big_int_(x, limb_count, 32)
    return """#if defined(OPENSSL_64_BIT)
  %s
#else
  %s
#endif""" % (big, small)

def format_n0(p):
    value = modinv(-p, 2**64)
    hi = value // (2**32)
    lo = value % (2**32)
    return "BN_MONT_CTX_N0(%s, %s)" % (format_limb(hi), format_limb(lo))

def const(value):
    return lambda _limb_bits: value

def big_int_limbs(p):
    return lambda limb_bits: (p.bit_count() + limb_bits - 1) // limb_bits

def generate_c(g, out_dir):
    q = g["q"]
    n = g["n"]

    name = format_curve_name(g)

    output = c_template % {
        "bits": q.bit_length(),
        "q" : format_big_int(const(q), big_int_limbs(q)),
        "q_n0": format_n0(q),
        "q_one" : format_big_int(lambda limb_bits: to_montgomery_value(1, q, limb_bits), big_int_limbs(q)),
        "q_plus_1_shr_1": format_big_int(const((q + 1) >> 1), big_int_limbs(q)),
        "n" : format_big_int(const(n), big_int_limbs(q)),
        "n_n0": format_n0(n),
        "w_bits": g["w_bits"],
    }

    out_path = os.path.join(out_dir, "gfp_%s.c" % name)
    with open(out_path, "wb") as f:
        f.write(output.encode("utf-8"))

def generate(g, out_dir):
    if g["a"] != -3:
        raise ValueError("Only curves where a == -3 are supported.")
    if g["cofactor"] != 1:
        raise ValueError("Only curves with cofactor 1 are supported.")
    if g["q"] != g["q_formula"]:
        raise ValueError("Polynomial representation of q doesn't match the "
                         "literal version given in the specification.")
    if g["n"] != g["n_formula"]:
        raise ValueError("Polynomial representation of n doesn't match the "
                         "literal version given in the specification.")

    generate_rs(g, out_dir)
    generate_c(g, out_dir)


# The curve parameters are from
# https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf.
# |q_formula| and |n_formula| are given in the polynomial representation so that
# their special structures are more evident. |q| and |n| are the hex literal
# representations of the same values given in the specs. Both are provided so that
# |generate_prime_curve_code| can verify that |q| and |n| are correct.

p256 = {
    "q_formula": 2**256 - 2**224 + 2**192 + 2**96 - 1,
    "q" : 115792089210356248762697446949407573530086143415290314195533631308867097853951,
    "n_formula": 2**256 - 2**224 + 2**192 - 2**128 + 0xbce6faad_a7179e84_f3b9cac2_fc632551,
    "n" : 0xffffffff_00000000_ffffffff_ffffffff_bce6faad_a7179e84_f3b9cac2_fc632551,
    "a": -3,
    "b":  0x5ac635d8_aa3a93e7_b3ebbd55_769886bc_651d06b0_cc53b0f6_3bce3c3e_27d2604b,
    "Gx": 0x6b17d1f2_e12c4247_f8bce6e5_63a440f2_77037d81_2deb33a0_f4a13945_d898c296,
    "Gy": 0x4fe342e2_fe1a7f9b_8ee7eb4a_7c0f9e16_2bce3357_6b315ece_cbb64068_37bf51f5,
    "cofactor": 1,
    "w_bits": 5,
}

p384 = {
    "q_formula": 2**384 - 2**128 - 2**96 + 2**32 - 1,
    "q" : 0xffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_fffffffe_ffffffff_00000000_00000000_ffffffff,
    "n_formula": 2**384 - 2**192 + 0xc7634d81_f4372ddf_581a0db2_48b0a77a_ecec196a_ccc52973,
    "n" : 0xffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_c7634d81_f4372ddf_581a0db2_48b0a77a_ecec196a_ccc52973,
    "a": -3,
    "b": 0xb3312fa7_e23ee7e4_988e056b_e3f82d19_181d9c6e_fe814112_0314088f_5013875a_c656398d_8a2ed19d_2a85c8ed_d3ec2aef,
    "Gx": 0xaa87ca22_be8b0537_8eb1c71e_f320ad74_6e1d3b62_8ba79b98_59f741e0_82542a38_5502f25d_bf55296c_3a545e38_72760ab7,
    "Gy": 0x3617de4a_96262c6f_5d9e98bf_9292dc29_f8f41dbd_289a147c_e9da3113_b5f0b8c0_0a60b1ce_1d7e819d_7a431d7c_90ea0e5f,
    "cofactor": 1,
    "w_bits": 5,
}

p521 = {
    "q_formula": 2**521 - 1,
    "q" : 0x1ff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff,
    "n_formula": 2**521 - 2**260 + 0xa_51868783_bf2f966b_7fcc0148_f709a5d0_3bb5c9b8_899c47ae_bb6fb71e_91386409,
    "n" : 0x1ff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_fffffffa_51868783_bf2f966b_7fcc0148_f709a5d0_3bb5c9b8_899c47ae_bb6fb71e_91386409,
    "a": -3,
    "b": 0x051_953eb961_8e1c9a1f_929a21a0_b68540ee_a2da725b_99b315f3_b8b48991_8ef109e1_56193951_ec7e937b_1652c0bd_3bb1bf07_3573df88_3d2c34f1_ef451fd4_6b503f00,
    "Gx": 0xc6_858e06b7_0404e9cd_9e3ecb66_2395b442_9c648139_053fb521_f828af60_6b4d3dba_a14b5e77_efe75928_fe1dc127_a2ffa8de_3348b3c1_856a429b_f97e7e31_c2e5bd66,
    "Gy": 0x118_39296a78_9a3bc004_5c8a5fb4_2c7d1bd9_98f54449_579b4468_17afbd17_273e662c_97ee7299_5ef42640_c550b901_3fad0761_353c7086_a272c240_88be9476_9fd16650,
    "cofactor": 1,
    "w_bits": 4,
}

import os
import subprocess

out_dir = "target/curves"
os.makedirs(out_dir, exist_ok=True)
for curve in [p256, p384, p521]:
    generate(curve, out_dir)
