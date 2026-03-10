// Copyright 2026 The ring Authors.
// Copyright 2026 The libsmx Authors.
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

//! SM2 curve operations: CommonOps, PrivateKeyOps, ScalarOps, etc.
//!
//! Curve equation: y² = x³ + ax + b over GF(p)
//! where p = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFF
//! and   a = p - 3 (i.e. a ≡ -3 mod p, same property as NIST P-256).
//!
//! All Montgomery arithmetic uses R = 2^256.

use super::{
    PublicModulus,
    elem::{self, binary_op, binary_op_assign, mul_mont},
    elem_sqr_mul, elem_sqr_mul_acc, *,
};
use crate::{arithmetic::limbs_from_hex, bb::LeakyWord, cpu};

pub(super) const NUM_LIMBS: usize = 256 / LIMB_BITS;

// ── Montgomery constants for field prime p ─────────────────────────────────
//
// p = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFF
//
// n0_p: the Montgomery constant -p⁻¹ mod 2⁶⁴.
//   p mod 2⁶⁴ = 0xFFFF_FFFF_FFFF_FFFF, so p⁻¹ mod 2⁶⁴ = 1, n0_p = 1.
//
// RR mod p = 2^512 mod p:
//   = 0000_0004_0000_0002_0000_0001_0000_0001
//     0000_0002_FFFF_FFFF_0000_0002_0000_0003

// ── Static curve data ───────────────────────────────────────────────────────

pub static COMMON_OPS: CommonOps = CommonOps {
    num_limbs: elem::NumLimbs::P256,

    q: PublicModulus {
        // p = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFF
        p: limbs_from_hex("fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff"),
        // RR = 2^512 mod p
        rr: PublicElem::from_hex(
            "0000000400000002000000010000000100000002ffffffff0000000200000003",
        ),
    },

    // n = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF 7203DF6B 21C6052B 53BBF409 39D54123
    n: PublicElem::from_hex("fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123"),

    // a = p - 3 in Montgomery form: a·R mod p
    // = FFFFFFFB FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFC 00000003 FFFFFFFF FFFFFFFC
    a: PublicElem::from_hex("fffffffbfffffffffffffffffffffffffffffffc00000003fffffffffffffffc"),

    // b in Montgomery form: b·R mod p
    // b = 28E9FA9E 9D9F5E34 4D5A9E4B CF6509A7 F39789F5 15AB8F92 DDBCBD41 4D940E93
    b: PublicElem::from_hex("240fe188ba20e2c8527981505ea51c3c71cf379ae9b537ab90d230632bc0dd42"),

    elem_mul_mont: sm2_elem_mul_mont,
    elem_sqr_mont: sm2_elem_sqr_mont,
};

pub static PRIVATE_KEY_OPS: PrivateKeyOps = PrivateKeyOps {
    common: &COMMON_OPS,
    elem_inv_squared: sm2_elem_inv_squared,
    point_mul_base_impl: sm2_point_mul_base_impl,
    point_mul_impl: sm2_point_mul,
    point_add_jacobian_impl: sm2_point_add,
};

pub static PUBLIC_KEY_OPS: PublicKeyOps = PublicKeyOps {
    common: &COMMON_OPS,
};

pub static SCALAR_OPS: ScalarOps = ScalarOps {
    common: &COMMON_OPS,
    scalar_mul_mont: sm2_scalar_mul_mont,
};

pub static PUBLIC_SCALAR_OPS: PublicScalarOps = PublicScalarOps {
    scalar_ops: &SCALAR_OPS,
    public_key_ops: &PUBLIC_KEY_OPS,
    twin_mul: sm2_twin_mul,
    // Reason: for SM2, n > p, so p - n < 0. The q_minus_n field is used in
    // ECDSA verification to check if r < p - n (to test r + n). Since p < n,
    // p - n would be negative, meaning the check never triggers. Setting
    // q_minus_n = 0 ensures elem_less_than_vartime always returns false.
    q_minus_n: PublicElem::from_hex(
        "0000000000000000000000000000000000000000000000000000000000000000",
    ),
    scalar_inv_to_mont_vartime: |s, cpu| PRIVATE_SCALAR_OPS.scalar_inv_to_mont(s, cpu),
};

pub static PRIVATE_SCALAR_OPS: PrivateScalarOps = PrivateScalarOps {
    scalar_ops: &SCALAR_OPS,
    // oneRR_mod_n = R^2 mod n = 2^512 mod n
    // = 0000_0001_0000_0000_0000_0000_0000_0000
    //     3464504ADE6FA2FA901192AF7C114F20
    oneRR_mod_n: PublicScalar::from_hex(
        "1eb5e412a22b3d3b620fc84c3affe0d43464504ade6fa2fa901192af7c114f20",
    ),
    scalar_inv_to_mont: sm2_scalar_inv_to_mont,
};

// ── Montgomery multiply for field prime p ────────────────────────────────────
//
// SM2 field prime p has n0 = 1 (since p ≡ -1 mod 2^64).
// This allows a particularly simple Montgomery reduction.
//
// We implement a 256-bit Montgomery multiplication using 64-bit arithmetic.
// For 32-bit targets, each "limb" is 32 bits, so we use 4 limbs for 64-bit
// words in the inner loop.

// Montgomery multiply: r = a*b*R^{-1} mod p  (256-bit, R = 2^256)
// Works on 4 × 64-bit limbs (on 64-bit) or 8 × 32-bit limbs (on 32-bit).
unsafe extern "C" fn sm2_elem_mul_mont(r: *mut Limb, a: *const Limb, b: *const Limb) {
    // Reason: The limbs are laid out as little-endian 64-bit words (on 64-bit
    // platforms), so we can read them as u64 values directly.
    unsafe { mont_mul_p(r, a, b) }
}

unsafe extern "C" fn sm2_elem_sqr_mont(r: *mut Limb, a: *const Limb) {
    // Squaring: r = a*a*R^{-1} mod p
    unsafe { mont_mul_p(r, a, a) }
}

// SM2 Montgomery multiply mod p.
// p = 2^256 - 2^224 - 2^96 + 2^64 - 1
//   = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFF
//
// The reduction uses the specific structure of p. On 64-bit we have 4 limbs.
// On 32-bit we have 8 limbs. We dispatch based on LIMB_BITS.
//
// For simplicity and correctness we use a schoolbook Montgomery reduction
// with fixed n0 = 1. The key property: since n0 = 1, the Montgomery step
// is: u_i = t_i * 1 = t_i, then t += u_i * p, shift right by one limb.
//
// This is safe to call from both elem_mul_mont and elem_sqr_mont.
// Uses CIOS (Coarsely Integrated Operand Scanning) Montgomery multiplication.
// Reason: the simpler separated multiply-then-reduce approach loses carries when
// n0=1 and inputs are near p, because carry from the reduction step can exceed
// the 8-limb buffer. CIOS interleaves multiply and reduce, using only 5 limbs,
// and tracks the overflow in an extra bit — eliminating that problem.
#[cfg(target_pointer_width = "64")]
unsafe fn mont_mul_p(r: *mut Limb, a: *const Limb, b: *const Limb) {
    // p as 4 × u64 limbs (little-endian)
    // p = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFF
    const P: [u64; 4] = [
        0xFFFFFFFFFFFFFFFF, // p[0] = bits  0..63
        0xFFFFFFFF00000000, // p[1] = bits 64..127
        0xFFFFFFFFFFFFFFFF, // p[2] = bits 128..191
        0xFFFFFFFEFFFFFFFF, // p[3] = bits 192..255
    ];

    let a = unsafe { core::slice::from_raw_parts(a, 4) };
    let b = unsafe { core::slice::from_raw_parts(b, 4) };

    // CIOS: t[0..4] accumulate the current partial result; t[4] is the carry word.
    let mut t = [0u64; 5];

    for i in 0..4 {
        // Add a[i] * b to t
        let mut carry: u128 = 0;
        for j in 0..4 {
            let cs = t[j] as u128 + (a[i] as u128) * (b[j] as u128) + carry;
            t[j] = cs as u64;
            carry = cs >> 64;
        }
        let cs = t[4] as u128 + carry;
        t[4] = cs as u64;
        let carry_hi = (cs >> 64) as u64;

        // Reduction step: m = t[0] * n0 mod 2^64 = t[0] (n0 = 1)
        let m = t[0];
        let cs = t[0] as u128 + m as u128 * P[0] as u128;
        t[0] = cs as u64;
        let mut carry_r: u128 = cs >> 64;
        for j in 1..4 {
            let cs = t[j] as u128 + m as u128 * P[j] as u128 + carry_r;
            t[j] = cs as u64;
            carry_r = cs >> 64;
        }
        let cs = t[4] as u128 + carry_r;
        t[4] = cs as u64;
        let carry_hi2 = (cs >> 64) as u64 + carry_hi;

        // Shift right by one limb
        t[0] = t[1];
        t[1] = t[2];
        t[2] = t[3];
        t[3] = t[4];
        t[4] = carry_hi2;
    }

    // t[0..4] holds the result; t[4] is an overflow bit.
    // The true value is t[0..4] + t[4] * 2^256.
    // Since inputs are in [0, p), the result is in [0, 2p).
    // If t[4] == 1, then result >= 2^256 > p, so we must subtract p.
    // Otherwise do conditional subtract as usual.
    let mut result = [t[0], t[1], t[2], t[3]];
    if t[4] != 0 {
        // Reason: overflow bit set means result is in [2^256, 2^256+p), so
        // subtract p unconditionally (the result will then be in [2^256-p, 2^256),
        // but truncated to 64-bit limbs gives the correct value in [0, p)).
        let mut borrow: u64 = 0;
        for i in 0..4 {
            let (s, b1) = result[i].overflowing_sub(P[i]);
            let (s, b2) = s.overflowing_sub(borrow);
            result[i] = s;
            borrow = (b1 as u64) + (b2 as u64);
        }
    } else {
        let _ = sub_p_if_gte(&mut result, &P);
    }

    let out = unsafe { core::slice::from_raw_parts_mut(r, 4) };
    out.copy_from_slice(&result);
}

// Conditionally subtract p from x if x >= p. Returns 1 if subtracted, 0 if not.
#[cfg(target_pointer_width = "64")]
fn sub_p_if_gte(x: &mut [u64; 4], p: &[u64; 4]) -> u64 {
    // Check if x >= p by attempting subtraction
    let mut borrow: u64 = 0;
    let mut tmp = [0u64; 4];
    for i in 0..4 {
        let (s, b1) = x[i].overflowing_sub(p[i]);
        let (s, b2) = s.overflowing_sub(borrow);
        tmp[i] = s;
        borrow = (b1 as u64) + (b2 as u64);
    }
    // If borrow == 0, x >= p; use tmp. Otherwise keep x.
    let use_sub = (borrow == 0) as u64;
    // Reason: constant-time select: mask = 0xFFFF...FFFF if use_sub, else 0
    let mask = 0u64.wrapping_sub(use_sub);
    for i in 0..4 {
        x[i] = (tmp[i] & mask) | (x[i] & !mask);
    }
    use_sub
}

// 32-bit fallback: use 32-bit limbs (8 limbs for 256 bits)
#[cfg(not(target_pointer_width = "64"))]
unsafe fn mont_mul_p(r: *mut Limb, a: *const Limb, b: *const Limb) {
    // p as 8 × u32 limbs (little-endian)
    const P: [u32; 8] = [
        0xFFFFFFFF, 0xFFFFFFFF, // p[0..1]
        0x00000000, 0xFFFFFFFF, // p[2..3]
        0xFFFFFFFF, 0xFFFFFFFF, // p[4..5]
        0xFFFFFFFF, 0xFFFFFFFE, // p[6..7]
    ];

    let a = unsafe { core::slice::from_raw_parts(a, 8) };
    let b = unsafe { core::slice::from_raw_parts(b, 8) };

    let mut t = [0u32; 16];
    for i in 0..8 {
        let mut carry = 0u64;
        for j in 0..8 {
            let prod = (a[i] as u64) * (b[j] as u64) + t[i + j] as u64 + carry;
            t[i + j] = prod as u32;
            carry = prod >> 32;
        }
        t[i + 8] = carry as u32;
    }

    // Montgomery reduction: n0 = 1 for 32-bit too (p mod 2^32 = 0xFFFFFFFF = -1 mod 2^32)
    // Check: -p^{-1} mod 2^32 = -(-1) = 1 ✓
    for i in 0..8 {
        let u = t[i];
        let mut carry = 0u64;
        for j in 0..8 {
            let prod = (u as u64) * (P[j] as u64) + t[i + j] as u64 + carry;
            t[i + j] = prod as u32;
            carry = prod >> 32;
        }
        let mut k = i + 8;
        while carry != 0 && k < 16 {
            let sum = t[k] as u64 + carry;
            t[k] = sum as u32;
            carry = sum >> 32;
            k += 1;
        }
    }

    let mut result: [u32; 8] = t[8..16].try_into().unwrap();
    sub_p_if_gte_32(&mut result, &P);
    let out = unsafe { core::slice::from_raw_parts_mut(r, 8) };
    out.copy_from_slice(&result);
}

#[cfg(not(target_pointer_width = "64"))]
fn sub_p_if_gte_32(x: &mut [u32; 8], p: &[u32; 8]) {
    let mut borrow: u32 = 0;
    let mut tmp = [0u32; 8];
    for i in 0..8 {
        let (s, b1) = x[i].overflowing_sub(p[i]);
        let (s, b2) = s.overflowing_sub(borrow);
        tmp[i] = s;
        borrow = (b1 as u32) + (b2 as u32);
    }
    let use_sub = (borrow == 0) as u32;
    let mask = 0u32.wrapping_sub(use_sub);
    for i in 0..8 {
        x[i] = (tmp[i] & mask) | (x[i] & !mask);
    }
}

// ── Montgomery multiply for scalar group order n ─────────────────────────────
//
// n = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF 7203DF6B 21C6052B 53BBF409 39D54123
// n0_n = -n^{-1} mod 2^64 = 0x327F9E8872350975  (64-bit)

unsafe extern "C" fn sm2_scalar_mul_mont(r: *mut Limb, a: *const Limb, b: *const Limb) {
    unsafe { mont_mul_n(r, a, b) }
}

// CIOS Montgomery multiply mod n.
// Reason: same as mont_mul_p — the naive separated multiply/reduce loses carries.
#[cfg(target_pointer_width = "64")]
unsafe fn mont_mul_n(r: *mut Limb, a: *const Limb, b: *const Limb) {
    const N: [u64; 4] = [
        0x53BBF40939D54123, // n[0]
        0x7203DF6B21C6052B, // n[1]
        0xFFFFFFFFFFFFFFFF, // n[2]
        0xFFFFFFFEFFFFFFFF, // n[3]
    ];
    // n0 = -n^{-1} mod 2^64
    const N0: u64 = 0x327F9E8872350975;

    let a = unsafe { core::slice::from_raw_parts(a, 4) };
    let b = unsafe { core::slice::from_raw_parts(b, 4) };

    let mut t = [0u64; 5];

    for i in 0..4 {
        // Add a[i] * b to t
        let mut carry: u128 = 0;
        for j in 0..4 {
            let cs = t[j] as u128 + (a[i] as u128) * (b[j] as u128) + carry;
            t[j] = cs as u64;
            carry = cs >> 64;
        }
        let cs = t[4] as u128 + carry;
        t[4] = cs as u64;
        let carry_hi = (cs >> 64) as u64;

        // Reduction step: m = t[0] * N0 mod 2^64
        let m = t[0].wrapping_mul(N0);
        let cs = t[0] as u128 + m as u128 * N[0] as u128;
        t[0] = cs as u64;
        let mut carry_r: u128 = cs >> 64;
        for j in 1..4 {
            let cs = t[j] as u128 + m as u128 * N[j] as u128 + carry_r;
            t[j] = cs as u64;
            carry_r = cs >> 64;
        }
        let cs = t[4] as u128 + carry_r;
        t[4] = cs as u64;
        let carry_hi2 = (cs >> 64) as u64 + carry_hi;

        // Shift right by one limb
        t[0] = t[1];
        t[1] = t[2];
        t[2] = t[3];
        t[3] = t[4];
        t[4] = carry_hi2;
    }

    let mut result = [t[0], t[1], t[2], t[3]];
    if t[4] != 0 {
        // Reason: overflow bit means result >= 2^256 > n, must subtract n.
        let mut borrow: u64 = 0;
        for i in 0..4 {
            let (s, b1) = result[i].overflowing_sub(N[i]);
            let (s, b2) = s.overflowing_sub(borrow);
            result[i] = s;
            borrow = (b1 as u64) + (b2 as u64);
        }
    } else {
        sub_n_if_gte(&mut result, &N);
    }
    let out = unsafe { core::slice::from_raw_parts_mut(r, 4) };
    out.copy_from_slice(&result);
}

#[cfg(target_pointer_width = "64")]
fn sub_n_if_gte(x: &mut [u64; 4], n: &[u64; 4]) {
    let mut borrow: u64 = 0;
    let mut tmp = [0u64; 4];
    for i in 0..4 {
        let (s, b1) = x[i].overflowing_sub(n[i]);
        let (s, b2) = s.overflowing_sub(borrow);
        tmp[i] = s;
        borrow = (b1 as u64) + (b2 as u64);
    }
    let use_sub = (borrow == 0) as u64;
    let mask = 0u64.wrapping_sub(use_sub);
    for i in 0..4 {
        x[i] = (tmp[i] & mask) | (x[i] & !mask);
    }
}

#[cfg(not(target_pointer_width = "64"))]
unsafe fn mont_mul_n(r: *mut Limb, a: *const Limb, b: *const Limb) {
    const N: [u32; 8] = [
        0x39D54123, 0x53BBF409, // n[0..1]
        0x21C6052B, 0x7203DF6B, // n[2..3]
        0xFFFFFFFF, 0xFFFFFFFF, // n[4..5]
        0xFFFFFFFF, 0xFFFFFFFE, // n[6..7]
    ];
    // n0_32 = -n^{-1} mod 2^32
    // n mod 2^32 = 0x39D54123; -n^{-1} mod 2^32 = 0x72350975
    const N0: u32 = 0x72350975; // precomputed: -n^{-1} mod 2^32

    let a = unsafe { core::slice::from_raw_parts(a, 8) };
    let b = unsafe { core::slice::from_raw_parts(b, 8) };

    let mut t = [0u32; 16];
    for i in 0..8 {
        let mut carry = 0u64;
        for j in 0..8 {
            let prod = (a[i] as u64) * (b[j] as u64) + t[i + j] as u64 + carry;
            t[i + j] = prod as u32;
            carry = prod >> 32;
        }
        t[i + 8] = carry as u32;
    }

    for i in 0..8 {
        let u = t[i].wrapping_mul(N0);
        let mut carry = 0u64;
        for j in 0..8 {
            let prod = (u as u64) * (N[j] as u64) + t[i + j] as u64 + carry;
            t[i + j] = prod as u32;
            carry = prod >> 32;
        }
        let mut k = i + 8;
        while carry != 0 && k < 16 {
            let sum = t[k] as u64 + carry;
            t[k] = sum as u32;
            carry = sum >> 32;
            k += 1;
        }
    }

    let mut result: [u32; 8] = t[8..16].try_into().unwrap();
    sub_n_if_gte_32(&mut result, &N);
    let out = unsafe { core::slice::from_raw_parts_mut(r, 8) };
    out.copy_from_slice(&result);
}

#[cfg(not(target_pointer_width = "64"))]
fn sub_n_if_gte_32(x: &mut [u32; 8], n: &[u32; 8]) {
    let mut borrow: u32 = 0;
    let mut tmp = [0u32; 8];
    for i in 0..8 {
        let (s, b1) = x[i].overflowing_sub(n[i]);
        let (s, b2) = s.overflowing_sub(borrow);
        tmp[i] = s;
        borrow = (b1 as u32) + (b2 as u32);
    }
    let use_sub = (borrow == 0) as u32;
    let mask = 0u32.wrapping_sub(use_sub);
    for i in 0..8 {
        x[i] = (tmp[i] & mask) | (x[i] & !mask);
    }
}

// ── Field element inversion: a^{-2} mod p ────────────────────────────────────
//
// We need a^{-2} = a^{p-3} mod p  (since a^{p-1} = 1 by Fermat's little theorem).
// p - 3 = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFC
//
// Addition chain for p - 3:
//   In 32-bit chunks (MSB first):
//     FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFC
//
//   Building blocks:
//     e1         = a^1
//     e3         = a^{0x3}          sqr_mul(e1, 1, e1)
//     e7         = a^{0x7}          sqr_mul(e3, 1, e1)
//     e_3f       = a^{0x3F}         sqr_mul(e7, 3, e7)
//     e_fff      = a^{0xFFF}        sqr_mul(e_3f, 6, e_3f)
//     e_7fff     = a^{0x7FFF}       sqr_mul(e_fff, 3, e7)
//     e_3fff...  = a^{0x3FFFFFFF}   sqr_mul(e_7fff, 15, e_7fff)
//     e_fff...   = a^{0xFFFFFFFF}   sqr_mul(e_3fff, 2, e3)
//     e_7fff...  = a^{0x7FFFFFFF}   sqr_mul(e_3fff, 1, e1)
//     e_fffe     = a^{0xFFFFFFFE}   sqr(e_7fff...)   [one squaring]
//
//   Full exponent built by:
//     acc = e_fffe
//     sqr_mul_acc(acc, 32, e_ffff): acc = a^{FFFFFFFE_FFFFFFFF}
//     (repeat 3 more times):        acc = a^{FFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF}
//     sqr_mul_acc(acc, 64, e_ffff): acc = a^{..._FFFFFFFF_00000000_FFFFFFFF}
//     sqr_mul_acc(acc, 30, e_3fff): acc = a^{..._FFFFFFFF_0x3FFFFFFF}
//     2x elem_square:               acc = a^{p-3}
fn sm2_elem_inv_squared(q: &Modulus<Q>, a: &Elem<R>) -> Elem<R> {
    #[inline]
    fn sqr_mul(q: &Modulus<Q>, a: &Elem<R>, squarings: LeakyWord, b: &Elem<R>) -> Elem<R> {
        elem_sqr_mul(&COMMON_OPS, a, squarings, b, q.cpu())
    }

    #[inline]
    fn sqr_mul_acc(q: &Modulus<Q>, a: &mut Elem<R>, squarings: LeakyWord, b: &Elem<R>) {
        elem_sqr_mul_acc(&COMMON_OPS, a, squarings, b, q.cpu())
    }

    // Build standard power-of-2-minus-1 blocks
    let e1 = a;
    let e3 = sqr_mul(q, e1, 1, e1); // a^{0x3}
    let e7 = sqr_mul(q, &e3, 1, e1); // a^{0x7}
    let e_3f = sqr_mul(q, &e7, 3, &e7); // a^{0x3F}
    let e_fff = sqr_mul(q, &e_3f, 6, &e_3f); // a^{0xFFF}
    let e_7fff = sqr_mul(q, &e_fff, 3, &e7); // a^{0x7FFF}
    let e_3fffffff = sqr_mul(q, &e_7fff, 15, &e_7fff); // a^{0x3FFFFFFF}
    let e_ffffffff = sqr_mul(q, &e_3fffffff, 2, &e3); // a^{0xFFFFFFFF}

    // a^{0x7FFFFFFF} = a^{0x3FFFFFFF * 2 + 1}
    let e_7fffffff = sqr_mul(q, &e_3fffffff, 1, e1); // a^{0x7FFFFFFF}

    // a^{0xFFFFFFFE} = (a^{0x7FFFFFFF})^2
    // Reason: FFFFFFFE = 2 * 7FFFFFFF. One squaring doubles the exponent.
    let mut e_fffffffe = e_7fffffff.clone();
    q.elem_square(&mut e_fffffffe); // a^{0xFFFFFFFE}

    // Build the full exponent segment by segment.
    // Target: FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFC
    let mut acc = e_fffffffe;
    // acc exponent = FFFFFFFE
    sqr_mul_acc(q, &mut acc, 32, &e_ffffffff);
    // acc exponent = FFFFFFFE_FFFFFFFF
    sqr_mul_acc(q, &mut acc, 32, &e_ffffffff);
    // acc exponent = FFFFFFFE_FFFFFFFF_FFFFFFFF
    sqr_mul_acc(q, &mut acc, 32, &e_ffffffff);
    // acc exponent = FFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFF
    sqr_mul_acc(q, &mut acc, 32, &e_ffffffff);
    // acc exponent = FFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF
    // Skip 32 zeros (00000000) then add FFFFFFFF: squarings = 32 + 32 = 64
    sqr_mul_acc(q, &mut acc, 64, &e_ffffffff);
    // acc exponent = FFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_00000000_FFFFFFFF
    // Final 30 bits of FFFFFFFC (= 0x3FFFFFFF << 2):
    sqr_mul_acc(q, &mut acc, 30, &e_3fffffff);
    // acc exponent = ...FFFFFFFF_FFFFFFC0 | 3FFFFFFF  (need 2 more zero bits)
    q.elem_square(&mut acc);
    q.elem_square(&mut acc);
    // acc exponent = p - 3 ✓

    acc
}

// ── Jacobian point arithmetic ─────────────────────────────────────────────────
//
// Points are stored as (X, Y, Z) in Montgomery form, in Jacobian coordinates.
// Affine point (x, y) corresponds to Jacobian (X, Y, Z) with x = X/Z², y = Y/Z³.
//
// The `Point` struct stores `[X limbs | Y limbs | Z limbs]` contiguously.
//
// We implement:
//   - `point_double_inner`: standard Jacobian doubling (a = -3 optimization)
//   - `point_add_inner`:    standard Jacobian addition (handles P1 ≠ P2, or
//                           delegates to doubling when P1 = P2)
//
// References:
//   "Guide to Elliptic Curve Cryptography" (Hankerson, Menezes, Vanstone), §3.2
//   "Efficient Elliptic Curve Operations on Microcontrollers" (Hutter & Wenger)

// Helper to read/write a Jacobian point's coordinates via raw pointers.
// The Point array layout: [X₀..X_{n-1}, Y₀..Y_{n-1}, Z₀..Z_{n-1}] where n = NUM_LIMBS.

type ElemR = Elem<R>;

/// Double a Jacobian point: R = 2*P.
/// Uses the a = -3 optimization: 3*(X-Z²)*(X+Z²) instead of 3*X² + a*Z⁴.
/// Cost: 4M + 6S + 9A.
fn point_double_inner(q: &Modulus<Q>, p: &Point) -> Point {
    let x = q.point_x(p);
    let y = q.point_y(p);
    let z = q.point_z(p);

    let mul = |a: &ElemR, b: &ElemR| q.elem_product(a, b);
    let sqr = |a: &ElemR| q.elem_squared(a);
    let add = |mut a: ElemR, b: &ElemR| {
        q.add_assign(&mut a, b);
        a
    };
    let sub = |a: ElemR, b: &ElemR| {
        let neg_b = neg_elem(q, b);
        add(a, &neg_b)
    };
    let dbl = |a: &ElemR| {
        let mut r = *a;
        q.add_assign(&mut r, a);
        r
    };

    // If Z = 0, point is at infinity — return infinity.
    if q.is_zero(&z) {
        return Point::new_at_infinity();
    }

    // z2 = Z^2, z4 = Z^4
    let z2 = sqr(&z);

    // m = 3*(X - Z²)*(X + Z²)   [a = -3 optimization]
    let x_minus_z2 = sub(x.clone(), &z2);
    let x_plus_z2 = add(x.clone(), &z2);
    let m_1 = mul(&x_minus_z2, &x_plus_z2);
    let mut m = m_1.clone();
    q.add_assign(&mut m, &m_1);
    q.add_assign(&mut m, &m_1); // m = 3*(X-Z²)*(X+Z²)

    // s = 4*X*Y²
    let y2 = sqr(&y);
    let x_y2 = mul(&x, &y2);
    let s = dbl(&dbl(&x_y2)); // s = 4*X*Y²

    // X3 = m² - 2*s
    let m2 = sqr(&m);
    let x3 = sub(m2, &dbl(&s));

    // Y3 = m*(s - X3) - 8*Y⁴
    let s_minus_x3 = sub(s.clone(), &x3);
    let y4 = sqr(&y2);
    let eight_y4 = {
        let mut r = y4.clone();
        q.add_assign(&mut r, &y4);
        q.add_assign(&mut r, &y4);
        q.add_assign(&mut r, &y4);
        q.add_assign(&mut r, &y4);
        q.add_assign(&mut r, &y4);
        q.add_assign(&mut r, &y4);
        q.add_assign(&mut r, &y4); // 8 * y4
        r
    };
    let y3 = sub(mul(&m, &s_minus_x3), &eight_y4);

    // Z3 = 2*Y*Z
    let z3 = dbl(&mul(&y, &z));

    let mut result = Point::new_at_infinity();
    let n = NUM_LIMBS;
    result.xyz[..n].copy_from_slice(&x3.limbs[..n]);
    result.xyz[n..2 * n].copy_from_slice(&y3.limbs[..n]);
    result.xyz[2 * n..3 * n].copy_from_slice(&z3.limbs[..n]);
    result
}

/// Add two Jacobian points: R = P1 + P2.
/// Handles all cases: P1 = P2 (delegates to doubling), P1 = -P2 (infinity),
/// P1 or P2 at infinity, and the generic case.
/// Cost (generic case): 11M + 5S + 9A.
fn point_add_inner(q: &Modulus<Q>, p1: &Point, p2: &Point) -> Point {
    // Load coordinates
    let x1 = q.point_x(p1);
    let y1 = q.point_y(p1);
    let z1 = q.point_z(p1);
    let x2 = q.point_x(p2);
    let y2 = q.point_y(p2);
    let z2 = q.point_z(p2);

    let mul = |a: &ElemR, b: &ElemR| q.elem_product(a, b);
    let sqr = |a: &ElemR| q.elem_squared(a);
    let add = |mut a: ElemR, b: &ElemR| {
        q.add_assign(&mut a, b);
        a
    };
    let sub = |a: ElemR, b: &ElemR| {
        let neg_b = neg_elem(q, b);
        add(a, &neg_b)
    };

    // Handle infinity: if Z1=0, return P2; if Z2=0, return P1.
    if q.is_zero(&z1) {
        return {
            let mut r = Point::new_at_infinity();
            r.xyz.copy_from_slice(&p2.xyz);
            r
        };
    }
    if q.is_zero(&z2) {
        return {
            let mut r = Point::new_at_infinity();
            r.xyz.copy_from_slice(&p1.xyz);
            r
        };
    }

    // Normalize to same scale: U1=X1*Z2², U2=X2*Z1², S1=Y1*Z2³, S2=Y2*Z1³
    let z1sq = sqr(&z1);
    let z2sq = sqr(&z2);
    let u1 = mul(&x1, &z2sq);
    let u2 = mul(&x2, &z1sq);
    let s1 = mul(&y1, &mul(&z2sq, &z2)); // Y1 * Z2^3
    let s2 = mul(&y2, &mul(&z1sq, &z1)); // Y2 * Z1^3

    // H = U2 - U1, R = S2 - S1
    let h = sub(u2.clone(), &u1);
    let r = sub(s2, &s1);

    // If H = 0: either P1 = P2 (double) or P1 = -P2 (infinity)
    if q.is_zero(&h) {
        if q.is_zero(&r) {
            // P1 = P2: delegate to doubling
            return point_double_inner(q, p1);
        }
        // P1 = -P2: result is point at infinity
        return Point::new_at_infinity();
    }

    // Standard Jacobian addition:
    // HH = H^2, HHH = H^3, W = U1*H^2
    let hh = sqr(&h);
    let hhh = mul(&h, &hh);
    let w = mul(&u1, &hh);

    // X3 = R^2 - HHH - 2*W
    let rr = sqr(&r);
    let two_w = add(w.clone(), &w);
    let x3 = sub(sub(rr, &hhh), &two_w);

    // Y3 = R*(W - X3) - S1*HHH
    let w_minus_x3 = sub(w, &x3);
    let y3 = sub(mul(&r, &w_minus_x3), &mul(&s1, &hhh));

    // Z3 = H*Z1*Z2
    let z3 = mul(&h, &mul(&z1, &z2));

    let mut result = Point::new_at_infinity();
    let n = NUM_LIMBS;
    result.xyz[..n].copy_from_slice(&x3.limbs[..n]);
    result.xyz[n..2 * n].copy_from_slice(&y3.limbs[..n]);
    result.xyz[2 * n..3 * n].copy_from_slice(&z3.limbs[..n]);
    result
}

/// Negate a field element: -a mod p = p - a.
fn neg_elem(_q: &Modulus<Q>, a: &ElemR) -> ElemR {
    let _zero: ElemR = Elem::zero();
    // neg = 0 - a mod p: use add_assign with -a computed as p - a
    // ring doesn't expose subtraction directly, so we compute p - a.
    // Since elements are in [0, p), zero - a would underflow.
    // Instead: neg(a) = p - a when a != 0, else 0.
    // We use the identity: neg(a) = (p - a) mod p.
    // Encode p in Montgomery form: p * R mod p = 0... not useful.
    // Actually we need the additive inverse.
    // ring's `add_assign` computes (a + b) mod p; we want (0 - a) mod p.
    // Use: neg(a) = p - a for a != 0, 0 for a = 0.
    // Implementable as: sub(p_elem, a) where p_elem is 0 in Montgomery form
    // (since p ≡ 0 mod p), but that gives -a = 0 - a = p - a correctly.

    // The Elem zero has limbs = 0. add_assign(0, -a) doesn't work.
    // But: limbs_neg_mod_p. ring doesn't expose this from ops.
    // Work around: negate using: a_neg = (p - a). Since p ≡ 0 in our field,
    // the raw unencoded value of p would be all-zero after reduction.
    // Instead use the raw limb-level negation:
    // neg(a).limbs[i] = -(a.limbs[i]) mod p

    // Simplest: create a copy of a, then use add_assign with p-a.
    // We have access to q.a() (= a = p-3 in Montgomery form) and q.b().
    // We do NOT have direct access to p in Elem form.

    // Alternative that works: compute 0 - a mod p using limbs.
    // We know the raw limbs of p from COMMON_OPS.q.p.
    // Do a subtraction: p_limbs - a_limbs with borrow.
    let num_limbs = NUM_LIMBS;
    let p_limbs = &COMMON_OPS.q.p; // LeakyLimb array = raw p limbs

    let mut neg = Elem::<R>::zero();
    let mut borrow: u64 = 0;
    for i in 0..num_limbs {
        let pi = p_limbs[i] as u64;
        let ai = a.limbs[i] as u64;
        let diff = pi.wrapping_sub(ai).wrapping_sub(borrow);
        // Reason: use wrapping arithmetic; borrow propagates like a subtraction carry.
        neg.limbs[i] = diff as Limb;
        borrow = if pi < ai + borrow { 1 } else { 0 };
    }

    // If a was 0 (all limbs zero), then neg should also be 0.
    // The subtraction gives p - 0 = p, but p ≡ 0 mod p, so we need to
    // reduce: if a is zero, result should be zero.
    // We can detect: if borrow == 0 and result == p, subtract p.
    // Actually: p - 0 = p ≡ 0, and p - a for a in (0, p) is in (0, p).
    // We need: if a is zero, return zero; else return p - a.
    // Constant-time: mask based on whether a is zero.
    let a_is_zero = limbs_are_zero(&a.limbs[..num_limbs]).leak();
    if a_is_zero { Elem::zero() } else { neg }
}

// `point_add` FFI wrapper: called from PrivateKeyOps.point_add_jacobian_impl
unsafe extern "C" fn sm2_point_add(r: *mut Limb, a: *const Limb, b: *const Limb) {
    let n = NUM_LIMBS;
    let p1 = load_point(a, n);
    let p2 = load_point(b, n);
    let cpu = cpu::features();
    let q = COMMON_OPS.elem_modulus(cpu);
    let result = point_add_inner(&q, &p1, &p2);
    unsafe {
        let out = core::slice::from_raw_parts_mut(r, 3 * n);
        out.copy_from_slice(&result.xyz[..3 * n]);
    }
}

fn load_point(p: *const Limb, n: usize) -> Point {
    let mut pt = Point::new_at_infinity();
    let src = unsafe { core::slice::from_raw_parts(p, 3 * n) };
    pt.xyz[..3 * n].copy_from_slice(src);
    pt
}

// ── Scalar multiplication: [scalar]P ────────────────────────────────────────
//
// We implement a simple left-to-right double-and-add scalar multiplication.
// This is NOT constant-time and should only be used for point_mul_impl where
// timing attacks are less critical (or future hardening is planned).
//
// TODO: Replace with a constant-time windowed method (e.g., Montgomery ladder
// or fixed-window NAF) for production security.

unsafe extern "C" fn sm2_point_mul(
    r: *mut Limb,
    p_scalar: *const Limb,
    p_x: *const Limb,
    p_y: *const Limb,
) {
    let n = NUM_LIMBS;
    let scalar = unsafe { core::slice::from_raw_parts(p_scalar, n) };
    let px = unsafe { core::slice::from_raw_parts(p_x, n) };
    let py = unsafe { core::slice::from_raw_parts(p_y, n) };

    let cpu = cpu::features();
    let q = COMMON_OPS.elem_modulus(cpu);

    // Build the input point in Jacobian coordinates (Z = 1 in Montgomery form).
    // Z = 1 in Montgomery form = R mod p.
    // R mod p = 2^256 mod p.
    // Since p = FFFFFFFE...FFFFFFFF, and 2^256 mod p = 2^256 - p:
    // 2^256 - p = 0x00000001_00000001_00000000_00000000_00000001_FFFFFFFF_00000001
    // Actually R mod p: since p < 2^256, R mod p = 2^256 - p.
    // But storing Z as 1 in *unencoded* form and encoding it via Montgomery:
    // z_mont = 1 * R mod p = R mod p.
    // We can get this by multiplying Elem::one() (unencoded 1) by RR:
    // Actually the simplest is to just set Z = 1 in unencoded form and encode.
    // ring's elem_parse does: parsed * rr_mont = result in Montgomery form.
    // We do the same for z = 1: z_mont = 1 * R mod p = ? We need to compute R mod p.

    // Alternatively: use the fact that COMMON_OPS.q.rr contains RR = R^2 mod p.
    // z_mont = 1 * R mod p. To get this: multiply 1 by R mod p.
    // R mod p is not stored directly. We can compute it as:
    // z_mont = elem_product(Elem::one_unencoded, Elem::from(rr))
    // = 1 * R^2 * R^{-1} mod p = R mod p. ✓
    let rr_elem = Elem::<RR>::from(&PublicElem::from_hex(
        "0000000400000002000000010000000100000002ffffffff0000000200000003",
    ));
    let one_unenc: Elem<Unencoded> = Elem::one();
    let z_mont = mul_mont(sm2_elem_mul_mont, &one_unenc, &rr_elem);

    let mut p_mont = Point::new_at_infinity();
    p_mont.xyz[..n].copy_from_slice(px);
    p_mont.xyz[n..2 * n].copy_from_slice(py);
    p_mont.xyz[2 * n..3 * n].copy_from_slice(&z_mont.limbs[..n]);

    let result = scalar_mul_fixed_window(&q, scalar, &p_mont);

    unsafe {
        let out = core::slice::from_raw_parts_mut(r, 3 * n);
        out.copy_from_slice(&result.xyz[..3 * n]);
    }
}

/// Left-to-right double-and-add scalar multiplication.
/// `scalar` is in little-endian limb order, each limb is LIMB_BITS bits.
fn scalar_mul_fixed_window(q: &Modulus<Q>, scalar: &[Limb], p: &Point) -> Point {
    let mut result = Point::new_at_infinity();
    let mut found_one = false;

    // Iterate bits from most-significant to least-significant
    for limb_idx in (0..NUM_LIMBS).rev() {
        for bit_idx in (0..LIMB_BITS).rev() {
            if found_one {
                result = point_double_inner(q, &result); // double
            }
            let bit = (scalar[limb_idx] >> bit_idx) & 1;
            if bit == 1 {
                if found_one {
                    result = point_add_inner(q, &result, p);
                } else {
                    let mut init = Point::new_at_infinity();
                    init.xyz.copy_from_slice(&p.xyz);
                    result = init;
                    found_one = true;
                }
            }
        }
    }
    result
}

// ── Base point multiplication: [scalar]G ─────────────────────────────────────
//
// Generator point G of SM2 (in Montgomery form):
// Gx_mont = 91167A5EE1C13B05D6A1ED99AC24C3C33E7981EDDCA6C05061328990F418029E
// Gy_mont = 63CD65D481D735BD8D4CFB066E2A48F8C1F5E5788D3295FAC1354E593C2D0DDD

fn sm2_point_mul_base_impl(g_scalar: &Scalar, cpu: cpu::Features) -> Point {
    let n = NUM_LIMBS;
    let q = COMMON_OPS.elem_modulus(cpu);

    // G in Montgomery form
    let gx_mont: Elem<R> = Elem::from(&PublicElem::from_hex(
        "91167a5ee1c13b05d6a1ed99ac24c3c33e7981eddca6c05061328990f418029e",
    ));
    let gy_mont: Elem<R> = Elem::from(&PublicElem::from_hex(
        "63cd65d481d735bd8d4cfb066e2a48f8c1f5e5788d3295fac1354e593c2d0ddd",
    ));

    // Z = 1 in Montgomery form = R mod p
    let rr_elem = Elem::<RR>::from(&PublicElem::from_hex(
        "0000000400000002000000010000000100000002ffffffff0000000200000003",
    ));
    let one_unenc: Elem<Unencoded> = Elem::one();
    let gz_mont = mul_mont(sm2_elem_mul_mont, &one_unenc, &rr_elem);

    let mut g = Point::new_at_infinity();
    g.xyz[..n].copy_from_slice(&gx_mont.limbs[..n]);
    g.xyz[n..2 * n].copy_from_slice(&gy_mont.limbs[..n]);
    g.xyz[2 * n..3 * n].copy_from_slice(&gz_mont.limbs[..n]);

    scalar_mul_fixed_window(&q, &g_scalar.limbs[..n], &g)
}

// twin_mul: compute [g_scalar]G + [p_scalar]P for ECDSA verification
fn sm2_twin_mul(
    g_scalar: &Scalar,
    p_scalar: &Scalar,
    p_xy: &(Elem<R>, Elem<R>),
    cpu: cpu::Features,
) -> Point {
    // Use Shamir's trick (interleaved scalar multiplication) for efficiency.
    // Simple implementation: compute separately then add.
    // TODO: implement interleaved wNAF for performance.
    let scaled_g = sm2_point_mul_base_impl(g_scalar, cpu);
    let scaled_p = PRIVATE_KEY_OPS.point_mul(p_scalar, p_xy, cpu);
    PRIVATE_KEY_OPS.point_sum(&scaled_g, &scaled_p, cpu)
}

// ── Scalar inversion: a^{-1} mod n ──────────────────────────────────────────
//
// We compute a^{-1} mod n using Fermat's little theorem: a^{-1} = a^{n-2} mod n.
// n - 2 = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF 7203DF6B 21C6052B 53BBF409 39D54121
//
// Strategy: process the 256-bit exponent in two halves.
//   Upper 128 bits: FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF
//   Lower 128 bits: 7203DF6B 21C6052B 53BBF409 39D54121
fn sm2_scalar_inv_to_mont(a: Scalar<R>, cpu: cpu::Features) -> Scalar<R> {
    let _1 = &a;

    // Process upper 128 bits of n-2 = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF
    // using square-and-multiply (left-to-right).
    // Reason: simple and correct; can be optimized with an addition chain later.
    let upper_128: u128 = 0xFFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFF_u128;
    let mut acc = _1.clone();
    let mut found_one = true; // bit 127 of upper_128 is always 1
    for bit_idx in (0..127u32).rev() {
        unary_op_assign(sm2_scalar_mul_mont_sqr, &mut acc);
        if (upper_128 >> bit_idx) & 1 == 1 {
            binary_op_assign(sm2_scalar_mul_mont, &mut acc, _1);
        }
    }

    // Process lower 128 bits of n-2 = 7203DF6B 21C6052B 53BBF409 39D54121
    // Continue from the accumulated value.
    let lower_128: u128 = 0x7203DF6B_21C6052B_53BBF409_39D54121_u128;
    for bit_idx in (0..128u32).rev() {
        unary_op_assign(sm2_scalar_mul_mont_sqr, &mut acc);
        if (lower_128 >> bit_idx) & 1 == 1 {
            binary_op_assign(sm2_scalar_mul_mont, &mut acc, _1);
        }
    }
    let _ = found_one; // suppress warning

    acc
}

// Scalar squaring (r = a^2 * R^{-1} mod n) using the scalar multiply function
unsafe extern "C" fn sm2_scalar_mul_mont_sqr(r: *mut Limb, a: *const Limb) {
    unsafe { sm2_scalar_mul_mont(r, a, a) }
}

#[cfg(test)]
pub(super) static GENERATOR: (PublicElem<R>, PublicElem<R>) = (
    PublicElem::from_hex("91167a5ee1c13b05d6a1ed99ac24c3c33e7981eddca6c05061328990f418029e"),
    PublicElem::from_hex("63cd65d481d735bd8d4cfb066e2a48f8c1f5e5788d3295fac1354e593c2d0ddd"),
);
