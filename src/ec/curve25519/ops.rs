// Copyright 2015-2017 Brian Smith.
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

//! Elliptic curve operations on the birationally equivalent curves Curve25519
//! and Edwards25519.

pub use super::scalar::{MaskedScalar, SCALAR_LEN, Scalar};
use crate::{
    cpu,
    limb::{LIMB_BITS, Limb},
};
use core::{marker::PhantomData, mem::MaybeUninit};

// Elem<Tight>` is `fe` in curve25519/internal.h.
// Elem<Loose> is `fe_loose` in curve25519/internal.h.
// Keep this in sync with curve25519/internal.h.
#[repr(C)]
pub struct Elem<E: Encoding> {
    limbs: [Limb; ELEM_LIMBS], // This is called `v` in the C code.
    encoding: PhantomData<E>,
}

pub trait Encoding {}
pub struct Tight;
impl Encoding for Tight {}

const ELEM_LIMBS: usize = 5 * 64 / LIMB_BITS;

impl Elem<Tight> {
    fn negate(&mut self) {
        unsafe {
            x25519_fe_neg(self);
        }
    }
}

// [RFC 8032] https://tools.ietf.org/html/rfc8032#section-5.1.2
// This is *NOT* the type to use for X25519 output.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct CompressedPoint([u8; ELEM_LEN]);

impl CompressedPoint {
    pub fn as_ref(&self) -> &[u8; ELEM_LEN] {
        &self.0
    }
}

pub const ELEM_LEN: usize = 32;

// Keep this in sync with `ge_p3` in curve25519/internal.h.
#[repr(C)]
pub struct P3 {
    x: Elem<Tight>,
    y: Elem<Tight>,
    z: Elem<Tight>,
    t: Elem<Tight>,
}

impl P3 {
    // Returns the result of multiplying the base point by the scalar in constant time.
    pub(super) fn from_scalarmult_base(scalar: &Scalar, cpu: cpu::Features) -> Self {
        #[cfg(all(target_arch = "x86_64", not(windows), not(target_os = "cygwin")))]
        if let Some(cpu) = super::adx::get_features(cpu) {
            return super::adx::scalarmult_base(scalar, cpu);
        }

        let _ = cpu;
        prefixed_extern! {
            unsafe fn x25519_ge_scalarmult_base(h: &mut MaybeUninit<P3>, a: &Scalar);
        }
        let mut r = MaybeUninit::uninit();
        unsafe {
            x25519_ge_scalarmult_base(&mut r, scalar);
            r.assume_init()
        }
    }

    pub(super) fn into_compressed_encoding(self, cpu_features: cpu::Features) -> CompressedPoint {
        encode_point(self.x, self.y, self.z, cpu_features)
    }

    pub(super) fn invert_vartime(&mut self) {
        self.x.negate();
        self.t.negate();
    }
}

// Keep this in sync with `ge_p2` in curve25519/internal.h.
#[repr(C)]
pub struct P2 {
    x: Elem<Tight>,
    y: Elem<Tight>,
    z: Elem<Tight>,
}

impl P2 {
    pub(super) fn into_compressed_encoding(self, cpu_features: cpu::Features) -> CompressedPoint {
        encode_point(self.x, self.y, self.z, cpu_features)
    }
}

fn encode_point(
    mut x: Elem<Tight>,
    mut y: Elem<Tight>,
    mut z: Elem<Tight>,
    _cpu_features: cpu::Features,
) -> CompressedPoint {
    unsafe {
        x25519_fe_invert(&mut z);
    }
    let recip = &mut z;

    unsafe {
        x25519_fe_mul_assign_tt(&mut x, recip);
    }
    let x_over_z = &x;

    unsafe {
        x25519_fe_mul_assign_tt(&mut y, recip);
    }
    let y_over_z = &y;

    let mut r = CompressedPoint([0u8; ELEM_LEN]);
    let bytes = &mut r.0;
    unsafe {
        x25519_fe_tobytes(bytes, y_over_z);
    }

    let sign_bit: u8 = unsafe { x25519_fe_isnegative(x_over_z) };

    // The preceding computations must execute in constant time, but this
    // doesn't need to.
    bytes[ELEM_LEN - 1] ^= sign_bit << 7;

    r
}

prefixed_extern! {
    unsafe fn x25519_fe_invert(z: &mut Elem<Tight>);
    unsafe fn x25519_fe_isnegative(elem: &Elem<Tight>) -> u8;
    unsafe fn x25519_fe_mul_assign_tt(f: &mut Elem<Tight>, g: &Elem<Tight>);
    unsafe fn x25519_fe_neg(f: &mut Elem<Tight>);
    unsafe fn x25519_fe_tobytes(bytes: &mut [u8; ELEM_LEN], elem: &Elem<Tight>);
}
