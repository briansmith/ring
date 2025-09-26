// Copyright 2017-2025 Brian Smith.
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

#[allow(unused_imports)]
use crate::polyfill::prelude::*;

pub use super::n0::N0;
#[allow(unused_imports)]
use super::MIN_LIMBS;
use super::{
    inout::{AliasSrc, AliasingSlices2, AliasingSlices3},
    LimbSliceError,
};
use crate::cpu;
use cfg_if::cfg_if;

// Indicates that the element is not encoded; there is no *R* factor
// that needs to be canceled out.
#[derive(Copy, Clone)]
pub enum Unencoded {}

// Indicates that the element is encoded; the value has one *R*
// factor that needs to be canceled out.
#[derive(Copy, Clone)]
pub enum R {}

// Indicates the element is encoded three times; the value has three
// *R* factors that need to be canceled out.
#[allow(clippy::upper_case_acronyms)]
#[derive(Copy, Clone)]
pub enum RRR {}

// Indicates the element is encoded twice; the value has two *R*
// factors that need to be canceled out.
#[derive(Copy, Clone)]
pub enum RR {}

// Indicates the element is inversely encoded; the value has one
// 1/*R* factor that needs to be canceled out.
#[derive(Copy, Clone)]
pub enum RInverse {}

pub trait Encoding {}

impl Encoding for RRR {}
impl Encoding for RR {}
impl Encoding for R {}
impl Encoding for Unencoded {}
impl Encoding for RInverse {}

/// The encoding of the result of a reduction.
pub trait ReductionEncoding {
    type Output: Encoding;
}

impl ReductionEncoding for RRR {
    type Output = RR;
}

impl ReductionEncoding for RR {
    type Output = R;
}
impl ReductionEncoding for R {
    type Output = Unencoded;
}
impl ReductionEncoding for Unencoded {
    type Output = RInverse;
}

/// The encoding of the result of a multiplication.
pub trait ProductEncoding {
    type Output: Encoding;
}

impl<E: ReductionEncoding> ProductEncoding for (Unencoded, E) {
    type Output = E::Output;
}

impl<E: Encoding> ProductEncoding for (R, E) {
    type Output = E;
}

impl ProductEncoding for (RR, RR) {
    type Output = RRR;
}

impl<E: ReductionEncoding> ProductEncoding for (RInverse, E)
where
    E::Output: ReductionEncoding,
{
    type Output = <<E as ReductionEncoding>::Output as ReductionEncoding>::Output;
}

// XXX: Rust doesn't allow overlapping impls,
// TODO (if/when Rust allows it):
// impl<E1, E2: ReductionEncoding> ProductEncoding for
//         (E1, E2) {
//     type Output = <(E2, E1) as ProductEncoding>::Output;
// }
impl ProductEncoding for (RR, Unencoded) {
    type Output = <(Unencoded, RR) as ProductEncoding>::Output;
}
impl ProductEncoding for (RR, RInverse) {
    type Output = <(RInverse, RR) as ProductEncoding>::Output;
}

impl ProductEncoding for (RRR, RInverse) {
    type Output = <(RInverse, RRR) as ProductEncoding>::Output;
}

#[allow(unused_imports)]
use crate::{bssl, c, limb::Limb};

#[inline(always)]
pub(super) fn limbs_mul_mont(
    in_out: impl AliasingSlices3<Limb>,
    n: &[Limb],
    n0: &N0,
    cpu: cpu::Features,
) -> Result<(), LimbSliceError> {
    #[allow(dead_code)]
    const MOD_FALLBACK: usize = 1; // No restriction.
    cfg_if! {
        if #[cfg(all(target_arch = "aarch64", target_endian = "little"))] {
            let _: cpu::Features = cpu;
            super::limbs::aarch64::mul_mont(in_out, n, n0)
        } else if #[cfg(all(target_arch = "arm", target_endian = "little"))] {
            const MIN_8X: usize = 8;
            const MOD_8X: usize = 8;
            if n.len() >= MIN_8X && n.len() % MOD_8X == 0 {
                use crate::cpu::{GetFeature as _, arm::Neon};
                if let Some(cpu) = cpu.get_feature() {
                    return bn_mul_mont_ffi!(in_out, n, n0, cpu, unsafe {
                        (MIN_8X, MOD_8X, Neon) => bn_mul8x_mont_neon
                    });
                }
            }
            // The ARM version of `bn_mul_mont_nohw` has a minimum of 2.
            const _MIN_LIMBS_AT_LEAST_2: () = assert!(MIN_LIMBS >= 2);
            bn_mul_mont_ffi!(in_out, n, n0, (), unsafe {
                (MIN_LIMBS, MOD_FALLBACK, ()) => bn_mul_mont_nohw
            })
        } else if #[cfg(target_arch = "x86")] {
            use crate::{cpu::GetFeature as _, cpu::intel::Sse2};
            // The X86 implementation of `bn_mul_mont_sse2` has a minimum of 4.
            const _MIN_LIMBS_AT_LEAST_4: () = assert!(MIN_LIMBS >= 4);
            if let Some(cpu) = cpu.get_feature() {
                bn_mul_mont_ffi!(in_out, n, n0, cpu, unsafe {
                    (MIN_LIMBS, MOD_FALLBACK, Sse2) => bn_mul_mont_sse2
                })
            } else {
                super::limbs::fallback::mont::limbs_mul_mont(in_out, n, n0)
            }
        } else if #[cfg(target_arch = "x86_64")] {
            use crate::{cpu::GetFeature as _};
            use super::limbs::x86_64;
            if n.len() >= x86_64::mont::MIN_4X {
                if let (n, []) = n.as_chunks() {
                    return x86_64::mont::mul_mont5_4x(in_out, n, n0, cpu.get_feature());
                }
            }
            bn_mul_mont_ffi!(in_out, n, n0, (), unsafe {
                (MIN_LIMBS, MOD_FALLBACK, ()) => bn_mul_mont_sse2
            })
        } else {
            super::limbs::fallback::mont::limbs_mul_mont(in_out, n, n0)
        }
    }
}

// `bigint` needs then when the `alloc` feature is enabled. `bn_mul_mont` above needs this when
// we are using the platforms for which we don't have `bn_mul_mont` in assembly.
pub(super) fn limbs_from_mont_in_place(r: &mut [Limb], tmp: &mut [Limb], m: &[Limb], n0: &N0) {
    prefixed_extern! {
        fn bn_from_montgomery_in_place(
            r: *mut Limb,
            num_r: c::size_t,
            a: *mut Limb,
            num_a: c::size_t,
            n: *const Limb,
            num_n: c::size_t,
            n0: &N0,
        ) -> bssl::Result;
    }
    let r_len = r.len();
    let r = r.as_mut_ptr();
    let tmp_len = tmp.len();
    let tmp = tmp.as_mut_ptr();
    Result::from(unsafe {
        bn_from_montgomery_in_place(r, r_len, tmp, tmp_len, m.as_ptr(), m.len(), n0)
    })
    .unwrap()
}

/// r = r**2
pub(super) fn limbs_square_mont(
    in_out: impl AliasingSlices2<Limb> + AliasSrc<Limb>,
    n: &[Limb],
    n0: &N0,
    cpu: cpu::Features,
) -> Result<(), LimbSliceError> {
    #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
    {
        use super::limbs::aarch64;
        if let (n, []) = n.as_chunks() {
            return aarch64::sqr_mont5(in_out, n, n0);
        }
    }

    #[cfg(target_arch = "x86_64")]
    {
        use super::limbs::x86_64;
        use crate::cpu::GetFeature as _;
        if let (n, []) = n.as_chunks() {
            return x86_64::mont::sqr_mont5(in_out, n, n0, cpu.get_feature());
        }
    }

    limbs_mul_mont(in_out.raa(), n, n0, cpu)
}
