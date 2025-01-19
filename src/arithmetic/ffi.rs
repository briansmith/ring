// Copyright 2024-2025 Brian Smith.
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

use super::{n0::N0, InOut};
use crate::{c, limb::Limb};

// See below.
// TODO: Replace this with `n.len() < 256 / LIMB_BITS` so that 32-bit and
// 64-bit platforms behave the same.
pub(crate) const BIGINT_MODULUS_MIN_LIMBS: usize = 4;

/// `unsafe { ([Limb; chunk_len], n, T) => f }` means it is safe to call `f` if
/// `n.len() >= (n * chunk_len) && n.len() % chunk_len == 0`, the slice(s) in
/// `in_out` have the same length as `n`, and we have constructed a value of
/// type `T`.
macro_rules! bn_mul_mont_ffi {
    ( $in_out:expr, $n:expr, $n0:expr, $cpu:expr,
      unsafe { ([Limb; $CHUNK:expr], $MIN_CHUNKS:expr, $Cpu:ty) => $f:ident }) => {{
        use crate::{c, limb::Limb};
        prefixed_extern! {
            // `r` and/or 'a' and/or 'b' may alias.
            // XXX: BoringSSL declares these functions to return `int`.
            fn $f(
                r: *mut Limb,
                a: *const Limb,
                b: *const Limb,
                n: *const Limb,
                n0: &N0,
                len: c::size_t,
            );
        }
        unsafe {
            crate::arithmetic::ffi::bn_mul_mont_ffi::<$Cpu, { $CHUNK }, { $CHUNK * $MIN_CHUNKS }>(
                $in_out, $n, $n0, $cpu, $f,
            )
        }
    }};
}

#[inline]
pub(super) unsafe fn bn_mul_mont_ffi<Cpu, const CHUNK: usize, const MIN_LEN: usize>(
    in_out: InOut<[Limb]>,
    n: &[Limb],
    n0: &N0,
    cpu: Cpu,
    f: unsafe extern "C" fn(
        r: *mut Limb,
        a: *const Limb,
        b: *const Limb,
        n: *const Limb,
        n0: &N0,
        len: c::size_t,
    ),
) {
    /// The x86 implementation of `bn_mul_mont`, at least, requires at least 4
    /// limbs. For a long time we have required 4 limbs for all targets, though
    /// this may be unnecessary.
    const _BIGINT_MODULUS_MIN_LIMBS_AT_LEAST_4: () = assert!(BIGINT_MODULUS_MIN_LIMBS >= 4);
    assert!(CHUNK > 0);
    assert!(n.len() % CHUNK == 0);
    assert!(MIN_LEN >= BIGINT_MODULUS_MIN_LIMBS);
    assert!(n.len() >= MIN_LEN);

    let (r, a, b) = match in_out {
        InOut::SquareInPlace(r) => {
            assert_eq!(r.len(), n.len());
            (r.as_mut_ptr(), r.as_ptr(), r.as_ptr())
        }
        InOut::InPlace(r, a) => {
            assert_eq!(r.len(), n.len());
            assert_eq!(a.len(), n.len());
            (r.as_mut_ptr(), r.as_ptr(), a.as_ptr())
        }
        InOut::Disjoint(r, a, b) => {
            assert_eq!(r.len(), n.len());
            assert_eq!(a.len(), n.len());
            assert_eq!(b.len(), n.len());
            (r.as_mut_ptr(), a.as_ptr(), b.as_ptr())
        }
    };
    let num_limbs = n.len();
    let n = n.as_ptr();
    let _: Cpu = cpu;
    unsafe { f(r, a, b, n, n0, num_limbs) };
}

// `bn_sqr8x_mont` has a weird signature so it has to be handled separately.
// Note that MULX is in BMI2.
#[cfg(target_arch = "x86_64")]
pub(super) fn bn_sqr8x_mont(
    r: &mut [Limb],
    n: &[[Limb; 8]],
    n0: &N0,
    mulx_adx: Option<(crate::cpu::intel::Bmi2, crate::cpu::intel::Adx)>,
) {
    use crate::{bssl, polyfill::slice};
    prefixed_extern! {
        // `rp` and `ap` may alias.
        fn bn_sqr8x_mont(
            rp: *mut Limb,
            ap: *const Limb,
            mulx_adx_capable: Limb,
            np: *const Limb,
            n0: &N0,
            num: c::size_t) -> bssl::Result;
    }
    assert!(!n.is_empty());
    let n = slice::flatten(n);
    assert_eq!(r.len(), n.len());

    let r_out = r.as_mut_ptr();
    let r_in = r.as_ptr();
    let mulx_adx_capable = Limb::from(mulx_adx.is_some());
    let num = n.len();
    let n = n.as_ptr();
    let r = unsafe { bn_sqr8x_mont(r_out, r_in, mulx_adx_capable, n, n0, num) };
    assert!(Result::from(r).is_ok());
}
