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

use super::{inout::AliasingSlices, n0::N0, LimbSliceError, MAX_LIMBS, MIN_LIMBS};
use crate::{c, error, limb::Limb, polyfill::usize_from_u32};
use core::mem::size_of;

const _MAX_LIMBS_ADDRESSES_MEMORY_SAFETY_ISSUES: () = {
    // BoringSSL's limit: 8 kiloBYTES.
    const BN_MONTGOMERY_MAX_WORDS: usize = (8 * 1092) / size_of::<Limb>();
    assert!(MAX_LIMBS <= BN_MONTGOMERY_MAX_WORDS);

    // Some 64-bit assembly implementations were written to take `len` as a
    // `c_int`, so they zero out the undefined top half of `len` to convert it
    // to a `usize`. But, others don't.
    assert!(MAX_LIMBS <= usize_from_u32(u32::MAX));
};

macro_rules! bn_mul_mont_ffi {
    ( $in_out:expr, $n:expr, $n0:expr, $cpu:expr,
      unsafe { ($MIN_LEN:expr, $Cpu:ty) => $f:ident }) => {{
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
            ) -> crate::bssl::Result;
        }
        unsafe {
            crate::arithmetic::ffi::bn_mul_mont_ffi::<$Cpu, { $MIN_LEN }>(
                $in_out, $n, $n0, $cpu, $f,
            )
        }
    }};
}

#[inline]
pub(super) unsafe fn bn_mul_mont_ffi<Cpu, const MIN_LEN: usize>(
    mut in_out: impl AliasingSlices<Limb>,
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
    ) -> crate::bssl::Result,
) -> Result<(), LimbSliceError> {
    /// The x86 implementation of `bn_mul_mont`, at least, requires at least 4
    /// limbs. For a long time we have required 4 limbs for all targets, though
    /// this may be unnecessary.
    const _MIN_LIMBS_AT_LEAST_4: () = assert!(MIN_LIMBS >= 4);
    // We haven't tested shorter lengths.
    assert!(MIN_LEN >= MIN_LIMBS);
    if n.len() < MIN_LEN {
        return Err(LimbSliceError::too_short(n.len()));
    }

    // Avoid stack overflow from the alloca inside.
    if n.len() > MAX_LIMBS {
        return Err(LimbSliceError::too_long(n.len()));
    }

    let len = n.len();
    in_out
        .with_pointers(n.len(), |r, a, b| {
            let n = n.as_ptr();
            let _: Cpu = cpu;
            let result = unsafe { f(r, a, b, n, n0, len) };
            Result::from(result)
        })
        .map_err(LimbSliceError::len_mismatch)?
        .map_err(
            #[cold]
            #[inline(never)]
            |_: error::Unspecified| LimbSliceError::too_short(len),
        )
}
