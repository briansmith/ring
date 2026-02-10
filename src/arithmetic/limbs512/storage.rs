// Copyright 2025 Brian Smith.
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

use super::LIMBS_PER_CHUNK;
use crate::{
    arithmetic::{LimbSliceError, MAX_LIMBS},
    error::LenMismatchError,
    limb::Limb,
    polyfill::StartPtr,
};
use core::{mem::MaybeUninit, num::NonZero, ptr};

// Some x86_64 assembly is written under the assumption that some of its
// input data and/or temporary storage is aligned to `MOD_EXP_CTIME_ALIGN`
// bytes, which was/is 64 in OpenSSL.
//
// We use this in the non-X86-64 implementation of exponentiation as well,
// with the hope of converging th two implementations into one.

#[repr(C, align(64))]
pub struct AlignedStorage<const N: usize>([MaybeUninit<Limb>; N]);

const _LIMB_SIZE_DIVIDES_ALIGNMENT: () =
    assert!(align_of::<AlignedStorage<1>>().is_multiple_of(size_of::<Limb>()));

impl<const N: usize> AlignedStorage<N> {
    pub fn uninit() -> Self {
        assert_eq!(N % LIMBS_PER_CHUNK, 0); // TODO: const.

        Self([const { MaybeUninit::uninit() }; N])
    }

    // The result will have every chunk aligned on a 64 byte boundary.
    pub fn aligned_chunks_mut(
        &mut self,
        num_entries: usize,
        chunks_per_entry: usize,
    ) -> Result<&'_ mut [[MaybeUninit<Limb>; LIMBS_PER_CHUNK]], LenMismatchError> {
        let total_limbs = num_entries * chunks_per_entry * LIMBS_PER_CHUNK;
        let len = self.0.len();
        let flattened = self
            .0
            .get_mut(..total_limbs)
            .ok_or_else(|| LenMismatchError::new(len))?;
        match flattened.as_chunks_mut() {
            (chunks, []) => Ok(chunks),
            (_, r) => Err(LenMismatchError::new(r.len())),
        }
    }
}

#[allow(dead_code)]
pub fn as_const_uninit<E, const N: usize>(table: &[[E; N]]) -> *const [[MaybeUninit<E>; N]] {
    ptr::from_ref(table) as *const [[MaybeUninit<E>; N]] // cast_uninit.
}

// Helps the compiler will be able to hoist all of these checks out of the
// loops in the caller. Try to help the compiler by doing the checks
// consistently in each function and also by inlining this function and all the
// callers.
#[inline(always)]
pub(crate) fn check_common(
    a: &[Limb],
    table_ptr: *const [[MaybeUninit<Limb>; LIMBS_PER_CHUNK]],
) -> Result<NonZero<usize>, LimbSliceError> {
    let table_len = table_ptr.len();
    assert_eq!(table_ptr.start_ptr() as usize % 16, 0); // According to BoringSSL.
    let num_limbs = NonZero::new(a.len()).ok_or_else(|| LimbSliceError::too_short(a.len()))?;
    if num_limbs.get() > MAX_LIMBS {
        return Err(LimbSliceError::too_long(a.len()));
    }
    if num_limbs.get() * (32 / LIMBS_PER_CHUNK) != table_len {
        Err(LenMismatchError::new(table_len))?;
    };
    Ok(num_limbs)
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub(crate) fn check_common_with_n(
    a: &[Limb],
    table_ptr: *const [[MaybeUninit<Limb>; LIMBS_PER_CHUNK]],
    n: &[[Limb; LIMBS_PER_CHUNK]],
) -> Result<NonZero<usize>, LimbSliceError> {
    // Choose `a` instead of `n` so that every function starts with
    // `check_common` passing the exact same arguments, so that the compiler
    // can easily de-dupe the checks.
    let num_limbs = check_common(a, table_ptr)?;
    let n = n.as_flattened();
    if n.len() != num_limbs.get() {
        Err(LenMismatchError::new(n.len()))?;
    }
    Ok(num_limbs)
}
