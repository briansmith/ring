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

use super::*;
use crate::{error::LenMismatchError, limb::*};
use core::num::NonZeroUsize;

/// Equivalent to `if (r >= m) { r -= m; }`
#[inline]
pub fn limbs_reduce_once(r: &mut [Limb], a: &[Limb], m: &[Limb]) -> Result<(), LenMismatchError> {
    let num_limbs = NonZeroUsize::new(m.len()).ok_or_else(|| LenMismatchError::new(m.len()))?;
    reduce_once(0, r, a, m, num_limbs)
}

fn reduce_once(
    a_high: Limb,
    r: &mut [Limb],
    a: &[Limb],
    m: &[Limb],
    num_limbs: NonZeroUsize,
) -> Result<(), LenMismatchError> {
    #[allow(clippy::useless_asref)]
    let borrow = limbs_sub(a_high, (r.as_mut(), a, m), num_limbs)?;
    limbs_cmov(borrow, r, a, num_limbs)
}
