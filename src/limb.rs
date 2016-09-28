// Copyright 2016 David Judd.
// Copyright 2016 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

//! Unsigned multi-precision integer arithmetic.
//!
//! Limbs ordered least-significant-limb to most-significant-limb. The bits
//! limbs use the native endianness.

use {polyfill, c};

// XXX: Not correct for x32 ABIs.
#[cfg(target_pointer_width = "64")] pub type Limb = u64;
#[cfg(target_pointer_width = "32")] pub type Limb = u32;
#[cfg(target_pointer_width = "64")] pub const LIMB_BITS: usize = 64;
#[cfg(target_pointer_width = "32")] pub const LIMB_BITS: usize = 32;

#[cfg(target_pointer_width = "64")]
#[allow(trivial_numeric_casts)] // XXX: workaround compiler bug.
#[derive(Debug, PartialEq)]
#[repr(u64)]
pub enum LimbMask {
    True = 0xffff_ffff_ffff_ffff,
    False = 0,
}

#[cfg(target_pointer_width = "32")]
#[allow(trivial_numeric_casts)] // XXX: workaround compiler bug.
#[derive(Debug, PartialEq)]
#[repr(u32)]
pub enum LimbMask {
    True = 0xffff_ffff,
    False = 0,
}

pub const LIMB_BYTES: usize = (LIMB_BITS + 7) / 8;

#[cfg(all(test, target_pointer_width = "64"))]
#[inline]
pub fn limbs_as_bytes<'a>(src: &'a [Limb]) -> &'a [u8] {
    polyfill::slice::u64_as_u8(src)
}

#[cfg(target_pointer_width = "64")]
#[inline]
pub fn limbs_as_bytes_mut<'a>(src: &'a mut [Limb]) -> &'a mut [u8] {
    polyfill::slice::u64_as_u8_mut(src)
}

#[cfg(all(test, target_pointer_width = "32"))]
#[inline]
pub fn limbs_as_bytes<'a>(src: &'a [Limb]) -> &'a [u8] {
    polyfill::slice::u32_as_u8(src)
}

#[cfg(target_pointer_width = "32")]
#[inline]
pub fn limbs_as_bytes_mut<'a>(src: &'a mut [Limb]) -> &'a mut [u8] {
    polyfill::slice::u32_as_u8_mut(src)
}

#[inline]
pub fn limbs_less_than_limbs_constant_time(a: &[Limb], b: &[Limb]) -> LimbMask {
    assert_eq!(a.len(), b.len());
    unsafe { GFp_constant_time_limbs_lt_limbs(a.as_ptr(), b.as_ptr(), b.len()) }
}

#[inline]
pub fn limbs_are_zero_constant_time(limbs: &[Limb]) -> LimbMask {
    unsafe { GFp_constant_time_limbs_are_zero(limbs.as_ptr(), limbs.len()) }
}

/// Equivalent to `if (r >= m) { r -= m; }`
#[inline]
pub fn limbs_reduce_once_constant_time(r: &mut [Limb], m: &[Limb]) {
    assert_eq!(r.len(), m.len());
    unsafe {
        GFp_constant_time_limbs_reduce_once(r.as_mut_ptr(), m.as_ptr(), m.len());
    }
}

extern {
    fn GFp_constant_time_limbs_are_zero(a: *const Limb, num_limbs: c::size_t)
                                        -> LimbMask;

    fn GFp_constant_time_limbs_lt_limbs(a: *const Limb, b: *const Limb,
                                        num_limbs: c::size_t) -> LimbMask;

    fn GFp_constant_time_limbs_reduce_once(r: *mut Limb, m: *const Limb,
                                           num_limbs: c::size_t);
}
