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

#![cfg_attr(not(feature = "use_heap"), allow(dead_code))]

use {polyfill, c, error, untrusted};

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
pub fn limbs_less_than_limbs_consttime(a: &[Limb], b: &[Limb]) -> LimbMask {
    assert_eq!(a.len(), b.len());
    unsafe { LIMBS_less_than(a.as_ptr(), b.as_ptr(), b.len()) }
}

#[inline]
pub fn limbs_less_than_limbs_vartime(a: &[Limb], b: &[Limb]) -> bool {
    limbs_less_than_limbs_consttime(a, b) == LimbMask::True
}

#[inline]
pub fn limbs_are_zero_constant_time(limbs: &[Limb]) -> LimbMask {
    unsafe { LIMBS_are_zero(limbs.as_ptr(), limbs.len()) }
}

/// Equivalent to `if (r >= m) { r -= m; }`
#[inline]
pub fn limbs_reduce_once_constant_time(r: &mut [Limb], m: &[Limb]) {
    assert_eq!(r.len(), m.len());
    unsafe { LIMBS_reduce_once(r.as_mut_ptr(), m.as_ptr(), m.len()) };
}

/// Parses `input` into `result`, verifies that the value is in the range
/// [min_exclusive, max_exclusive), and pads `result` with zeros to its length.
pub fn parse_big_endian_in_range_and_pad(
        input: untrusted::Input, min_inclusive: Limb, max_exclusive: &[Limb],
        result: &mut [Limb]) -> Result<(), error::Unspecified> {
    try!(parse_big_endian_and_pad(input, result));
    if !limbs_less_than_limbs_vartime(&result, max_exclusive) {
        return Err(error::Unspecified);
    }
    if result[0] < min_inclusive && result[1..].iter().all(|limb| *limb == 0) {
        return Err(error::Unspecified);
    }
    Ok(())
}

/// Parses `input` into `result`, padding `result` with zeros to its length.
pub fn parse_big_endian_and_pad(input: untrusted::Input, result: &mut [Limb])
                                -> Result<(), error::Unspecified> {
    if input.is_empty() {
        return Err(error::Unspecified);
    }

    // `bytes_in_current_limb` is the number of bytes in the current limb.
    // It will be `LIMB_BYTES` for all limbs except maybe the highest-order
    // limb.
    let mut bytes_in_current_limb = input.len() % LIMB_BYTES;
    if bytes_in_current_limb == 0 {
        bytes_in_current_limb = LIMB_BYTES;
    }

    let num_encoded_limbs =
        (input.len() / LIMB_BYTES) +
        (if bytes_in_current_limb == LIMB_BYTES { 0 } else { 1 });
    if num_encoded_limbs > result.len() {
        return Err(error::Unspecified);
    }

    try!(input.read_all(error::Unspecified, |input| {
        for i in 0..num_encoded_limbs {
            let mut limb: Limb = 0;
            for _ in 0..bytes_in_current_limb {
                let b = try!(input.read_byte());
                limb = (limb << 8) | (b as Limb);
            }
            result[num_encoded_limbs - i - 1] = limb;
            bytes_in_current_limb = LIMB_BYTES;
        }
        Ok(())
    }));

    for limb in &mut result[num_encoded_limbs..] {
        *limb = 0;
    }

    Ok(())
}

extern {
    fn LIMBS_are_zero(a: *const Limb, num_limbs: c::size_t) -> LimbMask;
    fn LIMBS_less_than(a: *const Limb, b: *const Limb, num_limbs: c::size_t)
                       -> LimbMask;
    fn LIMBS_reduce_once(r: *mut Limb, m: *const Limb, num_limbs: c::size_t);
}
