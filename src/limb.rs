// Copyright 2016 David Judd.
// Copyright 2016 Brian Smith.
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

//! Unsigned multi-precision integer arithmetic.
//!
//! Limbs ordered least-significant-limb to most-significant-limb. The bits
//! limbs use the native endianness.

use crate::{c, error, polyfill::ArrayFlatMap};

#[cfg(any(test, feature = "alloc"))]
use crate::{bits, constant_time, polyfill::usize_from_u32};

#[cfg(feature = "alloc")]
use core::num::Wrapping;

// XXX: Not correct for x32 ABIs.
pub type Limb = constant_time::Word;
pub const LIMB_BITS: usize = usize_from_u32(Limb::BITS);

#[cfg_attr(target_pointer_width = "64", repr(u64))]
#[cfg_attr(target_pointer_width = "32", repr(u32))]
pub enum LimbMask {
    #[cfg_attr(not(test), allow(dead_code))] // Only constructed by non-Rust & test code.
    True = Limb::MAX,
    #[cfg_attr(not(test), allow(dead_code))] // Only constructed by non-Rust & test code.
    False = 0,
}

impl LimbMask {
    pub fn leak(self) -> bool {
        !matches!(self, LimbMask::False)
    }
}

pub const LIMB_BYTES: usize = (LIMB_BITS + 7) / 8;

#[inline]
pub fn limbs_equal_limbs_consttime(a: &[Limb], b: &[Limb]) -> LimbMask {
    prefixed_extern! {
        fn LIMBS_equal(a: *const Limb, b: *const Limb, num_limbs: c::size_t) -> LimbMask;
    }

    assert_eq!(a.len(), b.len());
    unsafe { LIMBS_equal(a.as_ptr(), b.as_ptr(), a.len()) }
}

#[inline]
pub fn limbs_less_than_limbs_consttime(a: &[Limb], b: &[Limb]) -> LimbMask {
    assert_eq!(a.len(), b.len());
    unsafe { LIMBS_less_than(a.as_ptr(), b.as_ptr(), b.len()) }
}

#[inline]
pub fn limbs_less_than_limbs_vartime(a: &[Limb], b: &[Limb]) -> bool {
    limbs_less_than_limbs_consttime(a, b).leak()
}

#[inline]
#[cfg(feature = "alloc")]
pub fn limbs_less_than_limb_constant_time(a: &[Limb], b: Limb) -> LimbMask {
    unsafe { LIMBS_less_than_limb(a.as_ptr(), b, a.len()) }
}

#[inline]
pub fn limbs_are_zero_constant_time(limbs: &[Limb]) -> LimbMask {
    unsafe { LIMBS_are_zero(limbs.as_ptr(), limbs.len()) }
}

#[cfg(any(test, feature = "alloc"))]
#[inline]
pub fn limbs_are_even_constant_time(limbs: &[Limb]) -> LimbMask {
    unsafe { LIMBS_are_even(limbs.as_ptr(), limbs.len()) }
}

#[cfg(any(test, feature = "alloc"))]
#[inline]
pub fn limbs_equal_limb_constant_time(a: &[Limb], b: Limb) -> LimbMask {
    unsafe { LIMBS_equal_limb(a.as_ptr(), b, a.len()) }
}

/// Returns the number of bits in `a`.
//
// This strives to be constant-time with respect to the values of all bits
// except the most significant bit. This does not attempt to be constant-time
// with respect to `a.len()` or the value of the result or the value of the
// most significant bit (It's 1, unless the input is zero, in which case it's
// zero.)
#[cfg(any(test, feature = "alloc"))]
pub fn limbs_minimal_bits(a: &[Limb]) -> bits::BitLength {
    for num_limbs in (1..=a.len()).rev() {
        let high_limb = a[num_limbs - 1];

        // Find the number of set bits in |high_limb| by a linear scan from the
        // most significant bit to the least significant bit. This works great
        // for the most common inputs because usually the most significant bit
        // it set.
        for high_limb_num_bits in (1..=LIMB_BITS).rev() {
            let shifted = unsafe { LIMB_shr(high_limb, high_limb_num_bits - 1) };
            if shifted != 0 {
                return bits::BitLength::from_bits(
                    ((num_limbs - 1) * LIMB_BITS) + high_limb_num_bits,
                );
            }
        }
    }

    // No bits were set.
    bits::BitLength::from_bits(0)
}

/// Equivalent to `if (r >= m) { r -= m; }`
#[inline]
pub fn limbs_reduce_once_constant_time(r: &mut [Limb], m: &[Limb]) {
    assert_eq!(r.len(), m.len());
    unsafe { LIMBS_reduce_once(r.as_mut_ptr(), m.as_ptr(), m.len()) };
}

#[derive(Clone, Copy, PartialEq)]
pub enum AllowZero {
    No,
    Yes,
}

/// Parses `input` into `result`, verifies that the value is less than
/// `max_exclusive`, and pads `result` with zeros to its length. If `allow_zero`
/// is not `AllowZero::Yes`, zero values are rejected.
///
/// This attempts to be constant-time with respect to the actual value *only if*
/// the value is actually in range. In other words, this won't leak anything
/// about a valid value, but it might leak small amounts of information about an
/// invalid value (which constraint it failed).
pub fn parse_big_endian_in_range_and_pad_consttime(
    input: untrusted::Input,
    allow_zero: AllowZero,
    max_exclusive: &[Limb],
    result: &mut [Limb],
) -> Result<(), error::Unspecified> {
    parse_big_endian_and_pad_consttime(input, result)?;
    if !limbs_less_than_limbs_consttime(result, max_exclusive).leak() {
        return Err(error::Unspecified);
    }
    if allow_zero != AllowZero::Yes {
        if limbs_are_zero_constant_time(result).leak() {
            return Err(error::Unspecified);
        }
    }
    Ok(())
}

/// Parses `input` into `result`, padding `result` with zeros to its length.
/// This attempts to be constant-time with respect to the value but not with
/// respect to the length; it is assumed that the length is public knowledge.
pub fn parse_big_endian_and_pad_consttime(
    input: untrusted::Input,
    result: &mut [Limb],
) -> Result<(), error::Unspecified> {
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

    let num_encoded_limbs = (input.len() / LIMB_BYTES)
        + (if bytes_in_current_limb == LIMB_BYTES {
            0
        } else {
            1
        });
    if num_encoded_limbs > result.len() {
        return Err(error::Unspecified);
    }

    result.fill(0);

    // XXX: Questionable as far as constant-timedness is concerned.
    // TODO: Improve this.
    input.read_all(error::Unspecified, |input| {
        for i in 0..num_encoded_limbs {
            let mut limb: Limb = 0;
            for _ in 0..bytes_in_current_limb {
                let b: Limb = input.read_byte()?.into();
                limb = (limb << 8) | b;
            }
            result[num_encoded_limbs - i - 1] = limb;
            bytes_in_current_limb = LIMB_BYTES;
        }
        Ok(())
    })
}

pub fn big_endian_from_limbs(limbs: &[Limb], out: &mut [u8]) {
    let be_bytes = unstripped_be_bytes(limbs);
    assert_eq!(out.len(), be_bytes.len());
    out.iter_mut().zip(be_bytes).for_each(|(o, i)| {
        *o = i;
    });
}

/// Returns an iterator of the big-endian encoding of `limbs`.
///
/// The number of bytes returned will be a multiple of `LIMB_BYTES`
/// and thus may be padded with leading zeros.
pub fn unstripped_be_bytes(limbs: &[Limb]) -> impl ExactSizeIterator<Item = u8> + Clone + '_ {
    // The unwrap is safe because a slice can never be larger than `usize` bytes.
    ArrayFlatMap::new(limbs.iter().rev().copied(), Limb::to_be_bytes).unwrap()
}

#[cfg(feature = "alloc")]
pub type Window = Limb;

/// Processes `limbs` as a sequence of 5-bit windows, folding the windows from
/// most significant to least significant and returning the accumulated result.
/// The first window will be mapped by `init` to produce the initial value for
/// the accumulator. Then `f` will be called to fold the accumulator and the
/// next window until all windows are processed. When the input's bit length
/// isn't divisible by 5, the window passed to `init` will be partial; all
/// windows passed to `fold` will be full.
///
/// This is designed to avoid leaking the contents of `limbs` through side
/// channels as long as `init` and `fold` are side-channel free.
///
/// Panics if `limbs` is empty.
#[cfg(feature = "alloc")]
pub fn fold_5_bit_windows<R, I: FnOnce(Window) -> R, F: Fn(R, Window) -> R>(
    limbs: &[Limb],
    init: I,
    fold: F,
) -> R {
    #[derive(Clone, Copy)]
    #[repr(transparent)]
    struct BitIndex(Wrapping<c::size_t>);

    const WINDOW_BITS: Wrapping<c::size_t> = Wrapping(5);

    prefixed_extern! {
        fn LIMBS_window5_split_window(
            lower_limb: Limb,
            higher_limb: Limb,
            index_within_word: BitIndex,
        ) -> Window;
        fn LIMBS_window5_unsplit_window(limb: Limb, index_within_word: BitIndex) -> Window;
    }

    let num_limbs = limbs.len();
    let mut window_low_bit = {
        let num_whole_windows = (num_limbs * LIMB_BITS) / 5;
        let mut leading_bits = (num_limbs * LIMB_BITS) - (num_whole_windows * 5);
        if leading_bits == 0 {
            leading_bits = WINDOW_BITS.0;
        }
        BitIndex(Wrapping(LIMB_BITS - leading_bits))
    };

    let initial_value = {
        let leading_partial_window =
            unsafe { LIMBS_window5_split_window(*limbs.last().unwrap(), 0, window_low_bit) };
        window_low_bit.0 -= WINDOW_BITS;
        init(leading_partial_window)
    };

    let mut low_limb = 0;
    limbs
        .iter()
        .rev()
        .fold(initial_value, |mut acc, current_limb| {
            let higher_limb = low_limb;
            low_limb = *current_limb;

            if window_low_bit.0 > Wrapping(LIMB_BITS) - WINDOW_BITS {
                let window =
                    unsafe { LIMBS_window5_split_window(low_limb, higher_limb, window_low_bit) };
                window_low_bit.0 -= WINDOW_BITS;
                acc = fold(acc, window);
            };
            while window_low_bit.0 < Wrapping(LIMB_BITS) {
                let window = unsafe { LIMBS_window5_unsplit_window(low_limb, window_low_bit) };
                // The loop exits when this subtraction underflows, causing `window_low_bit` to
                // wrap around to a very large value.
                window_low_bit.0 -= WINDOW_BITS;
                acc = fold(acc, window);
            }
            window_low_bit.0 += Wrapping(LIMB_BITS); // "Fix" the underflow.

            acc
        })
}

#[inline]
pub(crate) fn limbs_add_assign_mod(a: &mut [Limb], b: &[Limb], m: &[Limb]) {
    debug_assert_eq!(a.len(), m.len());
    debug_assert_eq!(b.len(), m.len());
    prefixed_extern! {
        // `r` and `a` may alias.
        fn LIMBS_add_mod(
            r: *mut Limb,
            a: *const Limb,
            b: *const Limb,
            m: *const Limb,
            num_limbs: c::size_t,
        );
    }
    unsafe { LIMBS_add_mod(a.as_mut_ptr(), a.as_ptr(), b.as_ptr(), m.as_ptr(), m.len()) }
}

// r *= 2 (mod m).
pub(crate) fn limbs_double_mod(r: &mut [Limb], m: &[Limb]) {
    assert_eq!(r.len(), m.len());
    prefixed_extern! {
        fn LIMBS_shl_mod(r: *mut Limb, a: *const Limb, m: *const Limb, num_limbs: c::size_t);
    }
    unsafe {
        LIMBS_shl_mod(r.as_mut_ptr(), r.as_ptr(), m.as_ptr(), m.len());
    }
}

// *r = -a, assuming a is odd.
pub(crate) fn limbs_negative_odd(r: &mut [Limb], a: &[Limb]) {
    debug_assert_eq!(r.len(), a.len());
    // Two's complement step 1: flip all the bits.
    // The compiler should optimize this to vectorized (a ^ !0).
    r.iter_mut().zip(a.iter()).for_each(|(r, &a)| {
        *r = !a;
    });
    // Two's complement step 2: Add one. Since `a` is odd, `r` is even. Thus we
    // can use a bitwise or for addition.
    r[0] |= 1;
}

prefixed_extern! {
    fn LIMBS_are_zero(a: *const Limb, num_limbs: c::size_t) -> LimbMask;
    fn LIMBS_less_than(a: *const Limb, b: *const Limb, num_limbs: c::size_t) -> LimbMask;
    fn LIMBS_reduce_once(r: *mut Limb, m: *const Limb, num_limbs: c::size_t);
}

#[cfg(any(test, feature = "alloc"))]
prefixed_extern! {
    fn LIMB_shr(a: Limb, shift: c::size_t) -> Limb;
    fn LIMBS_are_even(a: *const Limb, num_limbs: c::size_t) -> LimbMask;
    fn LIMBS_equal_limb(a: *const Limb, b: Limb, num_limbs: c::size_t) -> LimbMask;
}

#[cfg(feature = "alloc")]
prefixed_extern! {
    fn LIMBS_less_than_limb(a: *const Limb, b: Limb, num_limbs: c::size_t) -> LimbMask;
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX: Limb = Limb::MAX;

    fn leak_in_test(a: LimbMask) -> bool {
        a.leak()
    }

    #[test]
    fn test_limbs_are_even() {
        static EVENS: &[&[Limb]] = &[
            &[],
            &[0],
            &[2],
            &[0, 0],
            &[2, 0],
            &[0, 1],
            &[0, 2],
            &[0, 3],
            &[0, 0, 0, 0, MAX],
        ];
        for even in EVENS {
            assert!(leak_in_test(limbs_are_even_constant_time(even)));
        }
        static ODDS: &[&[Limb]] = &[
            &[1],
            &[3],
            &[1, 0],
            &[3, 0],
            &[1, 1],
            &[1, 2],
            &[1, 3],
            &[1, 0, 0, 0, MAX],
        ];
        for odd in ODDS {
            assert!(!leak_in_test(limbs_are_even_constant_time(odd)));
        }
    }

    static ZEROES: &[&[Limb]] = &[
        &[],
        &[0],
        &[0, 0],
        &[0, 0, 0],
        &[0, 0, 0, 0],
        &[0, 0, 0, 0, 0],
        &[0, 0, 0, 0, 0, 0, 0],
        &[0, 0, 0, 0, 0, 0, 0, 0],
        &[0, 0, 0, 0, 0, 0, 0, 0, 0],
    ];

    static NONZEROES: &[&[Limb]] = &[
        &[1],
        &[0, 1],
        &[1, 1],
        &[1, 0, 0, 0],
        &[0, 1, 0, 0],
        &[0, 0, 1, 0],
        &[0, 0, 0, 1],
    ];

    #[test]
    fn test_limbs_are_zero() {
        for zero in ZEROES {
            assert!(leak_in_test(limbs_are_zero_constant_time(zero)));
        }
        for nonzero in NONZEROES {
            assert!(!leak_in_test(limbs_are_zero_constant_time(nonzero)));
        }
    }

    #[test]
    fn test_limbs_equal_limb() {
        for zero in ZEROES {
            assert!(leak_in_test(limbs_equal_limb_constant_time(zero, 0)));
        }
        for nonzero in NONZEROES {
            assert!(!leak_in_test(limbs_equal_limb_constant_time(nonzero, 0)));
        }
        static EQUAL: &[(&[Limb], Limb)] = &[
            (&[1], 1),
            (&[MAX], MAX),
            (&[1, 0], 1),
            (&[MAX, 0, 0], MAX),
            (&[0b100], 0b100),
            (&[0b100, 0], 0b100),
        ];
        for &(a, b) in EQUAL {
            assert!(leak_in_test(limbs_equal_limb_constant_time(a, b)));
        }
        static UNEQUAL: &[(&[Limb], Limb)] = &[
            (&[0], 1),
            (&[2], 1),
            (&[3], 1),
            (&[1, 1], 1),
            (&[0b100, 0b100], 0b100),
            (&[1, 0, 0b100, 0, 0, 0, 0, 0], 1),
            (&[1, 0, 0, 0, 0, 0, 0, 0b100], 1),
            (&[MAX, MAX], MAX),
            (&[MAX, 1], MAX),
        ];
        for &(a, b) in UNEQUAL {
            assert!(!leak_in_test(limbs_equal_limb_constant_time(a, b)));
        }
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn test_limbs_less_than_limb_constant_time() {
        static LESSER: &[(&[Limb], Limb)] = &[
            (&[0], 1),
            (&[0, 0], 1),
            (&[1, 0], 2),
            (&[2, 0], 3),
            (&[2, 0], 3),
            (&[MAX - 1], MAX),
            (&[MAX - 1, 0], MAX),
        ];
        for &(a, b) in LESSER {
            assert!(leak_in_test(limbs_less_than_limb_constant_time(a, b)));
        }
        static EQUAL: &[(&[Limb], Limb)] = &[
            (&[0], 0),
            (&[0, 0, 0, 0], 0),
            (&[1], 1),
            (&[1, 0, 0, 0, 0, 0, 0], 1),
            (&[MAX], MAX),
        ];
        static GREATER: &[(&[Limb], Limb)] = &[
            (&[1], 0),
            (&[2, 0], 1),
            (&[3, 0, 0, 0], 1),
            (&[0, 1, 0, 0], 1),
            (&[0, 0, 1, 0], 1),
            (&[0, 0, 1, 1], 1),
            (&[MAX], MAX - 1),
        ];
        for &(a, b) in EQUAL.iter().chain(GREATER.iter()) {
            assert!(!leak_in_test(limbs_less_than_limb_constant_time(a, b)));
        }
    }

    #[test]
    fn test_parse_big_endian_and_pad_consttime() {
        const LIMBS: usize = 4;

        {
            // Empty input.
            let inp = untrusted::Input::from(&[]);
            let mut result = [0; LIMBS];
            assert!(parse_big_endian_and_pad_consttime(inp, &mut result).is_err());
        }

        // The input is longer than will fit in the given number of limbs.
        {
            let inp = [1, 2, 3, 4, 5, 6, 7, 8, 9];
            let inp = untrusted::Input::from(&inp);
            let mut result = [0; 8 / LIMB_BYTES];
            assert!(parse_big_endian_and_pad_consttime(inp, &mut result[..]).is_err());
        }

        // Less than a full limb.
        {
            let inp = [0xfe];
            let inp = untrusted::Input::from(&inp);
            let mut result = [0; LIMBS];
            assert_eq!(
                Ok(()),
                parse_big_endian_and_pad_consttime(inp, &mut result[..])
            );
            assert_eq!(&[0xfe, 0, 0, 0], &result);
        }

        // A whole limb for 32-bit, half a limb for 64-bit.
        {
            let inp = [0xbe, 0xef, 0xf0, 0x0d];
            let inp = untrusted::Input::from(&inp);
            let mut result = [0; LIMBS];
            assert_eq!(Ok(()), parse_big_endian_and_pad_consttime(inp, &mut result));
            assert_eq!(&[0xbeeff00d, 0, 0, 0], &result);
        }

        // XXX: This is a weak set of tests. TODO: expand it.
    }

    #[test]
    fn test_big_endian_from_limbs_same_length() {
        #[cfg(target_pointer_width = "32")]
        let limbs = [
            0xbccddeef, 0x89900aab, 0x45566778, 0x01122334, 0xddeeff00, 0x99aabbcc, 0x55667788,
            0x11223344,
        ];

        #[cfg(target_pointer_width = "64")]
        let limbs = [
            0x8990_0aab_bccd_deef,
            0x0112_2334_4556_6778,
            0x99aa_bbcc_ddee_ff00,
            0x1122_3344_5566_7788,
        ];

        let expected = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff, 0x00, 0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x90, 0x0a, 0xab,
            0xbc, 0xcd, 0xde, 0xef,
        ];

        let mut out = [0xabu8; 32];
        big_endian_from_limbs(&limbs[..], &mut out);
        assert_eq!(&out[..], &expected[..]);
    }

    #[should_panic]
    #[test]
    fn test_big_endian_from_limbs_fewer_limbs() {
        #[cfg(target_pointer_width = "32")]
        // Two fewer limbs.
        let limbs = [
            0xbccddeef, 0x89900aab, 0x45566778, 0x01122334, 0xddeeff00, 0x99aabbcc,
        ];

        // One fewer limb.
        #[cfg(target_pointer_width = "64")]
        let limbs = [
            0x8990_0aab_bccd_deef,
            0x0112_2334_4556_6778,
            0x99aa_bbcc_ddee_ff00,
        ];

        let mut out = [0xabu8; 32];

        big_endian_from_limbs(&limbs[..], &mut out);
    }

    #[test]
    fn test_limbs_minimal_bits() {
        const ALL_ONES: Limb = Limb::MAX;
        static CASES: &[(&[Limb], usize)] = &[
            (&[], 0),
            (&[0], 0),
            (&[ALL_ONES], LIMB_BITS),
            (&[ALL_ONES, 0], LIMB_BITS),
            (&[ALL_ONES, 1], LIMB_BITS + 1),
            (&[0, 0], 0),
            (&[1, 0], 1),
            (&[0, 1], LIMB_BITS + 1),
            (&[0, ALL_ONES], 2 * LIMB_BITS),
            (&[ALL_ONES, ALL_ONES], 2 * LIMB_BITS),
            (&[ALL_ONES, ALL_ONES >> 1], 2 * LIMB_BITS - 1),
            (&[ALL_ONES, 0b100_0000], LIMB_BITS + 7),
            (&[ALL_ONES, 0b101_0000], LIMB_BITS + 7),
            (&[ALL_ONES, ALL_ONES >> 1], LIMB_BITS + (LIMB_BITS) - 1),
        ];
        for (limbs, bits) in CASES {
            assert_eq!(limbs_minimal_bits(limbs).as_bits(), *bits);
        }
    }
}
