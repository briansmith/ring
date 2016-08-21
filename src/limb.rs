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

use {rand, polyfill, c, core, error};

// XXX: Not correct for x32 ABIs.
#[cfg(target_pointer_width = "64")] pub type Limb = u64;
#[cfg(target_pointer_width = "32")] pub type Limb = u32;
#[cfg(target_pointer_width = "64")] pub const LIMB_BITS: usize = 64;
#[cfg(target_pointer_width = "32")] pub const LIMB_BITS: usize = 32;
#[cfg(target_pointer_width = "64")] const LIMB_BITS_U32: u32 = 64;
#[cfg(target_pointer_width = "32")] const LIMB_BITS_U32: u32 = 32;


pub const LIMB_BYTES: usize = (LIMB_BITS + 7) / 8;

/// References a positive integer range `[1..max_exclusive)`.
/// `max_exclusive` is assumed to be public, not secret.
pub struct Range<'a> {
    pub max_exclusive: &'a [Limb],
}

impl <'a> Range<'a> {
    pub fn from_max_exclusive(max_exclusive: &[Limb]) -> Range {
        debug_assert!(!limbs_are_zero_constant_time(max_exclusive));
        debug_assert!(max_exclusive[max_exclusive.len() - 1] > 0);

        Range {
            max_exclusive: max_exclusive
        }
    }

    /// Are these little-endian limbs within the range?
    ///
    /// Checks in constant time.
    pub fn are_limbs_within(&self, limbs: &[Limb]) -> bool {
        assert_eq!(self.max_exclusive.len(), limbs.len());

        let is_gt_zero = !limbs_are_zero_constant_time(limbs);
        let is_lt_max =
            limbs_less_than_limbs_constant_time(limbs, self.max_exclusive);

        is_lt_max && is_gt_zero
    }

    /// Chooses a positive integer within the range and stores it into `dest`.
    ///
    /// This function is intended to be suitable for generating private keys.
    //
    // TODO: DRY-up with `ec::suite_b::private_key::generate_private_key`.
    fn sample_into_limbs(&self, dest: &mut [Limb], rng: &rand::SecureRandom)
                         -> Result<(), error::Unspecified> {
        // Loosely based on [NSA Suite B Implementer's Guide to ECDSA]
        // Appendix A.1.2, and
        // [NSA Suite B Implementer's Guide to NIST SP 800-56A] Appendix B.2,
        // "Key Pair Generation by Testing Candidates".
        //
        // [NSA Suite B Implementer's Guide to ECDSA]: doc/ecdsa.pdf.
        // [NSA Suite B Implementer's Guide to NIST SP 800-56A]: doc/ecdh.pdf.

        assert_eq!(self.max_exclusive.len(), dest.len());

        let most_significant_limb =
            self.max_exclusive[self.max_exclusive.len() - 1];
        debug_assert!(most_significant_limb > 0);
        let most_significant_limb_mask =
            most_significant_limb_mask_variable_time(most_significant_limb);
        debug_assert!(most_significant_limb_mask != 0);

        // XXX: The value 100 was chosen to match OpenSSL due to uncertainty of
        // what specific value would be better, but it seems bad to try 100
        // times.
        for _ in 0..100 {
            {
                let mut dest_as_bytes = limbs_as_bytes_mut(dest);
                try!(rng.fill(&mut dest_as_bytes));
            }
            dest[self.max_exclusive.len() - 1] &= most_significant_limb_mask;

            if self.are_limbs_within(&dest) {
                return Ok(());
            }
        }

        Err(error::Unspecified)
    }
}

/// Returns a mask that has the same number of leading zeros as
/// `most_significant_limb`, with all the following bits set.
fn most_significant_limb_mask_variable_time(most_significant_limb: Limb)
                                            -> Limb {
    const ONE: Limb = 1;

    let bits_to_mask_off = most_significant_limb.leading_zeros();
    if bits_to_mask_off == 0 {
        Limb::max_value()
    } else {
        (ONE << (LIMB_BITS_U32 - bits_to_mask_off)) - 1
    }
}

#[allow(unsafe_code)]
#[allow(non_snake_case)]
#[doc(hidden)]
#[no_mangle]
pub unsafe extern fn GFp_rand_mod(dest: *mut Limb, max_exclusive: *const Limb,
                                  num_limbs: c::size_t, rng: *mut rand::RAND)
                                  -> c::int {
    const ERR: c::int = 0;
    const SUCCESS: c::int = 1;

    let range = Range::from_max_exclusive(
        core::slice::from_raw_parts(max_exclusive, num_limbs));
    let mut dest = core::slice::from_raw_parts_mut(dest, num_limbs);

    let result = range.sample_into_limbs(&mut dest, (*rng).rng);
    if result.is_err() {
        return ERR;
    }

    SUCCESS
}


#[cfg(target_pointer_width = "64")]
fn limbs_as_bytes_mut<'a>(src: &'a mut [Limb]) -> &'a mut [u8] {
    polyfill::slice::u64_as_u8_mut(src)
}

#[cfg(target_pointer_width = "32")]
fn limbs_as_bytes_mut<'a>(src: &'a mut [Limb]) -> &'a mut [u8] {
    polyfill::slice::u32_as_u8_mut(src)
}

#[allow(unsafe_code)]
pub fn limbs_less_than_limbs_constant_time(a: &[Limb], b: &[Limb]) -> bool {
    assert_eq!(a.len(), b.len());
    let result = unsafe {
        GFp_constant_time_limbs_lt_limbs(a.as_ptr(), b.as_ptr(), b.len())
    };
    result != 0
}

#[allow(unsafe_code)]
pub fn limbs_are_zero_constant_time(limbs: &[Limb]) -> bool {
    let result = unsafe {
        GFp_constant_time_limbs_are_zero(limbs.as_ptr(), limbs.len())
    };
    result != 0
}

extern {
    fn GFp_constant_time_limbs_are_zero(a: *const Limb, num_limbs: c::size_t)
                                        -> Limb;

    fn GFp_constant_time_limbs_lt_limbs(a: *const Limb, b: *const Limb,
                                        num_limbs: c::size_t) -> Limb;
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::most_significant_limb_mask_variable_time;
    use rand;

    #[test]
    fn test_most_significant_limb_mask() {
        assert_eq!(0, most_significant_limb_mask_variable_time(0));

        for i in 0..LIMB_BITS {
           let x = 1 << i;
            let expected = if i == LIMB_BITS - 1 {
                Limb::max_value()
            } else {
                (1 << (i + 1)) - 1
            };
            assert_eq!(expected, most_significant_limb_mask_variable_time(x),
                       "for {:?}", x);
            assert_eq!(expected,
                       most_significant_limb_mask_variable_time(x | 1),
                       "for {:?}", x | 1);
            assert_eq!(expected,
                       most_significant_limb_mask_variable_time(x | (x >> 1)),
                       "for {:?}", x | (x >> 1));
            assert_eq!(expected,
                       most_significant_limb_mask_variable_time(expected),
                       "for {:?}", expected);
        }
    }

    #[test]
    fn test_limbs_in_range() {
        let limbs = &[Limb::max_value(), Limb::max_value()];
        let range = Range::from_max_exclusive(limbs);
        assert!(!range.are_limbs_within(&[Limb::max_value(),
                                          Limb::max_value()]));
        assert!(range.are_limbs_within(&[Limb::max_value(),
                                         Limb::max_value() - 1]));
        assert!(range.are_limbs_within(&[Limb::max_value() - 1,
                                         Limb::max_value()]));
        assert!(!range.are_limbs_within(&[0, 0]));
        assert!(range.are_limbs_within(&[1, 0]));
        assert!(range.are_limbs_within(&[0, 1]));

        let limbs = &[0xdeadbeef, 0xdeadbeef];
        let range = Range::from_max_exclusive(limbs);
        assert!(!range.are_limbs_within(&[0xdeadbeef, 0xdeadbeef]));
        assert!(range.are_limbs_within(&[0xdeadbeee, 0xdeadbeef]));
        assert!(range.are_limbs_within(&[0xdeadbeef, 0xdeadbeee]));
        assert!(!range.are_limbs_within(&[0xdeadbeff, 0xdeadbeef]));
        assert!(!range.are_limbs_within(&[0xdeadbeef, 0xdeadbeff]));

        let limbs = &[2];
        let range = Range::from_max_exclusive(limbs);
        assert!(!range.are_limbs_within(&[0]));
        assert!(range.are_limbs_within(&[1]));
        assert!(!range.are_limbs_within(&[2]));
    }

    #[test]
    fn test_random_generation() {
        let rng = rand::SystemRandom::new();

        let mut dest: [Limb; 2] = [0; 2];
        let limbs = &[Limb::max_value(), Limb::max_value()];
        let range = Range::from_max_exclusive(limbs);
        assert!(range.sample_into_limbs(&mut dest, &rng).is_ok());
        assert!(dest.iter().any( |b| *b > 0 ));

        let mut dest: [Limb; 2] = [0; 2];
        let limbs = &[0xdeadbeef, 0xdeadbeef];
        let range = Range::from_max_exclusive(limbs);
        assert!(range.sample_into_limbs(&mut dest, &rng).is_ok());
        assert!(dest.iter().any( |b| *b > 0 ));

        let mut dest: [Limb; 1] = [0; 1];
        let limbs = &[2];
        let range = Range::from_max_exclusive(limbs);
        assert!(range.sample_into_limbs(&mut dest, &rng).is_ok());
        assert_eq!([1], dest);

        let mut dest: [Limb; 1] = [0; 1];
        let limbs = &[1 << (LIMB_BITS - 1)];
        let range = Range::from_max_exclusive(limbs);
        assert!(range.sample_into_limbs(&mut dest, &rng).is_ok());
        assert!(dest.iter().any( |b| *b > 0 ));
    }
}
