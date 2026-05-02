// Copyright 2015-2022 Brian Smith.
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

use crate::limb::{LIMB_BITS, Limb};

// n0 * N == -1 (mod r).
//
// r == 2**(N0::LIMBS_USED * LIMB_BITS) and LG_LITTLE_R == lg(r). This
// ensures that we can do integer division by |r| by simply ignoring
// `N0::LIMBS_USED` limbs. Similarly, we can calculate values modulo `r` by
// just looking at the lowest `N0::LIMBS_USED` limbs. This is what makes
// Montgomery multiplication efficient.
//
// As shown in Algorithm 1 of "Fast Prime Field Elliptic Curve Cryptography
// with 256 Bit Primes" by Shay Gueron and Vlad Krasnov, in the loop of a
// multi-limb Montgomery multiplication of a * b (mod n), given the
// unreduced product t == a * b, we repeatedly calculate:
//
//    t1 := t % r         |t1| is |t|'s lowest limb (see previous paragraph).
//    t2 := t1*n0*n
//    t3 := t + t2
//    t := t3 / r         copy all limbs of |t3| except the lowest to |t|.
//
// In the last step, it would only make sense to ignore the lowest limb of
// |t3| if it were zero. The middle steps ensure that this is the case:
//
//                            t3 ==  0 (mod r)
//                        t + t2 ==  0 (mod r)
//                   t + t1*n0*n ==  0 (mod r)
//                       t1*n0*n == -t (mod r)
//                        t*n0*n == -t (mod r)
//                          n0*n == -1 (mod r)
//                            n0 == -1/n (mod r)
//
// Thus, in each iteration of the loop, we multiply by the constant factor
// n0, the negative inverse of n (mod r).
//
// TODO(perf): Not all 32-bit platforms actually make use of n0[1]. For the
// ones that don't, we could use a shorter `R` value and use faster `Limb`
// calculations instead of double-precision `u64` calculations.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct N0<'a>(&'a [Limb; N0::LIMBS_USED]);

struct N0Storage([Limb; N0::LIMBS_USED]);

match_target_word_bits! {
    64 => {
        impl N0<'_> {
            pub(super) const LIMBS_USED: usize = 1;
        }

        impl N0Storage {
            #[inline]
            pub const fn precalculated(n0: u64) -> Self {
                Self([n0])
            }
        }
    },
    32 => {
         impl N0<'_> {
            pub(super) const LIMBS_USED: usize = 2;
        }

        impl N0Storage {
            #[inline]
            pub const fn precalculated(n0: u64) -> Self {
                Self([n0 as Limb, (n0 >> crate::limb::LIMB_BITS) as Limb])
            }
         }
    },
}

impl<'a> N0<'a> {
    #[allow(clippy::useless_conversion)]
    pub(super) fn write_into(out: &mut [Limb; N0::LIMBS_USED], m: &[Limb]) {
        // n_mod_r = n % r. As explained in the documentation for `n0`, this is
        // done by taking the lowest `N0::LIMBS_USED` limbs of `n`.
        prefixed_extern! {
            unsafe fn bn_neg_inv_mod_r_u64(n: u64) -> u64;
        }

        // XXX: u64::from isn't guaranteed to be constant time.
        let mut n_mod_r: u64 = u64::from(m[0]);

        if N0::LIMBS_USED == 2 {
            // XXX: If we use `<< LIMB_BITS` here then 64-bit builds
            // fail to compile because of `deny(exceeding_bitshifts)`.
            debug_assert_eq!(LIMB_BITS, 32);
            n_mod_r |= u64::from(m[1]) << 32;
        }
        let calculated = N0Storage::precalculated(unsafe { bn_neg_inv_mod_r_u64(n_mod_r) });
        *out = calculated.0;
    }

    pub(super) fn from_limbs_unchecked_less_safe(limbs: &'a [Limb; N0::LIMBS_USED]) -> Self {
        Self(limbs)
    }
}
