use crate::{
    limb::{self, Limb},
    polyfill::uninit::Uninit,
};
use cfg_if::cfg_if;

pub const LIMBS_USED: usize = if cfg!(target_arch = "x86") { 2 } else { 1 };
pub type Limbs = [Limb; LIMBS_USED];

/// Writes the limbs of an `N0` value into `out` assuming `n` is odd.
pub fn write_n0_assuming_odd(out: Uninit<'_, Limbs>, n: &Limbs) {
    // a_lo = n (mod 2**LIMB_BITS).
    let &[n_lo, ..] = n;

    // First compute the lower 32 bits, assuming 32-bit -> 32-bit arithmetic
    // is as good or better than `Limb` arithmetic.
    let r32 = u32_neg_inv_assuming_odd(n_lo);

    // Then compute the rest, as necessary.
    #[allow(clippy::needless_late_init)]
    let r;
    cfg_if! {
        if #[cfg(target_arch = "x86")] {
            r = u32_2_neg_inv_from_u32_neg_inv_assuming_odd(r32, n);
        } else {
            match_target_word_bits! {
                64 => {
                   r = [u64_neg_inv_from_u32_neg_inv_assuming_odd(r32, n_lo)];
                },
                32 => {
                    r = [r32];
                },
            }
        }
    }
    let _: &mut Limbs = out.write(r);
}

/// Compute -1/a (mod 2**32) assuming `a` is odd.
#[inline(always)]
fn u32_neg_inv_assuming_odd(a: Limb) -> u32 {
    // Like BoringSSL, we use a variant of the idea in Colin Plumb's 1994
    // sci.crypt messages in the thread "Computing multiplicative inverses",
    // modified to calculate the *negative* inverse.

    let a = limb::truncate_u32(a);

    // First, -a (mod 2**32) is odd since a is odd.
    //
    // Colin Plumb (Apr 6, 1994, 2:31:16 AM): "For all odd x, x*x == 1 (mod 8)";
    // so here we have x == -1/a (mod 2**3), which implies the loop invariant
    // below for `i == 1` since 3 >= (2**1).
    //
    // TODO: It might be nice to try the formula `(3*a) ^ 2` for
    // 1/a (mod 2**(2**2)) since that would allow us to skip the `i == 1`
    // iteration below, if we ever get around to verifying it.
    let mut x = a.wrapping_neg();

    for _i in 1..5 {
        // Invariant: x == -1/a (mod 2**(2**i)).

        // Colin Plumb (Apr 6, 1994, 8:41:35 PM): "[...] you can make the
        // iteration step x *= (2-a*x)". Since we need the negative inverse,
        // (2 - a*(-x)) == 2 + a*x == a*x + 2 (mod 2**32).
        x = x.wrapping_mul(a.wrapping_mul(x).wrapping_add(2));
    }

    x
}

/// Computes -1/a (mod 2**64) from inputs `x` and `a` where x = -1/a (mod 2**32).
#[allow(dead_code)]
#[inline(always)]
fn u64_neg_inv_from_u32_neg_inv_assuming_odd(x: u32, a: u64) -> u64 {
    let x = u64::from(x);
    // Same as above, except `u64` instead of `u32`.
    x.wrapping_mul(a.wrapping_mul(x).wrapping_add(2))
}

match_target_word_bits! {
    64 => {},
    32 => {
        /// Like `u64_neg_inv_from_u32_neg_inv_assuming_odd` but splitting
        /// the 64-bit `n0` into two limbs.
        #[allow(dead_code)]
        #[inline(always)]
        fn u32_2_neg_inv_from_u32_neg_inv_assuming_odd(
            x_lo: u32,
            a: &[u32; 2],
        ) -> [u32; 2] {
            let &[a_lo, a_hi] = a;
            let a = (u64::from(a_hi) << 32) | u64::from(a_lo);
            let x = u64_neg_inv_from_u32_neg_inv_assuming_odd(x_lo, a);
            #[allow(clippy::cast_possible_truncation)]
            let x_hi = (x >> 32) as u32;
            [x_lo, x_hi]
        }
    },
}
