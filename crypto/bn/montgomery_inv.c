/* Copyright 2016 Brian Smith.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include <openssl/bn.h>

#include <assert.h>

#include "internal.h"
#include "../internal.h"
#include "../limbs/limbs.h"

static uint64_t bn_neg_inv_mod_r_u64(uint64_t n);

OPENSSL_COMPILE_ASSERT(BN_MONT_CTX_N0_LIMBS == 1 || BN_MONT_CTX_N0_LIMBS == 2,
                       BN_MONT_CTX_N0_LIMBS_VALUE_INVALID);
OPENSSL_COMPILE_ASSERT(sizeof(uint64_t) ==
                       BN_MONT_CTX_N0_LIMBS * sizeof(BN_ULONG),
                       BN_MONT_CTX_N0_LIMBS_DOES_NOT_MATCH_UINT64_T);

/* LG_LITTLE_R is log_2(r). */
#define LG_LITTLE_R (BN_MONT_CTX_N0_LIMBS * BN_BITS2)

uint64_t GFp_bn_mont_n0(const BIGNUM *n) {
  /* These conditions are checked by the caller, |BN_MONT_CTX_set|. */
  assert(!GFp_BN_is_zero(n));
  assert(!GFp_BN_is_negative(n));
  assert(GFp_BN_is_odd(n));

  /* r == 2**(BN_MONT_CTX_N0_LIMBS * BN_BITS2) and LG_LITTLE_R == lg(r). This
   * ensures that we can do integer division by |r| by simply ignoring
   * |BN_MONT_CTX_N0_LIMBS| limbs. Similarly, we can calculate values modulo
   * |r| by just looking at the lowest |BN_MONT_CTX_N0_LIMBS| limbs. This is
   * what makes Montgomery multiplication efficient.
   *
   * As shown in Algorithm 1 of "Fast Prime Field Elliptic Curve Cryptography
   * with 256 Bit Primes" by Shay Gueron and Vlad Krasnov, in the loop of a
   * multi-limb Montgomery multiplication of |a * b (mod n)|, given the
   * unreduced product |t == a * b|, we repeatedly calculate:
   *
   *    t1 := t % r         |t1| is |t|'s lowest limb (see previous paragraph).
   *    t2 := t1*n0*n
   *    t3 := t + t2
   *    t := t3 / r         copy all limbs of |t3| except the lowest to |t|.
   *
   * In the last step, it would only make sense to ignore the lowest limb of
   * |t3| if it were zero. The middle steps ensure that this is the case:
   *
   *                            t3 ==  0 (mod r)
   *                        t + t2 ==  0 (mod r)
   *                   t + t1*n0*n ==  0 (mod r)
   *                       t1*n0*n == -t (mod r)
   *                        t*n0*n == -t (mod r)
   *                          n0*n == -1 (mod r)
   *                            n0 == -1/n (mod r)
   *
   * Thus, in each iteration of the loop, we multiply by the constant factor
   * |n0|, the negative inverse of n (mod r). */

  /* n_mod_r = n % r. As explained above, this is done by taking the lowest
   * |BN_MONT_CTX_N0_LIMBS| limbs of |n|. */
  uint64_t n_mod_r = n->d[0];
#if BN_MONT_CTX_N0_LIMBS == 2
  if (n->top > 1) {
    n_mod_r |= (uint64_t)n->d[1] << BN_BITS2;
  }
#endif

  return bn_neg_inv_mod_r_u64(n_mod_r);
}

/* bn_neg_inv_r_mod_n_u64 calculates the -1/n mod r; i.e. it calculates |v|
 * such that u*r - v*n == 1. |r| is the constant defined in |bn_mont_n0|. |n|
 * must be odd.
 *
 * This is derived from |xbinGCD| in Henry S. Warren, Jr.'s "Montgomery
 * Multiplication" (http://www.hackersdelight.org/MontgomeryMultiplication.pdf).
 * It is very similar to the MODULAR-INVERSE function in Stephen R. Dussé's and
 * Burton S. Kaliski Jr.'s "A Cryptographic Library for the Motorola DSP56000"
 * (http://link.springer.com/chapter/10.1007%2F3-540-46877-3_21).
 *
 * This is inspired by Joppe W. Bos's "Constant Time Modular Inversion"
 * (http://www.joppebos.com/files/CTInversion.pdf) so that the inversion is
 * constant-time with respect to |n|. We assume uint64_t additions,
 * subtractions, shifts, and bitwise operations are all constant time, which
 * may be a large leap of faith on 32-bit targets. We avoid division and
 * multiplication, which tend to be the most problematic in terms of timing
 * leaks.
 *
 * Most GCD implementations return values such that |u*r + v*n == 1|, so the
 * caller would have to negate the resultant |v| for the purpose of Montgomery
 * multiplication. This implementation does the negation implicitly by doing
 * the computations as a difference instead of a sum. */
static uint64_t bn_neg_inv_mod_r_u64(uint64_t n) {
  assert(n % 2 == 1);

  /* alpha == 2**(lg r - 1) == r / 2. */
  static const uint64_t alpha = UINT64_C(1) << (LG_LITTLE_R - 1);

  const uint64_t beta = n;

  uint64_t u = 1;
  uint64_t v = 0;

  /* The invariant maintained from here on is:
   * 2**(lg r - i) == u*2*alpha - v*beta. */
  for (size_t i = 0; i < LG_LITTLE_R; ++i) {
#if BN_BITS2 == 64 && defined(BN_ULLONG)
    assert((BN_ULLONG)(1) << (LG_LITTLE_R - i) ==
           ((BN_ULLONG)u * 2 * alpha) - ((BN_ULLONG)v * beta));
#endif

    /* Delete a common factor of 2 in u and v if |u| is even. Otherwise, set
     * |u = (u + beta) / 2| and |v = (v / 2) + alpha|. */

    uint64_t u_is_odd = UINT64_C(0) - (u & 1); /* Either 0xff..ff or 0. */

    /* The addition can overflow, so use Dietz's method for it.
     *
     * Dietz calculates (x+y)/2 by (x⊕y)>>1 + x&y. This is valid for all
     * (unsigned) x and y, even when x+y overflows. Evidence for 32-bit values
     * (embedded in 64 bits to so that overflow can be ignored):
     *
     * (declare-fun x () (_ BitVec 64))
     * (declare-fun y () (_ BitVec 64))
     * (assert (let (
     *    (one (_ bv1 64))
     *    (thirtyTwo (_ bv32 64)))
     *    (and
     *      (bvult x (bvshl one thirtyTwo))
     *      (bvult y (bvshl one thirtyTwo))
     *      (not (=
     *        (bvadd (bvlshr (bvxor x y) one) (bvand x y))
     *        (bvlshr (bvadd x y) one)))
     * )))
     * (check-sat) */
    uint64_t beta_if_u_is_odd = beta & u_is_odd; /* Either |beta| or 0. */
    u = ((u ^ beta_if_u_is_odd) >> 1) + (u & beta_if_u_is_odd);

    uint64_t alpha_if_u_is_odd = alpha & u_is_odd; /* Either |alpha| or 0. */
    v = (v >> 1) + alpha_if_u_is_odd;
  }

  /* The invariant now shows that u*r - v*n == 1 since r == 2 * alpha. */
#if BN_BITS2 == 64 && defined(BN_ULLONG)
  assert(1 == ((BN_ULLONG)u * 2 * alpha) - ((BN_ULLONG)v * beta));
#endif

  return v;
}

/* bn_mod_exp_base_2_vartime calculates r = 2**(2*p) (mod n). 2**p must be
 * larger than |n|. |n| must be positive and odd. */
int GFp_bn_mod_exp_base_2_vartime(BIGNUM *r, size_t p, const BIGNUM *n,
                                  BN_ULONG n0[BN_MONT_CTX_N0_LIMBS]) {
  assert(!GFp_BN_is_zero(n));
  assert(!GFp_BN_is_negative(n));
  assert(GFp_BN_is_odd(n));

  GFp_BN_zero(r);

  unsigned n_bits = GFp_BN_num_bits(n);
  assert(n_bits != 0);
  if (n_bits == 1) {
    return 1;
  }

  /* Set |r| to the largest power of two less than |n|. */
  if (GFp_bn_wexpand(r, n->top) == NULL) {
    return 0;
  }
  assert(p >= n_bits);
  if (!GFp_BN_set_bit(r, n_bits - 1)) {
    return 0;
  }
  assert(r->dmax >= n->top);
  assert(r->top == n->top || r->top == n->top - 1);
  if (r->top < n->top) {
    r->d[n->top] = 0;
  }
  size_t i = n_bits - 1;

  /* The first iteration results in r == 2**p == R.
   * The second iteration results in r == 2*R.
   *
   * Once we have 2*R, we can use either squaring or shifting depending on
   * the relative performance between the two. We assume that
   * Cshift < Csquare < 2*Cshift, where |CShift| is the cost of shifting and
   * Csquare is the cost of squaring. Therefore, we shift once more to get
   * r == 4*R, then we switch to squaring. */
  while (i < p + 2 && i < 2 * p) {
    LIMBS_shl_mod(r->d, r->d, n->d, n->top);
    ++i;
  }

  i = 2;
  while (2 * i <= p) {
    if (!GFp_BN_mod_mul_mont(r, r, r, n, n0)) {
      return 0;
    }
    i *= 2;
  }

  // TODO: Make sure we're testing {1023, 2047, 3071, 4091, 8191, etc.}-bit
  // moduli.

  /* For |p| in {1024, 2048, 4096, 8192}, at least, we will be done at this
   * point. Unfortunately for other cases we will need to do a bunch of
   * shifting. This is especially unfortunate for p == 3072 since that is
   * actually common for RSA verification. */
  assert(i == p || (p != 1024 && p != 2048 && p != 4096 && p != 8192));

  while (i < p) {
    LIMBS_shl_mod(r->d, r->d, n->d, n->top);
    ++i;
  }

  GFp_bn_correct_top(r);

  return 1;
}
