/* Copyright 2016 Brian Smith.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include "gfp_internal.h"

#include <openssl/type_check.h>

#include "../internal.h"

#include "gfp_limbs.inl"


/* Prototypes to avoid -Wmissing-prototypes warnings. */
GFp_Limb GFp_constant_time_limbs_are_zero(const GFp_Limb a[],
                                          size_t num_limbs);
GFp_Limb GFp_constant_time_limbs_lt_limbs(const GFp_Limb a[],
                                          const GFp_Limb b[],
                                          size_t num_limbs);
void GFp_constant_time_limbs_reduce_once(GFp_Limb r[], const GFp_Limb m[],
                                         size_t num_limbs);


/* We have constant time primitives on |size_t|. Rather than duplicate them,
 * take advantage of the fact that |size_t| and |GFp_Limb| are currently
 * compatible on all platforms we support. */
OPENSSL_COMPILE_ASSERT(sizeof(size_t) == sizeof(GFp_Limb),
                       size_t_and_gfp_limb_are_different_sizes);


/* Returns non-zero if |a| is all zero limbs, and zero otherwise. */
GFp_Limb GFp_constant_time_limbs_are_zero(const GFp_Limb a[],
                                          size_t num_limbs) {
  GFp_Limb is_zero = constant_time_is_zero_size_t(0);
  for (size_t i = 0; i < num_limbs; ++i) {
    is_zero = constant_time_select_size_t(
        is_zero, constant_time_is_zero_size_t(a[i]), 0);
  }
  return is_zero;
}

/* Returns non-zero if |a| is less than |b|, and zero otherwise. */
GFp_Limb GFp_constant_time_limbs_lt_limbs(const GFp_Limb a[],
                                          const GFp_Limb b[],
                                          size_t num_limbs) {
  /* There are lots of ways to implement this. It is implemented this way to
   * be consistent with |GFp_constant_time_limbs_reduce_once| and other code
   * that makes such comparisions as part of doing conditional reductions. */
  GFp_Limb dummy;
  GFp_Carry borrow = gfp_sub(&dummy, a[0], b[0]);
  for (size_t i = 1; i < num_limbs; ++i) {
    borrow = gfp_sbb(&dummy, a[i], b[i], borrow);
  }
  return constant_time_is_nonzero_size_t(borrow);
}

/* if (r >= m) { r -= m; } */
void GFp_constant_time_limbs_reduce_once(GFp_Limb r[], const GFp_Limb m[],
                                         size_t num_limbs) {
  /* This could be done more efficiently if we had |num_limbs| of extra space
   * available, by storing |r - m| and then doing a conditional copy of either
   * |r| or |r - m|. But, in order to operate in constant space, with an eye
   * towards this function being used in RSA in the future, we do things a
   * slightly less efficient way. */
  GFp_Limb lt = GFp_constant_time_limbs_lt_limbs(r, m, num_limbs);
  GFp_Carry borrow = gfp_sub(&r[0], r[0],
                             constant_time_select_size_t(lt, 0, m[0]));
  for (size_t i = 1; i < num_limbs; ++i) {
    /* XXX: This is probably particularly inefficient because the operations in
     * constant_time_select affect the carry flag, so there will likely be
     * loads and stores of |borrow|. */
    borrow = gfp_sbb(&r[i], r[i],
                     constant_time_select_size_t(lt, 0, m[i]), borrow);
  }
  assert(borrow == 0);
}
