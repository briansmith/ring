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


/* Prototypes to avoid -Wmissing-prototypes warnings. */
GFp_Limb GFp_constant_time_limbs_are_zero(const GFp_Limb a[],
                                          size_t num_limbs);
GFp_Limb GFp_constant_time_limbs_lt_limbs(const GFp_Limb a[],
                                          const GFp_Limb b[],
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
  GFp_Limb eq = constant_time_is_zero_size_t(0);
  GFp_Limb lt = constant_time_is_zero_size_t(1);
  for (size_t i = 0; i < num_limbs; ++i) {
    GFp_Limb a_limb = a[num_limbs - i - 1];
    GFp_Limb b_limb = b[num_limbs - i - 1];
    lt = constant_time_select_size_t(
      eq, constant_time_lt_size_t(a_limb, b_limb), lt);
    eq = constant_time_select_size_t(
      eq, constant_time_eq_size_t(a_limb, b_limb), 0);
  }
  return lt;
}
