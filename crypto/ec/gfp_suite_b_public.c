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

/* Common utilities on public keys for NIST curves. */

#include "gfp_internal.h"

#include "../bn/internal.h"


/* Declarations to avoid -Wmissing-prototypes warnings. */
int GFp_suite_b_public_twin_mult(EC_GROUP *group, BN_ULONG *xyz_out,
                                 const BN_ULONG *g_scalar,
                                 const BN_ULONG *p_scalar,
                                 const BN_ULONG p_x[], const BN_ULONG p_y[]);


int GFp_suite_b_public_twin_mult(EC_GROUP *group, BN_ULONG *xyz_out,
                                 const BN_ULONG *g_scalar,
                                 const BN_ULONG *p_scalar,
                                 const BN_ULONG p_x[], const BN_ULONG p_y[]) {
  assert(g_scalar != NULL || p_scalar != NULL);
  assert((p_scalar == NULL) == (p_x == NULL));
  assert((p_scalar == NULL) == (p_y == NULL));

  int ret = 0;

  EC_POINT *result = NULL;

  result = EC_POINT_new(group);
  if (result == NULL) {
    goto err;
  }

  size_t num_limbs =
    (ec_GFp_simple_group_get_degree(group) + (GFp_LIMB_BITS - 1)) /
    GFp_LIMB_BITS;

  BN_ULONG *x_out = xyz_out;
  BN_ULONG *y_out = x_out + num_limbs;
  BN_ULONG *z_out = y_out + num_limbs;

  if (!group->meth->mul(group, result, g_scalar, p_scalar, p_x, p_y) ||
      !bn_get_words(x_out, &result->X, num_limbs) ||
      !bn_get_words(y_out, &result->Y, num_limbs) ||
      !bn_get_words(z_out, &result->Z, num_limbs)) {
    goto err;
  }

  ret = 1;

err:
  EC_POINT_free(result);
  return ret;
}
