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
int GFp_suite_b_public_twin_mult(EC_GROUP *group, BN_ULONG *x_out,
                                 BN_ULONG *y_out, BN_ULONG *z_out,
                                 const BN_ULONG *g_scalar, const BN_ULONG *p_x,
                                 const BN_ULONG *p_y, const BN_ULONG *p_scalar);


EC_POINT *GFp_suite_b_make_point(const EC_GROUP *group,
                                 const GFp_Limb *peer_public_key_x,
                                 const GFp_Limb *peer_public_key_y) {
  BIGNUM x;
  BN_init(&x);

  BIGNUM y;
  BN_init(&y);

  int ok = 0;

  EC_POINT *result = EC_POINT_new(group);
  if (result == NULL) {
    goto err;
  }

  size_t num_limbs =
    (ec_GFp_simple_group_get_degree(group) + (GFp_LIMB_BITS - 1)) /
    GFp_LIMB_BITS;

  if (!bn_set_words(&result->X, peer_public_key_x, num_limbs) ||
      !bn_set_words(&result->Y, peer_public_key_y, num_limbs) ||
      !BN_copy(&result->Z, &group->one)) {
    goto err;
  }

  ok = 1;

err:
  BN_free(&x);
  BN_free(&y);
  if (!ok) {
    EC_POINT_free(result);
    result = NULL;
  }
  return result;
}

int GFp_suite_b_public_twin_mult(EC_GROUP *group, BN_ULONG *x_out,
                                 BN_ULONG *y_out, BN_ULONG *z_out,
                                 const BN_ULONG *g_scalar,
                                 const BN_ULONG *p_scalar, const BN_ULONG *p_x,
                                 const BN_ULONG *p_y) {
  BIGNUM g_scalar_bn;
  BN_init(&g_scalar_bn);

  BIGNUM p_scalar_bn;
  BN_init(&p_scalar_bn);

  int ret = 0;

  EC_POINT *result = NULL;
  EC_POINT *p = NULL;

  result = EC_POINT_new(group);
  if (result == NULL) {
    goto err;
  }

  p = GFp_suite_b_make_point(group, p_x, p_y);
  if (p == NULL) {
    goto err;
  }

  size_t num_limbs =
    (ec_GFp_simple_group_get_degree(group) + (GFp_LIMB_BITS - 1)) /
    GFp_LIMB_BITS;

  if (!bn_set_words(&g_scalar_bn, g_scalar, num_limbs) ||
      !bn_set_words(&p_scalar_bn, p_scalar, num_limbs) ||
      !group->meth->mul(group, result, &g_scalar_bn, p, &p_scalar_bn, NULL) ||
      !bn_get_words(x_out, &result->X, num_limbs) ||
      !bn_get_words(y_out, &result->Y, num_limbs) ||
      !bn_get_words(z_out, &result->Z, num_limbs)) {
    goto err;
  }

  ret = 1;

err:
  BN_free(&g_scalar_bn);
  BN_free(&p_scalar_bn);
  EC_POINT_free(result);
  EC_POINT_free(p);
  return ret;
}
