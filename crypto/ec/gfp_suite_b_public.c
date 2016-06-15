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


EC_POINT *GFp_suite_b_make_point(const EC_GROUP *group,
                                 const uint8_t *peer_public_key_x,
                                 size_t peer_public_key_x_len,
                                 const uint8_t *peer_public_key_y,
                                 size_t peer_public_key_y_len) {
  BIGNUM x;
  BN_init(&x);

  BIGNUM y;
  BN_init(&y);

  int ok = 0;

  EC_POINT *result = EC_POINT_new(group);
  if (result == NULL) {
    goto err;
  }

  /* |ec_GFp_simple_point_set_affine_coordinates| verifies that (x, y) is on
   * the curve and that each coordinate is a valid field element (i.e.
   * non-negative and less than `q`). The point cannot be the point at infinity
   * because it was given as affine coordinates. */
  if (BN_bin2bn(peer_public_key_x, peer_public_key_x_len, &x) == NULL ||
      BN_bin2bn(peer_public_key_y, peer_public_key_y_len, &y) == NULL ||
      !ec_GFp_simple_point_set_affine_coordinates(group, result, &x, &y,
                                                  NULL)) {
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
