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

#include <limits.h>


int GFp_suite_b_ecdh(const EC_GROUP *group, uint8_t *out, size_t out_len,
                     const uint8_t *private_key, size_t private_key_len,
                     const uint8_t *peer_public_key_x,
                     size_t peer_public_key_x_len,
                     const uint8_t *peer_public_key_y,
                     size_t peer_public_key_y_len) {
  BIGNUM private_key_bn;
  BN_init(&private_key_bn);

  BIGNUM result_x;
  BN_init(&result_x);

  EC_POINT *peer_point = NULL;
  EC_POINT *result_point = NULL;

  int ret = 0;

  if (BN_bin2bn(private_key, private_key_len, &private_key_bn) == NULL) {
    goto err;
  }

  peer_point = GFp_suite_b_make_point(group, peer_public_key_x,
                                      peer_public_key_x_len, peer_public_key_y,
                                      peer_public_key_y_len);
  if (peer_point == NULL) {
    goto err;
  }

  result_point = EC_POINT_new(group);
  if (result_point == NULL) {
    goto err;
  }

  if (!group->meth->mul_private(group, result_point, NULL, peer_point,
                                &private_key_bn, NULL) ||
      !EC_POINT_get_affine_coordinates_GFp(group, result_point, &result_x, NULL,
                                           NULL) ||
      !BN_bn2bin_padded(out, out_len, &result_x)) {
    goto err;
  }

  ret = 1;

err:
  EC_POINT_free(peer_point);
  EC_POINT_free(result_point);
  BN_free(&result_x);
  return ret;
}
