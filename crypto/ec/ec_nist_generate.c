/* Copyright 2016 Brian Smith.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>

#include "internal.h"


/* Prototypes to avoid missing prototype warnings. */
int EC_nist_generate_private_key(const EC_GROUP *group, BN_ULONG *out,
                                 size_t out_len, RAND *rng);


/* Generates a private key for the curve given in |group|, saving it in |out|,
 * least-significant-word first, zero-padded. It returns one on success or zero
 * otherwise. */
int EC_nist_generate_private_key(const EC_GROUP *group, BN_ULONG *out,
                                 size_t out_len, RAND *rng) {
  /* XXX: Not constant time. */

  int ret = 0;
  BIGNUM tmp;
  BN_init(&tmp);
  size_t iterations = 0;
  size_t n = BN_num_bits(&group->order);
  for (;;) {
    if (!BN_rand(&tmp, n, -1, 0, rng)) {
      return 0;
    }
    if (BN_cmp(&tmp, &group->order) < 0 && !BN_is_zero(&tmp)) {
      break;
    }
    ++iterations;
    if (iterations == 100) {
      OPENSSL_PUT_ERROR(BN, BN_R_TOO_MANY_ITERATIONS);
      goto err;
    }
  }

  if ((size_t)tmp.top > out_len) {
    goto err;
  }
  for (size_t i = 0; i < out_len; ++i) {
    out[i] = i < (size_t)tmp.top ? tmp.d[i] : 0;
  }

  ret = 1;

err:
  BN_free(&tmp);
  return ret;
}
