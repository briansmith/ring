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

/* Common utilities on private keys for NIST curves. */

#include <openssl/bn.h>

#include <assert.h>
#include <limits.h>

#include "internal.h"
#include "gfp_internal.h"


/* Generates a private key for the curve given in |group|, saving it in |out|,
 * least-significant-word first, zero-padded. It returns one on success or zero
 * otherwise. */
int GFp_suite_b_generate_private_key(const EC_GROUP *group,
                                     uint8_t *private_key_out, RAND *rng) {
  /* XXX: Not constant time. */

  unsigned order_bits = BN_num_bits(&group->order);
  assert(order_bits % 8 == 0);

  /* Because all the topmost bits are set, `BN_rand_range`'s more complicated
   * way of doing things isn't useful. */
  assert(BN_is_bit_set(&group->order, order_bits - 1));
  assert(BN_is_bit_set(&group->order, order_bits - 2));
  assert(BN_is_bit_set(&group->order, order_bits - 3));

  int ret = 0;
  BIGNUM tmp;
  BN_init(&tmp);

  unsigned iterations = 0;
  for (;;) {
    if (!BN_rand(&tmp, (int)order_bits, -1, 0, rng)) {
      goto err;
    }
    if (BN_cmp(&tmp, &group->order) < 0 &&
        !BN_is_zero(&tmp)) {
      break;
    }
    ++iterations;
    /* TODO: The value 100 was chosen to match what OpenSSL does. Is this
     * actually a sensible number of iterations? Should we switch to using an
     * *unbiased* modular reduction instead, to avoid this looping? */
    if (iterations == 100) {
      goto err;
    }
  }

  size_t private_key_out_len = (EC_GROUP_get_degree(group) + 7) / 8;
  if (!BN_bn2bin_padded(private_key_out, private_key_out_len, &tmp)) {
    goto err;
  }

  ret = 1;

err:
  BN_free(&tmp);
  return ret;
}
