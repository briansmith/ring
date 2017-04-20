/* Copyright (c) 2014, Intel Corporation.
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

#include "ecp_nistz.h"

#include <assert.h>

#include <GFp/bn.h>

#include "../bn/internal.h"


/* Fills |str| with the bytewise little-endian encoding of |scalar|, where
 * |scalar| has |num_limbs| limbs. |str| is padded with zeros at the end up
 * to |str_len| bytes. Actually, |str_len| must be exactly one byte more than
 * needed to encode |num_limbs| losslessly, so that there is an extra byte at
 * the end. The extra byte is useful because the caller will be breaking |str|
 * up into windows of a number of bits (5 or 7) that isn't divisible by 8, and
 * so it is useful for it to be able to read an extra zero byte. */
void gfp_little_endian_bytes_from_scalar(uint8_t str[], size_t str_len,
                                         const BN_ULONG scalar[],
                                         size_t num_limbs) {
  assert(str_len == (num_limbs * BN_BYTES) + 1);

  size_t i;
  for (i = 0; i < num_limbs * BN_BYTES; i += BN_BYTES) {
    BN_ULONG d = scalar[i / BN_BYTES];

    str[i + 0] = d & 0xff;
    str[i + 1] = (d >> 8) & 0xff;
    str[i + 2] = (d >> 16) & 0xff;
    str[i + 3] = (d >>= 24) & 0xff;
    if (BN_BYTES == 8) {
      d >>= 8;
      str[i + 4] = d & 0xff;
      str[i + 5] = (d >> 8) & 0xff;
      str[i + 6] = (d >> 16) & 0xff;
      str[i + 7] = (d >> 24) & 0xff;
    }
  }
  for (; i < str_len; i++) {
    str[i] = 0;
  }
}
