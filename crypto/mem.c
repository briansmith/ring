/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <ring-core/mem.h>
#include "internal.h"

int CRYPTO_memcmp(const void *in_a, const void *in_b, size_t len) {
  const aliasing_uint8_t *a = in_a;
  const aliasing_uint8_t *b = in_b;
  uint8_t x = 0;

  for (size_t i = 0; i < len; i++) {
    x |= a[i] ^ b[i];
  }

  return x;
}
