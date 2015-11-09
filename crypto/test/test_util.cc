/* Copyright (c) 2015, Google Inc.
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

#include "test_util.h"

#include <stdint.h>
#include <stdio.h>

#include "openssl/rand.h"


void hexdump(FILE *fp, const char *msg, const void *in, size_t len) {
  const uint8_t *data = reinterpret_cast<const uint8_t*>(in);
  size_t i;

  fputs(msg, fp);
  for (i = 0; i < len; i++) {
    fprintf(fp, "%02x", data[i]);
  }
  fputs("\n", fp);
}

// XXX: In *ring*, we implement |BN_generate_dsa_nonce_digest| in Rust so that
// we can use |ring::digest|. But, the tests don't link against any Rust code.
// Fortunately, we don't need secure nonces in the tests, so we can do the
// thing you're not supposed to do in this implementation. This will likely
// throw off the ECDSA_sign performance measurements in |bssl speed| though.
extern "C" int BN_generate_dsa_nonce_digest(uint8_t *out, size_t out_len,
                                            const uint8_t *, size_t,
                                            const uint8_t *, size_t,
                                            const uint8_t *, size_t,
                                            const uint8_t *, size_t,
                                            const uint8_t *, size_t) {
  return RAND_bytes(out, out_len);
}
