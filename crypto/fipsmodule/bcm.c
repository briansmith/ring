/* Copyright (c) 2017, Google Inc.
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

#include <openssl/base.h>
#include <openssl/crypto.h>
#include <openssl/hmac.h>

#include "../internal.h"

#include "digest/digest.c"
#include "digest/digests.c"
#include "hmac/hmac.c"
#include "md4/md4.c"
#include "md5/md5.c"
#include "sha/sha1-altivec.c"
#include "sha/sha1.c"
#include "sha/sha256.c"
#include "sha/sha512.c"


#if defined(BORINGSSL_FIPS)
static void hexdump(const uint8_t *in, size_t len) {
  for (size_t i = 0; i < len; i++) {
    printf("%02x", in[i]);
  }
}

/* These functions are removed by delocate.go and references to them are
 * rewritten to point to the start and end of the module, and the location of
 * the integrity hash. */
static void BORINGSSL_bcm_text_dummy_start(void) {}
static void BORINGSSL_bcm_text_dummy_end(void) {}
static void BORINGSSL_bcm_text_dummy_hash(void) {}

static void BORINGSSL_bcm_power_on_self_test(void) __attribute__((constructor));

static void BORINGSSL_bcm_power_on_self_test(void) {
  CRYPTO_library_init();

  const uint8_t *const start = (const uint8_t *)BORINGSSL_bcm_text_dummy_start;
  const uint8_t *const end = (const uint8_t *)BORINGSSL_bcm_text_dummy_end;

  static const uint8_t kHMACKey[32] = {0};
  uint8_t result[SHA256_DIGEST_LENGTH];

  unsigned result_len;
  if (!HMAC(EVP_sha256(), kHMACKey, sizeof(kHMACKey), start, end - start,
            result, &result_len) ||
      result_len != sizeof(result)) {
    goto err;
  }

  const uint8_t *const expected =
      (const uint8_t *)BORINGSSL_bcm_text_dummy_hash;

  if (OPENSSL_memcmp(expected, result, sizeof(result)) != 0) {
    printf("FIPS integrity test failed.\nExpected: ");
    hexdump(expected, sizeof(result));
    printf("\nCalculated: ");
    hexdump(result, sizeof(result));
    printf("\n");
    goto err;
  }

  // TODO(fips): KAT tests go here.

  return;

err:
  for (;;) {
    exit(1);
    abort();
  }
}
#endif  /* BORINGSSL_FIPS */
