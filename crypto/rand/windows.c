/* Copyright (c) 2014, Google Inc.
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

#include <openssl/rand.h>

#include <openssl/thread.h>


#if defined(OPENSSL_WINDOWS)

#include <stdlib.h>
#include <Windows.h>
#include <Wincrypt.h>

static char global_provider_init;
static HCRYPTPROV global_provider;

void RAND_cleanup(void) {
  CRYPTO_w_lock(CRYPTO_LOCK_RAND);
  CryptReleaseContext(global_provider, 0);
  global_provider_init = 0;
  CRYPTO_w_unlock(CRYPTO_LOCK_RAND);
}

int RAND_bytes(uint8_t *out, size_t requested) {
  HCRYPTPROV provider = 0;
  int ok;

  CRYPTO_r_lock(CRYPTO_LOCK_RAND);
  if (!global_provider_init) {
    CRYPTO_r_unlock(CRYPTO_LOCK_RAND);
    CRYPTO_w_lock(CRYPTO_LOCK_RAND);
    if (!global_provider_init) {
      if (CryptAcquireContext(&global_provider, NULL, NULL, PROV_RSA_FULL,
                              CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        global_provider_init = 1;
      }
    }
    CRYPTO_w_unlock(CRYPTO_LOCK_RAND);
    CRYPTO_r_lock(CRYPTO_LOCK_RAND);
  }

  ok = global_provider_init;
  provider = global_provider;
  CRYPTO_r_unlock(CRYPTO_LOCK_RAND);

  if (!ok) {
    abort();
    return ok;
  }

  if (TRUE != CryptGenRandom(provider, requested, out)) {
    abort();
    return 0;
  }

  return 1;
}

#endif  /* OPENSSL_WINDOWS */
