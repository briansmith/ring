/* Copyright (c) 2022, Google Inc.
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

#ifndef OPENSSL_HEADER_CRYPTO_FIPSMODULE_FIPS_BREAK_TEST_H
#define OPENSSL_HEADER_CRYPTO_FIPSMODULE_FIPS_BREAK_TEST_H

#include <openssl/base.h>

#include <stdlib.h>
#include <string.h>

#if defined(BORINGSSL_FIPS_BREAK_TESTS)

OPENSSL_INLINE int boringssl_fips_break_test(const char *test) {
  const char *const value = getenv("BORINGSSL_FIPS_BREAK_TEST");
  return value != NULL && strcmp(value, test) == 0;
}

#else

OPENSSL_INLINE int boringssl_fips_break_test(const char *test) {
  return 0;
}

#endif  // BORINGSSL_FIPS_BREAK_TESTS

#endif  // OPENSSL_HEADER_CRYPTO_FIPSMODULE_FIPS_BREAK_TEST_H
