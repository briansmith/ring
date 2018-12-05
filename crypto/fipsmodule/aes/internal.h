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

#ifndef OPENSSL_HEADER_AES_INTERNAL_H
#define OPENSSL_HEADER_AES_INTERNAL_H

#include "../../internal.h"

static inline int hwaes_capable(void) {
#if defined(OPENSSL_X86_64) || defined(OPENSSL_X86)
  return (GFp_ia32cap_P[1] & (1 << (57 - 32))) != 0;
#elif defined(OPENSSL_ARM) || defined(OPENSSL_AARCH64)
  return GFp_is_ARMv8_AES_capable();
#elif defined(OPENSSL_PPC64LE)
  return GFp_is_PPC64LE_vcrypto_capable();
#endif
}

#endif  // OPENSSL_HEADER_AES_INTERNAL_H
