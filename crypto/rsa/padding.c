/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project 2005.
 */
/* ====================================================================
 * Copyright (c) 2005 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com). */

#include <openssl/rsa.h>

#include <assert.h>
#include <limits.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/rand.h>

#include "internal.h"
#include "../internal.h"

/* TODO(fork): don't the check functions have to be constant time? */

int RSA_padding_add_PKCS1_type_1(uint8_t *to, unsigned to_len,
                                 const uint8_t *from, unsigned from_len) {
  unsigned j;

  if (to_len < RSA_PKCS1_PADDING_SIZE) {
    OPENSSL_PUT_ERROR(RSA, RSA_R_KEY_SIZE_TOO_SMALL);
    return 0;
  }

  if (from_len > to_len - RSA_PKCS1_PADDING_SIZE) {
    OPENSSL_PUT_ERROR(RSA, RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
    return 0;
  }

  uint8_t *p = to;

  *(p++) = 0;
  *(p++) = 1; /* Private Key BT (Block Type) */

  /* pad out with 0xff data */
  j = to_len - 3 - from_len;
  memset(p, 0xff, j);
  p += j;
  *(p++) = 0;
  memcpy(p, from, from_len);
  return 1;
}

/* RSA_padding_check_PKCS1_type_1 returns the length of the PKCS#1 padding,
 * not including the DigestInfo, if the padding is valid. Otherwise (if the
 * padding is not valid), it returns zero. Note that zero-length padding isn't
 * valid. */
size_t RSA_padding_check_PKCS1_type_1(const uint8_t *from, unsigned from_len) {
  size_t i, j;
  const uint8_t *p;

  if (from_len < 2) {
    OPENSSL_PUT_ERROR(RSA, RSA_R_DATA_TOO_SMALL);
    return 0;
  }

  p = from;
  if ((*(p++) != 0) || (*(p++) != 1)) {
    OPENSSL_PUT_ERROR(RSA, RSA_R_BLOCK_TYPE_IS_NOT_01);
    return 0;
  }

  /* scan over padding data */
  j = from_len - 2; /* one for leading 00, one for type. */
  for (i = 0; i < j; i++) {
    /* should decrypt to 0xff */
    if (*p != 0xff) {
      if (*p == 0) {
        p++;
        break;
      } else {
        OPENSSL_PUT_ERROR(RSA, RSA_R_BAD_FIXED_HEADER_DECRYPT);
        return 0;
      }
    }
    p++;
  }

  if (i == j) {
    OPENSSL_PUT_ERROR(RSA, RSA_R_NULL_BEFORE_BLOCK_MISSING);
    return 0;
  }

  if (i < 8) {
    OPENSSL_PUT_ERROR(RSA, RSA_R_BAD_PAD_BYTE_COUNT);
    return 0;
  }
  i++; /* Skip over the '\0' */
  return from_len - (j - i);
}

int RSA_padding_add_PKCS1_type_2(uint8_t *to, unsigned to_len,
                                 const uint8_t *from, unsigned from_len,
                                 RAND *rng) {
  unsigned i, j;

  if (to_len < RSA_PKCS1_PADDING_SIZE) {
    OPENSSL_PUT_ERROR(RSA, RSA_R_KEY_SIZE_TOO_SMALL);
    return 0;
  }

  if (from_len > to_len - RSA_PKCS1_PADDING_SIZE) {
    OPENSSL_PUT_ERROR(RSA, RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
    return 0;
  }

  uint8_t *p = to;

  *(p++) = 0;
  *(p++) = 2; /* Public Key BT (Block Type) */

  /* pad out with non-zero random data */
  j = to_len - 3 - from_len;

  if (!RAND_bytes(rng, p, j)) {
    return 0;
  }

  for (i = 0; i < j; i++) {
    while (*p == 0) {
      if (!RAND_bytes(rng, p, 1)) {
        return 0;
      }
    }
    p++;
  }

  *(p++) = 0;

  memcpy(p, from, from_len);
  return 1;
}

int RSA_padding_add_none(uint8_t *to, unsigned to_len, const uint8_t *from,
                         unsigned from_len) {
  if (from_len > to_len) {
    OPENSSL_PUT_ERROR(RSA, RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
    return 0;
  }

  if (from_len < to_len) {
    OPENSSL_PUT_ERROR(RSA, RSA_R_DATA_TOO_SMALL_FOR_KEY_SIZE);
    return 0;
  }

  memcpy(to, from, from_len);
  return 1;
}
