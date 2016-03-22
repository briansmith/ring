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
                                 const uint8_t *from, unsigned from_len) {
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

  if (!RAND_bytes(p, j)) {
    return 0;
  }

  for (i = 0; i < j; i++) {
    while (*p == 0) {
      if (!RAND_bytes(p, 1)) {
        return 0;
      }
    }
    p++;
  }

  *(p++) = 0;

  memcpy(p, from, from_len);
  return 1;
}

int RSA_padding_check_PKCS1_type_2(uint8_t *to, unsigned to_len,
                                   const uint8_t *from, unsigned from_len) {
  if (from_len == 0) {
    OPENSSL_PUT_ERROR(RSA, RSA_R_EMPTY_PUBLIC_KEY);
    return -1;
  }

  /* PKCS#1 v1.5 decryption. See "PKCS #1 v2.2: RSA Cryptography
   * Standard", section 7.2.2. */
  if (from_len < RSA_PKCS1_PADDING_SIZE) {
    /* |from| is zero-padded to the size of the RSA modulus, a public value, so
     * this can be rejected in non-constant time. */
    OPENSSL_PUT_ERROR(RSA, RSA_R_KEY_SIZE_TOO_SMALL);
    return -1;
  }

  unsigned first_byte_is_zero = constant_time_eq(from[0], 0);
  unsigned second_byte_is_two = constant_time_eq(from[1], 2);

  unsigned i, zero_index = 0, looking_for_index = ~0u;
  for (i = 2; i < from_len; i++) {
    unsigned equals0 = constant_time_is_zero(from[i]);
    zero_index = constant_time_select(looking_for_index & equals0, (unsigned)i,
                                      zero_index);
    looking_for_index = constant_time_select(equals0, 0, looking_for_index);
  }

  /* The input must begin with 00 02. */
  unsigned valid_index = first_byte_is_zero;
  valid_index &= second_byte_is_two;

  /* We must have found the end of PS. */
  valid_index &= ~looking_for_index;

  /* PS must be at least 8 bytes long, and it starts two bytes into |from|. */
  valid_index &= constant_time_ge(zero_index, 2 + 8);

  /* Skip the zero byte. */
  zero_index++;

  /* NOTE: Although this logic attempts to be constant time, the API contracts
   * of this function and |RSA_decrypt| with |RSA_PKCS1_PADDING| make it
   * impossible to completely avoid Bleichenbacher's attack. Consumers should
   * use |RSA_unpad_key_pkcs1|. */
  if (!valid_index) {
    OPENSSL_PUT_ERROR(RSA, RSA_R_PKCS_DECODING_ERROR);
    return -1;
  }

  const unsigned msg_len = from_len - zero_index;
  if (msg_len > to_len) {
    /* This shouldn't happen because this function is always called with
     * |to_len| as the key size and |from_len| is bounded by the key size. */
    OPENSSL_PUT_ERROR(RSA, RSA_R_PKCS_DECODING_ERROR);
    return -1;
  }

  if (msg_len > INT_MAX) {
    OPENSSL_PUT_ERROR(RSA, ERR_R_OVERFLOW);
    return -1;
  }

  memcpy(to, &from[zero_index], msg_len);
  return (int)msg_len;
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
