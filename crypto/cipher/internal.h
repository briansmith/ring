/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.] */

#ifndef OPENSSL_HEADER_CIPHER_INTERNAL_H
#define OPENSSL_HEADER_CIPHER_INTERNAL_H

#if !defined(__STDC_CONSTANT_MACROS)
#define __STDC_CONSTANT_MACROS
#endif

#include <openssl/base.h>

#include <assert.h>
#include <stdint.h>

#include <openssl/err.h>

#include "../internal.h"

#if defined(__cplusplus)
extern "C" {
#endif


/* Preconditions for AEAD implementation methods. */

/* aead_check_alias returns 0 if |out| points within the buffer determined by
 * |in| and |in_len| and 1 otherwise.
 *
 * When processing, there's only an issue if |out| points within in[:in_len]
 * and isn't equal to |in|. If that's the case then writing the output will
 * stomp input that hasn't been read yet.
 *
 * This function checks for that case. */
inline int aead_check_alias(const uint8_t *in, size_t in_len,
                            const uint8_t *out) {
  if (out <= in) {
    return 1;
  } else if (in + in_len <= out) {
    return 1;
  }
  return 0;
}

/* |CRYPTO_chacha_20| uses a 32-bit block counter. Therefore we disallow
 * individual operations that work on more than 256GB at a time, for all AEADs.
 * |in_len_64| is needed because, on 32-bit platforms, size_t is only
 * 32-bits and this produces a warning because it's always false.
 * Casting to uint64_t inside the conditional is not sufficient to stop
 * the warning. */
inline int aead_check_in_len(size_t in_len) {
  const uint64_t in_len_64 = in_len;
  return in_len_64 < (1ull << 32) * 64 - 64;
}

inline int aead_seal_out_max_out_in_tag_len(size_t *out_len, size_t max_out_len,
                                            size_t in_len, size_t tag_len) {
  if (SIZE_MAX - tag_len < in_len) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_TOO_LARGE);
    return 0;
  }
  size_t ciphertext_len = in_len + tag_len;
  if (max_out_len < ciphertext_len) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BUFFER_TOO_SMALL);
    return 0;
  }
  *out_len = ciphertext_len;
  return 1;
}

inline int aead_open_out_max_out_in_tag_len(size_t *out_len, size_t max_out_len,
                                            size_t in_len, size_t tag_len) {
  if (in_len < tag_len) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BAD_DECRYPT);
    return 0;
  }
  size_t plaintext_len = in_len - tag_len;
  if (max_out_len < plaintext_len) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BUFFER_TOO_SMALL);
    return 0;
  }
  *out_len = plaintext_len;
  return 1;
}

static inline void aead_assert_init_preconditions(size_t ctx_struct_alignment,
                                                  size_t ctx_struct_size,
                                                  const void *ctx_buf,
                                                  size_t ctx_buf_len,
                                                  const uint8_t *key) {
#if defined(NDEBUG)
  (void)ctx_struct_alignment;
  (void)ctx_struct_size;
  (void)ctx_buf;
  (void)ctx_buf_len;
  (void)key;
#endif
  assert(ctx_buf != NULL);
  assert(((uintptr_t)ctx_buf) % ctx_struct_alignment == 0);
  assert(ctx_buf_len >= ctx_struct_size);
  assert(key != NULL);
}

inline void aead_assert_open_seal_preconditions(size_t ctx_struct_alignment,
                                                const void *ctx_buf,
                                                uint8_t *out, size_t *out_len,
                                                const uint8_t *nonce,
                                                const uint8_t *in,
                                                size_t in_len,
                                                const uint8_t *ad,
                                                size_t ad_len) {
#if defined(NDEBUG)
  (void)ctx_struct_alignment;
  (void)ctx_buf;
  (void)out;
  (void)out_len;
  (void)nonce;
  (void)in;
  (void)in_len;
  (void)ad;
  (void)ad_len;
#endif
  assert(ctx_buf != NULL);
  assert(((uintptr_t)ctx_buf) % ctx_struct_alignment == 0);
  assert(out != NULL);
  assert(out_len != NULL);
  assert(nonce != NULL);
  assert(in != NULL || in_len == 0);
  assert(aead_check_in_len(in_len));
  assert(aead_check_alias(in, in_len, out));
  assert(ad != NULL || ad_len == 0);
}

#if defined(__cplusplus)
} /* extern C */
#endif

#endif /* OPENSSL_HEADER_CIPHER_INTERNAL_H */
