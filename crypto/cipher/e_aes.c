/* ====================================================================
 * Copyright (c) 2001-2011 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
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
 * ==================================================================== */

#include <string.h>

#include <openssl/aes.h>
#include <openssl/cpu.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>

#include "internal.h"
#include "../internal.h"
#include "../modes/internal.h"

#if defined(OPENSSL_ARM) || defined(OPENSSL_AARCH64)
#include <openssl/arm_arch.h>
#endif


#define EVP_AEAD_AES_GCM_NONCE_LEN 12
#define EVP_AEAD_AES_GCM_TAG_LEN 16

#if !defined(OPENSSL_NO_ASM) && \
    (defined(OPENSSL_X86_64) || defined(OPENSSL_X86))

#define VPAES
static char vpaes_capable(void) {
  return (OPENSSL_ia32cap_P[1] & (1 << (41 - 32))) != 0;
}

#if defined(OPENSSL_X86_64)
#define BSAES
static char bsaes_capable(void) {
  return vpaes_capable();
}
#endif

#elif !defined(OPENSSL_NO_ASM) && \
    (defined(OPENSSL_ARM) || defined(OPENSSL_AARCH64))

#if defined(OPENSSL_ARM) && __ARM_MAX_ARCH__ >= 7
#define BSAES
static char bsaes_capable(void) {
  return CRYPTO_is_NEON_capable();
}
#endif

#define HWAES
static int hwaes_capable(void) {
  return CRYPTO_is_ARMv8_AES_capable();
}

int aes_v8_set_encrypt_key(const uint8_t *user_key, const int bits,
                           AES_KEY *key);
void aes_v8_encrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key);
void aes_v8_ctr32_encrypt_blocks(const uint8_t *in, uint8_t *out, size_t len,
                                 const AES_KEY *key, const uint8_t ivec[16]);

#endif  /* OPENSSL_ARM */

#if defined(BSAES)
/* On platforms where BSAES gets defined (just above), then these functions are
 * provided by asm. */
void bsaes_ctr32_encrypt_blocks(const uint8_t *in, uint8_t *out, size_t len,
                                const AES_KEY *key, const uint8_t ivec[16]);
#endif

#if defined(VPAES)
/* On platforms where VPAES gets defined (just above), then these functions are
 * provided by asm. */
int vpaes_set_encrypt_key(const uint8_t *userKey, int bits, AES_KEY *key);
void vpaes_encrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key);
#endif

#if !defined(OPENSSL_NO_ASM) && \
    (defined(OPENSSL_X86_64) || defined(OPENSSL_X86))
#define AESNI
int aesni_set_encrypt_key(const uint8_t *userKey, int bits, AES_KEY *key);
void aesni_encrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key);
void aesni_ctr32_encrypt_blocks(const uint8_t *in, uint8_t *out, size_t blocks,
                                const AES_KEY *key, const uint8_t *ivec);
static char aesni_capable(void);
#endif

static aes_ctr_f aes_ctr_set_key(AES_KEY *aes_key, GCM128_CONTEXT *gcm_ctx,
                                const uint8_t *key, size_t key_len) {
#if defined(AESNI)
  if (aesni_capable()) {
    aesni_set_encrypt_key(key, key_len * 8, aes_key);
    CRYPTO_gcm128_init(gcm_ctx, aes_key, aesni_encrypt);
    return aesni_ctr32_encrypt_blocks;
  }
#endif

#if defined(HWAES)
  if (hwaes_capable()) {
    aes_v8_set_encrypt_key(key, key_len * 8, aes_key);
    CRYPTO_gcm128_init(gcm_ctx, aes_key, aes_v8_encrypt);
    return aes_v8_ctr32_encrypt_blocks;
  }
#endif

#if defined(BSAES)
  if (bsaes_capable()) {
    AES_set_encrypt_key(key, key_len * 8, aes_key);
    CRYPTO_gcm128_init(gcm_ctx, aes_key, AES_encrypt);
    return bsaes_ctr32_encrypt_blocks;
  }
#endif

#if defined(VPAES)
  if (vpaes_capable()) {
    vpaes_set_encrypt_key(key, key_len * 8, aes_key);
    CRYPTO_gcm128_init(gcm_ctx, aes_key, vpaes_encrypt);
    return NULL;
  }
#endif

  AES_set_encrypt_key(key, key_len * 8, aes_key);
  CRYPTO_gcm128_init(gcm_ctx, aes_key, AES_encrypt);
  return NULL;
}

#if defined(AESNI)
static char aesni_capable(void) {
  return (OPENSSL_ia32cap_P[1] & (1 << (57 - 32))) != 0;
}
#endif

struct aead_aes_gcm_ctx {
  union {
    double align;
    AES_KEY ks;
  } ks;
  GCM128_CONTEXT gcm;
  aes_ctr_f ctr;
};

int evp_aead_aes_gcm_init(void *ctx_buf, size_t ctx_buf_len, const uint8_t *key,
                          size_t key_len) {
  aead_assert_init_preconditions(alignof(struct aead_aes_gcm_ctx),
                                 sizeof(struct aead_aes_gcm_ctx), ctx_buf,
                                 ctx_buf_len, key);

  struct aead_aes_gcm_ctx *gcm_ctx = ctx_buf;
  gcm_ctx->ctr = aes_ctr_set_key(&gcm_ctx->ks.ks, &gcm_ctx->gcm, key, key_len);
  return 1;
}

int evp_aead_aes_gcm_seal(const void *ctx_buf, uint8_t *in_out,
                          size_t in_out_len,
                          uint8_t tag_out[EVP_AEAD_AES_GCM_TAG_LEN],
                          const uint8_t nonce[EVP_AEAD_AES_GCM_NONCE_LEN],
                          const uint8_t *ad, size_t ad_len) {
  assert(ctx_buf != NULL);
  assert(((uintptr_t)ctx_buf) % alignof(struct aead_aes_gcm_ctx) == 0);
  assert(in_out != NULL || in_out_len == 0);
  assert(aead_check_in_len(in_out_len));
  assert(tag_out != NULL);
  assert(nonce != NULL);
  assert(ad != NULL || ad_len == 0);

  const struct aead_aes_gcm_ctx *gcm_ctx = ctx_buf;

  GCM128_CONTEXT gcm;

  const AES_KEY *key = &gcm_ctx->ks.ks;

  memcpy(&gcm, &gcm_ctx->gcm, sizeof(gcm));
  CRYPTO_gcm128_set_96_bit_iv(&gcm, key, nonce);

  if (ad_len > 0 && !CRYPTO_gcm128_aad(&gcm, ad, ad_len)) {
    return 0;
  }
  if (in_out_len > 0) {
    if (gcm_ctx->ctr) {
      if (!CRYPTO_gcm128_encrypt_ctr32(&gcm, key, in_out, in_out, in_out_len,
                                       gcm_ctx->ctr)) {
        return 0;
      }
    } else {
      if (!CRYPTO_gcm128_encrypt(&gcm, key, in_out, in_out, in_out_len)) {
        return 0;
      }
    }
  }
  CRYPTO_gcm128_tag(&gcm, tag_out, EVP_AEAD_AES_GCM_TAG_LEN);
  return 1;
}

int evp_aead_aes_gcm_open(const void *ctx_buf, uint8_t *out,
                          size_t in_out_len,
                          uint8_t tag_out[EVP_AEAD_AES_GCM_TAG_LEN],
                          const uint8_t nonce[EVP_AEAD_AES_GCM_NONCE_LEN],
                          const uint8_t *in,  const uint8_t *ad, size_t ad_len) {
  assert(ctx_buf != NULL);
  assert(((uintptr_t)ctx_buf) % alignof(struct aead_aes_gcm_ctx) == 0);
  assert(out != NULL || in_out_len == 0);
  assert(aead_check_in_len(in_out_len));
  assert(aead_check_alias(in, in_out_len, out));
  assert(tag_out != NULL);
  assert(nonce != NULL);
  assert(in != NULL || in_out_len == 0);
  assert(ad != NULL || ad_len == 0);

  const struct aead_aes_gcm_ctx *gcm_ctx = ctx_buf;

  GCM128_CONTEXT gcm;

  const AES_KEY *key = &gcm_ctx->ks.ks;

  memcpy(&gcm, &gcm_ctx->gcm, sizeof(gcm));
  CRYPTO_gcm128_set_96_bit_iv(&gcm, key, nonce);

  if (!CRYPTO_gcm128_aad(&gcm, ad, ad_len)) {
    return 0;
  }
  if (in_out_len > 0) {
    if (gcm_ctx->ctr) {
      if (!CRYPTO_gcm128_decrypt_ctr32(&gcm, key, in, out, in_out_len,
                                       gcm_ctx->ctr)) {
        return 0;
      }
    } else {
      if (!CRYPTO_gcm128_decrypt(&gcm, key, in, out, in_out_len)) {
        return 0;
      }
    }
  }
  CRYPTO_gcm128_tag(&gcm, tag_out, EVP_AEAD_AES_GCM_TAG_LEN);
  return 1;
}


int EVP_has_aes_hardware(void) {
#if defined(AESNI)
  return aesni_capable() && crypto_gcm_clmul_enabled();
#elif defined(HWAES)
  return hwaes_capable() && CRYPTO_is_ARMv8_PMULL_capable();
#else
  return 0;
#endif
}
