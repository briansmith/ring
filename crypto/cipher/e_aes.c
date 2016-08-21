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

#include "internal.h"
#include "../internal.h"
#include "../modes/internal.h"

#if defined(OPENSSL_ARM) || defined(OPENSSL_AARCH64)
#include <openssl/arm_arch.h>
#endif


#define EVP_AEAD_AES_GCM_NONCE_LEN 12
#define EVP_AEAD_AES_GCM_TAG_LEN 16

 /* Declarations for extern functions only called by Rust code, to avoid
 * -Wmissing-prototypes warnings. */
int evp_aead_aes_gcm_init(void *ctx_buf, size_t ctx_buf_len, const uint8_t *key,
                          size_t key_len);
int evp_aead_aes_gcm_open(const void *ctx_buf, uint8_t *out,
                          size_t in_out_len,
                          uint8_t tag_out[EVP_AEAD_AES_GCM_TAG_LEN],
                          const uint8_t nonce[EVP_AEAD_AES_GCM_NONCE_LEN],
                          const uint8_t *in, const uint8_t *ad, size_t ad_len);
int evp_aead_aes_gcm_seal(const void *ctx_buf, uint8_t *in_out,
                          size_t in_out_len,
                          uint8_t tag_out[EVP_AEAD_AES_GCM_TAG_LEN],
                          const uint8_t nonce[EVP_AEAD_AES_GCM_NONCE_LEN],
                          const uint8_t *ad, size_t ad_len);
int EVP_has_aes_hardware(void);


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

int aes_v8_set_encrypt_key(const uint8_t *user_key, const unsigned bits,
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
int vpaes_set_encrypt_key(const uint8_t *userKey, unsigned bits, AES_KEY *key);
void vpaes_encrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key);
#endif

#if !defined(OPENSSL_NO_ASM) && \
    (defined(OPENSSL_X86_64) || defined(OPENSSL_X86))
#define AESNI
int aesni_set_encrypt_key(const uint8_t *userKey, unsigned bits, AES_KEY *key);
void aesni_encrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key);
static char aesni_capable(void);
#endif

typedef int (*aes_set_key_f)(const uint8_t *userKey, unsigned bits,
                             AES_KEY *key);

static aes_set_key_f aes_set_key(void) {
#if defined(AESNI)
  if (aesni_capable()) {
    return aesni_set_encrypt_key;
  }
#endif

#if defined(HWAES)
  if (hwaes_capable()) {
    return aes_v8_set_encrypt_key;
  }
#endif

#if defined(BSAES)
  if (bsaes_capable()) {
    return AES_set_encrypt_key;
  }
#endif

#if defined(VPAES)
  if (vpaes_capable()) {
    return vpaes_set_encrypt_key;
  }
#endif

  return AES_set_encrypt_key;
}

static aes_block_f aes_block(void) {
  /* Keep this in sync with |set_set_key| and |aes_ctr|. */

#if defined(AESNI)
  if (aesni_capable()) {
    return aesni_encrypt;
  }
#endif

#if defined(HWAES)
  if (hwaes_capable()) {
    return aes_v8_encrypt;
  }
#endif

#if defined(VPAES)
#if defined(BSAES)
  if (bsaes_capable()) {
    return AES_encrypt;
  }
#endif

  if (vpaes_capable()) {
    return vpaes_encrypt;
  }
#endif

  return AES_encrypt;
}

static aes_ctr_f aes_ctr(void) {
  /* Keep this in sync with |set_set_key| and |aes_block|. */

#if defined(AESNI)
  if (aesni_capable()) {
    return aesni_ctr32_encrypt_blocks;
  }
#endif

#if defined(HWAES)
  if (hwaes_capable()) {
    return aes_v8_ctr32_encrypt_blocks;
  }
#endif

#if defined(BSAES)
  if (bsaes_capable()) {
    return bsaes_ctr32_encrypt_blocks;
  }
#endif

  return NULL;
}

#if defined(AESNI)
static char aesni_capable(void) {
  return (OPENSSL_ia32cap_P[1] & (1 << (57 - 32))) != 0;
}
#endif

int evp_aead_aes_gcm_init(void *ctx_buf, size_t ctx_buf_len, const uint8_t *key,
                          size_t key_len) {
  alignas(16) AES_KEY ks;
  assert(ctx_buf_len >= sizeof(ks) + GCM128_SERIALIZED_LEN);
  if (ctx_buf_len < sizeof(ks) + GCM128_SERIALIZED_LEN) {
    return 0;
  }

  /* XXX: Ignores return value. TODO: These functions should return |void|
   * anyway. */
  (void)(aes_set_key())(key, key_len * 8, &ks);

  CRYPTO_gcm128_init_serialized((uint8_t *)ctx_buf + sizeof(ks), &ks,
                                aes_block());
  memcpy(ctx_buf, &ks, sizeof(ks));
  return 1;
}

static int evp_aead_aes_gcm_init_and_aad(GCM128_CONTEXT *gcm, AES_KEY *ks,
                                         const void *ctx_buf,
                                         const uint8_t nonce[],
                                         const uint8_t ad[], size_t ad_len) {
  assert(ad != NULL || ad_len == 0);
  memcpy(ks, ctx_buf, sizeof(*ks));
  CRYPTO_gcm128_init(gcm, ks, aes_block(),
                     (const uint8_t *)ctx_buf + sizeof(*ks), nonce);
  if (ad_len > 0) {
    if (!CRYPTO_gcm128_aad(gcm, ad, ad_len)) {
      return 0;
    }
  }
  return 1;
}

int evp_aead_aes_gcm_seal(const void *ctx_buf, uint8_t *in_out,
                          size_t in_out_len,
                          uint8_t tag_out[EVP_AEAD_AES_GCM_TAG_LEN],
                          const uint8_t nonce[EVP_AEAD_AES_GCM_NONCE_LEN],
                          const uint8_t *ad, size_t ad_len) {
  assert(in_out != NULL || in_out_len == 0);
  assert(aead_check_in_len(in_out_len));
  assert(ad != NULL || ad_len == 0);

  GCM128_CONTEXT gcm;
  alignas(16) AES_KEY ks;
  if (!evp_aead_aes_gcm_init_and_aad(&gcm, &ks, ctx_buf, nonce, ad, ad_len)) {
    return 0;
  }
  if (in_out_len > 0) {
    aes_ctr_f ctr = aes_ctr();
    if (ctr != NULL) {
      if (!CRYPTO_gcm128_encrypt_ctr32(&gcm, &ks, in_out, in_out, in_out_len,
                                       ctr)) {
        return 0;
      }
    } else {
      if (!CRYPTO_gcm128_encrypt(&gcm, &ks, in_out, in_out, in_out_len)) {
        return 0;
      }
    }
  }
  CRYPTO_gcm128_tag(&gcm, tag_out);
  return 1;
}

int evp_aead_aes_gcm_open(const void *ctx_buf, uint8_t *out,
                          size_t in_out_len,
                          uint8_t tag_out[EVP_AEAD_AES_GCM_TAG_LEN],
                          const uint8_t nonce[EVP_AEAD_AES_GCM_NONCE_LEN],
                          const uint8_t *in,  const uint8_t *ad, size_t ad_len) {
  assert(out != NULL || in_out_len == 0);
  assert(aead_check_in_len(in_out_len));
  assert(aead_check_alias(in, in_out_len, out));
  assert(in != NULL || in_out_len == 0);
  assert(ad != NULL || ad_len == 0);

  GCM128_CONTEXT gcm;
  alignas(16) AES_KEY ks;
  if (!evp_aead_aes_gcm_init_and_aad(&gcm, &ks, ctx_buf, nonce, ad, ad_len)) {
    return 0;
  }
  if (in_out_len > 0) {
    aes_ctr_f ctr = aes_ctr();
    if (ctr != NULL) {
      if (!CRYPTO_gcm128_decrypt_ctr32(&gcm, &ks, in, out, in_out_len, ctr)) {
        return 0;
      }
    } else {
      if (!CRYPTO_gcm128_decrypt(&gcm, &ks, in, out, in_out_len)) {
        return 0;
      }
    }
  }
  CRYPTO_gcm128_tag(&gcm, tag_out);
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
