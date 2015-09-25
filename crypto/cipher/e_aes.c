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

#include <openssl/aead.h>
#include <openssl/aes.h>
#include <openssl/cpu.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/modes.h>
#include <openssl/obj.h>
#include <openssl/rand.h>

#include "cipher.h"
#include "internal.h"
#include "../internal.h"
#include "../modes/internal.h"

#if defined(OPENSSL_ARM) || defined(OPENSSL_AARCH64)
#include <openssl/arm_arch.h>
#endif


#define EVP_AEAD_AES_GCM_NONCE_LEN 12
#define EVP_AEAD_AES_GCM_TAG_LEN 16

typedef struct {
  union {
    double align;
    AES_KEY ks;
  } ks;
  block128_f block;
  union {
    cbc128_f cbc;
    ctr128_f ctr;
  } stream;
} EVP_AES_KEY;

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
  return (OPENSSL_armcap_P & ARMV8_AES) != 0;
}

int aes_v8_set_encrypt_key(const uint8_t *user_key, const int bits,
                           AES_KEY *key);
int aes_v8_set_decrypt_key(const uint8_t *user_key, const int bits,
                           AES_KEY *key);
void aes_v8_encrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key);
void aes_v8_decrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key);
void aes_v8_cbc_encrypt(const uint8_t *in, uint8_t *out, size_t length,
                        const AES_KEY *key, uint8_t *ivec, const int enc);
void aes_v8_ctr32_encrypt_blocks(const uint8_t *in, uint8_t *out, size_t len,
                                 const AES_KEY *key, const uint8_t ivec[16]);

#endif  /* OPENSSL_ARM */

#if defined(BSAES)
/* On platforms where BSAES gets defined (just above), then these functions are
 * provided by asm. */
void bsaes_cbc_encrypt(const uint8_t *in, uint8_t *out, size_t length,
                       const AES_KEY *key, uint8_t ivec[16], int enc);
void bsaes_ctr32_encrypt_blocks(const uint8_t *in, uint8_t *out, size_t len,
                                const AES_KEY *key, const uint8_t ivec[16]);
#else
static char bsaes_capable(void) {
  return 0;
}

/* On other platforms, bsaes_capable() will always return false and so the
 * following will never be called. */
static void bsaes_cbc_encrypt(const uint8_t *in, uint8_t *out, size_t length,
                              const AES_KEY *key, uint8_t ivec[16], int enc) {
  abort();
}

static void bsaes_ctr32_encrypt_blocks(const uint8_t *in, uint8_t *out,
                                       size_t len, const AES_KEY *key,
                                       const uint8_t ivec[16]) {
  abort();
}
#endif

#if defined(VPAES)
/* On platforms where VPAES gets defined (just above), then these functions are
 * provided by asm. */
int vpaes_set_encrypt_key(const uint8_t *userKey, int bits, AES_KEY *key);
int vpaes_set_decrypt_key(const uint8_t *userKey, int bits, AES_KEY *key);

void vpaes_encrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key);
void vpaes_decrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key);

void vpaes_cbc_encrypt(const uint8_t *in, uint8_t *out, size_t length,
                       const AES_KEY *key, uint8_t *ivec, int enc);
#else
static char vpaes_capable(void) {
  return 0;
}

/* On other platforms, vpaes_capable() will always return false and so the
 * following will never be called. */
static int vpaes_set_encrypt_key(const uint8_t *userKey, int bits,
                                 AES_KEY *key) {
  abort();
}
static int vpaes_set_decrypt_key(const uint8_t *userKey, int bits,
                                 AES_KEY *key) {
  abort();
}
static void vpaes_encrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key) {
  abort();
}
static void vpaes_decrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key) {
  abort();
}
static void vpaes_cbc_encrypt(const uint8_t *in, uint8_t *out, size_t length,
                              const AES_KEY *key, uint8_t *ivec, int enc) {
  abort();
}
#endif

#if !defined(HWAES)
/* If HWAES isn't defined then we provide dummy functions for each of the hwaes
 * functions. */
static int hwaes_capable(void) {
  return 0;
}

static int aes_v8_set_encrypt_key(const uint8_t *user_key, int bits,
                                  AES_KEY *key) {
  abort();
}

static int aes_v8_set_decrypt_key(const uint8_t *user_key, int bits,
                                  AES_KEY *key) {
  abort();
}

static void aes_v8_encrypt(const uint8_t *in, uint8_t *out,
                           const AES_KEY *key) {
  abort();
}

static void aes_v8_decrypt(const uint8_t *in, uint8_t *out,
                           const AES_KEY *key) {
  abort();
}

static void aes_v8_cbc_encrypt(const uint8_t *in, uint8_t *out, size_t length,
                               const AES_KEY *key, uint8_t *ivec, int enc) {
  abort();
}

static void aes_v8_ctr32_encrypt_blocks(const uint8_t *in, uint8_t *out,
                                        size_t len, const AES_KEY *key,
                                        const uint8_t ivec[16]) {
  abort();
}
#endif

#if !defined(OPENSSL_NO_ASM) && \
    (defined(OPENSSL_X86_64) || defined(OPENSSL_X86))
int aesni_set_encrypt_key(const uint8_t *userKey, int bits, AES_KEY *key);
int aesni_set_decrypt_key(const uint8_t *userKey, int bits, AES_KEY *key);

void aesni_encrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key);
void aesni_decrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key);

void aesni_cbc_encrypt(const uint8_t *in, uint8_t *out, size_t length,
                       const AES_KEY *key, uint8_t *ivec, int enc);

void aesni_ctr32_encrypt_blocks(const uint8_t *in, uint8_t *out, size_t blocks,
                                const void *key, const uint8_t *ivec);

#else

/* On other platforms, aesni_capable() will always return false and so the
 * following will never be called. */
static void aesni_encrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key) {
  abort();
}
static int aesni_set_encrypt_key(const uint8_t *userKey, int bits,
                                 AES_KEY *key) {
  abort();
}
static void aesni_ctr32_encrypt_blocks(const uint8_t *in, uint8_t *out,
                                       size_t blocks, const void *key,
                                       const uint8_t *ivec) {
  abort();
}

#endif

static int aes_init_key(EVP_CIPHER_CTX *ctx, const uint8_t *key,
                        const uint8_t *iv, int enc)
                        OPENSSL_SUPPRESS_UNREACHABLE_CODE_WARNINGS {
  int ret, mode;
  EVP_AES_KEY *dat = (EVP_AES_KEY *)ctx->cipher_data;

  mode = ctx->cipher->flags & EVP_CIPH_MODE_MASK;
  if (mode == EVP_CIPH_CBC_MODE && !enc) {
    if (hwaes_capable()) {
      ret = aes_v8_set_decrypt_key(key, ctx->key_len * 8, &dat->ks.ks);
      dat->block = (block128_f)aes_v8_decrypt;
      dat->stream.cbc = NULL;
      dat->stream.cbc = (cbc128_f)aes_v8_cbc_encrypt;
    } else if (bsaes_capable()) {
      ret = AES_set_decrypt_key(key, ctx->key_len * 8, &dat->ks.ks);
      dat->block = (block128_f)AES_decrypt;
      dat->stream.cbc = (cbc128_f)bsaes_cbc_encrypt;
    } else if (vpaes_capable()) {
      ret = vpaes_set_decrypt_key(key, ctx->key_len * 8, &dat->ks.ks);
      dat->block = (block128_f)vpaes_decrypt;
      dat->stream.cbc = (cbc128_f)vpaes_cbc_encrypt;
    } else {
      ret = AES_set_decrypt_key(key, ctx->key_len * 8, &dat->ks.ks);
      dat->block = (block128_f)AES_decrypt;
      dat->stream.cbc = (cbc128_f)AES_cbc_encrypt;
    }
  } else if (hwaes_capable()) {
    ret = aes_v8_set_encrypt_key(key, ctx->key_len * 8, &dat->ks.ks);
    dat->block = (block128_f)aes_v8_encrypt;
    dat->stream.cbc = NULL;
    if (mode == EVP_CIPH_CBC_MODE) {
      dat->stream.cbc = (cbc128_f)aes_v8_cbc_encrypt;
    } else if (mode == EVP_CIPH_CTR_MODE) {
      dat->stream.ctr = (ctr128_f)aes_v8_ctr32_encrypt_blocks;
    }
  } else if (bsaes_capable() && mode == EVP_CIPH_CTR_MODE) {
    ret = AES_set_encrypt_key(key, ctx->key_len * 8, &dat->ks.ks);
    dat->block = (block128_f)AES_encrypt;
    dat->stream.ctr = (ctr128_f)bsaes_ctr32_encrypt_blocks;
  } else if (vpaes_capable()) {
    ret = vpaes_set_encrypt_key(key, ctx->key_len * 8, &dat->ks.ks);
    dat->block = (block128_f)vpaes_encrypt;
    dat->stream.cbc =
        mode == EVP_CIPH_CBC_MODE ? (cbc128_f)vpaes_cbc_encrypt : NULL;
  } else {
    ret = AES_set_encrypt_key(key, ctx->key_len * 8, &dat->ks.ks);
    dat->block = (block128_f)AES_encrypt;
    dat->stream.cbc =
        mode == EVP_CIPH_CBC_MODE ? (cbc128_f)AES_cbc_encrypt : NULL;
  }

  if (ret < 0) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_AES_KEY_SETUP_FAILED);
    return 0;
  }

  return 1;
}

static int aes_cbc_cipher(EVP_CIPHER_CTX *ctx, uint8_t *out, const uint8_t *in,
                          size_t len) {
  EVP_AES_KEY *dat = (EVP_AES_KEY *)ctx->cipher_data;

  if (dat->stream.cbc) {
    (*dat->stream.cbc)(in, out, len, &dat->ks, ctx->iv, ctx->encrypt);
  } else if (ctx->encrypt) {
    CRYPTO_cbc128_encrypt(in, out, len, &dat->ks, ctx->iv, dat->block);
  } else {
    CRYPTO_cbc128_decrypt(in, out, len, &dat->ks, ctx->iv, dat->block);
  }

  return 1;
}

static int aes_ctr_cipher(EVP_CIPHER_CTX *ctx, uint8_t *out, const uint8_t *in,
                          size_t len) {
  unsigned int num = ctx->num;
  EVP_AES_KEY *dat = (EVP_AES_KEY *)ctx->cipher_data;

  if (dat->stream.ctr) {
    CRYPTO_ctr128_encrypt_ctr32(in, out, len, &dat->ks, ctx->iv, ctx->buf, &num,
                                dat->stream.ctr);
  } else {
    CRYPTO_ctr128_encrypt(in, out, len, &dat->ks, ctx->iv, ctx->buf, &num,
                          dat->block);
  }
  ctx->num = (size_t)num;
  return 1;
}

static char aesni_capable(void);

static ctr128_f aes_ctr_set_key(AES_KEY *aes_key, GCM128_CONTEXT *gcm_ctx,
                                block128_f *out_block, const uint8_t *key,
                                size_t key_len)
                                OPENSSL_SUPPRESS_UNREACHABLE_CODE_WARNINGS {
  if (aesni_capable()) {
    aesni_set_encrypt_key(key, key_len * 8, aes_key);
    if (gcm_ctx != NULL) {
      CRYPTO_gcm128_init(gcm_ctx, aes_key, (block128_f)aesni_encrypt);
    }
    if (out_block) {
      *out_block = (block128_f) aesni_encrypt;
    }
    return (ctr128_f)aesni_ctr32_encrypt_blocks;
  }

  if (hwaes_capable()) {
    aes_v8_set_encrypt_key(key, key_len * 8, aes_key);
    if (gcm_ctx != NULL) {
      CRYPTO_gcm128_init(gcm_ctx, aes_key, (block128_f)aes_v8_encrypt);
    }
    if (out_block) {
      *out_block = (block128_f) aes_v8_encrypt;
    }
    return (ctr128_f)aes_v8_ctr32_encrypt_blocks;
  }

  if (bsaes_capable()) {
    AES_set_encrypt_key(key, key_len * 8, aes_key);
    if (gcm_ctx != NULL) {
      CRYPTO_gcm128_init(gcm_ctx, aes_key, (block128_f)AES_encrypt);
    }
    if (out_block) {
      *out_block = (block128_f) AES_encrypt;
    }
    return (ctr128_f)bsaes_ctr32_encrypt_blocks;
  }

  if (vpaes_capable()) {
    vpaes_set_encrypt_key(key, key_len * 8, aes_key);
    if (out_block) {
      *out_block = (block128_f) vpaes_encrypt;
    }
    if (gcm_ctx != NULL) {
      CRYPTO_gcm128_init(gcm_ctx, aes_key, (block128_f)vpaes_encrypt);
    }
    return NULL;
  }

  AES_set_encrypt_key(key, key_len * 8, aes_key);
  if (gcm_ctx != NULL) {
    CRYPTO_gcm128_init(gcm_ctx, aes_key, (block128_f)AES_encrypt);
  }
  if (out_block) {
    *out_block = (block128_f) AES_encrypt;
  }
  return NULL;
}

/* increment counter (64-bit int) by 1 */
static void ctr64_inc(uint8_t *counter) {
  int n = 8;
  uint8_t c;

  do {
    --n;
    c = counter[n];
    ++c;
    counter[n] = c;
    if (c) {
      return;
    }
  } while (n);
}

static const EVP_CIPHER aes_128_cbc = {
    16 /* block_size */, 16 /* key_size */,
    16 /* iv_len */,     sizeof(EVP_AES_KEY), EVP_CIPH_CBC_MODE,
    NULL /* app_data */, aes_init_key,        aes_cbc_cipher,
    NULL /* cleanup */,  NULL /* ctrl */};

static const EVP_CIPHER aes_128_ctr = {
    1 /* block_size */,  16 /* key_size */,
    16 /* iv_len */,     sizeof(EVP_AES_KEY), EVP_CIPH_CTR_MODE,
    NULL /* app_data */, aes_init_key,        aes_ctr_cipher,
    NULL /* cleanup */,  NULL /* ctrl */};


static const EVP_CIPHER aes_256_cbc = {
    16 /* block_size */, 32 /* key_size */,
    16 /* iv_len */,     sizeof(EVP_AES_KEY), EVP_CIPH_CBC_MODE,
    NULL /* app_data */, aes_init_key,        aes_cbc_cipher,
    NULL /* cleanup */,  NULL /* ctrl */};

static const EVP_CIPHER aes_256_ctr = {
    1 /* block_size */,  32 /* key_size */,
    16 /* iv_len */,     sizeof(EVP_AES_KEY), EVP_CIPH_CTR_MODE,
    NULL /* app_data */, aes_init_key,        aes_ctr_cipher,
    NULL /* cleanup */,  NULL /* ctrl */};

#if !defined(OPENSSL_NO_ASM) && \
    (defined(OPENSSL_X86_64) || defined(OPENSSL_X86))

/* AES-NI section. */

static char aesni_capable(void) {
  return (OPENSSL_ia32cap_P[1] & (1 << (57 - 32))) != 0;
}

static int aesni_init_key(EVP_CIPHER_CTX *ctx, const uint8_t *key,
                          const uint8_t *iv, int enc) {
  int ret, mode;
  EVP_AES_KEY *dat = (EVP_AES_KEY *)ctx->cipher_data;

  mode = ctx->cipher->flags & EVP_CIPH_MODE_MASK;
  if (mode == EVP_CIPH_CBC_MODE && !enc) {
    ret = aesni_set_decrypt_key(key, ctx->key_len * 8, ctx->cipher_data);
    dat->block = (block128_f)aesni_decrypt;
    dat->stream.cbc =
        mode == EVP_CIPH_CBC_MODE ? (cbc128_f)aesni_cbc_encrypt : NULL;
  } else {
    ret = aesni_set_encrypt_key(key, ctx->key_len * 8, ctx->cipher_data);
    dat->block = (block128_f)aesni_encrypt;
    if (mode == EVP_CIPH_CBC_MODE) {
      dat->stream.cbc = (cbc128_f)aesni_cbc_encrypt;
    } else if (mode == EVP_CIPH_CTR_MODE) {
      dat->stream.ctr = (ctr128_f)aesni_ctr32_encrypt_blocks;
    } else {
      dat->stream.cbc = NULL;
    }
  }

  if (ret < 0) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_AES_KEY_SETUP_FAILED);
    return 0;
  }

  return 1;
}

static int aesni_cbc_cipher(EVP_CIPHER_CTX *ctx, uint8_t *out,
                            const uint8_t *in, size_t len) {
  aesni_cbc_encrypt(in, out, len, ctx->cipher_data, ctx->iv, ctx->encrypt);

  return 1;
}

static const EVP_CIPHER aesni_128_cbc = {
    16 /* block_size */, 16 /* key_size */,
    16 /* iv_len */,     sizeof(EVP_AES_KEY), EVP_CIPH_CBC_MODE,
    NULL /* app_data */, aesni_init_key,      aesni_cbc_cipher,
    NULL /* cleanup */,  NULL /* ctrl */};

static const EVP_CIPHER aesni_128_ctr = {
    1 /* block_size */,  16 /* key_size */,
    16 /* iv_len */,     sizeof(EVP_AES_KEY), EVP_CIPH_CTR_MODE,
    NULL /* app_data */, aesni_init_key,      aes_ctr_cipher,
    NULL /* cleanup */,  NULL /* ctrl */};


static const EVP_CIPHER aesni_256_cbc = {
    16 /* block_size */, 32 /* key_size */,
    16 /* iv_len */,     sizeof(EVP_AES_KEY), EVP_CIPH_CBC_MODE,
    NULL /* app_data */, aesni_init_key,      aesni_cbc_cipher,
    NULL /* cleanup */,  NULL /* ctrl */};

static const EVP_CIPHER aesni_256_ctr = {
    1 /* block_size */,  32 /* key_size */,
    16 /* iv_len */,     sizeof(EVP_AES_KEY), EVP_CIPH_CTR_MODE,
    NULL /* app_data */, aesni_init_key,      aes_ctr_cipher,
    NULL /* cleanup */,  NULL /* ctrl */};

#define EVP_CIPHER_FUNCTION(keybits, mode)             \
  const EVP_CIPHER *EVP_aes_##keybits##_##mode(void) { \
    if (aesni_capable()) {                             \
      return &aesni_##keybits##_##mode;                \
    } else {                                           \
      return &aes_##keybits##_##mode;                  \
    }                                                  \
  }

#else  /* ^^^  OPENSSL_X86_64 || OPENSSL_X86 */

static char aesni_capable(void) {
  return 0;
}

#define EVP_CIPHER_FUNCTION(keybits, mode)             \
  const EVP_CIPHER *EVP_aes_##keybits##_##mode(void) { \
    return &aes_##keybits##_##mode;                    \
  }

#endif

EVP_CIPHER_FUNCTION(128, cbc)
EVP_CIPHER_FUNCTION(128, ctr)

EVP_CIPHER_FUNCTION(256, cbc)
EVP_CIPHER_FUNCTION(256, ctr)


struct aead_aes_gcm_ctx {
  union {
    double align;
    AES_KEY ks;
  } ks;
  GCM128_CONTEXT gcm;
  ctr128_f ctr;
  uint8_t tag_len;
};

int evp_aead_aes_gcm_init(EVP_AEAD_CTX *ctx, const uint8_t *key,
                          size_t key_len, size_t tag_len) {
  struct aead_aes_gcm_ctx *gcm_ctx;
  const size_t key_bits = key_len * 8;

  if (key_bits != 128 && key_bits != 256) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BAD_KEY_LENGTH);
    return 0; /* EVP_AEAD_CTX_init should catch this. */
  }

  if (tag_len == EVP_AEAD_DEFAULT_TAG_LENGTH) {
    tag_len = EVP_AEAD_AES_GCM_TAG_LEN;
  }

  if (tag_len > EVP_AEAD_AES_GCM_TAG_LEN) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_TAG_TOO_LARGE);
    return 0;
  }

  gcm_ctx = OPENSSL_malloc(sizeof(struct aead_aes_gcm_ctx));
  if (gcm_ctx == NULL) {
    return 0;
  }

  gcm_ctx->ctr =
      aes_ctr_set_key(&gcm_ctx->ks.ks, &gcm_ctx->gcm, NULL, key, key_len);
  gcm_ctx->tag_len = tag_len;
  ctx->aead_state = gcm_ctx;

  return 1;
}

void evp_aead_aes_gcm_cleanup(EVP_AEAD_CTX *ctx) {
  struct aead_aes_gcm_ctx *gcm_ctx = ctx->aead_state;
  OPENSSL_cleanse(gcm_ctx, sizeof(struct aead_aes_gcm_ctx));
  OPENSSL_free(gcm_ctx);
}

int evp_aead_aes_gcm_seal(const EVP_AEAD_CTX *ctx, uint8_t *out,
                          size_t *out_len, size_t max_out_len,
                          const uint8_t *nonce, const uint8_t *in,
                          size_t in_len, const uint8_t *ad, size_t ad_len) {
  size_t bulk = 0;
  const struct aead_aes_gcm_ctx *gcm_ctx = ctx->aead_state;
  GCM128_CONTEXT gcm;

  if (in_len + gcm_ctx->tag_len < in_len) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_TOO_LARGE);
    return 0;
  }

  if (max_out_len < in_len + gcm_ctx->tag_len) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BUFFER_TOO_SMALL);
    return 0;
  }

  memcpy(&gcm, &gcm_ctx->gcm, sizeof(gcm));
  CRYPTO_gcm128_setiv(&gcm, nonce, EVP_AEAD_AES_GCM_NONCE_LEN);

  if (ad_len > 0 && !CRYPTO_gcm128_aad(&gcm, ad, ad_len)) {
    return 0;
  }

  if (gcm_ctx->ctr) {
    if (!CRYPTO_gcm128_encrypt_ctr32(&gcm, in + bulk, out + bulk, in_len - bulk,
                                     gcm_ctx->ctr)) {
      return 0;
    }
  } else {
    if (!CRYPTO_gcm128_encrypt(&gcm, in + bulk, out + bulk, in_len - bulk)) {
      return 0;
    }
  }

  CRYPTO_gcm128_tag(&gcm, out + in_len, gcm_ctx->tag_len);
  *out_len = in_len + gcm_ctx->tag_len;
  return 1;
}

int evp_aead_aes_gcm_open(const EVP_AEAD_CTX *ctx, uint8_t *out,
                          size_t *out_len, size_t max_out_len,
                          const uint8_t *nonce, const uint8_t *in,
                          size_t in_len, const uint8_t *ad, size_t ad_len) {
  size_t bulk = 0;
  const struct aead_aes_gcm_ctx *gcm_ctx = ctx->aead_state;
  uint8_t tag[EVP_AEAD_AES_GCM_TAG_LEN];
  size_t plaintext_len;
  GCM128_CONTEXT gcm;

  if (in_len < gcm_ctx->tag_len) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BAD_DECRYPT);
    return 0;
  }

  plaintext_len = in_len - gcm_ctx->tag_len;

  if (max_out_len < plaintext_len) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BUFFER_TOO_SMALL);
    return 0;
  }

  memcpy(&gcm, &gcm_ctx->gcm, sizeof(gcm));
  CRYPTO_gcm128_setiv(&gcm, nonce, EVP_AEAD_AES_GCM_NONCE_LEN);

  if (!CRYPTO_gcm128_aad(&gcm, ad, ad_len)) {
    return 0;
  }

  if (gcm_ctx->ctr) {
    if (!CRYPTO_gcm128_decrypt_ctr32(&gcm, in + bulk, out + bulk,
                                     in_len - bulk - gcm_ctx->tag_len,
                                     gcm_ctx->ctr)) {
      return 0;
    }
  } else {
    if (!CRYPTO_gcm128_decrypt(&gcm, in + bulk, out + bulk,
                               in_len - bulk - gcm_ctx->tag_len)) {
      return 0;
    }
  }

  CRYPTO_gcm128_tag(&gcm, tag, gcm_ctx->tag_len);
  if (CRYPTO_memcmp(tag, in + plaintext_len, gcm_ctx->tag_len) != 0) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BAD_DECRYPT);
    return 0;
  }

  *out_len = plaintext_len;
  return 1;
}

/* TODO(ring): We currently duplicate these between Rust and C. Avoid doing that. */
static const EVP_AEAD aead_aes_128_gcm = {
    16,                       /* key len */
    EVP_AEAD_AES_GCM_NONCE_LEN, /* nonce len */
    EVP_AEAD_AES_GCM_TAG_LEN, /* overhead */
    EVP_AEAD_AES_GCM_TAG_LEN, /* max tag length */
    evp_aead_aes_gcm_init,
    NULL, /* init_with_direction */
    evp_aead_aes_gcm_cleanup,
    evp_aead_aes_gcm_seal,
    evp_aead_aes_gcm_open,
};

/* TODO(ring): We currently duplicate these between Rust and C. Avoid doing that. */
static const EVP_AEAD aead_aes_256_gcm = {
    32,                       /* key len */
    EVP_AEAD_AES_GCM_NONCE_LEN, /* nonce len */
    EVP_AEAD_AES_GCM_TAG_LEN, /* overhead */
    EVP_AEAD_AES_GCM_TAG_LEN, /* max tag length */
    evp_aead_aes_gcm_init,
    NULL, /* init_with_direction */
    evp_aead_aes_gcm_cleanup,
    evp_aead_aes_gcm_seal,
    evp_aead_aes_gcm_open,
};

const EVP_AEAD *EVP_aead_aes_128_gcm(void) { return &aead_aes_128_gcm; }

const EVP_AEAD *EVP_aead_aes_256_gcm(void) { return &aead_aes_256_gcm; }


/* AES Key Wrap is specified in
 * http://csrc.nist.gov/groups/ST/toolkit/documents/kms/key-wrap.pdf
 * or https://tools.ietf.org/html/rfc3394 */

struct aead_aes_key_wrap_ctx {
  uint8_t key[32];
  unsigned key_bits;
};

static int aead_aes_key_wrap_init(EVP_AEAD_CTX *ctx, const uint8_t *key,
                                  size_t key_len, size_t tag_len) {
  struct aead_aes_key_wrap_ctx *kw_ctx;
  const size_t key_bits = key_len * 8;

  if (key_bits != 128 && key_bits != 256) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BAD_KEY_LENGTH);
    return 0; /* EVP_AEAD_CTX_init should catch this. */
  }

  if (tag_len == EVP_AEAD_DEFAULT_TAG_LENGTH) {
    tag_len = 8;
  }

  if (tag_len != 8) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_UNSUPPORTED_TAG_SIZE);
    return 0;
  }

  kw_ctx = OPENSSL_malloc(sizeof(struct aead_aes_key_wrap_ctx));
  if (kw_ctx == NULL) {
    OPENSSL_PUT_ERROR(CIPHER, ERR_R_MALLOC_FAILURE);
    return 0;
  }

  memcpy(kw_ctx->key, key, key_len);
  kw_ctx->key_bits = key_bits;

  ctx->aead_state = kw_ctx;
  return 1;
}

static void aead_aes_key_wrap_cleanup(EVP_AEAD_CTX *ctx) {
  struct aead_aes_key_wrap_ctx *kw_ctx = ctx->aead_state;
  OPENSSL_cleanse(kw_ctx, sizeof(struct aead_aes_key_wrap_ctx));
  OPENSSL_free(kw_ctx);
}

static int aead_aes_key_wrap_seal(const EVP_AEAD_CTX *ctx, uint8_t *out,
                                  size_t *out_len, size_t max_out_len,
                                  const uint8_t *nonce, const uint8_t *in,
                                  size_t in_len, const uint8_t *ad,
                                  size_t ad_len) {
  const struct aead_aes_key_wrap_ctx *kw_ctx = ctx->aead_state;
  union {
    double align;
    AES_KEY ks;
  } ks;
  /* Variables in this function match up with the variables in the second half
   * of section 2.2.1. */
  unsigned i, j, n;
  uint8_t A[AES_BLOCK_SIZE];

  if (ad_len != 0) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_UNSUPPORTED_AD_SIZE);
    return 0;
  }

  if (in_len % 8 != 0) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_UNSUPPORTED_INPUT_SIZE);
    return 0;
  }

  /* The code below only handles a 32-bit |t| thus 6*|n| must be less than
   * 2^32, where |n| is |in_len| / 8. So in_len < 4/3 * 2^32 and we
   * conservatively cap it to 2^32-16 to stop 32-bit platforms complaining that
   * a comparison is always true. */
  if (in_len > 0xfffffff0) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_TOO_LARGE);
    return 0;
  }

  n = in_len / 8;

  if (n < 2) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_UNSUPPORTED_INPUT_SIZE);
    return 0;
  }

  if (in_len + 8 < in_len) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_TOO_LARGE);
    return 0;
  }

  if (max_out_len < in_len + 8) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BUFFER_TOO_SMALL);
    return 0;
  }

  if (AES_set_encrypt_key(kw_ctx->key, kw_ctx->key_bits, &ks.ks) < 0) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_AES_KEY_SETUP_FAILED);
    return 0;
  }

  memmove(out + 8, in, in_len);
  memcpy(A, nonce, 8);

  for (j = 0; j < 6; j++) {
    for (i = 1; i <= n; i++) {
      uint32_t t;

      memcpy(A + 8, out + 8 * i, 8);
      AES_encrypt(A, A, &ks.ks);
      t = n * j + i;
      A[7] ^= t & 0xff;
      A[6] ^= (t >> 8) & 0xff;
      A[5] ^= (t >> 16) & 0xff;
      A[4] ^= (t >> 24) & 0xff;
      memcpy(out + 8 * i, A + 8, 8);
    }
  }

  memcpy(out, A, 8);
  *out_len = in_len + 8;
  return 1;
}

static int aead_aes_key_wrap_open(const EVP_AEAD_CTX *ctx, uint8_t *out,
                                  size_t *out_len, size_t max_out_len,
                                  const uint8_t *nonce,
                                  const uint8_t *in, size_t in_len,
                                  const uint8_t *ad, size_t ad_len) {
  const struct aead_aes_key_wrap_ctx *kw_ctx = ctx->aead_state;
  union {
    double align;
    AES_KEY ks;
  } ks;
  /* Variables in this function match up with the variables in the second half
   * of section 2.2.1. */
  unsigned i, j, n;
  uint8_t A[AES_BLOCK_SIZE];

  if (ad_len != 0) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_UNSUPPORTED_AD_SIZE);
    return 0;
  }

  if (in_len % 8 != 0) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_UNSUPPORTED_INPUT_SIZE);
    return 0;
  }

  /* The code below only handles a 32-bit |t| thus 6*|n| must be less than
   * 2^32, where |n| is |in_len| / 8. So in_len < 4/3 * 2^32 and we
   * conservatively cap it to 2^32-8 to stop 32-bit platforms complaining that
   * a comparison is always true. */
  if (in_len > 0xfffffff8) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_TOO_LARGE);
    return 0;
  }

  if (in_len < 24) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BAD_DECRYPT);
    return 0;
  }

  n = (in_len / 8) - 1;

  if (max_out_len < in_len - 8) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BUFFER_TOO_SMALL);
    return 0;
  }

  if (AES_set_decrypt_key(kw_ctx->key, kw_ctx->key_bits, &ks.ks) < 0) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_AES_KEY_SETUP_FAILED);
    return 0;
  }

  memcpy(A, in, 8);
  memmove(out, in + 8, in_len - 8);

  for (j = 5; j < 6; j--) {
    for (i = n; i > 0; i--) {
      uint32_t t;

      t = n * j + i;
      A[7] ^= t & 0xff;
      A[6] ^= (t >> 8) & 0xff;
      A[5] ^= (t >> 16) & 0xff;
      A[4] ^= (t >> 24) & 0xff;
      memcpy(A + 8, out + 8 * (i - 1), 8);
      AES_decrypt(A, A, &ks.ks);
      memcpy(out + 8 * (i - 1), A + 8, 8);
    }
  }

  if (CRYPTO_memcmp(A, nonce, 8) != 0) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BAD_DECRYPT);
    return 0;
  }

  *out_len = in_len - 8;
  return 1;
}

static const EVP_AEAD aead_aes_128_key_wrap = {
    16, /* key len */
    8,  /* nonce len */
    8,  /* overhead */
    8,  /* max tag length */
    aead_aes_key_wrap_init,
    NULL, /* init_with_direction */
    aead_aes_key_wrap_cleanup,
    aead_aes_key_wrap_seal,
    aead_aes_key_wrap_open,
};

static const EVP_AEAD aead_aes_256_key_wrap = {
    32, /* key len */
    8,  /* nonce len */
    8,  /* overhead */
    8,  /* max tag length */
    aead_aes_key_wrap_init,
    NULL, /* init_with_direction */
    aead_aes_key_wrap_cleanup,
    aead_aes_key_wrap_seal,
    aead_aes_key_wrap_open,
};

const EVP_AEAD *EVP_aead_aes_128_key_wrap(void) { return &aead_aes_128_key_wrap; }

const EVP_AEAD *EVP_aead_aes_256_key_wrap(void) { return &aead_aes_256_key_wrap; }

const uint8_t *EVP_aead_aes_key_wrap_default_iv(void) {
  /* kDefaultAESKeyWrapNonce is the default nonce value given in 2.2.3.1. */
  static const uint8_t kDefaultAESKeyWrapNonce[8] = {
    0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6
  };
  return kDefaultAESKeyWrapNonce;
}

int EVP_has_aes_hardware(void) {
#if defined(OPENSSL_X86) || defined(OPENSSL_X86_64)
  return aesni_capable() && crypto_gcm_clmul_enabled();
#elif defined(OPENSSL_ARM) || defined(OPENSSL_AARCH64)
  return hwaes_capable() && (OPENSSL_armcap_P & ARMV8_PMULL);
#else
  return 0;
#endif
}
