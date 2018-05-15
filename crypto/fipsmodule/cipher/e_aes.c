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

#include <GFp/aes.h>
#include <GFp/cpu.h>
#include <GFp/mem.h>

#include "internal.h"
#include "../../internal.h"
#include "../aes/internal.h"
#include "../modes/internal.h"

#if defined(OPENSSL_ARM) || defined(OPENSSL_AARCH64)
#include <GFp/arm_arch.h>
#endif


#define EVP_AEAD_AES_GCM_NONCE_LEN 12
#define EVP_AEAD_AES_GCM_TAG_LEN 16

// Declarations for extern functions only called by Rust code, to avoid
// -Wmissing-prototypes warnings.
int GFp_aes_gcm_init(void *ctx_buf, size_t ctx_buf_len, const uint8_t *key,
                     size_t key_len);
int GFp_aes_gcm_open(const void *ctx_buf, uint8_t *out, size_t in_out_len,
                     uint8_t tag_out[EVP_AEAD_AES_GCM_TAG_LEN],
                     const uint8_t nonce[EVP_AEAD_AES_GCM_NONCE_LEN],
                     const uint8_t *in, const uint8_t *ad, size_t ad_len);
int GFp_aes_gcm_seal(const void *ctx_buf, uint8_t *in_out, size_t in_out_len,
                     uint8_t tag_out[EVP_AEAD_AES_GCM_TAG_LEN],
                     const uint8_t nonce[EVP_AEAD_AES_GCM_NONCE_LEN],
                     const uint8_t *ad, size_t ad_len);
int GFp_AES_set_encrypt_key(const uint8_t *user_key, unsigned bits,
                            AES_KEY *key);
void GFp_AES_encrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key);
int GFp_has_aes_hardware(void);


#if !defined(GFp_C_AES)
int GFp_asm_AES_set_encrypt_key(const uint8_t *key, unsigned bits,
                                AES_KEY *aeskey);
void GFp_asm_AES_encrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key);
#endif

#if !defined(OPENSSL_NO_ASM) && \
    (defined(OPENSSL_X86_64) || defined(OPENSSL_X86))
#define VPAES
static char vpaes_capable(void) {
  return (GFp_ia32cap_P[1] & (1 << (41 - 32))) != 0;
}
#endif

#if !defined(OPENSSL_NO_ASM) && \
    defined(OPENSSL_ARM) && __ARM_MAX_ARCH__ >= 7
#define BSAES
static char bsaes_capable(void) {
  return GFp_is_NEON_capable();
}
#endif

#if defined(BSAES)
// On platforms where BSAES gets defined (just above), then these functions are
// provided by asm.
void GFp_bsaes_ctr32_encrypt_blocks(const uint8_t *in, uint8_t *out, size_t len,
                                    const AES_KEY *key, const uint8_t ivec[16]);
#endif

#if defined(HWAES)
int GFp_aes_hw_set_encrypt_key(const uint8_t *user_key, unsigned bits,
                               AES_KEY *key);
void GFp_aes_hw_encrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key);
void GFp_aes_hw_ctr32_encrypt_blocks(const uint8_t *in, uint8_t *out,
                                     size_t len, const AES_KEY *key,
                                     const uint8_t ivec[16]);
#endif

static void aes_ctr32_encrypt_blocks(const uint8_t *in, uint8_t *out,
                                     size_t len, const AES_KEY *key,
                                     const uint8_t ivec[16]);

#if defined(VPAES)
// On platforms where VPAES gets defined (just above), then these functions are
// provided by asm.
int GFp_vpaes_set_encrypt_key(const uint8_t *userKey, unsigned bits,
                              AES_KEY *key);
void GFp_vpaes_encrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key);
#endif

int GFp_AES_set_encrypt_key(const uint8_t *user_key, unsigned bits,
                            AES_KEY *key) {
  // Keep this in sync with |gcm128_init_gmult_ghash| and |aes_ctr|.

#if defined(HWAES)
  if (hwaes_capable()) {
    return GFp_aes_hw_set_encrypt_key(user_key, bits, key);
  }
#endif

#if defined(VPAES)
#if defined(BSAES)
#error "BSAES and VPAES are enabled at the same time, unexpectedly."
#endif
  if (vpaes_capable()) {
    return GFp_vpaes_set_encrypt_key(user_key, bits, key);
  }
#endif

#if defined(GFp_C_AES)
  return GFp_aes_c_set_encrypt_key(user_key, bits, key);
#else
  return GFp_asm_AES_set_encrypt_key(user_key, bits, key);
#endif
}

static aes_block_f aes_block(void) {
  // Keep this in sync with |GFp_AES_set_encrypt_key| and |aes_ctr|.

#if defined(HWAES)
  if (hwaes_capable()) {
    return GFp_aes_hw_encrypt;
  }
#endif

#if defined(VPAES)
#if defined(BSAES)
#error "BSAES and VPAES are enabled at the same time, unexpectedly."
#endif
  if (vpaes_capable()) {
    return GFp_vpaes_encrypt;
  }
#endif

#if defined(GFp_C_AES)
  return GFp_aes_c_encrypt;
#else
  return GFp_asm_AES_encrypt;
#endif
}

void GFp_AES_encrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key) {
  (aes_block())(in, out, key);
}

static aes_ctr_f aes_ctr(void) {
  // Keep this in sync with |set_set_key| and |aes_block|.

#if defined(HWAES)
  if (hwaes_capable()) {
    return GFp_aes_hw_ctr32_encrypt_blocks;
  }
#endif

#if defined(BSAES)
  if (bsaes_capable()) {
    return GFp_bsaes_ctr32_encrypt_blocks;
  }
#endif

  return aes_ctr32_encrypt_blocks;
}

static void aes_ctr32_encrypt_blocks(const uint8_t *in, uint8_t *out,
                                     size_t blocks, const AES_KEY *key,
                                     const uint8_t ivec[16]) {
  alignas(16) uint8_t counter_plaintext[16];
  memcpy(counter_plaintext, ivec, 16);
  uint32_t counter = from_be_u32_ptr(&counter_plaintext[12]);

  aes_block_f block = aes_block();

  for (size_t current_block = 0; current_block < blocks; ++current_block) {
    alignas(16) uint8_t counter_ciphertext[16];
    block(counter_plaintext, counter_ciphertext, key);
    for (size_t i = 0; i < 16; ++i) {
      out[i] = in[i] ^ counter_ciphertext[i];
    }
    // The caller must ensure the counter won't wrap around.
    ++counter;
    assert(counter != 0);
    to_be_u32_ptr(&counter_plaintext[12], counter);
    out += 16;
    in += 16;
  }
}

int GFp_aes_gcm_init(void *ctx_buf, size_t ctx_buf_len, const uint8_t *key,
                     size_t key_len) {
  alignas(16) AES_KEY ks;
  assert(ctx_buf_len >= sizeof(ks) + GCM128_SERIALIZED_LEN);
  if (ctx_buf_len < sizeof(ks) + GCM128_SERIALIZED_LEN) {
    return 0;
  }

  // XXX: Ignores return value. TODO: These functions should return |void|
  // anyway.
  GFp_AES_set_encrypt_key(key, (unsigned)key_len * 8, &ks);

  GFp_gcm128_init_serialized((uint8_t *)ctx_buf + sizeof(ks), &ks, aes_block());
  memcpy(ctx_buf, &ks, sizeof(ks));
  return 1;
}

static int gfp_aes_gcm_init_and_aad(GCM128_CONTEXT *gcm, AES_KEY *ks,
                                    const void *ctx_buf, const uint8_t nonce[],
                                    const uint8_t ad[], size_t ad_len) {
  assert(ad != NULL || ad_len == 0);
  memcpy(ks, ctx_buf, sizeof(*ks));

  GFp_gcm128_init(gcm, ks, aes_block(), (const uint8_t *)ctx_buf + sizeof(*ks),
                  nonce);
  if (ad_len > 0) {
    if (!GFp_gcm128_aad(gcm, ad, ad_len)) {
      return 0;
    }
  }
  return 1;
}

int GFp_aes_gcm_seal(const void *ctx_buf, uint8_t *in_out, size_t in_out_len,
                     uint8_t tag_out[EVP_AEAD_AES_GCM_TAG_LEN],
                     const uint8_t nonce[EVP_AEAD_AES_GCM_NONCE_LEN],
                     const uint8_t *ad, size_t ad_len) {
  assert(in_out != NULL || in_out_len == 0);
  assert(ad != NULL || ad_len == 0);

  GCM128_CONTEXT gcm;
  alignas(16) AES_KEY ks;
  if (!gfp_aes_gcm_init_and_aad(&gcm, &ks, ctx_buf, nonce, ad, ad_len)) {
    return 0;
  }
  if (in_out_len > 0) {
    aes_ctr_f ctr = aes_ctr();
    if (!GFp_gcm128_encrypt_ctr32(&gcm, &ks, in_out, in_out, in_out_len,
                                  ctr)) {
      return 0;
    }
  }
  GFp_gcm128_tag(&gcm, tag_out);
  return 1;
}

int GFp_aes_gcm_open(const void *ctx_buf, uint8_t *out, size_t in_out_len,
                     uint8_t tag_out[EVP_AEAD_AES_GCM_TAG_LEN],
                     const uint8_t nonce[EVP_AEAD_AES_GCM_NONCE_LEN],
                     const uint8_t *in, const uint8_t *ad, size_t ad_len) {
  assert(out != NULL || in_out_len == 0);
  assert(aead_check_alias(in, in_out_len, out));
  assert(in != NULL || in_out_len == 0);
  assert(ad != NULL || ad_len == 0);

  GCM128_CONTEXT gcm;
  alignas(16) AES_KEY ks;
  if (!gfp_aes_gcm_init_and_aad(&gcm, &ks, ctx_buf, nonce, ad, ad_len)) {
    return 0;
  }
  if (in_out_len > 0) {
    aes_ctr_f ctr = aes_ctr();
    if (!GFp_gcm128_decrypt_ctr32(&gcm, &ks, in, out, in_out_len, ctr)) {
      return 0;
    }
  }
  GFp_gcm128_tag(&gcm, tag_out);
  return 1;
}


int GFp_has_aes_hardware(void) {
#if defined(HWAES) && (defined(OPENSSL_X86) || defined(OPENSSL_X86_64))
  return hwaes_capable() && GFp_gcm_clmul_enabled();
#elif defined(HWAES) && (defined(OPENSSL_ARM) || defined(OPENSSL_AARCH64))
  return hwaes_capable() && GFp_is_ARMv8_PMULL_capable();
#else
  return 0;
#endif
}
