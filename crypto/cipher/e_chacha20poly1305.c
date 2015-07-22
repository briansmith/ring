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

#include <openssl/aead.h>

#include <string.h>

#include <openssl/chacha.h>
#include <openssl/cipher.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/poly1305.h>

#include "internal.h"


#define POLY1305_TAG_LEN 16
#define CHACHA20_NONCE_LEN 8

struct aead_chacha20_poly1305_ctx {
  unsigned char key[32];
  unsigned char tag_len;
};

static int aead_chacha20_poly1305_init(EVP_AEAD_CTX *ctx, const uint8_t *key,
                                       size_t key_len, size_t tag_len) {
  struct aead_chacha20_poly1305_ctx *c20_ctx;

  if (tag_len == 0) {
    tag_len = POLY1305_TAG_LEN;
  }

  if (tag_len > POLY1305_TAG_LEN) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_TOO_LARGE);
    return 0;
  }

  if (key_len != sizeof(c20_ctx->key)) {
    return 0; /* internal error - EVP_AEAD_CTX_init should catch this. */
  }

  c20_ctx = OPENSSL_malloc(sizeof(struct aead_chacha20_poly1305_ctx));
  if (c20_ctx == NULL) {
    return 0;
  }

  memcpy(c20_ctx->key, key, key_len);
  c20_ctx->tag_len = tag_len;
  ctx->aead_state = c20_ctx;

  return 1;
}

static void aead_chacha20_poly1305_cleanup(EVP_AEAD_CTX *ctx) {
  struct aead_chacha20_poly1305_ctx *c20_ctx = ctx->aead_state;
  OPENSSL_cleanse(c20_ctx->key, sizeof(c20_ctx->key));
  OPENSSL_free(c20_ctx);
}

static void poly1305_update_with_length(poly1305_state *poly1305,
                                        const uint8_t *data, size_t data_len) {
  size_t j = data_len;
  uint8_t length_bytes[8];
  unsigned i;

  for (i = 0; i < sizeof(length_bytes); i++) {
    length_bytes[i] = j;
    j >>= 8;
  }

  CRYPTO_poly1305_update(poly1305, data, data_len);
  CRYPTO_poly1305_update(poly1305, length_bytes, sizeof(length_bytes));
}

#if defined(__arm__)
#define ALIGNED __attribute__((aligned(16)))
#else
#define ALIGNED
#endif

static int aead_chacha20_poly1305_seal(const EVP_AEAD_CTX *ctx, uint8_t *out,
                                       size_t *out_len, size_t max_out_len,
                                       const uint8_t *nonce, size_t nonce_len,
                                       const uint8_t *in, size_t in_len,
                                       const uint8_t *ad, size_t ad_len) {
  const struct aead_chacha20_poly1305_ctx *c20_ctx = ctx->aead_state;
  uint8_t poly1305_key[32] ALIGNED;
  poly1305_state poly1305;
  const uint64_t in_len_64 = in_len;

  /* The underlying ChaCha implementation may not overflow the block
   * counter into the second counter word. Therefore we disallow
   * individual operations that work on more than 256GB at a time.
   * |in_len_64| is needed because, on 32-bit platforms, size_t is only
   * 32-bits and this produces a warning because it's always false.
   * Casting to uint64_t inside the conditional is not sufficient to stop
   * the warning. */
  if (in_len_64 >= (1ull << 32) * 64 - 64) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_TOO_LARGE);
    return 0;
  }

  if (in_len + c20_ctx->tag_len < in_len) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_TOO_LARGE);
    return 0;
  }

  if (max_out_len < in_len + c20_ctx->tag_len) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BUFFER_TOO_SMALL);
    return 0;
  }

  if (nonce_len != CHACHA20_NONCE_LEN) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_IV_TOO_LARGE);
    return 0;
  }

  memset(poly1305_key, 0, sizeof(poly1305_key));
  CRYPTO_chacha_20(poly1305_key, poly1305_key, sizeof(poly1305_key),
                   c20_ctx->key, nonce, 0);

  CRYPTO_poly1305_init(&poly1305, poly1305_key);
  poly1305_update_with_length(&poly1305, ad, ad_len);
  CRYPTO_chacha_20(out, in, in_len, c20_ctx->key, nonce, 1);
  poly1305_update_with_length(&poly1305, out, in_len);

  uint8_t tag[POLY1305_TAG_LEN] ALIGNED;
  CRYPTO_poly1305_finish(&poly1305, tag);
  memcpy(out + in_len, tag, c20_ctx->tag_len);
  *out_len = in_len + c20_ctx->tag_len;
  return 1;
}

static int aead_chacha20_poly1305_open(const EVP_AEAD_CTX *ctx, uint8_t *out,
                                       size_t *out_len, size_t max_out_len,
                                       const uint8_t *nonce, size_t nonce_len,
                                       const uint8_t *in, size_t in_len,
                                       const uint8_t *ad, size_t ad_len) {
  const struct aead_chacha20_poly1305_ctx *c20_ctx = ctx->aead_state;
  uint8_t mac[POLY1305_TAG_LEN];
  uint8_t poly1305_key[32] ALIGNED;
  size_t plaintext_len;
  poly1305_state poly1305;
  const uint64_t in_len_64 = in_len;

  if (in_len < c20_ctx->tag_len) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BAD_DECRYPT);
    return 0;
  }

  /* The underlying ChaCha implementation may not overflow the block
   * counter into the second counter word. Therefore we disallow
   * individual operations that work on more than 256GB at a time.
   * |in_len_64| is needed because, on 32-bit platforms, size_t is only
   * 32-bits and this produces a warning because it's always false.
   * Casting to uint64_t inside the conditional is not sufficient to stop
   * the warning. */
  if (in_len_64 >= (1ull << 32) * 64 - 64) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_TOO_LARGE);
    return 0;
  }

  if (nonce_len != CHACHA20_NONCE_LEN) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_IV_TOO_LARGE);
    return 0;
  }

  plaintext_len = in_len - c20_ctx->tag_len;

  if (max_out_len < plaintext_len) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BUFFER_TOO_SMALL);
    return 0;
  }

  memset(poly1305_key, 0, sizeof(poly1305_key));
  CRYPTO_chacha_20(poly1305_key, poly1305_key, sizeof(poly1305_key),
                   c20_ctx->key, nonce, 0);

  CRYPTO_poly1305_init(&poly1305, poly1305_key);
  poly1305_update_with_length(&poly1305, ad, ad_len);
  poly1305_update_with_length(&poly1305, in, plaintext_len);
  CRYPTO_poly1305_finish(&poly1305, mac);

  if (CRYPTO_memcmp(mac, in + plaintext_len, c20_ctx->tag_len) != 0) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BAD_DECRYPT);
    return 0;
  }

  CRYPTO_chacha_20(out, in, plaintext_len, c20_ctx->key, nonce, 1);
  *out_len = plaintext_len;
  return 1;
}

static const EVP_AEAD aead_chacha20_poly1305 = {
    32,                 /* key len */
    CHACHA20_NONCE_LEN, /* nonce len */
    POLY1305_TAG_LEN,   /* overhead */
    POLY1305_TAG_LEN,   /* max tag length */
    aead_chacha20_poly1305_init,
    NULL, /* init_with_direction */
    aead_chacha20_poly1305_cleanup,
    aead_chacha20_poly1305_seal,
    aead_chacha20_poly1305_open,
};

const EVP_AEAD *EVP_aead_chacha20_poly1305(void) {
  return &aead_chacha20_poly1305;
}
