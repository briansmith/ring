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

#include <openssl/aead.h>
#include <openssl/cipher.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

#include "internal.h"


#if !defined(OPENSSL_SMALL)

#define EVP_AEAD_AES_GCM_SIV_NONCE_LEN 12
#define EVP_AEAD_AES_GCM_SIV_TAG_LEN 16

struct aead_aes_gcm_siv_ctx {
  union {
    double align;
    AES_KEY ks;
  } ks;
  block128_f kgk_block;
  unsigned is_256:1;
};

static int aead_aes_gcm_siv_init(EVP_AEAD_CTX *ctx, const uint8_t *key,
                                 size_t key_len, size_t tag_len) {
  const size_t key_bits = key_len * 8;

  if (key_bits != 128 && key_bits != 256) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BAD_KEY_LENGTH);
    return 0; /* EVP_AEAD_CTX_init should catch this. */
  }

  if (tag_len == EVP_AEAD_DEFAULT_TAG_LENGTH) {
    tag_len = EVP_AEAD_AES_GCM_SIV_TAG_LEN;
  }

  if (tag_len != EVP_AEAD_AES_GCM_SIV_TAG_LEN) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_TAG_TOO_LARGE);
    return 0;
  }

  struct aead_aes_gcm_siv_ctx *gcm_siv_ctx =
      OPENSSL_malloc(sizeof(struct aead_aes_gcm_siv_ctx));
  if (gcm_siv_ctx == NULL) {
    return 0;
  }
  OPENSSL_memset(gcm_siv_ctx, 0, sizeof(struct aead_aes_gcm_siv_ctx));

  aes_ctr_set_key(&gcm_siv_ctx->ks.ks, NULL, &gcm_siv_ctx->kgk_block, key,
                  key_len);
  gcm_siv_ctx->is_256 = (key_len == 32);
  ctx->aead_state = gcm_siv_ctx;

  return 1;
}

static void aead_aes_gcm_siv_cleanup(EVP_AEAD_CTX *ctx) {
  struct aead_aes_gcm_siv_ctx *gcm_siv_ctx = ctx->aead_state;
  OPENSSL_cleanse(gcm_siv_ctx, sizeof(struct aead_aes_gcm_siv_ctx));
  OPENSSL_free(gcm_siv_ctx);
}

/* gcm_siv_crypt encrypts (or decrypts—it's the same thing) |in_len| bytes from
 * |in| to |out|, using the block function |enc_block| with |key| in counter
 * mode, starting at |initial_counter|. This differs from the traditional
 * counter mode code in that the counter is handled little-endian, only the
 * first four bytes are used and the GCM-SIV tweak to the final byte is
 * applied. The |in| and |out| pointers may be equal but otherwise must not
 * alias. */
static void gcm_siv_crypt(uint8_t *out, const uint8_t *in, size_t in_len,
                          const uint8_t initial_counter[AES_BLOCK_SIZE],
                          block128_f enc_block, const AES_KEY *key) {
  union {
    uint32_t w[4];
    uint8_t c[16];
  } counter;

  OPENSSL_memcpy(counter.c, initial_counter, AES_BLOCK_SIZE);
  counter.c[15] |= 0x80;

  for (size_t done = 0; done < in_len;) {
    uint8_t keystream[AES_BLOCK_SIZE];
    enc_block(counter.c, keystream, key);
    counter.w[0]++;

    size_t todo = AES_BLOCK_SIZE;
    if (in_len - done < todo) {
      todo = in_len - done;
    }

    for (size_t i = 0; i < todo; i++) {
      out[done + i] = keystream[i] ^ in[done + i];
    }

    done += todo;
  }
}

/* gcm_siv_polyval evaluates POLYVAL at |auth_key| on the given plaintext and
 * AD. The result is written to |out_tag|. */
static void gcm_siv_polyval(
    uint8_t out_tag[16], const uint8_t *in, size_t in_len, const uint8_t *ad,
    size_t ad_len, const uint8_t auth_key[16],
    const uint8_t nonce[EVP_AEAD_AES_GCM_SIV_NONCE_LEN]) {
  struct polyval_ctx polyval_ctx;
  CRYPTO_POLYVAL_init(&polyval_ctx, auth_key);

  CRYPTO_POLYVAL_update_blocks(&polyval_ctx, ad, ad_len & ~15);

  uint8_t scratch[16];
  if (ad_len & 15) {
    OPENSSL_memset(scratch, 0, sizeof(scratch));
    OPENSSL_memcpy(scratch, &ad[ad_len & ~15], ad_len & 15);
    CRYPTO_POLYVAL_update_blocks(&polyval_ctx, scratch, sizeof(scratch));
  }

  CRYPTO_POLYVAL_update_blocks(&polyval_ctx, in, in_len & ~15);
  if (in_len & 15) {
    OPENSSL_memset(scratch, 0, sizeof(scratch));
    OPENSSL_memcpy(scratch, &in[in_len & ~15], in_len & 15);
    CRYPTO_POLYVAL_update_blocks(&polyval_ctx, scratch, sizeof(scratch));
  }

  union {
    uint8_t c[16];
    struct {
      uint64_t ad;
      uint64_t in;
    } bitlens;
  } length_block;

  length_block.bitlens.ad = ad_len * 8;
  length_block.bitlens.in = in_len * 8;
  CRYPTO_POLYVAL_update_blocks(&polyval_ctx, length_block.c,
                               sizeof(length_block));

  CRYPTO_POLYVAL_finish(&polyval_ctx, out_tag);
  for (size_t i = 0; i < EVP_AEAD_AES_GCM_SIV_NONCE_LEN; i++) {
    out_tag[i] ^= nonce[i];
  }
  out_tag[15] &= 0x7f;
}

/* gcm_siv_record_keys contains the keys used for a specific GCM-SIV record. */
struct gcm_siv_record_keys {
  uint8_t auth_key[16];
  union {
    double align;
    AES_KEY ks;
  } enc_key;
  block128_f enc_block;
};

/* gcm_siv_keys calculates the keys for a specific GCM-SIV record with the
 * given nonce and writes them to |*out_keys|. */
static void gcm_siv_keys(
    const struct aead_aes_gcm_siv_ctx *gcm_siv_ctx,
    struct gcm_siv_record_keys *out_keys,
    const uint8_t nonce[EVP_AEAD_AES_GCM_SIV_NONCE_LEN]) {
  const AES_KEY *const key = &gcm_siv_ctx->ks.ks;
  uint8_t key_material[(128 /* POLYVAL key */ + 256 /* max AES key */) / 8];
  const size_t blocks_needed = gcm_siv_ctx->is_256 ? 6 : 4;

  uint8_t counter[AES_BLOCK_SIZE];
  OPENSSL_memset(counter, 0, AES_BLOCK_SIZE - EVP_AEAD_AES_GCM_SIV_NONCE_LEN);
  OPENSSL_memcpy(counter + AES_BLOCK_SIZE - EVP_AEAD_AES_GCM_SIV_NONCE_LEN,
                 nonce, EVP_AEAD_AES_GCM_SIV_NONCE_LEN);
  for (size_t i = 0; i < blocks_needed; i++) {
    counter[0] = i;

    uint8_t ciphertext[AES_BLOCK_SIZE];
    gcm_siv_ctx->kgk_block(counter, ciphertext, key);
    OPENSSL_memcpy(&key_material[i * 8], ciphertext, 8);
  }

  OPENSSL_memcpy(out_keys->auth_key, key_material, 16);
  aes_ctr_set_key(&out_keys->enc_key.ks, NULL, &out_keys->enc_block,
                  key_material + 16, gcm_siv_ctx->is_256 ? 32 : 16);
}

static int aead_aes_gcm_siv_seal(const EVP_AEAD_CTX *ctx, uint8_t *out,
                                 size_t *out_len, size_t max_out_len,
                                 const uint8_t *nonce, size_t nonce_len,
                                 const uint8_t *in, size_t in_len,
                                 const uint8_t *ad, size_t ad_len) {
  const struct aead_aes_gcm_siv_ctx *gcm_siv_ctx = ctx->aead_state;
  const uint64_t in_len_64 = in_len;
  const uint64_t ad_len_64 = ad_len;

  if (in_len + EVP_AEAD_AES_GCM_SIV_TAG_LEN < in_len ||
      in_len_64 > (UINT64_C(1) << 36) ||
      ad_len_64 >= (UINT64_C(1) << 61)) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_TOO_LARGE);
    return 0;
  }

  if (max_out_len < in_len + EVP_AEAD_AES_GCM_SIV_TAG_LEN) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BUFFER_TOO_SMALL);
    return 0;
  }

  if (nonce_len != EVP_AEAD_AES_GCM_SIV_NONCE_LEN) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_UNSUPPORTED_NONCE_SIZE);
    return 0;
  }

  struct gcm_siv_record_keys keys;
  gcm_siv_keys(gcm_siv_ctx, &keys, nonce);

  uint8_t tag[16];
  gcm_siv_polyval(tag, in, in_len, ad, ad_len, keys.auth_key, nonce);
  keys.enc_block(tag, tag, &keys.enc_key.ks);

  gcm_siv_crypt(out, in, in_len, tag, keys.enc_block, &keys.enc_key.ks);

  OPENSSL_memcpy(&out[in_len], tag, EVP_AEAD_AES_GCM_SIV_TAG_LEN);
  *out_len = in_len + EVP_AEAD_AES_GCM_SIV_TAG_LEN;

  return 1;
}

static int aead_aes_gcm_siv_open(const EVP_AEAD_CTX *ctx, uint8_t *out,
                                 size_t *out_len, size_t max_out_len,
                                 const uint8_t *nonce, size_t nonce_len,
                                 const uint8_t *in, size_t in_len,
                                 const uint8_t *ad, size_t ad_len) {
  const uint64_t ad_len_64 = ad_len;
  if (ad_len_64 >= (UINT64_C(1) << 61)) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_TOO_LARGE);
    return 0;
  }

  const uint64_t in_len_64 = in_len;
  if (in_len < EVP_AEAD_AES_GCM_SIV_TAG_LEN ||
      in_len_64 > (UINT64_C(1) << 36) + AES_BLOCK_SIZE) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BAD_DECRYPT);
    return 0;
  }

  if (nonce_len != EVP_AEAD_AES_GCM_SIV_NONCE_LEN) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_UNSUPPORTED_NONCE_SIZE);
    return 0;
  }

  const struct aead_aes_gcm_siv_ctx *gcm_siv_ctx = ctx->aead_state;
  const size_t plaintext_len = in_len - EVP_AEAD_AES_GCM_SIV_TAG_LEN;

  if (max_out_len < plaintext_len) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BUFFER_TOO_SMALL);
    return 0;
  }

  struct gcm_siv_record_keys keys;
  gcm_siv_keys(gcm_siv_ctx, &keys, nonce);

  gcm_siv_crypt(out, in, plaintext_len, &in[plaintext_len], keys.enc_block,
                &keys.enc_key.ks);

  uint8_t expected_tag[EVP_AEAD_AES_GCM_SIV_TAG_LEN];
  gcm_siv_polyval(expected_tag, out, plaintext_len, ad, ad_len, keys.auth_key,
                  nonce);
  keys.enc_block(expected_tag, expected_tag, &keys.enc_key.ks);

  if (CRYPTO_memcmp(expected_tag, &in[plaintext_len], sizeof(expected_tag)) !=
      0) {
    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BAD_DECRYPT);
    return 0;
  }

  *out_len = plaintext_len;
  return 1;
}

static const EVP_AEAD aead_aes_128_gcm_siv = {
    16,                             /* key length */
    EVP_AEAD_AES_GCM_SIV_NONCE_LEN, /* nonce length */
    EVP_AEAD_AES_GCM_SIV_TAG_LEN,   /* overhead */
    EVP_AEAD_AES_GCM_SIV_TAG_LEN,   /* max tag length */

    aead_aes_gcm_siv_init,
    NULL /* init_with_direction */,
    aead_aes_gcm_siv_cleanup,
    aead_aes_gcm_siv_seal,
    aead_aes_gcm_siv_open,
    NULL /* get_iv */,
};

static const EVP_AEAD aead_aes_256_gcm_siv = {
    32,                             /* key length */
    EVP_AEAD_AES_GCM_SIV_NONCE_LEN, /* nonce length */
    EVP_AEAD_AES_GCM_SIV_TAG_LEN,   /* overhead */
    EVP_AEAD_AES_GCM_SIV_TAG_LEN,   /* max tag length */

    aead_aes_gcm_siv_init,
    NULL /* init_with_direction */,
    aead_aes_gcm_siv_cleanup,
    aead_aes_gcm_siv_seal,
    aead_aes_gcm_siv_open,
    NULL /* get_iv */,
};

const EVP_AEAD *EVP_aead_aes_128_gcm_siv(void) {
  return &aead_aes_128_gcm_siv;
}

const EVP_AEAD *EVP_aead_aes_256_gcm_siv(void) {
  return &aead_aes_256_gcm_siv;
}

#endif  /* !OPENSSL_SMALL */
