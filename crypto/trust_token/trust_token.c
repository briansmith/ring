/* Copyright (c) 2019, Google Inc.
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

#include <openssl/bytestring.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/sha.h>
#include <openssl/trust_token.h>

#include "internal.h"


// The Trust Token API is described in
// https://github.com/WICG/trust-token-api/blob/master/README.md and provides a
// protocol for issuing and redeeming tokens built on top of the PMBTokens
// construction.

static int cbb_add_raw_point(CBB *cbb, const EC_GROUP *group,
                             const EC_RAW_POINT *point) {
  size_t len =
      ec_point_to_bytes(group, point, POINT_CONVERSION_UNCOMPRESSED, NULL, 0);
  if (len == 0) {
    return 0;
  }
  uint8_t *p;
  return CBB_add_u16(cbb, len) && CBB_add_space(cbb, &p, len) &&
         ec_point_to_bytes(group, point, POINT_CONVERSION_UNCOMPRESSED, p,
                           len) == len;
}

static int cbs_get_raw_point(CBS *cbs, const EC_GROUP *group,
                             EC_RAW_POINT *out) {
  CBS child;
  return CBS_get_u16_length_prefixed(cbs, &child) &&
         ec_point_from_uncompressed(group, out, CBS_data(&child),
                                    CBS_len(&child));
}

TRUST_TOKEN *TRUST_TOKEN_new(const uint8_t *data, size_t len) {
  TRUST_TOKEN *ret = OPENSSL_malloc(sizeof(TRUST_TOKEN));
  if (ret == NULL) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    return NULL;
  }
  OPENSSL_memset(ret, 0, sizeof(TRUST_TOKEN));
  ret->data = OPENSSL_memdup(data, len);
  if (len != 0 && ret->data == NULL) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    OPENSSL_free(ret);
    return NULL;
  }
  ret->len = len;
  return ret;
}

void TRUST_TOKEN_free(TRUST_TOKEN *token) {
  if (token == NULL) {
    return;
  }
  OPENSSL_free(token->data);
  OPENSSL_free(token);
}

TRUST_TOKEN_CLIENT *TRUST_TOKEN_CLIENT_new(uint16_t max_batchsize) {
  TRUST_TOKEN_CLIENT *ret = OPENSSL_malloc(sizeof(TRUST_TOKEN_CLIENT));
  if (ret == NULL) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    return NULL;
  }
  OPENSSL_memset(ret, 0, sizeof(TRUST_TOKEN_CLIENT));
  ret->max_batchsize = max_batchsize;
  ret->pretokens = sk_PMBTOKEN_PRETOKEN_new_null();
  if (ret->pretokens == NULL) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    OPENSSL_free(ret);
    return NULL;
  }
  return ret;
}

void TRUST_TOKEN_CLIENT_free(TRUST_TOKEN_CLIENT *ctx) {
  if (ctx == NULL) {
    return;
  }
  EVP_PKEY_free(ctx->srr_key);
  sk_PMBTOKEN_PRETOKEN_pop_free(ctx->pretokens, PMBTOKEN_PRETOKEN_free);
  OPENSSL_free(ctx);
}

int TRUST_TOKEN_CLIENT_add_key(TRUST_TOKEN_CLIENT *ctx, size_t *out_key_index,
                               const uint8_t *key, size_t key_len) {
  EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp521r1);
  if (group == NULL) {
    return 0;
  }

  if (ctx->num_keys == OPENSSL_ARRAY_SIZE(ctx->keys)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_TOO_MANY_KEYS);
    return 0;
  }

  struct trust_token_client_key_st *key_s = &ctx->keys[ctx->num_keys];

  CBS cbs;
  CBS_init(&cbs, key, key_len);
  uint32_t key_id;
  if (!CBS_get_u32(&cbs, &key_id) ||
      !cbs_get_raw_point(&cbs, group, &key_s->pub0) ||
      !cbs_get_raw_point(&cbs, group, &key_s->pub1) ||
      !cbs_get_raw_point(&cbs, group, &key_s->pubs) ||
      CBS_len(&cbs) != 0) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_FAILURE);
    return 0;
  }
  key_s->id = key_id;
  *out_key_index = ctx->num_keys;
  ctx->num_keys += 1;
  return 1;
}

int TRUST_TOKEN_CLIENT_set_srr_key(TRUST_TOKEN_CLIENT *ctx, EVP_PKEY *key) {
  EVP_PKEY_free(ctx->srr_key);
  EVP_PKEY_up_ref(key);
  ctx->srr_key = key;
  return 1;
}

int TRUST_TOKEN_CLIENT_begin_issuance(TRUST_TOKEN_CLIENT *ctx, uint8_t **out,
                                      size_t *out_len, size_t count) {
  EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp521r1);
  if (group == NULL) {
    return 0;
  }

  if (count > ctx->max_batchsize) {
    count = ctx->max_batchsize;
  }

  int ret = 0;
  CBB request;
  if (!CBB_init(&request, 0) ||
      !CBB_add_u16(&request, count)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  for (size_t i = 0; i < count; i++) {
    PMBTOKEN_PRETOKEN *pretoken = pmbtoken_blind();
    if (pretoken == NULL ||
        !cbb_add_raw_point(&request, group, &pretoken->Tp) ||
        !sk_PMBTOKEN_PRETOKEN_push(ctx->pretokens, pretoken)) {
      PMBTOKEN_PRETOKEN_free(pretoken);
      goto err;
    }
  }

  if (!CBB_finish(&request, out, out_len)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  ret = 1;

err:
  CBB_cleanup(&request);
  return ret;
}

STACK_OF(TRUST_TOKEN) *
    TRUST_TOKEN_CLIENT_finish_issuance(TRUST_TOKEN_CLIENT *ctx,
                                       size_t *out_key_index,
                                       const uint8_t *response,
                                       size_t response_len) {
  EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp521r1);
  if (group == NULL) {
    return 0;
  }

  CBS in;
  CBS_init(&in, response, response_len);
  uint16_t count;
  uint32_t key_id;
  if (!CBS_get_u16(&in, &count) ||
      !CBS_get_u32(&in, &key_id)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_FAILURE);
    return NULL;
  }

  size_t key_index = 0;
  const struct trust_token_client_key_st *key = NULL;
  for (size_t i = 0; i < ctx->num_keys; i++) {
    if (ctx->keys[i].id == key_id) {
      key_index = i;
      key = &ctx->keys[i];
      break;
    }
  }

  if (key == NULL) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_INVALID_KEY_ID);
    return NULL;
  }

  if (count > sk_PMBTOKEN_PRETOKEN_num(ctx->pretokens)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_FAILURE);
    return NULL;
  }

  int ok = 0;
  STACK_OF(TRUST_TOKEN) *tokens = sk_TRUST_TOKEN_new_null();
  if (tokens == NULL) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    return NULL;
  }

  for (size_t i = 0; i < count; i++) {
    uint8_t s[PMBTOKEN_NONCE_SIZE];
    EC_RAW_POINT Wp, Wsp;
    CBS proof;
    if (!CBS_copy_bytes(&in, s, PMBTOKEN_NONCE_SIZE) ||
        !cbs_get_raw_point(&in, group, &Wp) ||
        !cbs_get_raw_point(&in, group, &Wsp) ||
        !CBS_get_u16_length_prefixed(&in, &proof)) {
      OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_FAILURE);
      goto err;
    }

    PMBTOKEN_PRETOKEN *pretoken = sk_PMBTOKEN_PRETOKEN_value(ctx->pretokens, i);
    PMBTOKEN_TOKEN pmbtoken;
    if (!pmbtoken_unblind(&pmbtoken, key, s, &Wp, &Wsp, CBS_data(&proof),
                          CBS_len(&proof), pretoken)) {
      goto err;
    }

    int token_ok = 0;
    TRUST_TOKEN *token = NULL;
    CBB token_cbb;
    if (!CBB_init(&token_cbb, 0) ||
        !CBB_add_u32(&token_cbb, key_id) ||
        !CBB_add_bytes(&token_cbb, pmbtoken.t, PMBTOKEN_NONCE_SIZE) ||
        !cbb_add_raw_point(&token_cbb, group, &pmbtoken.S) ||
        !cbb_add_raw_point(&token_cbb, group, &pmbtoken.W) ||
        !cbb_add_raw_point(&token_cbb, group, &pmbtoken.Ws)) {
      goto token_err;
    }

    token = TRUST_TOKEN_new(CBB_data(&token_cbb), CBB_len(&token_cbb));
    if (token == NULL) {
      OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
      goto token_err;
    }

    if (!sk_TRUST_TOKEN_push(tokens, token)) {
      OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
      goto token_err;
    }
    token_ok = 1;

  token_err:
    CBB_cleanup(&token_cbb);
    if (!token_ok) {
      TRUST_TOKEN_free(token);
      goto err;
    }
  }

  if (CBS_len(&in) != 0) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_FAILURE);
    goto err;
  }

  sk_PMBTOKEN_PRETOKEN_pop_free(ctx->pretokens, PMBTOKEN_PRETOKEN_free);
  ctx->pretokens = NULL;

  *out_key_index = key_index;
  ok = 1;

err:
  if (!ok) {
    sk_TRUST_TOKEN_pop_free(tokens, TRUST_TOKEN_free);
    return NULL;
  } else {
    return tokens;
  }
}

int TRUST_TOKEN_CLIENT_begin_redemption(TRUST_TOKEN_CLIENT *ctx, uint8_t **out,
                                        size_t *out_len,
                                        const TRUST_TOKEN *token,
                                        const uint8_t *data, size_t data_len,
                                        uint64_t time) {
  CBB request, token_inner, inner;
  if (!CBB_init(&request, 0) ||
      !CBB_add_u16_length_prefixed(&request, &token_inner) ||
      !CBB_add_bytes(&token_inner, token->data, token->len) ||
      !CBB_add_u16_length_prefixed(&request, &inner) ||
      !CBB_add_bytes(&inner, data, data_len) ||
      !CBB_add_u64(&request, time) ||
      !CBB_finish(&request, out, out_len)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    CBB_cleanup(&request);
    return 0;
  }
  return 1;
}

int TRUST_TOKEN_CLIENT_finish_redemption(TRUST_TOKEN_CLIENT *ctx,
                                         uint8_t **out_srr, size_t *out_srr_len,
                                         uint8_t **out_sig, size_t *out_sig_len,
                                         const uint8_t *response,
                                         size_t response_len) {
  if (ctx->srr_key == NULL) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_NO_SRR_KEY_CONFIGURED);
    return 0;
  }

  CBS in, srr, sig;
  CBS_init(&in, response, response_len);
  if (!CBS_get_u16_length_prefixed(&in, &srr) ||
      !CBS_get_u16_length_prefixed(&in, &sig)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_ERROR);
    return 0;
  }

  EVP_MD_CTX md_ctx;
  EVP_MD_CTX_init(&md_ctx);
  int sig_ok = EVP_DigestVerifyInit(&md_ctx, NULL, NULL, NULL, ctx->srr_key) &&
               EVP_DigestVerify(&md_ctx, CBS_data(&sig), CBS_len(&sig),
                                CBS_data(&srr), CBS_len(&srr));
  EVP_MD_CTX_cleanup(&md_ctx);

  if (!sig_ok) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_SRR_SIGNATURE_ERROR);
    return 0;
  }

  uint8_t *srr_buf = NULL, *sig_buf = NULL;
  size_t srr_len, sig_len;
  if (!CBS_stow(&srr, &srr_buf, &srr_len) ||
      !CBS_stow(&sig, &sig_buf, &sig_len)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    OPENSSL_free(srr_buf);
    OPENSSL_free(sig_buf);
    return 0;
  }

  *out_srr = srr_buf;
  *out_srr_len = srr_len;
  *out_sig = sig_buf;
  *out_sig_len = sig_len;
  return 1;
}

TRUST_TOKEN_ISSUER *TRUST_TOKEN_ISSUER_new(uint16_t max_batchsize) {
  TRUST_TOKEN_ISSUER *ret = OPENSSL_malloc(sizeof(TRUST_TOKEN_ISSUER));
  if (ret == NULL) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    return NULL;
  }
  OPENSSL_memset(ret, 0, sizeof(TRUST_TOKEN_ISSUER));
  ret->max_batchsize = max_batchsize;
  return ret;
}

void TRUST_TOKEN_ISSUER_free(TRUST_TOKEN_ISSUER *ctx) {
  if (ctx == NULL) {
    return;
  }
  EVP_PKEY_free(ctx->srr_key);
  OPENSSL_free(ctx->metadata_key);
  OPENSSL_free(ctx);
}

int TRUST_TOKEN_ISSUER_add_key(TRUST_TOKEN_ISSUER *ctx, const uint8_t *key,
                               size_t key_len) {
  EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp521r1);
  if (group == NULL) {
    return 0;
  }

  if (ctx->num_keys == OPENSSL_ARRAY_SIZE(ctx->keys)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_TOO_MANY_KEYS);
    return 0;
  }

  CBS cbs, tmp;
  CBS_init(&cbs, key, key_len);
  uint32_t key_id;
  if (!CBS_get_u32(&cbs, &key_id)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_FAILURE);
    return 0;
  }

  size_t scalar_len = BN_num_bytes(&group->order);
  struct trust_token_issuer_key_st *key_s = &(ctx->keys[ctx->num_keys]);
  EC_SCALAR *scalars[] = {&key_s->x0, &key_s->y0, &key_s->x1,
                          &key_s->y1, &key_s->xs, &key_s->ys};
  for (size_t i = 0; i < OPENSSL_ARRAY_SIZE(scalars); i++) {
    if (!CBS_get_bytes(&cbs, &tmp, scalar_len) ||
        !ec_scalar_from_bytes(group, scalars[i], CBS_data(&tmp),
                              CBS_len(&tmp))) {
      OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_FAILURE);
     return 0;
    }
  }

  if (!pmbtoken_compute_public(key_s)) {
    return 0;
  }

  key_s->id = key_id;
  ctx->num_keys += 1;
  return 1;
}

int TRUST_TOKEN_ISSUER_set_srr_key(TRUST_TOKEN_ISSUER *ctx, EVP_PKEY *key) {
  EVP_PKEY_free(ctx->srr_key);
  EVP_PKEY_up_ref(key);
  ctx->srr_key = key;
  return 1;
}

int TRUST_TOKEN_ISSUER_set_metadata_key(TRUST_TOKEN_ISSUER *ctx,
                                        const uint8_t *key, size_t len) {
  if (len < 32) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_INVALID_METADATA_KEY);
  }
  OPENSSL_free(ctx->metadata_key);
  ctx->metadata_key_len = 0;
  ctx->metadata_key = OPENSSL_memdup(key, len);
  if (ctx->metadata_key == NULL) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    return 0;
  }
  ctx->metadata_key_len = len;
  return 1;
}

int TRUST_TOKEN_ISSUER_issue(const TRUST_TOKEN_ISSUER *ctx, uint8_t **out,
                             size_t *out_len, uint8_t *out_tokens_issued,
                             const uint8_t *request, size_t request_len,
                             uint32_t public_metadata, uint8_t private_metadata,
                             size_t max_issuance) {
  EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp521r1);
  if (group == NULL) {
    return 0;
  }

  if (max_issuance > ctx->max_batchsize) {
    max_issuance = ctx->max_batchsize;
  }

  int found_public_metadata = 0;
  for (size_t i = 0; i < ctx->num_keys; i++) {
    if (ctx->keys[i].id == public_metadata) {
      found_public_metadata = 1;
      break;
    }
  }

  if (!found_public_metadata || private_metadata > 1) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_INVALID_METADATA);
    return 0;
  }

  CBS in;
  CBS_init(&in, request, request_len);

  CBB response;
  if (!CBB_init(&response, 0)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    return 0;
  }

  int ret = 0;
  uint16_t count;
  if (!CBS_get_u16(&in, &count)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_FAILURE);
    goto err;
  }

  if (count > max_issuance) {
    count = max_issuance;
  }

  if (!CBB_add_u16(&response, count) ||
      !CBB_add_u32(&response, public_metadata)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  for (size_t i = 0; i < count; i++) {
    EC_RAW_POINT Tp;
    if (!cbs_get_raw_point(&in, group, &Tp)) {
      OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_FAILURE);
      goto err;
    }

    uint8_t s[PMBTOKEN_NONCE_SIZE];
    EC_RAW_POINT Wp, Wsp;
    uint8_t *proof = NULL;
    size_t proof_len;
    if (!pmbtoken_sign(ctx, s, &Wp, &Wsp, &proof, &proof_len, &Tp,
                       public_metadata, private_metadata)) {
      goto err;
    }

    if (!CBB_add_bytes(&response, s, PMBTOKEN_NONCE_SIZE) ||
        !cbb_add_raw_point(&response, group, &Wp) ||
        !cbb_add_raw_point(&response, group, &Wsp) ||
        !CBB_add_u16(&response, proof_len) ||
        !CBB_add_bytes(&response, proof, proof_len)) {
      OPENSSL_free(proof);
      goto err;
    }
    OPENSSL_free(proof);
  }

  *out_tokens_issued = count;

  if (!CBB_finish(&response, out, out_len)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  ret = 1;

err:
  CBB_cleanup(&response);
  return ret;
}

// https://tools.ietf.org/html/rfc7049#section-2.1
static int add_cbor_int_with_type(CBB *cbb, uint8_t major_type,
                                  uint64_t value) {
  if (value <= 23) {
    return CBB_add_u8(cbb, value | major_type);
  }
  if (value <= 0xff) {
    return CBB_add_u8(cbb, 0x18 | major_type) && CBB_add_u8(cbb, value);
  }
  if (value <= 0xffff) {
    return CBB_add_u8(cbb, 0x19 | major_type) && CBB_add_u16(cbb, value);
  }
  if (value <= 0xffffffff) {
    return CBB_add_u8(cbb, 0x1a | major_type) && CBB_add_u32(cbb, value);
  }
  if (value <= 0xffffffffffffffff) {
    return CBB_add_u8(cbb, 0x1b | major_type) && CBB_add_u64(cbb, value);
  }

  return 0;
}

// https://tools.ietf.org/html/rfc7049#section-2.1
static int add_cbor_int(CBB *cbb, uint64_t value) {
  return add_cbor_int_with_type(cbb, 0, value);
}

// https://tools.ietf.org/html/rfc7049#section-2.1
static int add_cbor_text(CBB *cbb, const char *data, size_t len) {
  return add_cbor_int_with_type(cbb, 0x60, len) &&
         CBB_add_bytes(cbb, (const uint8_t *)data, len);
}

// https://tools.ietf.org/html/rfc7049#section-2.1
static int add_cbor_map(CBB *cbb, uint8_t size) {
  return add_cbor_int_with_type(cbb, 0xa0, size);
}

static uint8_t get_metadata_obfuscator(const uint8_t *key, size_t key_len,
                                       const uint8_t *client_data,
                                       size_t client_data_len) {
  uint8_t metadata_obfuscator[SHA256_DIGEST_LENGTH];
  SHA256_CTX sha_ctx;
  SHA256_Init(&sha_ctx);
  SHA256_Update(&sha_ctx, key, key_len);
  SHA256_Update(&sha_ctx, client_data, client_data_len);
  SHA256_Final(metadata_obfuscator, &sha_ctx);
  return metadata_obfuscator[0] >> 7;
}

int TRUST_TOKEN_ISSUER_redeem(const TRUST_TOKEN_ISSUER *ctx, uint8_t **out,
                              size_t *out_len, TRUST_TOKEN **out_token,
                              uint8_t **out_client_data,
                              size_t *out_client_data_len,
                              uint64_t *out_redemption_time,
                              const uint8_t *request, size_t request_len,
                              uint64_t lifetime) {
  EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp521r1);
  if (group == NULL) {
    return 0;
  }

  CBS request_cbs, token_cbs;
  CBS_init(&request_cbs, request, request_len);
  if (!CBS_get_u16_length_prefixed(&request_cbs, &token_cbs)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_ERROR);
    return 0;
  }

  uint32_t public_metadata = 0;
  uint8_t private_metadata = 0;

  // Parse the token. If there is an error, treat it as an invalid token.
  PMBTOKEN_TOKEN pmbtoken;
  if (!CBS_get_u32(&token_cbs, &public_metadata) ||
      !CBS_copy_bytes(&token_cbs, pmbtoken.t, PMBTOKEN_NONCE_SIZE) ||
      !cbs_get_raw_point(&token_cbs, group, &pmbtoken.S) ||
      !cbs_get_raw_point(&token_cbs, group, &pmbtoken.W) ||
      !cbs_get_raw_point(&token_cbs, group, &pmbtoken.Ws) ||
      CBS_len(&token_cbs) != 0 ||
      !pmbtoken_read(ctx, &private_metadata, &pmbtoken, public_metadata)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_INVALID_TOKEN);
    return 0;
  }

  int ok = 0;
  CBB response, srr;
  uint8_t *srr_buf = NULL, *sig_buf = NULL, *client_data_buf = NULL;
  size_t srr_len = 0, sig_len = 0, client_data_len = 0;
  EVP_MD_CTX md_ctx;
  EVP_MD_CTX_init(&md_ctx);
  CBB_zero(&srr);
  if (!CBB_init(&response, 0)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  CBS client_data;
  uint64_t redemption_time;
  if (!CBS_get_u16_length_prefixed(&request_cbs, &client_data) ||
      !CBS_get_u64(&request_cbs, &redemption_time)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_DECODE_ERROR);
    goto err;
  }

  uint8_t metadata_obfuscator =
      get_metadata_obfuscator(ctx->metadata_key, ctx->metadata_key_len,
                              CBS_data(&client_data), CBS_len(&client_data));

  // The SRR is constructed as per the format described in
  // https://docs.google.com/document/d/1TNnya6B8pyomDK2F1R9CL3dY10OAmqWlnCxsWyOBDVQ/edit#heading=h.7mkzvhpqb8l5

  static const char kClientDataLabel[] = "client-data";
  static const char kExpiryTimestampLabel[] = "expiry-timestamp";
  static const char kMetadataLabel[] = "metadata";
  static const char kPrivateLabel[] = "private";
  static const char kPublicLabel[] = "public";

  // CBOR requires map keys to be sorted by length then sorted lexically.
  // https://tools.ietf.org/html/rfc7049#section-3.9
  assert(strlen(kMetadataLabel) < strlen(kClientDataLabel));
  assert(strlen(kClientDataLabel) < strlen(kExpiryTimestampLabel));
  assert(strlen(kPublicLabel) < strlen(kPrivateLabel));

  if (!CBB_init(&srr, 0) ||
      !add_cbor_map(&srr, 3) ||  // SRR map
      !add_cbor_text(&srr, kMetadataLabel, strlen(kMetadataLabel)) ||
      !add_cbor_map(&srr, 2) ||  // Metadata map
      !add_cbor_text(&srr, kPublicLabel, strlen(kPublicLabel)) ||
      !add_cbor_int(&srr, public_metadata) ||
      !add_cbor_text(&srr, kPrivateLabel, strlen(kPrivateLabel)) ||
      !add_cbor_int(&srr, private_metadata ^ metadata_obfuscator) ||
      !add_cbor_text(&srr, kClientDataLabel, strlen(kClientDataLabel)) ||
      !CBB_add_bytes(&srr, CBS_data(&client_data), CBS_len(&client_data)) ||
      !add_cbor_text(&srr, kExpiryTimestampLabel,
                     strlen(kExpiryTimestampLabel)) ||
      !add_cbor_int(&srr, redemption_time + lifetime) ||
      !CBB_finish(&srr, &srr_buf, &srr_len)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  if (!EVP_DigestSignInit(&md_ctx, NULL, NULL, NULL, ctx->srr_key) ||
      !EVP_DigestSign(&md_ctx, NULL, &sig_len, srr_buf, srr_len)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_SRR_SIGNATURE_ERROR);
    goto err;
  }

  CBB child;
  uint8_t *ptr;
  if (!CBB_add_u16_length_prefixed(&response, &child) ||
      !CBB_add_bytes(&child, srr_buf, srr_len) ||
      !CBB_add_u16_length_prefixed(&response, &child) ||
      !CBB_reserve(&child, &ptr, sig_len) ||
      !EVP_DigestSign(&md_ctx, ptr, &sig_len, srr_buf, srr_len) ||
      !CBB_did_write(&child, sig_len)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  if (!CBS_stow(&client_data, &client_data_buf, &client_data_len) ||
      !CBB_finish(&response, out, out_len)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  TRUST_TOKEN *token = TRUST_TOKEN_new(pmbtoken.t, PMBTOKEN_NONCE_SIZE);
  if (token == NULL) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    goto err;
  }
  *out_token = token;
  *out_client_data = client_data_buf;
  *out_client_data_len = client_data_len;
  *out_redemption_time = redemption_time;

  ok = 1;

err:
  CBB_cleanup(&response);
  CBB_cleanup(&srr);
  OPENSSL_free(srr_buf);
  OPENSSL_free(sig_buf);
  EVP_MD_CTX_cleanup(&md_ctx);
  if (!ok) {
    OPENSSL_free(client_data_buf);
  }
  return ok;
}

int TRUST_TOKEN_decode_private_metadata(uint8_t *out_value, const uint8_t *key,
                                        size_t key_len,
                                        const uint8_t *client_data,
                                        size_t client_data_len,
                                        uint8_t encrypted_bit) {
  uint8_t metadata_obfuscator =
      get_metadata_obfuscator(key, key_len, client_data, client_data_len);
  *out_value = encrypted_bit ^ metadata_obfuscator;
  return 1;
}
