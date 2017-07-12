/* Copyright (c) 2015, Google Inc.
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

#include <openssl/ssl.h>

#include <assert.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/bytestring.h>
#include <openssl/curve25519.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/nid.h>

#include "internal.h"
#include "../crypto/internal.h"


/* |EC_POINT| implementation. */

static void ssl_ec_point_cleanup(SSL_ECDH_CTX *ctx) {
  BIGNUM *private_key = (BIGNUM *)ctx->data;
  BN_clear_free(private_key);
}

static int ssl_ec_point_offer(SSL_ECDH_CTX *ctx, CBB *out) {
  /* Set up a shared |BN_CTX| for all operations. */
  bssl::UniquePtr<BN_CTX> bn_ctx(BN_CTX_new());
  if (!bn_ctx) {
    return 0;
  }
  bssl::BN_CTXScope scope(bn_ctx.get());

  /* Generate a private key. */
  bssl::UniquePtr<EC_GROUP> group(EC_GROUP_new_by_curve_name(ctx->method->nid));
  bssl::UniquePtr<BIGNUM> private_key(BN_new());
  if (!group || !private_key ||
      !BN_rand_range_ex(private_key.get(), 1,
                        EC_GROUP_get0_order(group.get()))) {
    return 0;
  }

  /* Compute the corresponding public key and serialize it. */
  bssl::UniquePtr<EC_POINT> public_key(EC_POINT_new(group.get()));
  if (!public_key ||
      !EC_POINT_mul(group.get(), public_key.get(), private_key.get(), NULL,
                    NULL, bn_ctx.get()) ||
      !EC_POINT_point2cbb(out, group.get(), public_key.get(),
                          POINT_CONVERSION_UNCOMPRESSED, bn_ctx.get())) {
    return 0;
  }

  assert(ctx->data == NULL);
  ctx->data = private_key.release();
  return 1;
}

static int ssl_ec_point_finish(SSL_ECDH_CTX *ctx, uint8_t **out_secret,
                               size_t *out_secret_len, uint8_t *out_alert,
                               const uint8_t *peer_key, size_t peer_key_len) {
  BIGNUM *private_key = (BIGNUM *)ctx->data;
  assert(private_key != NULL);
  *out_alert = SSL_AD_INTERNAL_ERROR;

  /* Set up a shared |BN_CTX| for all operations. */
  bssl::UniquePtr<BN_CTX> bn_ctx(BN_CTX_new());
  if (!bn_ctx) {
    return 0;
  }
  bssl::BN_CTXScope scope(bn_ctx.get());

  bssl::UniquePtr<EC_GROUP> group(EC_GROUP_new_by_curve_name(ctx->method->nid));
  if (!group) {
    return 0;
  }

  bssl::UniquePtr<EC_POINT> peer_point(EC_POINT_new(group.get()));
  bssl::UniquePtr<EC_POINT> result(EC_POINT_new(group.get()));
  BIGNUM *x = BN_CTX_get(bn_ctx.get());
  if (!peer_point || !result || !x) {
    return 0;
  }

  if (!EC_POINT_oct2point(group.get(), peer_point.get(), peer_key, peer_key_len,
                          bn_ctx.get())) {
    *out_alert = SSL_AD_DECODE_ERROR;
    return 0;
  }

  /* Compute the x-coordinate of |peer_key| * |private_key|. */
  if (!EC_POINT_mul(group.get(), result.get(), NULL, peer_point.get(),
                    private_key, bn_ctx.get()) ||
      !EC_POINT_get_affine_coordinates_GFp(group.get(), result.get(), x, NULL,
                                           bn_ctx.get())) {
    return 0;
  }

  /* Encode the x-coordinate left-padded with zeros. */
  size_t secret_len = (EC_GROUP_get_degree(group.get()) + 7) / 8;
  bssl::UniquePtr<uint8_t> secret((uint8_t *)OPENSSL_malloc(secret_len));
  if (!secret || !BN_bn2bin_padded(secret.get(), secret_len, x)) {
    return 0;
  }

  *out_secret = secret.release();
  *out_secret_len = secret_len;
  return 1;
}

static int ssl_ec_point_accept(SSL_ECDH_CTX *ctx, CBB *out_public_key,
                               uint8_t **out_secret, size_t *out_secret_len,
                               uint8_t *out_alert, const uint8_t *peer_key,
                               size_t peer_key_len) {
  *out_alert = SSL_AD_INTERNAL_ERROR;
  if (!ssl_ec_point_offer(ctx, out_public_key) ||
      !ssl_ec_point_finish(ctx, out_secret, out_secret_len, out_alert, peer_key,
                           peer_key_len)) {
    return 0;
  }
  return 1;
}

/* X25119 implementation. */

static void ssl_x25519_cleanup(SSL_ECDH_CTX *ctx) {
  if (ctx->data == NULL) {
    return;
  }
  OPENSSL_cleanse(ctx->data, 32);
  OPENSSL_free(ctx->data);
}

static int ssl_x25519_offer(SSL_ECDH_CTX *ctx, CBB *out) {
  assert(ctx->data == NULL);

  ctx->data = OPENSSL_malloc(32);
  if (ctx->data == NULL) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
    return 0;
  }
  uint8_t public_key[32];
  X25519_keypair(public_key, (uint8_t *)ctx->data);
  return CBB_add_bytes(out, public_key, sizeof(public_key));
}

static int ssl_x25519_finish(SSL_ECDH_CTX *ctx, uint8_t **out_secret,
                             size_t *out_secret_len, uint8_t *out_alert,
                             const uint8_t *peer_key, size_t peer_key_len) {
  assert(ctx->data != NULL);
  *out_alert = SSL_AD_INTERNAL_ERROR;

  uint8_t *secret = (uint8_t *)OPENSSL_malloc(32);
  if (secret == NULL) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
    return 0;
  }

  if (peer_key_len != 32 ||
      !X25519(secret, (uint8_t *)ctx->data, peer_key)) {
    OPENSSL_free(secret);
    *out_alert = SSL_AD_DECODE_ERROR;
    OPENSSL_PUT_ERROR(SSL, SSL_R_BAD_ECPOINT);
    return 0;
  }

  *out_secret = secret;
  *out_secret_len = 32;
  return 1;
}

static int ssl_x25519_accept(SSL_ECDH_CTX *ctx, CBB *out_public_key,
                             uint8_t **out_secret, size_t *out_secret_len,
                             uint8_t *out_alert, const uint8_t *peer_key,
                             size_t peer_key_len) {
  *out_alert = SSL_AD_INTERNAL_ERROR;
  if (!ssl_x25519_offer(ctx, out_public_key) ||
      !ssl_x25519_finish(ctx, out_secret, out_secret_len, out_alert, peer_key,
                         peer_key_len)) {
    return 0;
  }
  return 1;
}


static const SSL_ECDH_METHOD kMethods[] = {
    {
        NID_secp224r1,
        SSL_CURVE_SECP224R1,
        "P-224",
        ssl_ec_point_cleanup,
        ssl_ec_point_offer,
        ssl_ec_point_accept,
        ssl_ec_point_finish,
    },
    {
        NID_X9_62_prime256v1,
        SSL_CURVE_SECP256R1,
        "P-256",
        ssl_ec_point_cleanup,
        ssl_ec_point_offer,
        ssl_ec_point_accept,
        ssl_ec_point_finish,
    },
    {
        NID_secp384r1,
        SSL_CURVE_SECP384R1,
        "P-384",
        ssl_ec_point_cleanup,
        ssl_ec_point_offer,
        ssl_ec_point_accept,
        ssl_ec_point_finish,
    },
    {
        NID_secp521r1,
        SSL_CURVE_SECP521R1,
        "P-521",
        ssl_ec_point_cleanup,
        ssl_ec_point_offer,
        ssl_ec_point_accept,
        ssl_ec_point_finish,
    },
    {
        NID_X25519,
        SSL_CURVE_X25519,
        "X25519",
        ssl_x25519_cleanup,
        ssl_x25519_offer,
        ssl_x25519_accept,
        ssl_x25519_finish,
    },
};

static const SSL_ECDH_METHOD *method_from_group_id(uint16_t group_id) {
  for (size_t i = 0; i < OPENSSL_ARRAY_SIZE(kMethods); i++) {
    if (kMethods[i].group_id == group_id) {
      return &kMethods[i];
    }
  }
  return NULL;
}

static const SSL_ECDH_METHOD *method_from_nid(int nid) {
  for (size_t i = 0; i < OPENSSL_ARRAY_SIZE(kMethods); i++) {
    if (kMethods[i].nid == nid) {
      return &kMethods[i];
    }
  }
  return NULL;
}

static const SSL_ECDH_METHOD *method_from_name(const char *name, size_t len) {
  for (size_t i = 0; i < OPENSSL_ARRAY_SIZE(kMethods); i++) {
    if (len == strlen(kMethods[i].name) &&
        !strncmp(kMethods[i].name, name, len)) {
      return &kMethods[i];
    }
  }
  return NULL;
}

const char* SSL_get_curve_name(uint16_t group_id) {
  const SSL_ECDH_METHOD *method = method_from_group_id(group_id);
  if (method == NULL) {
    return NULL;
  }
  return method->name;
}

int ssl_nid_to_group_id(uint16_t *out_group_id, int nid) {
  const SSL_ECDH_METHOD *method = method_from_nid(nid);
  if (method == NULL) {
    return 0;
  }
  *out_group_id = method->group_id;
  return 1;
}

int ssl_name_to_group_id(uint16_t *out_group_id, const char *name, size_t len) {
  const SSL_ECDH_METHOD *method = method_from_name(name, len);
  if (method == NULL) {
    return 0;
  }
  *out_group_id = method->group_id;
  return 1;
}

int SSL_ECDH_CTX_init(SSL_ECDH_CTX *ctx, uint16_t group_id) {
  SSL_ECDH_CTX_cleanup(ctx);

  const SSL_ECDH_METHOD *method = method_from_group_id(group_id);
  if (method == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_UNSUPPORTED_ELLIPTIC_CURVE);
    return 0;
  }
  ctx->method = method;
  return 1;
}

void SSL_ECDH_CTX_cleanup(SSL_ECDH_CTX *ctx) {
  if (ctx->method == NULL) {
    return;
  }
  ctx->method->cleanup(ctx);
  ctx->method = NULL;
  ctx->data = NULL;
}

uint16_t SSL_ECDH_CTX_get_id(const SSL_ECDH_CTX *ctx) {
  return ctx->method->group_id;
}

int SSL_ECDH_CTX_offer(SSL_ECDH_CTX *ctx, CBB *out_public_key) {
  return ctx->method->offer(ctx, out_public_key);
}

int SSL_ECDH_CTX_accept(SSL_ECDH_CTX *ctx, CBB *out_public_key,
                        uint8_t **out_secret, size_t *out_secret_len,
                        uint8_t *out_alert, const uint8_t *peer_key,
                        size_t peer_key_len) {
  return ctx->method->accept(ctx, out_public_key, out_secret, out_secret_len,
                             out_alert, peer_key, peer_key_len);
}

int SSL_ECDH_CTX_finish(SSL_ECDH_CTX *ctx, uint8_t **out_secret,
                        size_t *out_secret_len, uint8_t *out_alert,
                        const uint8_t *peer_key, size_t peer_key_len) {
  return ctx->method->finish(ctx, out_secret, out_secret_len, out_alert,
                             peer_key, peer_key_len);
}
