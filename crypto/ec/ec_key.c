/* Originally written by Bodo Moeller for the OpenSSL project.
 * ====================================================================
 * Copyright (c) 1998-2005 The OpenSSL Project.  All rights reserved.
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
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 *
 * Portions of the attached software ("Contribution") are developed by
 * SUN MICROSYSTEMS, INC., and are contributed to the OpenSSL project.
 *
 * The Contribution is licensed pursuant to the OpenSSL open source
 * license provided above.
 *
 * The elliptic curve binary polynomial software is originally written by
 * Sheueling Chang Shantz and Douglas Stebila of Sun Microsystems
 * Laboratories. */

#include <openssl/ec_key.h>

#include <string.h>

#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/thread.h>

#include "internal.h"
#include "../internal.h"


EC_KEY *EC_KEY_new_ex(EC_GROUP_new_fn ec_group_new) {
  EC_KEY *ret = (EC_KEY *)OPENSSL_malloc(sizeof(EC_KEY));
  if (ret == NULL) {
    OPENSSL_PUT_ERROR(EC, ERR_R_MALLOC_FAILURE);
    return NULL;
  }

  memset(ret, 0, sizeof(EC_KEY));

  ret->group = ec_group_new();
  if (ret->group == NULL) {
    OPENSSL_free(ret);
    return NULL;
  }

  ret->references = 1;

  return ret;
}

void EC_KEY_free(EC_KEY *r) {
  if (r == NULL) {
    return;
  }

  if (!CRYPTO_refcount_dec_and_test_zero(&r->references)) {
    return;
  }

  EC_GROUP_free(r->group);
  EC_POINT_free(r->pub_key);
  BN_clear_free(r->priv_key);

  OPENSSL_cleanse((void *)r, sizeof(EC_KEY));
  OPENSSL_free(r);
}

int EC_KEY_up_ref(EC_KEY *r) {
  CRYPTO_refcount_inc(&r->references);
  return 1;
}

const EC_GROUP *EC_KEY_get0_group(const EC_KEY *key) { return key->group; }

const BIGNUM *EC_KEY_get0_private_key(const EC_KEY *key) {
  return key->priv_key;
}

const EC_POINT *EC_KEY_get0_public_key(const EC_KEY *key) {
  return key->pub_key;
}

int EC_KEY_set_public_key(EC_KEY *key, const EC_POINT *pub_key) {
  EC_POINT_free(key->pub_key);
  key->pub_key = EC_POINT_dup(pub_key, key->group);
  return (key->pub_key == NULL) ? 0 : 1;
}

int EC_KEY_check_key(const EC_KEY *eckey) {
  int ok = 0;
  BN_CTX *ctx = NULL;
  const BIGNUM *order = NULL;
  EC_POINT *point = NULL;

  if (!eckey || !eckey->group || !eckey->pub_key) {
    OPENSSL_PUT_ERROR(EC, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }

  if (EC_POINT_is_at_infinity(eckey->group, eckey->pub_key)) {
    OPENSSL_PUT_ERROR(EC, EC_R_POINT_AT_INFINITY);
    goto err;
  }

  ctx = BN_CTX_new();
  point = EC_POINT_new(eckey->group);

  if (ctx == NULL ||
      point == NULL) {
    goto err;
  }

  /* testing whether the pub_key is on the elliptic curve */
  if (!EC_POINT_is_on_curve(eckey->group, eckey->pub_key, ctx)) {
    OPENSSL_PUT_ERROR(EC, EC_R_POINT_IS_NOT_ON_CURVE);
    goto err;
  }
  /* testing whether pub_key * order is the point at infinity */
  /* TODO(fork): can this be skipped if the cofactor is one or if we're about
   * to check the private key, below? */
  order = &eckey->group->order;
  if (BN_is_zero(order)) {
    OPENSSL_PUT_ERROR(EC, EC_R_INVALID_GROUP_ORDER);
    goto err;
  }
  if (!EC_POINT_mul(eckey->group, point, NULL, eckey->pub_key, order, ctx)) {
    OPENSSL_PUT_ERROR(EC, ERR_R_EC_LIB);
    goto err;
  }
  if (!EC_POINT_is_at_infinity(eckey->group, point)) {
    OPENSSL_PUT_ERROR(EC, EC_R_WRONG_ORDER);
    goto err;
  }
  /* in case the priv_key is present :
   * check if generator * priv_key == pub_key
   */
  if (eckey->priv_key) {
    if (BN_cmp(eckey->priv_key, order) >= 0) {
      OPENSSL_PUT_ERROR(EC, EC_R_WRONG_ORDER);
      goto err;
    }
    if (!EC_POINT_mul(eckey->group, point, eckey->priv_key, NULL, NULL, ctx)) {
      OPENSSL_PUT_ERROR(EC, ERR_R_EC_LIB);
      goto err;
    }
    if (EC_POINT_cmp(eckey->group, point, eckey->pub_key, ctx) != 0) {
      OPENSSL_PUT_ERROR(EC, EC_R_INVALID_PRIVATE_KEY);
      goto err;
    }
  }
  ok = 1;

err:
  BN_CTX_free(ctx);
  EC_POINT_free(point);
  return ok;
}

int EC_KEY_generate_key(EC_KEY *eckey) {
  int ok = 0;
  BN_CTX *ctx = NULL;
  BIGNUM *priv_key = NULL, *order = NULL;
  EC_POINT *pub_key = NULL;

  if (!eckey || !eckey->group) {
    OPENSSL_PUT_ERROR(EC, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }

  order = BN_new();
  ctx = BN_CTX_new();

  if (order == NULL ||
      ctx == NULL) {
    goto err;
  }

  if (eckey->priv_key == NULL) {
    priv_key = BN_new();
    if (priv_key == NULL) {
      goto err;
    }
  } else {
    priv_key = eckey->priv_key;
  }

  if (!EC_GROUP_get_order(eckey->group, order, ctx)) {
    goto err;
  }

  do {
    if (!BN_rand_range(priv_key, order)) {
      goto err;
    }
  } while (BN_is_zero(priv_key));

  if (eckey->pub_key == NULL) {
    pub_key = EC_POINT_new(eckey->group);
    if (pub_key == NULL) {
      goto err;
    }
  } else {
    pub_key = eckey->pub_key;
  }

  if (!EC_POINT_mul(eckey->group, pub_key, priv_key, NULL, NULL, ctx)) {
    goto err;
  }

  eckey->priv_key = priv_key;
  eckey->pub_key = pub_key;

  ok = 1;

err:
  BN_free(order);
  if (eckey->pub_key == NULL) {
    EC_POINT_free(pub_key);
  }
  if (eckey->priv_key == NULL) {
    BN_free(priv_key);
  }
  BN_CTX_free(ctx);
  return ok;
}

EC_KEY *EC_KEY_generate_key_ex(EC_GROUP_new_fn ec_group_new) {
  EC_KEY *key = EC_KEY_new_ex(ec_group_new);
  if (!key) {
    return NULL;
  }
  if (!EC_KEY_generate_key(key)) {
    EC_KEY_free(key);
    return NULL;
  }
  return key;
}

size_t EC_KEY_public_key_to_oct(const EC_KEY *key, uint8_t *out, size_t out_len) {
  return EC_POINT_point2oct(EC_KEY_get0_group(key), EC_KEY_get0_public_key(key),
                            POINT_CONVERSION_UNCOMPRESSED, out, out_len, NULL);
}
