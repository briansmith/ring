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

#include <assert.h>
#include <string.h>

#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/mem.h>

#include "internal.h"
#include "../internal.h"


/* Prototypes for code only called from Rust, to avoid -Wmissing-prototypes
 * warnings. */
EC_KEY *ec_key_new_ex(const EC_GROUP *group);

EC_KEY *ec_key_new_ex(const EC_GROUP *group) {
  EC_KEY *ret = OPENSSL_malloc(sizeof(EC_KEY));
  if (ret == NULL) {
    OPENSSL_PUT_ERROR(EC, ERR_R_MALLOC_FAILURE);
    return NULL;
  }

  memset(ret, 0, sizeof(EC_KEY));

  ret->group = group;

  return ret;
}

void EC_KEY_free(EC_KEY *r) {
  if (r == NULL) {
    return;
  }

  EC_POINT_free(r->pub_key);
  BN_free(r->priv_key);

  OPENSSL_free(r);
}

const EC_GROUP *EC_KEY_get0_group(const EC_KEY *key) { return key->group; }

const BIGNUM *EC_KEY_get0_private_key(const EC_KEY *key) {
  return key->priv_key;
}

const EC_POINT *EC_KEY_get0_public_key(const EC_KEY *key) {
  return key->pub_key;
}

int EC_KEY_check_key(const EC_KEY *eckey) {
  int ok = 0;
  BN_CTX *ctx = NULL;
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

  if (ctx == NULL) {
    goto err;
  }

  /* testing whether the pub_key is on the elliptic curve */
  if (!EC_POINT_is_on_curve(eckey->group, eckey->pub_key, ctx)) {
    OPENSSL_PUT_ERROR(EC, EC_R_POINT_IS_NOT_ON_CURVE);
    goto err;
  }

  /* BoringSSL has a check here that pub_key * order is the point at infinity.
   * That check isn't needed for the curves *ring* supports because all of the
   * curves *ring* supports have cofactor 1 and prime order; see section A.3 of
   * the NSA's "Suite B Implementer's Guide to FIPS 186-3 (ECDSA)". */

  /* in case the priv_key is present :
   * check if generator * priv_key == pub_key
   */
  if (eckey->priv_key) {
    /* XXX: |BN_cmp| is not constant time. */
    if (BN_cmp(eckey->priv_key, &eckey->group->order) >= 0) {
      OPENSSL_PUT_ERROR(EC, EC_R_WRONG_ORDER);
      goto err;
    }
    point = EC_POINT_new(eckey->group);
    if (point == NULL ||
        !eckey->group->meth->mul_private(eckey->group, point, eckey->priv_key,
                                         NULL, NULL, ctx)) {
      OPENSSL_PUT_ERROR(EC, ERR_R_EC_LIB);
      goto err;
    }
    BIGNUM *point_x = BN_CTX_get(ctx);
    BIGNUM *point_y = BN_CTX_get(ctx);
    BIGNUM *pub_key_x = BN_CTX_get(ctx);
    BIGNUM *pub_key_y = BN_CTX_get(ctx);
    if (point_x == NULL ||
        point_y == NULL ||
        pub_key_x == NULL ||
        pub_key_y == NULL) {
      OPENSSL_PUT_ERROR(EC, ERR_R_BN_LIB);
      goto err;
    }
    if (BN_cmp(point_x, pub_key_x) != 0 ||
        BN_cmp(point_y, pub_key_y) != 0) {
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

EC_KEY *EC_KEY_generate_key_ex(const EC_GROUP *group) {
  EC_KEY *eckey = ec_key_new_ex(group);
  if (!eckey) {
    return NULL;
  }

  assert(eckey->priv_key == NULL);
  eckey->priv_key = BN_new();
  if (eckey->priv_key == NULL) {
    goto err;
  }

  do {
    if (!BN_rand_range(eckey->priv_key, &eckey->group->order)) {
      goto err;
    }
  } while (BN_is_zero(eckey->priv_key));

  assert(eckey->pub_key == NULL);
  eckey->pub_key = EC_POINT_new(eckey->group);
  if (eckey->pub_key == NULL) {
    goto err;
  }

  if (!eckey->group->meth->mul_private(eckey->group, eckey->pub_key,
                                       eckey->priv_key, NULL, NULL, NULL)) {
    goto err;
  }

  return eckey;

err:
  EC_KEY_free(eckey);
  return NULL;
}

size_t EC_KEY_public_key_to_oct(const EC_KEY *key, uint8_t *out, size_t out_len) {
  return EC_POINT_point2oct(EC_KEY_get0_group(key), EC_KEY_get0_public_key(key),
                            out, out_len, NULL);
}
