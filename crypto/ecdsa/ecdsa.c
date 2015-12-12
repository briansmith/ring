/* ====================================================================
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
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
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
 * Hudson (tjh@cryptsoft.com). */

#include <openssl/ecdsa.h>

#include <assert.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/bytestring.h>
#include <openssl/err.h>
#include <openssl/mem.h>

#include "../ec/internal.h"


int ECDSA_verify_signed_digest(const EC_GROUP *group, int hash_nid,
                               const uint8_t *digest, size_t digest_len,
                               const uint8_t *sig, size_t sig_len,
                               const uint8_t *ec_key, const size_t ec_key_len) {
  int ret = 0;
  ECDSA_SIG *s = NULL;

  EC_POINT *point = EC_POINT_new(group);
  if (!point ||
      !EC_POINT_oct2point(group, point, ec_key, ec_key_len, NULL)) {
    goto err;
  }

  s = ECDSA_SIG_from_bytes(sig, sig_len);
  if (s == NULL) {
    goto err;
  }

  ret = ECDSA_do_verify_point(digest, digest_len, s, group, point);

err:
  ECDSA_SIG_free(s);
  EC_POINT_free(point);

  return ret;
}

/* digest_to_bn interprets |digest_len| bytes from |digest| as a big-endian
 * number and sets |out| to that value. It then truncates |out| so that it's,
 * at most, as long as |order|. It returns one on success and zero otherwise. */
static int digest_to_bn(BIGNUM *out, const uint8_t *digest, size_t digest_len,
                        const BIGNUM *order) {
  size_t num_bits;

  num_bits = BN_num_bits(order);
  /* Need to truncate digest if it is too long: first truncate whole
   * bytes. */
  if (8 * digest_len > num_bits) {
    digest_len = (num_bits + 7) / 8;
  }
  if (!BN_bin2bn(digest, digest_len, out)) {
    OPENSSL_PUT_ERROR(ECDSA, ERR_R_BN_LIB);
    return 0;
  }

  /* If still too long truncate remaining bits with a shift */
  if ((8 * digest_len > num_bits) &&
      !BN_rshift(out, out, 8 - (num_bits & 0x7))) {
    OPENSSL_PUT_ERROR(ECDSA, ERR_R_BN_LIB);
    return 0;
  }

  return 1;
}

int ECDSA_do_verify_point(const uint8_t *digest, size_t digest_len,
                          const ECDSA_SIG *sig, const EC_GROUP *group,
                          const EC_POINT *pub_key) {
  int ret = 0;
  BN_CTX *ctx;
  BIGNUM *u1, *u2, *m, *X;
  EC_POINT *point = NULL;

  /* check input values */
  ctx = BN_CTX_new();
  if (!ctx) {
    OPENSSL_PUT_ERROR(ECDSA, ERR_R_MALLOC_FAILURE);
    return 0;
  }
  BN_CTX_start(ctx);
  u1 = BN_CTX_get(ctx);
  u2 = BN_CTX_get(ctx);
  m = BN_CTX_get(ctx);
  X = BN_CTX_get(ctx);
  if (u1 == NULL || u2 == NULL || m == NULL || X == NULL) {
    OPENSSL_PUT_ERROR(ECDSA, ERR_R_BN_LIB);
    goto err;
  }

  if (BN_is_zero(sig->r) || BN_is_negative(sig->r) ||
      BN_ucmp(sig->r, &group->order) >= 0 || BN_is_zero(sig->s) ||
      BN_is_negative(sig->s) || BN_ucmp(sig->s, &group->order) >= 0) {
    OPENSSL_PUT_ERROR(ECDSA, ECDSA_R_BAD_SIGNATURE);
    ret = 0; /* signature is invalid */
    goto err;
  }
  /* calculate tmp1 = inv(S) mod order */
  if (!BN_mod_inverse(u2, sig->s, &group->order, ctx)) {
    OPENSSL_PUT_ERROR(ECDSA, ERR_R_BN_LIB);
    goto err;
  }
  if (!digest_to_bn(m, digest, digest_len, &group->order)) {
    goto err;
  }
  /* u1 = m * tmp mod order */
  if (!BN_mod_mul(u1, m, u2, &group->order, ctx)) {
    OPENSSL_PUT_ERROR(ECDSA, ERR_R_BN_LIB);
    goto err;
  }
  /* u2 = r * w mod q */
  if (!BN_mod_mul(u2, sig->r, u2, &group->order, ctx)) {
    OPENSSL_PUT_ERROR(ECDSA, ERR_R_BN_LIB);
    goto err;
  }

  point = EC_POINT_new(group);
  if (point == NULL) {
    OPENSSL_PUT_ERROR(ECDSA, ERR_R_MALLOC_FAILURE);
    goto err;
  }
  if (!group->meth->mul_public(group, point, u1, pub_key, u2, ctx)) {
    OPENSSL_PUT_ERROR(ECDSA, ERR_R_EC_LIB);
    goto err;
  }
  if (!EC_POINT_get_affine_coordinates_GFp(group, point, X, NULL, ctx)) {
    OPENSSL_PUT_ERROR(ECDSA, ERR_R_EC_LIB);
    goto err;
  }
  if (!BN_nnmod(u1, X, &group->order, ctx)) {
    OPENSSL_PUT_ERROR(ECDSA, ERR_R_BN_LIB);
    goto err;
  }
  /* if the signature is correct u1 is equal to sig->r */
  ret = (BN_ucmp(u1, sig->r) == 0);

err:
  BN_CTX_end(ctx);
  BN_CTX_free(ctx);
  EC_POINT_free(point);
  return ret;
}

static int ecdsa_sign_setup(EC_KEY *eckey, BN_CTX *ctx, BIGNUM **kinvp,
                            BIGNUM **rp, const uint8_t *digest,
                            size_t digest_len) {
  BIGNUM *k = NULL, *r = NULL, *X = NULL;
  EC_POINT *tmp_point = NULL;
  const EC_GROUP *group;
  int ret = 0;

  if (eckey == NULL || (group = EC_KEY_get0_group(eckey)) == NULL) {
    OPENSSL_PUT_ERROR(ECDSA, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }

  k = BN_new(); /* this value is later returned in *kinvp */
  r = BN_new(); /* this value is later returned in *rp    */
  X = BN_new();
  if (k == NULL || r == NULL || X == NULL) {
    OPENSSL_PUT_ERROR(ECDSA, ERR_R_MALLOC_FAILURE);
    goto err;
  }
  tmp_point = EC_POINT_new(group);
  if (tmp_point == NULL) {
    OPENSSL_PUT_ERROR(ECDSA, ERR_R_EC_LIB);
    goto err;
  }

  do {
    do {
      if (!BN_generate_dsa_nonce(k, &group->order,
                                 EC_KEY_get0_private_key(eckey), digest,
                                 digest_len, ctx)) {
        OPENSSL_PUT_ERROR(ECDSA, ECDSA_R_RANDOM_NUMBER_GENERATION_FAILED);
        goto err;
      }
    } while (BN_is_zero(k));

    /* compute r the x-coordinate of generator * k */
    if (!group->meth->mul_private(group, tmp_point, k, NULL, NULL, ctx)) {
      OPENSSL_PUT_ERROR(ECDSA, ERR_R_EC_LIB);
      goto err;
    }
    if (!EC_POINT_get_affine_coordinates_GFp(group, tmp_point, X, NULL, ctx)) {
      OPENSSL_PUT_ERROR(ECDSA, ERR_R_EC_LIB);
      goto err;
    }

    if (!BN_nnmod(r, X, &group->order, ctx)) {
      OPENSSL_PUT_ERROR(ECDSA, ERR_R_BN_LIB);
      goto err;
    }
  } while (BN_is_zero(r));

  /* Compute the inverse of k. We want inverse in constant time, therefore we
   * use Fermat's Little Theorem, which works because the subgroup order is
   * prime.
   *
   * XXX: This isn't perfectly constant-time because the implementation of
   * BN_mod_exp_mont_consttime isn't perfectly constant time. */
  if (!BN_mod_exp_mont_consttime(k, k, &group->order_minus_2, &group->order,
                                 ctx, &group->order_mont)) {
    OPENSSL_PUT_ERROR(ECDSA, ERR_R_BN_LIB);
    goto err;
  }

  /* clear old values if necessary */
  BN_clear_free(*rp);
  BN_clear_free(*kinvp);

  /* save the pre-computed values  */
  *rp = r;
  *kinvp = k;
  ret = 1;

err:
  if (!ret) {
    BN_clear_free(k);
    BN_clear_free(r);
  }
  EC_POINT_free(tmp_point);
  BN_clear_free(X);
  return ret;
}

ECDSA_SIG *ECDSA_do_sign(const uint8_t *digest, size_t digest_len,
                         EC_KEY *eckey) {
  int ok = 0;
  BIGNUM *kinv = NULL, *s, *m = NULL, *tmp = NULL;
  const BIGNUM *ckinv;
  BN_CTX *ctx = NULL;
  const EC_GROUP *group;
  ECDSA_SIG *ret;
  const BIGNUM *priv_key;

  group = EC_KEY_get0_group(eckey);
  priv_key = EC_KEY_get0_private_key(eckey);

  if (group == NULL || priv_key == NULL) {
    OPENSSL_PUT_ERROR(ECDSA, ERR_R_PASSED_NULL_PARAMETER);
    return NULL;
  }

  ret = ECDSA_SIG_new();
  if (!ret) {
    OPENSSL_PUT_ERROR(ECDSA, ERR_R_MALLOC_FAILURE);
    return NULL;
  }
  s = ret->s;

  if ((ctx = BN_CTX_new()) == NULL ||
      (tmp = BN_new()) == NULL || (m = BN_new()) == NULL) {
    OPENSSL_PUT_ERROR(ECDSA, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  if (!digest_to_bn(m, digest, digest_len, &group->order)) {
    goto err;
  }
  for (;;) {
    if (!ecdsa_sign_setup(eckey, ctx, &kinv, &ret->r, digest, digest_len)) {
      OPENSSL_PUT_ERROR(ECDSA, ERR_R_ECDSA_LIB);
      goto err;
    }
    ckinv = kinv;

    if (!BN_mod_mul(tmp, priv_key, ret->r, &group->order, ctx)) {
      OPENSSL_PUT_ERROR(ECDSA, ERR_R_BN_LIB);
      goto err;
    }
    if (!BN_mod_add_quick(s, tmp, m, &group->order)) {
      OPENSSL_PUT_ERROR(ECDSA, ERR_R_BN_LIB);
      goto err;
    }
    if (!BN_mod_mul(s, s, ckinv, &group->order, ctx)) {
      OPENSSL_PUT_ERROR(ECDSA, ERR_R_BN_LIB);
      goto err;
    }
    if (!BN_is_zero(s)) {
      /* s != 0 => we have a valid signature */
      break;
    }
  }

  ok = 1;

err:
  if (!ok) {
    ECDSA_SIG_free(ret);
    ret = NULL;
  }
  BN_CTX_free(ctx);
  BN_clear_free(m);
  BN_clear_free(tmp);
  BN_clear_free(kinv);
  return ret;
}

int ECDSA_sign(int type, const uint8_t *digest, size_t digest_len, uint8_t *sig,
               unsigned int *sig_len, EC_KEY *eckey) {
  int ret = 0;
  ECDSA_SIG *s = NULL;

  s = ECDSA_do_sign(digest, digest_len, eckey);
  if (s == NULL) {
    *sig_len = 0;
    goto err;
  }

  CBB cbb;
  CBB_zero(&cbb);
  size_t len;
  if (!CBB_init_fixed(&cbb, sig, ECDSA_size(eckey)) ||
      !ECDSA_SIG_marshal(&cbb, s) ||
      !CBB_finish(&cbb, NULL, &len)) {
    OPENSSL_PUT_ERROR(ECDSA, ECDSA_R_ENCODE_ERROR);
    CBB_cleanup(&cbb);
    *sig_len = 0;
    goto err;
  }
  *sig_len = (unsigned)len;
  ret = 1;

err:
  ECDSA_SIG_free(s);
  return ret;
}
