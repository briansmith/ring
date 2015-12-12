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


static int digest_to_bn(BIGNUM *out, const uint8_t *digest, size_t digest_len,
                        const BIGNUM *order);


int ECDSA_sign(int type, const uint8_t *digest, size_t digest_len, uint8_t *sig,
               unsigned int *sig_len, EC_KEY *eckey) {
  const EC_GROUP *group = EC_KEY_get0_group(eckey);
  const BIGNUM *priv_key = EC_KEY_get0_private_key(eckey);
  if (group == NULL || priv_key == NULL) {
    OPENSSL_PUT_ERROR(ECDSA, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }

  BN_CTX *ctx = BN_CTX_new();
  if (ctx == NULL) {
    OPENSSL_PUT_ERROR(ECDSA, ERR_R_MALLOC_FAILURE);
    return 0;
  }
  BN_CTX_start(ctx);

  int ret = 0;
  EC_POINT *tmp_point = tmp_point = EC_POINT_new(group);
  if (tmp_point == NULL) {
    OPENSSL_PUT_ERROR(ECDSA, ERR_R_EC_LIB);
    goto err;
  }

  BIGNUM *m = BN_CTX_get(ctx);
  BIGNUM *k = BN_CTX_get(ctx);
  BIGNUM *r = BN_CTX_get(ctx);
  BIGNUM *X = BN_CTX_get(ctx);
  BIGNUM *s = BN_CTX_get(ctx);
  BIGNUM *tmp = BN_CTX_get(ctx);
  if (m == NULL ||
      k == NULL ||
      r == NULL ||
      X == NULL ||
      s == NULL ||
      tmp == NULL) {
    OPENSSL_PUT_ERROR(ECDSA, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  if (!digest_to_bn(m, digest, digest_len, &group->order)) {
    goto err;
  }

  do {
    do {
      do {
        if (!BN_generate_dsa_nonce(k, &group->order,
                                   EC_KEY_get0_private_key(eckey), digest,
                                   digest_len, ctx)) {
          OPENSSL_PUT_ERROR(ECDSA, ECDSA_R_RANDOM_NUMBER_GENERATION_FAILED);
          goto err;
        }
      } while (BN_is_zero(k));

      /* Compute |r|, the X coordinate of |generator * k|. */
      if (!group->meth->mul_private(group, tmp_point, k, NULL, NULL, ctx) ||
          !EC_POINT_get_affine_coordinates_GFp(group, tmp_point, X, NULL, ctx)) {
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

    if (!BN_mod_mul(tmp, priv_key, r, &group->order, ctx) ||
        !BN_mod_add_quick(s, tmp, m, &group->order) ||
        !BN_mod_mul(s, s, k, &group->order, ctx)) {
      OPENSSL_PUT_ERROR(ECDSA, ERR_R_BN_LIB);
      goto err;
    }
  } while (BN_is_zero(s));

  /* s != 0 => we have a valid signature */

  ECDSA_SIG ecdsa_sig;
  ecdsa_sig.r = r;
  ecdsa_sig.s = s;

  CBB cbb;
  CBB_zero(&cbb);
  size_t len;
  if (!CBB_init_fixed(&cbb, sig, ECDSA_size(eckey)) ||
      !ECDSA_SIG_marshal(&cbb, &ecdsa_sig) ||
      !CBB_finish(&cbb, NULL, &len)) {
    OPENSSL_PUT_ERROR(ECDSA, ECDSA_R_ENCODE_ERROR);
    CBB_cleanup(&cbb);
    goto err;
  }
  *sig_len = (unsigned)len;
  ret = 1;

err:
  if (!ret) {
    *sig_len = 0;
  }
  EC_POINT_free(tmp_point);
  BN_CTX_end(ctx);
  BN_CTX_free(ctx);
  return ret;
}

int ECDSA_verify_signed_digest(const EC_GROUP *group, int hash_nid,
                               const uint8_t *digest, size_t digest_len,
                               const uint8_t *sig_, size_t sig_len,
                               const uint8_t *ec_key, const size_t ec_key_len) {
  BN_CTX *ctx = BN_CTX_new();
  if (ctx == NULL) {
    OPENSSL_PUT_ERROR(ECDSA, ERR_R_MALLOC_FAILURE);
    return 0;
  }

  BN_CTX_start(ctx);

  int ret = 0;
  ECDSA_SIG *sig = NULL;
  EC_POINT *point = NULL;

  EC_POINT *pub_key = EC_POINT_new(group);
  if (!pub_key ||
      !EC_POINT_oct2point(group, pub_key, ec_key, ec_key_len, NULL)) {
    goto err;
  }

  sig = ECDSA_SIG_from_bytes(sig_, sig_len);
  if (sig == NULL) {
    goto err;
  }

  /* check input values */
  BIGNUM *u1 = BN_CTX_get(ctx);
  BIGNUM *u2 = BN_CTX_get(ctx);
  BIGNUM *m = BN_CTX_get(ctx);
  BIGNUM *X = BN_CTX_get(ctx);
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
  EC_POINT_free(pub_key);
  ECDSA_SIG_free(sig);
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
