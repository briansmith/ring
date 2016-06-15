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
#include <openssl/err.h>

#include "../bn/internal.h"
#include "../ec/gfp_internal.h"
#include "../ec/internal.h"


/* Declarations to suppress -Wmissing-prototypes warnings. */
int ECDSA_verify_signed_digest(const EC_GROUP *group, const GFp_Limb *m,
                               const GFp_Limb *sig_r, const GFp_Limb *sig_s,
                               const GFp_Limb *sig_s_inv_mont,
                               const GFp_Limb *peer_public_key_x,
                               const GFp_Limb *peer_public_key_y);


/* ECDSA_verify_signed_digest verifies that the signature (|sig_r|, |sig_s|)
 * constitute a valid signature of |digest| for the public key |ec_key| for
 * the curve represented by the |EC_GROUP| created by |ec_group_new|.
 * The caller must ensure that |sig_r| and |sig_s| are in the range [1, n). It
 * returns one on success or zero if the signature is invalid or on error. */
int ECDSA_verify_signed_digest(const EC_GROUP *group, const GFp_Limb *m,
                               const GFp_Limb *sig_r, const GFp_Limb *sig_s,
                               const GFp_Limb *sig_s_inv_mont,
                               const GFp_Limb *peer_public_key_x,
                               const GFp_Limb *peer_public_key_y) {
  BN_CTX *ctx = BN_CTX_new();
  if (ctx == NULL) {
    OPENSSL_PUT_ERROR(ECDSA, ERR_R_MALLOC_FAILURE);
    return 0;
  }

  BN_CTX_start(ctx);

  int ret = 0;
  EC_POINT *point = NULL;

  EC_POINT *pub_key = GFp_suite_b_make_point(group, peer_public_key_x,
                                             peer_public_key_y);
  if (pub_key == NULL) {
    OPENSSL_PUT_ERROR(ECDSA, ERR_R_EC_LIB);
    goto err;
  }

  /* check input values */
  BIGNUM *r = BN_CTX_get(ctx);
  BIGNUM *s = BN_CTX_get(ctx);
  BIGNUM *u1 = BN_CTX_get(ctx);
  BIGNUM *u2 = BN_CTX_get(ctx);
  BIGNUM *m_bn = BN_CTX_get(ctx);
  BIGNUM *X = BN_CTX_get(ctx);
  if (r == NULL || s == NULL || u1 == NULL || u2 == NULL || m_bn == NULL ||
      X == NULL) {
    OPENSSL_PUT_ERROR(ECDSA, ERR_R_BN_LIB);
    goto err;
  }

  size_t scalar_limbs =
      (EC_GROUP_get_degree(group) + (BN_BITS2 - 1)) / BN_BITS2;
  if (!bn_set_words(r, sig_r, scalar_limbs) ||
      !bn_set_words(s, sig_s, scalar_limbs) ||
      !bn_set_words(m_bn, m, scalar_limbs)) {
    OPENSSL_PUT_ERROR(ECDSA, ERR_R_BN_LIB);
    goto err;
  }

  /* These properties are guaranteed by the caller. */
  assert(!BN_is_negative(r));
  assert(!BN_is_zero(r));
  assert(BN_ucmp(r, &group->order) < 0);
  assert(!BN_is_negative(s));
  assert(!BN_is_zero(s));
  assert(BN_ucmp(s, &group->order) < 0);
  assert(BN_ucmp(m_bn, &group->order) < 0);

  /* u2 = inv(S) mod order (Montgomery-encoded) */
  if (!bn_set_words(u2, sig_s_inv_mont, scalar_limbs)) {
    OPENSSL_PUT_ERROR(ECDSA, ERR_R_BN_LIB);
    goto err;
  }

  /* u1 = m * u2 mod order. Since only one input is Montgomery-encoded, the
   * result will not be Montgomery-encoded. */
  if (!BN_mod_mul_montgomery(u1, m_bn, u2, &group->order_mont, ctx)) {
    OPENSSL_PUT_ERROR(ECDSA, ERR_R_BN_LIB);
    goto err;
  }
  /* u2 = r * w mod order. Since only one input is Montgomery-encoded, the
   * result will not be Montgomery-encoded. */
  if (!BN_mod_mul_montgomery(u2, r, u2, &group->order_mont, ctx)) {
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
  ret = (BN_ucmp(u1, r) == 0);

err:
  BN_CTX_end(ctx);
  BN_CTX_free(ctx);
  EC_POINT_free(pub_key);
  EC_POINT_free(point);
  return ret;
}
