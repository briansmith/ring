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

#include "../ec/gfp_internal.h"
#include "../ec/internal.h"


/* Declarations to suppress -Wmissing-prototypes warnings. */
int ECDSA_verify_signed_digest(const EC_GROUP *group, int hash_nid,
                               const uint8_t *digest, size_t digest_len,
                               const uint8_t *sig_r, size_t sig_r_len,
                               const uint8_t *sig_s, size_t sig_s_len,
                               const GFp_Limb *peer_public_key_x,
                               const GFp_Limb *peer_public_key_y);


static int digest_to_bn(BIGNUM *out, const uint8_t *digest, size_t digest_len,
                        const BIGNUM *order);


/* ECDSA_verify_signed_digest verifies that the signature (|sig_r|, |sig_s|)
 * constitute a valid signature of |digest| for the public key |ec_key| for
 * the curve represented by the |EC_GROUP| created by |ec_group_new|.
 * |hash_nid| must be the identifier of the digest function used to calculate
 * |digest|. The caller must ensure that |sig_r| and |sig_s| are encodings of
 * *positive* integers. It returns one on success or zero if the signature is
 * invalid or on error. */
int ECDSA_verify_signed_digest(const EC_GROUP *group, int hash_nid,
                               const uint8_t *digest, size_t digest_len,
                               const uint8_t *sig_r, size_t sig_r_len,
                               const uint8_t *sig_s, size_t sig_s_len,
                               const GFp_Limb *peer_public_key_x,
                               const GFp_Limb *peer_public_key_y) {
  (void)hash_nid; /* TODO: Verify |digest_len| is right for |hash_nid|. */

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
  BIGNUM *m = BN_CTX_get(ctx);
  BIGNUM *X = BN_CTX_get(ctx);
  if (r == NULL || s == NULL || u1 == NULL || u2 == NULL || m == NULL ||
      X == NULL) {
    OPENSSL_PUT_ERROR(ECDSA, ERR_R_BN_LIB);
    goto err;
  }

  if (BN_bin2bn(sig_r, sig_r_len, r) == NULL ||
      BN_bin2bn(sig_s, sig_s_len, s) == NULL ||
      BN_ucmp(r, &group->order) >= 0 ||
      BN_ucmp(s, &group->order) >= 0) {
    OPENSSL_PUT_ERROR(ECDSA, ECDSA_R_BAD_SIGNATURE);
    ret = 0; /* signature is invalid */
    goto err;
  }

  /* These properties are guaranteed by the caller. */
  assert(!BN_is_negative(r));
  assert(!BN_is_zero(r));
  assert(!BN_is_negative(s));
  assert(!BN_is_zero(s));

  /* calculate tmp1 = inv(S) mod order */
  if (!BN_mod_inverse(u2, s, &group->order, ctx)) {
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
  if (!BN_mod_mul(u2, r, u2, &group->order, ctx)) {
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
