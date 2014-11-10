/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 *
 * The Elliptic Curve Public-Key Crypto Library (ECC Code) included
 * herein is developed by SUN MICROSYSTEMS, INC., and is contributed
 * to the OpenSSL project.
 *
 * The ECC Code is licensed pursuant to the OpenSSL open source
 * license provided below.
 *
 * The ECDH software is originally written by Douglas Stebila of
 * Sun Microsystems Laboratories.
 *
 */
/* ====================================================================
 * Copyright (c) 2000-2002 The OpenSSL Project.  All rights reserved.
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
 *    licensing@OpenSSL.org.
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

#include <openssl/ecdh.h>

#include <openssl/bn.h>
#include <openssl/digest.h>
#include <openssl/err.h>
#include <openssl/mem.h>


int ECDH_compute_key(void *out, size_t outlen, const EC_POINT *pub_key,
                     EC_KEY *priv_key, void *(*KDF)(const void *in, size_t inlen,
                                                void *out, size_t *outlen)) {
  BN_CTX *ctx;
  EC_POINT *tmp = NULL;
  BIGNUM *x = NULL, *y = NULL;
  const BIGNUM *priv;
  const EC_GROUP *group;
  int ret = -1;
  size_t buflen;
  uint8_t *buf = NULL;

  if ((ctx = BN_CTX_new()) == NULL) {
    goto err;
  }
  BN_CTX_start(ctx);
  x = BN_CTX_get(ctx);
  y = BN_CTX_get(ctx);

  priv = EC_KEY_get0_private_key(priv_key);
  if (priv == NULL) {
    OPENSSL_PUT_ERROR(ECDH, ECDH_compute_key, ECDH_R_NO_PRIVATE_VALUE);
    goto err;
  }

  group = EC_KEY_get0_group(priv_key);

  tmp = EC_POINT_new(group);
  if (tmp == NULL) {
    OPENSSL_PUT_ERROR(ECDH, ECDH_compute_key, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  if (!EC_POINT_mul(group, tmp, NULL, pub_key, priv, ctx)) {
    OPENSSL_PUT_ERROR(ECDH, ECDH_compute_key, ECDH_R_POINT_ARITHMETIC_FAILURE);
    goto err;
  }

  if (!EC_POINT_get_affine_coordinates_GFp(group, tmp, x, y, ctx)) {
    OPENSSL_PUT_ERROR(ECDH, ECDH_compute_key, ECDH_R_POINT_ARITHMETIC_FAILURE);
    goto err;
  }

  buflen = (EC_GROUP_get_degree(group) + 7) / 8;
  buf = OPENSSL_malloc(buflen);
  if (buf == NULL) {
    OPENSSL_PUT_ERROR(ECDH, ECDH_compute_key, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  if (!BN_bn2bin_padded(buf, buflen, x)) {
    OPENSSL_PUT_ERROR(ECDH, ECDH_compute_key, ERR_R_INTERNAL_ERROR);
    goto err;
  }

  if (KDF != 0) {
    if (KDF(buf, buflen, out, &outlen) == NULL) {
      OPENSSL_PUT_ERROR(ECDH, ECDH_compute_key, ECDH_R_KDF_FAILED);
      goto err;
    }
    ret = outlen;
  } else {
    /* no KDF, just copy as much as we can */
    if (outlen > buflen) {
      outlen = buflen;
    }
    memcpy(out, buf, outlen);
    ret = outlen;
  }

err:
  if (tmp)
    EC_POINT_free(tmp);
  if (ctx)
    BN_CTX_end(ctx);
  if (ctx)
    BN_CTX_free(ctx);
  if (buf)
    OPENSSL_free(buf);
  return ret;
}

/* Key derivation function from X9.62/SECG */
/* Way more than we will ever need */
#define ECDH_KDF_MAX	(1 << 30)

int ECDH_KDF_X9_62(uint8_t *out, size_t outlen, const uint8_t *Z,
                   size_t Zlen, const uint8_t *sinfo, size_t sinfolen,
                   const EVP_MD *md) {
  EVP_MD_CTX mctx;
  int rv = 0;
  unsigned int i;
  size_t mdlen;
  uint8_t ctr[4];

  if (sinfolen > ECDH_KDF_MAX || outlen > ECDH_KDF_MAX || Zlen > ECDH_KDF_MAX) {
    return 0;
  }
  mdlen = EVP_MD_size(md);
  EVP_MD_CTX_init(&mctx);

  for (i = 1;; i++) {
    uint8_t mtmp[EVP_MAX_MD_SIZE];
    EVP_DigestInit_ex(&mctx, md, NULL);
    ctr[3] = i & 0xFF;
    ctr[2] = (i >> 8) & 0xFF;
    ctr[1] = (i >> 16) & 0xFF;
    ctr[0] = (i >> 24) & 0xFF;
    if (!EVP_DigestUpdate(&mctx, Z, Zlen) ||
        !EVP_DigestUpdate(&mctx, ctr, sizeof(ctr)) ||
        !EVP_DigestUpdate(&mctx, sinfo, sinfolen)) {
      goto err;
    }

    if (outlen >= mdlen) {
      if (!EVP_DigestFinal(&mctx, out, NULL)) {
        goto err;
      }
      outlen -= mdlen;
      if (outlen == 0) {
        break;
      }
      out += mdlen;
    } else {
      if (!EVP_DigestFinal(&mctx, mtmp, NULL)) {
        goto err;
      }
      memcpy(out, mtmp, outlen);
      OPENSSL_cleanse(mtmp, mdlen);
      break;
    }
  }
  rv = 1;

err:
  EVP_MD_CTX_cleanup(&mctx);
  return rv;
}
