/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project 2000.
 */
/* ====================================================================
 * Copyright (c) 2000-2005 The OpenSSL Project.  All rights reserved.
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

#include <openssl/rsa.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>

#include "internal.h"


/* Override the default free and new methods */
static int rsa_cb(int operation, ASN1_VALUE **pval, const ASN1_ITEM *it,
                  void *exarg) {
  RSA *rsa = (RSA *)*pval;
  BN_CTX *ctx = NULL;
  BIGNUM *product_of_primes_so_far = NULL;
  int ret = 0;

  if (operation == ASN1_OP_NEW_PRE) {
    *pval = (ASN1_VALUE *)RSA_new();
    if (*pval) {
      return 2;
    }
    return 0;
  } else if (operation == ASN1_OP_FREE_PRE) {
    RSA_free(rsa);
    *pval = NULL;
    return 2;
  } else if (operation == ASN1_OP_D2I_POST) {
    if (rsa->additional_primes != NULL) {
      ctx = BN_CTX_new();
      product_of_primes_so_far = BN_new();
      if (ctx == NULL ||
          product_of_primes_so_far == NULL ||
          !BN_mul(product_of_primes_so_far, rsa->p, rsa->q, ctx)) {
        goto err;
      }

      size_t i;
      for (i = 0; i < sk_RSA_additional_prime_num(rsa->additional_primes); i++) {
        RSA_additional_prime *ap =
            sk_RSA_additional_prime_value(rsa->additional_primes, i);
        ap->r = BN_dup(product_of_primes_so_far);
        if (ap->r == NULL ||
            !BN_mul(product_of_primes_so_far, product_of_primes_so_far,
                    ap->prime, ctx)) {
          goto err;
        }
      }
    }
    ret = 2;
  } else {
    return 1;
  }

err:
  BN_CTX_free(ctx);
  BN_free(product_of_primes_so_far);
  return ret;
}

ASN1_SEQUENCE(RSA_additional_prime) = {
    ASN1_SIMPLE(RSA_additional_prime, prime, BIGNUM),
    ASN1_SIMPLE(RSA_additional_prime, exp, BIGNUM),
    ASN1_SIMPLE(RSA_additional_prime, coeff, BIGNUM),
} ASN1_SEQUENCE_END(RSA_additional_prime);

ASN1_SEQUENCE_cb(RSAPrivateKey, rsa_cb) = {
  ASN1_SIMPLE(RSA, version, LONG),
  ASN1_SIMPLE(RSA, n, BIGNUM),
  ASN1_SIMPLE(RSA, e, BIGNUM),
  ASN1_SIMPLE(RSA, d, BIGNUM),
  ASN1_SIMPLE(RSA, p, BIGNUM),
  ASN1_SIMPLE(RSA, q, BIGNUM),
  ASN1_SIMPLE(RSA, dmp1, BIGNUM),
  ASN1_SIMPLE(RSA, dmq1, BIGNUM),
  ASN1_SIMPLE(RSA, iqmp, BIGNUM),
  ASN1_SEQUENCE_OF_OPT(RSA, additional_primes, RSA_additional_prime),
} ASN1_SEQUENCE_END_cb(RSA, RSAPrivateKey);

ASN1_SEQUENCE_cb(RSAPublicKey, rsa_cb) = {
    ASN1_SIMPLE(RSA, n, BIGNUM),
    ASN1_SIMPLE(RSA, e, BIGNUM),
} ASN1_SEQUENCE_END_cb(RSA, RSAPublicKey);

ASN1_SEQUENCE(RSA_PSS_PARAMS) = {
  ASN1_EXP_OPT(RSA_PSS_PARAMS, hashAlgorithm, X509_ALGOR,0),
  ASN1_EXP_OPT(RSA_PSS_PARAMS, maskGenAlgorithm, X509_ALGOR,1),
  ASN1_EXP_OPT(RSA_PSS_PARAMS, saltLength, ASN1_INTEGER,2),
  ASN1_EXP_OPT(RSA_PSS_PARAMS, trailerField, ASN1_INTEGER,3),
} ASN1_SEQUENCE_END(RSA_PSS_PARAMS);

IMPLEMENT_ASN1_FUNCTIONS(RSA_PSS_PARAMS);

ASN1_SEQUENCE(RSA_OAEP_PARAMS) = {
  ASN1_EXP_OPT(RSA_OAEP_PARAMS, hashFunc, X509_ALGOR, 0),
  ASN1_EXP_OPT(RSA_OAEP_PARAMS, maskGenFunc, X509_ALGOR, 1),
  ASN1_EXP_OPT(RSA_OAEP_PARAMS, pSourceFunc, X509_ALGOR, 2),
} ASN1_SEQUENCE_END(RSA_OAEP_PARAMS);

IMPLEMENT_ASN1_FUNCTIONS(RSA_OAEP_PARAMS);

IMPLEMENT_ASN1_ENCODE_FUNCTIONS_const_fname(RSA, RSAPrivateKey, RSAPrivateKey);

IMPLEMENT_ASN1_ENCODE_FUNCTIONS_const_fname(RSA, RSAPublicKey, RSAPublicKey);

RSA *RSAPublicKey_dup(const RSA *rsa) {
  return ASN1_item_dup(ASN1_ITEM_rptr(RSAPublicKey), (RSA *) rsa);
}

RSA *RSAPrivateKey_dup(const RSA *rsa) {
  return ASN1_item_dup(ASN1_ITEM_rptr(RSAPrivateKey), (RSA *) rsa);
}
