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

#include <assert.h>
#include <limits.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/bn.h>
#include <openssl/bytestring.h>
#include <openssl/err.h>
#include <openssl/mem.h>

#include "internal.h"


static int parse_integer(CBS *cbs, BIGNUM **out) {
  assert(*out == NULL);
  *out = BN_new();
  if (*out == NULL) {
    return 0;
  }
  return BN_cbs2unsigned(cbs, *out);
}

static int marshal_integer(CBB *cbb, BIGNUM *bn) {
  if (bn == NULL) {
    /* An RSA object may be missing some components. */
    OPENSSL_PUT_ERROR(RSA, marshal_integer, RSA_R_VALUE_MISSING);
    return 0;
  }
  return BN_bn2cbb(cbb, bn);
}

RSA *RSA_parse_public_key(CBS *cbs) {
  RSA *ret = RSA_new();
  if (ret == NULL) {
    return NULL;
  }
  CBS child;
  if (!CBS_get_asn1(cbs, &child, CBS_ASN1_SEQUENCE) ||
      !parse_integer(&child, &ret->n) ||
      !parse_integer(&child, &ret->e) ||
      CBS_len(&child) != 0) {
    OPENSSL_PUT_ERROR(RSA, RSA_parse_public_key, RSA_R_BAD_ENCODING);
    RSA_free(ret);
    return NULL;
  }
  return ret;
}

RSA *RSA_public_key_from_bytes(const uint8_t *in, size_t in_len) {
  CBS cbs;
  CBS_init(&cbs, in, in_len);
  RSA *ret = RSA_parse_public_key(&cbs);
  if (ret == NULL || CBS_len(&cbs) != 0) {
    OPENSSL_PUT_ERROR(RSA, RSA_public_key_from_bytes, RSA_R_BAD_ENCODING);
    RSA_free(ret);
    return NULL;
  }
  return ret;
}

int RSA_marshal_public_key(CBB *cbb, const RSA *rsa) {
  CBB child;
  if (!CBB_add_asn1(cbb, &child, CBS_ASN1_SEQUENCE) ||
      !marshal_integer(&child, rsa->n) ||
      !marshal_integer(&child, rsa->e) ||
      !CBB_flush(cbb)) {
    OPENSSL_PUT_ERROR(RSA, RSA_marshal_public_key, RSA_R_ENCODE_ERROR);
    return 0;
  }
  return 1;
}

int RSA_public_key_to_bytes(uint8_t **out_bytes, size_t *out_len,
                            const RSA *rsa) {
  CBB cbb;
  CBB_zero(&cbb);
  if (!CBB_init(&cbb, 0) ||
      !RSA_marshal_public_key(&cbb, rsa) ||
      !CBB_finish(&cbb, out_bytes, out_len)) {
    OPENSSL_PUT_ERROR(RSA, RSA_public_key_to_bytes, RSA_R_ENCODE_ERROR);
    CBB_cleanup(&cbb);
    return 0;
  }
  return 1;
}

RSA *d2i_RSAPublicKey(RSA **out, const uint8_t **inp, long len) {
  if (len < 0) {
    return NULL;
  }
  CBS cbs;
  CBS_init(&cbs, *inp, (size_t)len);
  RSA *ret = RSA_parse_public_key(&cbs);
  if (ret == NULL) {
    return NULL;
  }
  if (out != NULL) {
    RSA_free(*out);
    *out = ret;
  }
  *inp += (size_t)len - CBS_len(&cbs);
  return ret;
}

int i2d_RSAPublicKey(const RSA *in, uint8_t **outp) {
  uint8_t *der;
  size_t der_len;
  if (!RSA_public_key_to_bytes(&der, &der_len, in)) {
    return -1;
  }
  if (der_len > INT_MAX) {
    OPENSSL_PUT_ERROR(RSA, i2d_RSAPublicKey, ERR_R_OVERFLOW);
    OPENSSL_free(der);
    return -1;
  }
  if (outp != NULL) {
    if (*outp == NULL) {
      *outp = der;
      der = NULL;
    } else {
      memcpy(*outp, der, der_len);
      *outp += der_len;
    }
  }
  OPENSSL_free(der);
  return (int)der_len;
}

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

RSA *RSAPublicKey_dup(const RSA *rsa) {
  uint8_t *der;
  size_t der_len;
  if (!RSA_public_key_to_bytes(&der, &der_len, rsa)) {
    return NULL;
  }
  RSA *ret = RSA_public_key_from_bytes(der, der_len);
  OPENSSL_free(der);
  return ret;
}

RSA *RSAPrivateKey_dup(const RSA *rsa) {
  return ASN1_item_dup(ASN1_ITEM_rptr(RSAPrivateKey), (RSA *) rsa);
}
