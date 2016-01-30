/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project 2006.
 */
/* ====================================================================
 * Copyright (c) 2006 The OpenSSL Project.  All rights reserved.
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

#include <openssl/evp.h>

#include <openssl/asn1.h>
#include <openssl/bytestring.h>
#include <openssl/digest.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/obj.h>
#include <openssl/rsa.h>

#include "../rsa/internal.h"
#include "internal.h"


static int rsa_pub_encode(CBB *out, const EVP_PKEY *key) {
  /* See RFC 3279, section 2.3.1. */
  CBB spki, algorithm, null, key_bitstring;
  if (!CBB_add_asn1(out, &spki, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1(&spki, &algorithm, CBS_ASN1_SEQUENCE) ||
      !OBJ_nid2cbb(&algorithm, NID_rsaEncryption) ||
      !CBB_add_asn1(&algorithm, &null, CBS_ASN1_NULL) ||
      !CBB_add_asn1(&spki, &key_bitstring, CBS_ASN1_BITSTRING) ||
      !CBB_add_u8(&key_bitstring, 0 /* padding */) ||
      !RSA_marshal_public_key(&key_bitstring, key->pkey.rsa) ||
      !CBB_flush(out)) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_ENCODE_ERROR);
    return 0;
  }

  return 1;
}

static int rsa_pub_decode(EVP_PKEY *out, CBS *params, CBS *key) {
  /* See RFC 3279, section 2.3.1. */

  /* The parameters must be NULL. */
  CBS null;
  if (!CBS_get_asn1(params, &null, CBS_ASN1_NULL) ||
      CBS_len(&null) != 0 ||
      CBS_len(params) != 0) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);
    return 0;
  }

  /* Estonian IDs issued between September 2014 to September 2015 are
   * broken. See https://crbug.com/532048 and https://crbug.com/534766.
   *
   * TODO(davidben): Switch this to the strict version in March 2016 or when
   * Chromium can force client certificates down a different codepath, whichever
   * comes first. */
  RSA *rsa = RSA_parse_public_key_buggy(key);
  if (rsa == NULL || CBS_len(key) != 0) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);
    RSA_free(rsa);
    return 0;
  }

  EVP_PKEY_assign_RSA(out, rsa);
  return 1;
}

static int rsa_pub_cmp(const EVP_PKEY *a, const EVP_PKEY *b) {
  return BN_cmp(b->pkey.rsa->n, a->pkey.rsa->n) == 0 &&
         BN_cmp(b->pkey.rsa->e, a->pkey.rsa->e) == 0;
}

static int rsa_priv_encode(CBB *out, const EVP_PKEY *key) {
  CBB pkcs8, algorithm, null, private_key;
  if (!CBB_add_asn1(out, &pkcs8, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1_uint64(&pkcs8, 0 /* version */) ||
      !CBB_add_asn1(&pkcs8, &algorithm, CBS_ASN1_SEQUENCE) ||
      !OBJ_nid2cbb(&algorithm, NID_rsaEncryption) ||
      !CBB_add_asn1(&algorithm, &null, CBS_ASN1_NULL) ||
      !CBB_add_asn1(&pkcs8, &private_key, CBS_ASN1_OCTETSTRING) ||
      !RSA_marshal_private_key(&private_key, key->pkey.rsa) ||
      !CBB_flush(out)) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_ENCODE_ERROR);
    return 0;
  }

  return 1;
}

static int rsa_priv_decode(EVP_PKEY *out, CBS *params, CBS *key) {
  /* Per RFC 3447, A.1, the parameters have type NULL. */
  CBS null;
  if (!CBS_get_asn1(params, &null, CBS_ASN1_NULL) ||
      CBS_len(&null) != 0 ||
      CBS_len(params) != 0) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);
    return 0;
  }

  RSA *rsa = RSA_parse_private_key(key);
  if (rsa == NULL || CBS_len(key) != 0) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);
    RSA_free(rsa);
    return 0;
  }

  EVP_PKEY_assign_RSA(out, rsa);
  return 1;
}

static int rsa_opaque(const EVP_PKEY *pkey) {
  return RSA_is_opaque(pkey->pkey.rsa);
}

static int rsa_supports_digest(const EVP_PKEY *pkey, const EVP_MD *md) {
  return RSA_supports_digest(pkey->pkey.rsa, md);
}

static int int_rsa_size(const EVP_PKEY *pkey) {
  return RSA_size(pkey->pkey.rsa);
}

static int rsa_bits(const EVP_PKEY *pkey) {
  return BN_num_bits(pkey->pkey.rsa->n);
}

static void int_rsa_free(EVP_PKEY *pkey) { RSA_free(pkey->pkey.rsa); }

static void update_buflen(const BIGNUM *b, size_t *pbuflen) {
  size_t i;

  if (!b) {
    return;
  }

  i = BN_num_bytes(b);
  if (*pbuflen < i) {
    *pbuflen = i;
  }
}

static int do_rsa_print(BIO *out, const RSA *rsa, int off,
                        int include_private) {
  char *str;
  const char *s;
  uint8_t *m = NULL;
  int ret = 0, mod_len = 0;
  size_t buf_len = 0;

  update_buflen(rsa->n, &buf_len);
  update_buflen(rsa->e, &buf_len);

  if (include_private) {
    update_buflen(rsa->d, &buf_len);
    update_buflen(rsa->p, &buf_len);
    update_buflen(rsa->q, &buf_len);
    update_buflen(rsa->dmp1, &buf_len);
    update_buflen(rsa->dmq1, &buf_len);
    update_buflen(rsa->iqmp, &buf_len);

    if (rsa->additional_primes != NULL) {
      size_t i;

      for (i = 0; i < sk_RSA_additional_prime_num(rsa->additional_primes);
           i++) {
        const RSA_additional_prime *ap =
            sk_RSA_additional_prime_value(rsa->additional_primes, i);
        update_buflen(ap->prime, &buf_len);
        update_buflen(ap->exp, &buf_len);
        update_buflen(ap->coeff, &buf_len);
      }
    }
  }

  m = OPENSSL_malloc(buf_len + 10);
  if (m == NULL) {
    OPENSSL_PUT_ERROR(EVP, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  if (rsa->n != NULL) {
    mod_len = BN_num_bits(rsa->n);
  }

  if (!BIO_indent(out, off, 128)) {
    goto err;
  }

  if (include_private && rsa->d) {
    if (BIO_printf(out, "Private-Key: (%d bit)\n", mod_len) <= 0) {
      goto err;
    }
    str = "modulus:";
    s = "publicExponent:";
  } else {
    if (BIO_printf(out, "Public-Key: (%d bit)\n", mod_len) <= 0) {
      goto err;
    }
    str = "Modulus:";
    s = "Exponent:";
  }
  if (!ASN1_bn_print(out, str, rsa->n, m, off) ||
      !ASN1_bn_print(out, s, rsa->e, m, off)) {
    goto err;
  }

  if (include_private) {
    if (!ASN1_bn_print(out, "privateExponent:", rsa->d, m, off) ||
        !ASN1_bn_print(out, "prime1:", rsa->p, m, off) ||
        !ASN1_bn_print(out, "prime2:", rsa->q, m, off) ||
        !ASN1_bn_print(out, "exponent1:", rsa->dmp1, m, off) ||
        !ASN1_bn_print(out, "exponent2:", rsa->dmq1, m, off) ||
        !ASN1_bn_print(out, "coefficient:", rsa->iqmp, m, off)) {
      goto err;
    }

    if (rsa->additional_primes != NULL &&
        sk_RSA_additional_prime_num(rsa->additional_primes) > 0) {
      size_t i;

      if (BIO_printf(out, "otherPrimeInfos:\n") <= 0) {
        goto err;
      }
      for (i = 0; i < sk_RSA_additional_prime_num(rsa->additional_primes);
           i++) {
        const RSA_additional_prime *ap =
            sk_RSA_additional_prime_value(rsa->additional_primes, i);

        if (BIO_printf(out, "otherPrimeInfo (prime %u):\n",
                       (unsigned)(i + 3)) <= 0 ||
            !ASN1_bn_print(out, "prime:", ap->prime, m, off) ||
            !ASN1_bn_print(out, "exponent:", ap->exp, m, off) ||
            !ASN1_bn_print(out, "coeff:", ap->coeff, m, off)) {
          goto err;
        }
      }
    }
  }
  ret = 1;

err:
  OPENSSL_free(m);
  return ret;
}

static int rsa_pub_print(BIO *bp, const EVP_PKEY *pkey, int indent,
                         ASN1_PCTX *ctx) {
  return do_rsa_print(bp, pkey->pkey.rsa, indent, 0);
}

static int rsa_priv_print(BIO *bp, const EVP_PKEY *pkey, int indent,
                          ASN1_PCTX *ctx) {
  return do_rsa_print(bp, pkey->pkey.rsa, indent, 1);
}

static int old_rsa_priv_decode(EVP_PKEY *pkey, const uint8_t **pder,
                               int derlen) {
  RSA *rsa = d2i_RSAPrivateKey(NULL, pder, derlen);
  if (rsa == NULL) {
    OPENSSL_PUT_ERROR(EVP, ERR_R_RSA_LIB);
    return 0;
  }
  EVP_PKEY_assign_RSA(pkey, rsa);
  return 1;
}

const EVP_PKEY_ASN1_METHOD rsa_asn1_meth = {
  EVP_PKEY_RSA,
  "RSA",

  rsa_pub_decode,
  rsa_pub_encode,
  rsa_pub_cmp,
  rsa_pub_print,

  rsa_priv_decode,
  rsa_priv_encode,
  rsa_priv_print,

  rsa_opaque,
  rsa_supports_digest,

  int_rsa_size,
  rsa_bits,

  0,0,0,0,

  int_rsa_free,

  old_rsa_priv_decode,
};
