/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project 1999-2004.
 */
/* ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
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

#include <assert.h>
#include <limits.h>
#include <string.h>

#include <openssl/asn1t.h>
#include <openssl/bytestring.h>
#include <openssl/cipher.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/obj.h>
#include <openssl/pkcs8.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include "internal.h"
#include "../internal.h"


/* PKCS#5 v2.0 password based encryption structures */

ASN1_SEQUENCE(PBE2PARAM) = {
	ASN1_SIMPLE(PBE2PARAM, keyfunc, X509_ALGOR),
	ASN1_SIMPLE(PBE2PARAM, encryption, X509_ALGOR)
} ASN1_SEQUENCE_END(PBE2PARAM)

IMPLEMENT_ASN1_FUNCTIONS(PBE2PARAM)

ASN1_SEQUENCE(PBKDF2PARAM) = {
	ASN1_SIMPLE(PBKDF2PARAM, salt, ASN1_ANY),
	ASN1_SIMPLE(PBKDF2PARAM, iter, ASN1_INTEGER),
	ASN1_OPT(PBKDF2PARAM, keylength, ASN1_INTEGER),
	ASN1_OPT(PBKDF2PARAM, prf, X509_ALGOR)
} ASN1_SEQUENCE_END(PBKDF2PARAM)

IMPLEMENT_ASN1_FUNCTIONS(PBKDF2PARAM)

X509_ALGOR *PKCS5_pbe2_set(const EVP_CIPHER *cipher, int iter,
                           const uint8_t *salt, size_t salt_len) {
  int cipher_nid = EVP_CIPHER_nid(cipher);
  if (cipher_nid == NID_undef) {
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_CIPHER_HAS_NO_OBJECT_IDENTIFIER);
    return NULL;
  }

  if (iter <= 0) {
    iter = PKCS5_DEFAULT_ITERATIONS;
  }

  /* Generate a random IV. */
  uint8_t iv[EVP_MAX_IV_LENGTH];
  if (!RAND_bytes(iv, EVP_CIPHER_iv_length(cipher))) {
    return NULL;
  }

  /* Generate a random PBKDF2 salt if necessary. This will be parsed back out of
   * the serialized |X509_ALGOR|. */
  X509_ALGOR *ret = NULL;
  uint8_t *salt_buf = NULL, *der = NULL;
  size_t der_len;
  if (salt == NULL) {
    if (salt_len == 0) {
      salt_len = PKCS5_SALT_LEN;
    }

    salt_buf = OPENSSL_malloc(salt_len);
    if (salt_buf == NULL ||
        !RAND_bytes(salt_buf, salt_len)) {
      goto err;
    }

    salt = salt_buf;
  }

  /* See RFC 2898, appendix A. */
  CBB cbb, algorithm, param, kdf, kdf_param, salt_cbb, cipher_cbb, iv_cbb;
  if (!CBB_init(&cbb, 16) ||
      !CBB_add_asn1(&cbb, &algorithm, CBS_ASN1_SEQUENCE) ||
      !OBJ_nid2cbb(&algorithm, NID_pbes2) ||
      !CBB_add_asn1(&algorithm, &param, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1(&param, &kdf, CBS_ASN1_SEQUENCE) ||
      !OBJ_nid2cbb(&kdf, NID_id_pbkdf2) ||
      !CBB_add_asn1(&kdf, &kdf_param, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1(&kdf_param, &salt_cbb, CBS_ASN1_OCTETSTRING) ||
      !CBB_add_bytes(&salt_cbb, salt, salt_len) ||
      !CBB_add_asn1_uint64(&kdf_param, iter) ||
      /* Specify a key length for RC2. */
      (cipher_nid == NID_rc2_cbc &&
       !CBB_add_asn1_uint64(&kdf_param, EVP_CIPHER_key_length(cipher))) ||
      /* Omit the PRF. We use the default hmacWithSHA1. */
      !CBB_add_asn1(&param, &cipher_cbb, CBS_ASN1_SEQUENCE) ||
      !OBJ_nid2cbb(&cipher_cbb, cipher_nid) ||
      /* RFC 2898 says RC2-CBC and RC5-CBC-Pad use a SEQUENCE with version and
       * IV, but OpenSSL always uses an OCTET STRING IV, so we do the same. */
      !CBB_add_asn1(&cipher_cbb, &iv_cbb, CBS_ASN1_OCTETSTRING) ||
      !CBB_add_bytes(&iv_cbb, iv, EVP_CIPHER_iv_length(cipher)) ||
      !CBB_finish(&cbb, &der, &der_len)) {
    goto err;
  }

  const uint8_t *ptr = der;
  ret = d2i_X509_ALGOR(NULL, &ptr, der_len);
  if (ret == NULL || ptr != der + der_len) {
    OPENSSL_PUT_ERROR(PKCS8, ERR_R_INTERNAL_ERROR);
    X509_ALGOR_free(ret);
    ret = NULL;
  }

err:
  OPENSSL_free(der);
  OPENSSL_free(salt_buf);
  CBB_cleanup(&cbb);
  return ret;
}

static int PKCS5_v2_PBKDF2_keyivgen(EVP_CIPHER_CTX *ctx,
                                    const uint8_t *pass_raw,
                                    size_t pass_raw_len, const ASN1_TYPE *param,
                                    const ASN1_TYPE *iv, int enc) {
  int rv = 0;
  PBKDF2PARAM *pbkdf2param = NULL;

  if (EVP_CIPHER_CTX_cipher(ctx) == NULL) {
    OPENSSL_PUT_ERROR(PKCS8, CIPHER_R_NO_CIPHER_SET);
    goto err;
  }

  /* Decode parameters. */
  if (param == NULL || param->type != V_ASN1_SEQUENCE) {
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_DECODE_ERROR);
    goto err;
  }

  const uint8_t *pbuf = param->value.sequence->data;
  int plen = param->value.sequence->length;
  pbkdf2param = d2i_PBKDF2PARAM(NULL, &pbuf, plen);
  if (pbkdf2param == NULL || pbuf != param->value.sequence->data + plen) {
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_DECODE_ERROR);
    goto err;
  }

  /* Now check the parameters. */
  uint8_t key[EVP_MAX_KEY_LENGTH];
  const size_t key_len = EVP_CIPHER_CTX_key_length(ctx);
  assert(key_len <= sizeof(key));

  if (pbkdf2param->keylength != NULL &&
      ASN1_INTEGER_get(pbkdf2param->keylength) != (int) key_len) {
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_UNSUPPORTED_KEYLENGTH);
    goto err;
  }

  if (pbkdf2param->prf != NULL &&
      OBJ_obj2nid(pbkdf2param->prf->algorithm) != NID_hmacWithSHA1) {
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_UNSUPPORTED_PRF);
    goto err;
  }

  if (pbkdf2param->salt->type != V_ASN1_OCTET_STRING) {
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_UNSUPPORTED_SALT_TYPE);
    goto err;
  }

  if (pbkdf2param->iter->type != V_ASN1_INTEGER) {
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_BAD_ITERATION_COUNT);
    goto err;
  }
  long iterations = ASN1_INTEGER_get(pbkdf2param->iter);
  if (iterations <= 0 ||
      (sizeof(long) > sizeof(unsigned) && iterations > (long)UINT_MAX)) {
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_BAD_ITERATION_COUNT);
    goto err;
  }

  if (iv->type != V_ASN1_OCTET_STRING || iv->value.octet_string == NULL) {
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_ERROR_SETTING_CIPHER_PARAMS);
    goto err;
  }

  const size_t iv_len = EVP_CIPHER_CTX_iv_length(ctx);
  if ((size_t) iv->value.octet_string->length != iv_len) {
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_ERROR_SETTING_CIPHER_PARAMS);
    goto err;
  }

  if (!PKCS5_PBKDF2_HMAC_SHA1((const char *) pass_raw, pass_raw_len,
                              pbkdf2param->salt->value.octet_string->data,
                              pbkdf2param->salt->value.octet_string->length,
                              iterations, key_len, key)) {
    goto err;
  }

  rv = EVP_CipherInit_ex(ctx, NULL /* cipher */, NULL /* engine */, key,
                         iv->value.octet_string->data, enc);

 err:
  PBKDF2PARAM_free(pbkdf2param);
  return rv;
}

int PKCS5_v2_PBE_keyivgen(EVP_CIPHER_CTX *ctx, const uint8_t *pass_raw,
                          size_t pass_raw_len, ASN1_TYPE *param,
                          const EVP_CIPHER *unused, const EVP_MD *unused2,
                          int enc) {
  PBE2PARAM *pbe2param = NULL;
  int rv = 0;

  if (param == NULL ||
      param->type != V_ASN1_SEQUENCE ||
      param->value.sequence == NULL) {
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_DECODE_ERROR);
    goto err;
  }

  const uint8_t *pbuf = param->value.sequence->data;
  int plen = param->value.sequence->length;
  pbe2param = d2i_PBE2PARAM(NULL, &pbuf, plen);
  if (pbe2param == NULL || pbuf != param->value.sequence->data + plen) {
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_DECODE_ERROR);
    goto err;
  }

  /* Check that the key derivation function is PBKDF2. */
  if (OBJ_obj2nid(pbe2param->keyfunc->algorithm) != NID_id_pbkdf2) {
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_UNSUPPORTED_KEY_DERIVATION_FUNCTION);
    goto err;
  }

  /* See if we recognise the encryption algorithm. */
  const EVP_CIPHER *cipher =
      EVP_get_cipherbynid(OBJ_obj2nid(pbe2param->encryption->algorithm));
  if (cipher == NULL) {
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_UNSUPPORTED_CIPHER);
    goto err;
  }

  /* Fixup cipher based on AlgorithmIdentifier. */
  if (!EVP_CipherInit_ex(ctx, cipher, NULL /* engine */, NULL /* key */,
                         NULL /* iv */, enc)) {
    goto err;
  }

  rv = PKCS5_v2_PBKDF2_keyivgen(ctx, pass_raw, pass_raw_len,
                                pbe2param->keyfunc->parameter,
                                pbe2param->encryption->parameter, enc);

 err:
  PBE2PARAM_free(pbe2param);
  return rv;
}
