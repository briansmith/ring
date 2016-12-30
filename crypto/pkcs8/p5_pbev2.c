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

#include <openssl/pkcs8.h>

#include <limits.h>
#include <string.h>

#include <openssl/bytestring.h>
#include <openssl/cipher.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/obj.h>
#include <openssl/rand.h>

#include "internal.h"
#include "../internal.h"


static int pkcs5_pbe2_cipher_init(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                                  unsigned iterations, const uint8_t *pass_raw,
                                  size_t pass_raw_len, const uint8_t *salt,
                                  size_t salt_len, const uint8_t *iv,
                                  size_t iv_len, int enc) {
  if (iv_len != EVP_CIPHER_iv_length(cipher)) {
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_ERROR_SETTING_CIPHER_PARAMS);
    return 0;
  }

  uint8_t key[EVP_MAX_KEY_LENGTH];
  int ret = PKCS5_PBKDF2_HMAC_SHA1((const char *)pass_raw, pass_raw_len, salt,
                                   salt_len, iterations,
                                   EVP_CIPHER_key_length(cipher), key) &&
            EVP_CipherInit_ex(ctx, cipher, NULL /* engine */, key, iv, enc);
  OPENSSL_cleanse(key, EVP_MAX_KEY_LENGTH);
  return ret;
}

int PKCS5_pbe2_encrypt_init(CBB *out, EVP_CIPHER_CTX *ctx,
                            const EVP_CIPHER *cipher, unsigned iterations,
                            const uint8_t *pass_raw, size_t pass_raw_len,
                            const uint8_t *salt, size_t salt_len) {
  int cipher_nid = EVP_CIPHER_nid(cipher);
  if (cipher_nid == NID_undef) {
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_CIPHER_HAS_NO_OBJECT_IDENTIFIER);
    return 0;
  }

  /* Generate a random IV. */
  uint8_t iv[EVP_MAX_IV_LENGTH];
  if (!RAND_bytes(iv, EVP_CIPHER_iv_length(cipher))) {
    return 0;
  }

  /* See RFC 2898, appendix A. */
  CBB algorithm, param, kdf, kdf_param, salt_cbb, cipher_cbb, iv_cbb;
  if (!CBB_add_asn1(out, &algorithm, CBS_ASN1_SEQUENCE) ||
      !OBJ_nid2cbb(&algorithm, NID_pbes2) ||
      !CBB_add_asn1(&algorithm, &param, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1(&param, &kdf, CBS_ASN1_SEQUENCE) ||
      !OBJ_nid2cbb(&kdf, NID_id_pbkdf2) ||
      !CBB_add_asn1(&kdf, &kdf_param, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1(&kdf_param, &salt_cbb, CBS_ASN1_OCTETSTRING) ||
      !CBB_add_bytes(&salt_cbb, salt, salt_len) ||
      !CBB_add_asn1_uint64(&kdf_param, iterations) ||
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
      !CBB_flush(out)) {
    return 0;
  }

  return pkcs5_pbe2_cipher_init(ctx, cipher, iterations, pass_raw, pass_raw_len,
                                salt, salt_len, iv,
                                EVP_CIPHER_iv_length(cipher), 1 /* encrypt */);
}

int PKCS5_pbe2_decrypt_init(const struct pbe_suite *suite, EVP_CIPHER_CTX *ctx,
                            const uint8_t *pass_raw, size_t pass_raw_len,
                            CBS *param) {
  CBS pbe_param, kdf, kdf_obj, enc_scheme, enc_obj;
  if (!CBS_get_asn1(param, &pbe_param, CBS_ASN1_SEQUENCE) ||
      CBS_len(param) != 0 ||
      !CBS_get_asn1(&pbe_param, &kdf, CBS_ASN1_SEQUENCE) ||
      !CBS_get_asn1(&pbe_param, &enc_scheme, CBS_ASN1_SEQUENCE) ||
      CBS_len(&pbe_param) != 0 ||
      !CBS_get_asn1(&kdf, &kdf_obj, CBS_ASN1_OBJECT) ||
      !CBS_get_asn1(&enc_scheme, &enc_obj, CBS_ASN1_OBJECT)) {
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_DECODE_ERROR);
    return 0;
  }

  /* Check that the key derivation function is PBKDF2. */
  if (OBJ_cbs2nid(&kdf_obj) != NID_id_pbkdf2) {
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_UNSUPPORTED_KEY_DERIVATION_FUNCTION);
    return 0;
  }

  /* See if we recognise the encryption algorithm. */
  const EVP_CIPHER *cipher = EVP_get_cipherbynid(OBJ_cbs2nid(&enc_obj));
  if (cipher == NULL) {
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_UNSUPPORTED_CIPHER);
    return 0;
  }

  /* Parse the KDF parameters. */
  CBS pbkdf2_params, salt;
  uint64_t iterations;
  if (!CBS_get_asn1(&kdf, &pbkdf2_params, CBS_ASN1_SEQUENCE) ||
      CBS_len(&kdf) != 0 ||
      !CBS_get_asn1(&pbkdf2_params, &salt, CBS_ASN1_OCTETSTRING) ||
      !CBS_get_asn1_uint64(&pbkdf2_params, &iterations)) {
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_DECODE_ERROR);
    return 0;
  }

  if (iterations == 0 || iterations > UINT_MAX) {
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_BAD_ITERATION_COUNT);
    return 0;
  }

  /* The optional keyLength parameter, if present, must match the key length of
   * the cipher. */
  if (CBS_peek_asn1_tag(&pbkdf2_params, CBS_ASN1_INTEGER)) {
    uint64_t key_len;
    if (!CBS_get_asn1_uint64(&pbkdf2_params, &key_len)) {
      OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_DECODE_ERROR);
      return 0;
    }

    if (key_len != EVP_CIPHER_key_length(cipher)) {
      OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_UNSUPPORTED_KEYLENGTH);
      return 0;
    }
  }

  if (CBS_len(&pbkdf2_params) != 0) {
    CBS prf;
    if (!CBS_get_asn1(&pbkdf2_params, &prf, CBS_ASN1_OBJECT) ||
        CBS_len(&pbkdf2_params) != 0) {
      OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_DECODE_ERROR);
      return 0;
    }

    /* We only support hmacWithSHA1. It is the DEFAULT, so DER requires it be
     * omitted, but we match OpenSSL in tolerating it being present. */
    if (OBJ_cbs2nid(&prf) != NID_hmacWithSHA1) {
      OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_UNSUPPORTED_PRF);
      return 0;
    }
  }

  /* Parse the encryption scheme parameters. Note OpenSSL does not match the
   * specification. Per RFC 2898, this should depend on the encryption scheme.
   * In particular, RC2-CBC and RC5-CBC-Pad use a SEQUENCE with version and IV.
   * We align with OpenSSL. */
  CBS iv;
  if (!CBS_get_asn1(&enc_scheme, &iv, CBS_ASN1_OCTETSTRING) ||
      CBS_len(&enc_scheme) != 0) {
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_UNSUPPORTED_PRF);
    return 0;
  }

  return pkcs5_pbe2_cipher_init(ctx, cipher, (unsigned)iterations, pass_raw,
                                pass_raw_len, CBS_data(&salt), CBS_len(&salt),
                                CBS_data(&iv), CBS_len(&iv), 0 /* decrypt */);
}
