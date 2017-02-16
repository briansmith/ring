/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project 1999.
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

#include <assert.h>
#include <limits.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/buf.h>
#include <openssl/bytestring.h>
#include <openssl/cipher.h>
#include <openssl/digest.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/mem.h>
#include <openssl/obj.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include "internal.h"
#include "../internal.h"
#include "../bytestring/internal.h"


#define PKCS12_KEY_ID 1
#define PKCS12_IV_ID 2
#define PKCS12_MAC_ID 3

static int ascii_to_ucs2(const char *ascii, size_t ascii_len,
                         uint8_t **out, size_t *out_len) {
  size_t ulen = ascii_len * 2 + 2;
  if (ascii_len * 2 < ascii_len || ulen < ascii_len * 2) {
    return 0;
  }

  uint8_t *unitmp = OPENSSL_malloc(ulen);
  if (unitmp == NULL) {
    return 0;
  }
  for (size_t i = 0; i < ulen - 2; i += 2) {
    unitmp[i] = 0;
    unitmp[i + 1] = ascii[i >> 1];
  }

  /* Terminate the result with a UCS-2 NUL. */
  unitmp[ulen - 2] = 0;
  unitmp[ulen - 1] = 0;
  *out_len = ulen;
  *out = unitmp;
  return 1;
}

static int pkcs12_key_gen_raw(const uint8_t *pass_raw, size_t pass_raw_len,
                              const uint8_t *salt, size_t salt_len,
                              uint8_t id, unsigned iterations,
                              size_t out_len, uint8_t *out,
                              const EVP_MD *md) {
  /* See https://tools.ietf.org/html/rfc7292#appendix-B. Quoted parts of the
   * specification have errata applied and other typos fixed. */

  if (iterations < 1) {
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_BAD_ITERATION_COUNT);
    return 0;
  }

  /* In the spec, |block_size| is called "v", but measured in bits. */
  size_t block_size = EVP_MD_block_size(md);

  /* 1. Construct a string, D (the "diversifier"), by concatenating v/8 copies
   * of ID. */
  uint8_t D[EVP_MAX_MD_BLOCK_SIZE];
  OPENSSL_memset(D, id, block_size);

  /* 2. Concatenate copies of the salt together to create a string S of length
   * v(ceiling(s/v)) bits (the final copy of the salt may be truncated to
   * create S). Note that if the salt is the empty string, then so is S.
   *
   * 3. Concatenate copies of the password together to create a string P of
   * length v(ceiling(p/v)) bits (the final copy of the password may be
   * truncated to create P).  Note that if the password is the empty string,
   * then so is P.
   *
   * 4. Set I=S||P to be the concatenation of S and P. */
  if (salt_len + block_size - 1 < salt_len ||
      pass_raw_len + block_size - 1 < pass_raw_len) {
    OPENSSL_PUT_ERROR(PKCS8, ERR_R_OVERFLOW);
    return 0;
  }
  size_t S_len = block_size * ((salt_len + block_size - 1) / block_size);
  size_t P_len = block_size * ((pass_raw_len + block_size - 1) / block_size);
  size_t I_len = S_len + P_len;
  if (I_len < S_len) {
    OPENSSL_PUT_ERROR(PKCS8, ERR_R_OVERFLOW);
    return 0;
  }

  uint8_t *I = OPENSSL_malloc(I_len);
  if (I_len != 0 && I == NULL) {
    OPENSSL_PUT_ERROR(PKCS8, ERR_R_MALLOC_FAILURE);
    return 0;
  }

  for (size_t i = 0; i < S_len; i++) {
    I[i] = salt[i % salt_len];
  }
  for (size_t i = 0; i < P_len; i++) {
    I[i + S_len] = pass_raw[i % pass_raw_len];
  }

  int ret = 0;
  EVP_MD_CTX ctx;
  EVP_MD_CTX_init(&ctx);

  while (out_len != 0) {
    /* A. Set A_i=H^r(D||I). (i.e., the r-th hash of D||I,
     * H(H(H(... H(D||I)))) */
    uint8_t A[EVP_MAX_MD_SIZE];
    unsigned A_len;
    if (!EVP_DigestInit_ex(&ctx, md, NULL) ||
        !EVP_DigestUpdate(&ctx, D, block_size) ||
        !EVP_DigestUpdate(&ctx, I, I_len) ||
        !EVP_DigestFinal_ex(&ctx, A, &A_len)) {
      goto err;
    }
    for (unsigned iter = 1; iter < iterations; iter++) {
      if (!EVP_DigestInit_ex(&ctx, md, NULL) ||
          !EVP_DigestUpdate(&ctx, A, A_len) ||
          !EVP_DigestFinal_ex(&ctx, A, &A_len)) {
        goto err;
      }
    }

    size_t todo = out_len < A_len ? out_len : A_len;
    OPENSSL_memcpy(out, A, todo);
    out += todo;
    out_len -= todo;
    if (out_len == 0) {
      break;
    }

    /* B. Concatenate copies of A_i to create a string B of length v bits (the
     * final copy of A_i may be truncated to create B). */
    uint8_t B[EVP_MAX_MD_BLOCK_SIZE];
    for (size_t i = 0; i < block_size; i++) {
      B[i] = A[i % A_len];
    }

    /* C. Treating I as a concatenation I_0, I_1, ..., I_(k-1) of v-bit blocks,
     * where k=ceiling(s/v)+ceiling(p/v), modify I by setting I_j=(I_j+B+1) mod
     * 2^v for each j. */
    assert(I_len % block_size == 0);
    for (size_t i = 0; i < I_len; i += block_size) {
      unsigned carry = 1;
      for (size_t j = block_size - 1; j < block_size; j--) {
        carry += I[i + j] + B[j];
        I[i + j] = (uint8_t)carry;
        carry >>= 8;
      }
    }
  }

  ret = 1;

err:
  OPENSSL_cleanse(I, I_len);
  OPENSSL_free(I);
  EVP_MD_CTX_cleanup(&ctx);
  return ret;
}

static int pkcs12_pbe_cipher_init(const struct pbe_suite *suite,
                                  EVP_CIPHER_CTX *ctx, unsigned iterations,
                                  const uint8_t *pass_raw, size_t pass_raw_len,
                                  const uint8_t *salt, size_t salt_len,
                                  int is_encrypt) {
  const EVP_CIPHER *cipher = suite->cipher_func();
  const EVP_MD *md = suite->md_func();

  uint8_t key[EVP_MAX_KEY_LENGTH];
  if (!pkcs12_key_gen_raw(pass_raw, pass_raw_len, salt,
                          salt_len, PKCS12_KEY_ID, iterations,
                          EVP_CIPHER_key_length(cipher), key, md)) {
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_KEY_GEN_ERROR);
    return 0;
  }

  uint8_t iv[EVP_MAX_IV_LENGTH];
  if (!pkcs12_key_gen_raw(pass_raw, pass_raw_len, salt,
                          salt_len, PKCS12_IV_ID, iterations,
                          EVP_CIPHER_iv_length(cipher), iv, md)) {
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_KEY_GEN_ERROR);
    return 0;
  }

  int ret = EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, is_encrypt);
  OPENSSL_cleanse(key, EVP_MAX_KEY_LENGTH);
  OPENSSL_cleanse(iv, EVP_MAX_IV_LENGTH);
  return ret;
}

static int pkcs12_pbe_decrypt_init(const struct pbe_suite *suite,
                                   EVP_CIPHER_CTX *ctx, const uint8_t *pass_raw,
                                   size_t pass_raw_len, CBS *param) {
  CBS pbe_param, salt;
  uint64_t iterations;
  if (!CBS_get_asn1(param, &pbe_param, CBS_ASN1_SEQUENCE) ||
      !CBS_get_asn1(&pbe_param, &salt, CBS_ASN1_OCTETSTRING) ||
      !CBS_get_asn1_uint64(&pbe_param, &iterations) ||
      CBS_len(&pbe_param) != 0 ||
      CBS_len(param) != 0) {
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_DECODE_ERROR);
    return 0;
  }

  if (iterations == 0 || iterations > UINT_MAX) {
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_BAD_ITERATION_COUNT);
    return 0;
  }

  return pkcs12_pbe_cipher_init(suite, ctx, (unsigned)iterations, pass_raw,
                                pass_raw_len, CBS_data(&salt), CBS_len(&salt),
                                0 /* decrypt */);
}

static const struct pbe_suite kBuiltinPBE[] = {
    {
        NID_pbe_WithSHA1And40BitRC2_CBC, EVP_rc2_40_cbc, EVP_sha1,
        pkcs12_pbe_decrypt_init, PBE_UCS2_CONVERT_PASSWORD,
    },
    {
        NID_pbe_WithSHA1And128BitRC4, EVP_rc4, EVP_sha1,
        pkcs12_pbe_decrypt_init, PBE_UCS2_CONVERT_PASSWORD,
    },
    {
        NID_pbe_WithSHA1And3_Key_TripleDES_CBC, EVP_des_ede3_cbc, EVP_sha1,
        pkcs12_pbe_decrypt_init, PBE_UCS2_CONVERT_PASSWORD,
    },
    {
        NID_pbes2, NULL, NULL, PKCS5_pbe2_decrypt_init, 0,
    },
};

static const struct pbe_suite *get_pbe_suite(int pbe_nid) {
  unsigned i;
  for (i = 0; i < OPENSSL_ARRAY_SIZE(kBuiltinPBE); i++) {
    if (kBuiltinPBE[i].pbe_nid == pbe_nid) {
      return &kBuiltinPBE[i];
    }
  }

  return NULL;
}

/* pass_to_pass_raw performs a password conversion (possibly a no-op)
 * appropriate to the supplied |pbe_nid|. The input |pass| is treated as a
 * NUL-terminated string if |pass_len| is -1, otherwise it is treated as a
 * buffer of the specified length. If the supplied PBE NID sets the
 * |PBE_UCS2_CONVERT_PASSWORD| flag, the supplied |pass| will be converted to
 * UCS-2.
 *
 * It sets |*out_pass_raw| to a new buffer that must be freed by the caller. It
 * returns one on success and zero on error. */
static int pass_to_pass_raw(int pbe_nid, const char *pass, int pass_len,
                            uint8_t **out_pass_raw, size_t *out_pass_raw_len) {
  if (pass == NULL) {
    *out_pass_raw = NULL;
    *out_pass_raw_len = 0;
    return 1;
  }

  if (pass_len == -1) {
    pass_len = strlen(pass);
  } else if (pass_len < 0 || pass_len > 2000000000) {
    OPENSSL_PUT_ERROR(PKCS8, ERR_R_OVERFLOW);
    return 0;
  }

  const struct pbe_suite *suite = get_pbe_suite(pbe_nid);
  if (suite != NULL && (suite->flags & PBE_UCS2_CONVERT_PASSWORD)) {
    if (!ascii_to_ucs2(pass, pass_len, out_pass_raw, out_pass_raw_len)) {
      OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_DECODE_ERROR);
      return 0;
    }
  } else {
    *out_pass_raw = BUF_memdup(pass, pass_len);
    if (*out_pass_raw == NULL) {
      OPENSSL_PUT_ERROR(PKCS8, ERR_R_MALLOC_FAILURE);
      return 0;
    }
    *out_pass_raw_len = (size_t)pass_len;
  }

  return 1;
}

static int pkcs12_pbe_encrypt_init(CBB *out, EVP_CIPHER_CTX *ctx, int alg,
                                   unsigned iterations, const uint8_t *pass_raw,
                                   size_t pass_raw_len, const uint8_t *salt,
                                   size_t salt_len) {
  const struct pbe_suite *suite = get_pbe_suite(alg);
  if (suite == NULL) {
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_UNKNOWN_ALGORITHM);
    return 0;
  }

  /* See RFC 2898, appendix A.3. */
  CBB algorithm, param, salt_cbb;
  if (!CBB_add_asn1(out, &algorithm, CBS_ASN1_SEQUENCE) ||
      !OBJ_nid2cbb(&algorithm, alg) ||
      !CBB_add_asn1(&algorithm, &param, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1(&param, &salt_cbb, CBS_ASN1_OCTETSTRING) ||
      !CBB_add_bytes(&salt_cbb, salt, salt_len) ||
      !CBB_add_asn1_uint64(&param, iterations) ||
      !CBB_flush(out)) {
    return 0;
  }

  return pkcs12_pbe_cipher_init(suite, ctx, iterations, pass_raw, pass_raw_len,
                                salt, salt_len, 1 /* encrypt */);
}

static int pbe_decrypt(uint8_t **out, size_t *out_len, CBS *algorithm,
                       const uint8_t *pass_raw, size_t pass_raw_len,
                       const uint8_t *in, size_t in_len) {
  int ret = 0;
  uint8_t *buf = NULL;;
  EVP_CIPHER_CTX ctx;
  EVP_CIPHER_CTX_init(&ctx);

  CBS obj;
  if (!CBS_get_asn1(algorithm, &obj, CBS_ASN1_OBJECT)) {
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_DECODE_ERROR);
    goto err;
  }

  const struct pbe_suite *suite = get_pbe_suite(OBJ_cbs2nid(&obj));
  if (suite == NULL) {
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_UNKNOWN_ALGORITHM);
    goto err;
  }

  if (!suite->decrypt_init(suite, &ctx, pass_raw, pass_raw_len, algorithm)) {
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_KEYGEN_FAILURE);
    goto err;
  }

  buf = OPENSSL_malloc(in_len);
  if (buf == NULL) {
    OPENSSL_PUT_ERROR(PKCS8, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  if (in_len > INT_MAX) {
    OPENSSL_PUT_ERROR(PKCS8, ERR_R_OVERFLOW);
    goto err;
  }

  int n1, n2;
  if (!EVP_DecryptUpdate(&ctx, buf, &n1, in, (int)in_len) ||
      !EVP_DecryptFinal_ex(&ctx, buf + n1, &n2)) {
    goto err;
  }

  *out = buf;
  *out_len = n1 + n2;
  ret = 1;
  buf = NULL;

err:
  OPENSSL_free(buf);
  EVP_CIPHER_CTX_cleanup(&ctx);
  return ret;
}

static PKCS8_PRIV_KEY_INFO *pkcs8_decrypt_raw(X509_SIG *pkcs8,
                                              const uint8_t *pass_raw,
                                              size_t pass_raw_len) {
  PKCS8_PRIV_KEY_INFO *ret = NULL;
  uint8_t *in = NULL, *out = NULL;
  size_t out_len = 0;

  /* Convert the legacy ASN.1 object to a byte string. */
  int in_len = i2d_X509_SIG(pkcs8, &in);
  if (in_len < 0) {
    goto err;
  }

  /* See RFC 5208, section 6. */
  CBS cbs, epki, algorithm, ciphertext;
  CBS_init(&cbs, in, in_len);
  if (!CBS_get_asn1(&cbs, &epki, CBS_ASN1_SEQUENCE) ||
      !CBS_get_asn1(&epki, &algorithm, CBS_ASN1_SEQUENCE) ||
      !CBS_get_asn1(&epki, &ciphertext, CBS_ASN1_OCTETSTRING) ||
      CBS_len(&epki) != 0 ||
      CBS_len(&cbs) != 0) {
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_DECODE_ERROR);
    goto err;
  }

  if (!pbe_decrypt(&out, &out_len, &algorithm, pass_raw, pass_raw_len,
                   CBS_data(&ciphertext), CBS_len(&ciphertext))) {
    goto err;
  }

  if (out_len > LONG_MAX) {
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_DECODE_ERROR);
    goto err;
  }

  /* Convert back to legacy ASN.1 objects. */
  const uint8_t *ptr = out;
  ret = d2i_PKCS8_PRIV_KEY_INFO(NULL, &ptr, (long)out_len);
  OPENSSL_cleanse(out, out_len);
  if (ret == NULL || ptr != out + out_len) {
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_DECODE_ERROR);
    PKCS8_PRIV_KEY_INFO_free(ret);
    ret = NULL;
  }

err:
  OPENSSL_free(in);
  OPENSSL_cleanse(out, out_len);
  OPENSSL_free(out);
  return ret;
}

PKCS8_PRIV_KEY_INFO *PKCS8_decrypt(X509_SIG *pkcs8, const char *pass,
                                   int pass_len) {
  uint8_t *pass_raw = NULL;
  size_t pass_raw_len = 0;
  if (!pass_to_pass_raw(OBJ_obj2nid(pkcs8->algor->algorithm), pass, pass_len,
                        &pass_raw, &pass_raw_len)) {
    return NULL;
  }

  PKCS8_PRIV_KEY_INFO *ret = pkcs8_decrypt_raw(pkcs8, pass_raw, pass_raw_len);

  if (pass_raw) {
    OPENSSL_cleanse(pass_raw, pass_raw_len);
    OPENSSL_free(pass_raw);
  }
  return ret;
}

static X509_SIG *pkcs8_encrypt_raw(int pbe_nid, const EVP_CIPHER *cipher,
                                   const uint8_t *pass_raw, size_t pass_raw_len,
                                   const uint8_t *salt, size_t salt_len,
                                   int iterations, PKCS8_PRIV_KEY_INFO *p8inf) {
  X509_SIG *ret = NULL;
  uint8_t *plaintext = NULL, *salt_buf = NULL, *der = NULL;
  int plaintext_len = -1;
  size_t der_len;
  CBB cbb;
  CBB_zero(&cbb);
  EVP_CIPHER_CTX ctx;
  EVP_CIPHER_CTX_init(&ctx);

  /* Generate a random salt if necessary. */
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

  if (iterations <= 0) {
    iterations = PKCS5_DEFAULT_ITERATIONS;
  }

  /* Convert the input from the legacy ASN.1 format. */
  plaintext_len = i2d_PKCS8_PRIV_KEY_INFO(p8inf, &plaintext);
  if (plaintext_len < 0) {
    goto err;
  }

  CBB epki;
  if (!CBB_init(&cbb, 128) ||
      !CBB_add_asn1(&cbb, &epki, CBS_ASN1_SEQUENCE)) {
    goto err;
  }

  int alg_ok;
  if (pbe_nid == -1) {
    alg_ok = PKCS5_pbe2_encrypt_init(&epki, &ctx, cipher, (unsigned)iterations,
                                     pass_raw, pass_raw_len, salt, salt_len);
  } else {
    alg_ok = pkcs12_pbe_encrypt_init(&epki, &ctx, pbe_nid, (unsigned)iterations,
                                     pass_raw, pass_raw_len, salt, salt_len);
  }
  if (!alg_ok) {
    goto err;
  }

  size_t max_out = (size_t)plaintext_len + EVP_CIPHER_CTX_block_size(&ctx);
  if (max_out < (size_t)plaintext_len) {
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_TOO_LONG);
    goto err;
  }

  CBB ciphertext;
  uint8_t *out;
  int n1, n2;
  if (!CBB_add_asn1(&epki, &ciphertext, CBS_ASN1_OCTETSTRING) ||
      !CBB_reserve(&ciphertext, &out, max_out) ||
      !EVP_CipherUpdate(&ctx, out, &n1, plaintext, plaintext_len) ||
      !EVP_CipherFinal_ex(&ctx, out + n1, &n2) ||
      !CBB_did_write(&ciphertext, n1 + n2) ||
      !CBB_finish(&cbb, &der, &der_len)) {
    goto err;
  }

  /* Convert back to legacy ASN.1 objects. */
  const uint8_t *ptr = der;
  ret = d2i_X509_SIG(NULL, &ptr, der_len);
  if (ret == NULL || ptr != der + der_len) {
    OPENSSL_PUT_ERROR(PKCS8, ERR_R_INTERNAL_ERROR);
    X509_SIG_free(ret);
    ret = NULL;
  }

err:
  if (plaintext_len > 0) {
    OPENSSL_cleanse(plaintext, plaintext_len);
  }
  OPENSSL_free(plaintext);
  OPENSSL_free(salt_buf);
  OPENSSL_free(der);
  CBB_cleanup(&cbb);
  EVP_CIPHER_CTX_cleanup(&ctx);
  return ret;
}

X509_SIG *PKCS8_encrypt(int pbe_nid, const EVP_CIPHER *cipher, const char *pass,
                        int pass_len, const uint8_t *salt, size_t salt_len,
                        int iterations, PKCS8_PRIV_KEY_INFO *p8inf) {
  uint8_t *pass_raw = NULL;
  size_t pass_raw_len = 0;
  if (!pass_to_pass_raw(pbe_nid, pass, pass_len, &pass_raw, &pass_raw_len)) {
    return NULL;
  }

  X509_SIG *ret = pkcs8_encrypt_raw(pbe_nid, cipher, pass_raw, pass_raw_len,
                                    salt, salt_len, iterations, p8inf);

  if (pass_raw) {
    OPENSSL_cleanse(pass_raw, pass_raw_len);
    OPENSSL_free(pass_raw);
  }
  return ret;
}

EVP_PKEY *EVP_PKCS82PKEY(PKCS8_PRIV_KEY_INFO *p8) {
  uint8_t *der = NULL;
  int der_len = i2d_PKCS8_PRIV_KEY_INFO(p8, &der);
  if (der_len < 0) {
    return NULL;
  }

  CBS cbs;
  CBS_init(&cbs, der, (size_t)der_len);
  EVP_PKEY *ret = EVP_parse_private_key(&cbs);
  if (ret == NULL || CBS_len(&cbs) != 0) {
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_DECODE_ERROR);
    EVP_PKEY_free(ret);
    OPENSSL_free(der);
    return NULL;
  }

  OPENSSL_free(der);
  return ret;
}

PKCS8_PRIV_KEY_INFO *EVP_PKEY2PKCS8(EVP_PKEY *pkey) {
  CBB cbb;
  uint8_t *der = NULL;
  size_t der_len;
  if (!CBB_init(&cbb, 0) ||
      !EVP_marshal_private_key(&cbb, pkey) ||
      !CBB_finish(&cbb, &der, &der_len) ||
      der_len > LONG_MAX) {
    CBB_cleanup(&cbb);
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_ENCODE_ERROR);
    goto err;
  }

  const uint8_t *p = der;
  PKCS8_PRIV_KEY_INFO *p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, (long)der_len);
  if (p8 == NULL || p != der + der_len) {
    PKCS8_PRIV_KEY_INFO_free(p8);
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_DECODE_ERROR);
    goto err;
  }

  OPENSSL_free(der);
  return p8;

err:
  OPENSSL_free(der);
  return NULL;
}

struct pkcs12_context {
  EVP_PKEY **out_key;
  STACK_OF(X509) *out_certs;
  uint8_t *password;
  size_t password_len;
};

/* PKCS12_handle_sequence parses a BER-encoded SEQUENCE of elements in a PKCS#12
 * structure. */
static int PKCS12_handle_sequence(
    CBS *sequence, struct pkcs12_context *ctx,
    int (*handle_element)(CBS *cbs, struct pkcs12_context *ctx)) {
  uint8_t *der_bytes = NULL;
  size_t der_len;
  CBS in;
  int ret = 0;

  /* Although a BER->DER conversion is done at the beginning of |PKCS12_parse|,
   * the ASN.1 data gets wrapped in OCTETSTRINGs and/or encrypted and the
   * conversion cannot see through those wrappings. So each time we step
   * through one we need to convert to DER again. */
  if (!CBS_asn1_ber_to_der(sequence, &der_bytes, &der_len)) {
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_BAD_PKCS12_DATA);
    return 0;
  }

  if (der_bytes != NULL) {
    CBS_init(&in, der_bytes, der_len);
  } else {
    CBS_init(&in, CBS_data(sequence), CBS_len(sequence));
  }

  CBS child;
  if (!CBS_get_asn1(&in, &child, CBS_ASN1_SEQUENCE) ||
      CBS_len(&in) != 0) {
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_BAD_PKCS12_DATA);
    goto err;
  }

  while (CBS_len(&child) > 0) {
    CBS element;
    if (!CBS_get_asn1(&child, &element, CBS_ASN1_SEQUENCE)) {
      OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_BAD_PKCS12_DATA);
      goto err;
    }

    if (!handle_element(&element, ctx)) {
      goto err;
    }
  }

  ret = 1;

err:
  OPENSSL_free(der_bytes);
  return ret;
}

/* PKCS12_handle_safe_bag parses a single SafeBag element in a PKCS#12
 * structure. */
static int PKCS12_handle_safe_bag(CBS *safe_bag, struct pkcs12_context *ctx) {
  CBS bag_id, wrapped_value;
  if (!CBS_get_asn1(safe_bag, &bag_id, CBS_ASN1_OBJECT) ||
      !CBS_get_asn1(safe_bag, &wrapped_value,
                        CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0)
      /* Ignore the bagAttributes field. */) {
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_BAD_PKCS12_DATA);
    return 0;
  }

  int nid = OBJ_cbs2nid(&bag_id);
  if (nid == NID_pkcs8ShroudedKeyBag) {
    /* See RFC 7292, section 4.2.2. */
    if (*ctx->out_key) {
      OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_MULTIPLE_PRIVATE_KEYS_IN_PKCS12);
      return 0;
    }

    if (CBS_len(&wrapped_value) > LONG_MAX) {
      OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_BAD_PKCS12_DATA);
      return 0;
    }

    /* |encrypted| isn't actually an X.509 signature, but it has the same
     * structure as one and so |X509_SIG| is reused to store it. */
    const uint8_t *inp = CBS_data(&wrapped_value);
    X509_SIG *encrypted =
        d2i_X509_SIG(NULL, &inp, (long)CBS_len(&wrapped_value));
    if (encrypted == NULL) {
      OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_BAD_PKCS12_DATA);
      return 0;
    }
    if (inp != CBS_data(&wrapped_value) + CBS_len(&wrapped_value)) {
      OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_BAD_PKCS12_DATA);
      X509_SIG_free(encrypted);
      return 0;
    }

    PKCS8_PRIV_KEY_INFO *pki =
        pkcs8_decrypt_raw(encrypted, ctx->password, ctx->password_len);
    X509_SIG_free(encrypted);
    if (pki == NULL) {
      return 0;
    }

    *ctx->out_key = EVP_PKCS82PKEY(pki);
    PKCS8_PRIV_KEY_INFO_free(pki);
    return ctx->out_key != NULL;
  }

  if (nid == NID_certBag) {
    /* See RFC 7292, section 4.2.3. */
    CBS cert_bag, cert_type, wrapped_cert, cert;
    if (!CBS_get_asn1(&wrapped_value, &cert_bag, CBS_ASN1_SEQUENCE) ||
        !CBS_get_asn1(&cert_bag, &cert_type, CBS_ASN1_OBJECT) ||
        !CBS_get_asn1(&cert_bag, &wrapped_cert,
                      CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0) ||
        !CBS_get_asn1(&wrapped_cert, &cert, CBS_ASN1_OCTETSTRING)) {
      OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_BAD_PKCS12_DATA);
      return 0;
    }

    if (OBJ_cbs2nid(&cert_type) != NID_x509Certificate) {
      return 1;
    }

    if (CBS_len(&cert) > LONG_MAX) {
      OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_BAD_PKCS12_DATA);
      return 0;
    }

    const uint8_t *inp = CBS_data(&cert);
    X509 *x509 = d2i_X509(NULL, &inp, (long)CBS_len(&cert));
    if (!x509) {
      OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_BAD_PKCS12_DATA);
      return 0;
    }

    if (inp != CBS_data(&cert) + CBS_len(&cert)) {
      OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_BAD_PKCS12_DATA);
      X509_free(x509);
      return 0;
    }

    if (0 == sk_X509_push(ctx->out_certs, x509)) {
      X509_free(x509);
      return 0;
    }

    return 1;
  }

  /* Unknown element type - ignore it. */
  return 1;
}

/* PKCS12_handle_content_info parses a single PKCS#7 ContentInfo element in a
 * PKCS#12 structure. */
static int PKCS12_handle_content_info(CBS *content_info,
                                      struct pkcs12_context *ctx) {
  CBS content_type, wrapped_contents, contents;
  int nid, ret = 0;
  uint8_t *storage = NULL;

  if (!CBS_get_asn1(content_info, &content_type, CBS_ASN1_OBJECT) ||
      !CBS_get_asn1(content_info, &wrapped_contents,
                        CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0) ||
      CBS_len(content_info) != 0) {
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_BAD_PKCS12_DATA);
    goto err;
  }

  nid = OBJ_cbs2nid(&content_type);
  if (nid == NID_pkcs7_encrypted) {
    /* See https://tools.ietf.org/html/rfc2315#section-13.
     *
     * PKCS#7 encrypted data inside a PKCS#12 structure is generally an
     * encrypted certificate bag and it's generally encrypted with 40-bit
     * RC2-CBC. */
    CBS version_bytes, eci, contents_type, ai, encrypted_contents;
    uint8_t *out;
    size_t out_len;

    if (!CBS_get_asn1(&wrapped_contents, &contents, CBS_ASN1_SEQUENCE) ||
        !CBS_get_asn1(&contents, &version_bytes, CBS_ASN1_INTEGER) ||
        /* EncryptedContentInfo, see
         * https://tools.ietf.org/html/rfc2315#section-10.1 */
        !CBS_get_asn1(&contents, &eci, CBS_ASN1_SEQUENCE) ||
        !CBS_get_asn1(&eci, &contents_type, CBS_ASN1_OBJECT) ||
        /* AlgorithmIdentifier, see
         * https://tools.ietf.org/html/rfc5280#section-4.1.1.2 */
        !CBS_get_asn1(&eci, &ai, CBS_ASN1_SEQUENCE) ||
        !CBS_get_asn1_implicit_string(
            &eci, &encrypted_contents, &storage,
            CBS_ASN1_CONTEXT_SPECIFIC | 0, CBS_ASN1_OCTETSTRING)) {
      OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_BAD_PKCS12_DATA);
      goto err;
    }

    if (OBJ_cbs2nid(&contents_type) != NID_pkcs7_data) {
      OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_BAD_PKCS12_DATA);
      goto err;
    }

    if (!pbe_decrypt(&out, &out_len, &ai, ctx->password, ctx->password_len,
                     CBS_data(&encrypted_contents),
                     CBS_len(&encrypted_contents))) {
      goto err;
    }

    CBS safe_contents;
    CBS_init(&safe_contents, out, out_len);
    ret = PKCS12_handle_sequence(&safe_contents, ctx, PKCS12_handle_safe_bag);
    OPENSSL_free(out);
  } else if (nid == NID_pkcs7_data) {
    CBS octet_string_contents;

    if (!CBS_get_asn1(&wrapped_contents, &octet_string_contents,
                      CBS_ASN1_OCTETSTRING)) {
      OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_BAD_PKCS12_DATA);
      goto err;
    }

    ret = PKCS12_handle_sequence(&octet_string_contents, ctx,
                                 PKCS12_handle_safe_bag);
  } else {
    /* Unknown element type - ignore it. */
    ret = 1;
  }

err:
  OPENSSL_free(storage);
  return ret;
}

int PKCS12_get_key_and_certs(EVP_PKEY **out_key, STACK_OF(X509) *out_certs,
                             CBS *ber_in, const char *password) {
  uint8_t *der_bytes = NULL;
  size_t der_len;
  CBS in, pfx, mac_data, authsafe, content_type, wrapped_authsafes, authsafes;
  uint64_t version;
  int ret = 0;
  struct pkcs12_context ctx;
  const size_t original_out_certs_len = sk_X509_num(out_certs);

  /* The input may be in BER format. */
  if (!CBS_asn1_ber_to_der(ber_in, &der_bytes, &der_len)) {
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_BAD_PKCS12_DATA);
    return 0;
  }
  if (der_bytes != NULL) {
    CBS_init(&in, der_bytes, der_len);
  } else {
    CBS_init(&in, CBS_data(ber_in), CBS_len(ber_in));
  }

  *out_key = NULL;
  OPENSSL_memset(&ctx, 0, sizeof(ctx));

  /* See ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-12/pkcs-12v1.pdf, section
   * four. */
  if (!CBS_get_asn1(&in, &pfx, CBS_ASN1_SEQUENCE) ||
      CBS_len(&in) != 0 ||
      !CBS_get_asn1_uint64(&pfx, &version)) {
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_BAD_PKCS12_DATA);
    goto err;
  }

  if (version < 3) {
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_BAD_PKCS12_VERSION);
    goto err;
  }

  if (!CBS_get_asn1(&pfx, &authsafe, CBS_ASN1_SEQUENCE)) {
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_BAD_PKCS12_DATA);
    goto err;
  }

  if (CBS_len(&pfx) == 0) {
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_MISSING_MAC);
    goto err;
  }

  if (!CBS_get_asn1(&pfx, &mac_data, CBS_ASN1_SEQUENCE)) {
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_BAD_PKCS12_DATA);
    goto err;
  }

  /* authsafe is a PKCS#7 ContentInfo. See
   * https://tools.ietf.org/html/rfc2315#section-7. */
  if (!CBS_get_asn1(&authsafe, &content_type, CBS_ASN1_OBJECT) ||
      !CBS_get_asn1(&authsafe, &wrapped_authsafes,
                        CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0)) {
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_BAD_PKCS12_DATA);
    goto err;
  }

  /* The content type can either be |NID_pkcs7_data| or |NID_pkcs7_signed|. The
   * latter indicates that it's signed by a public key, which isn't
   * supported. */
  if (OBJ_cbs2nid(&content_type) != NID_pkcs7_data) {
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_PKCS12_PUBLIC_KEY_INTEGRITY_NOT_SUPPORTED);
    goto err;
  }

  if (!CBS_get_asn1(&wrapped_authsafes, &authsafes, CBS_ASN1_OCTETSTRING)) {
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_BAD_PKCS12_DATA);
    goto err;
  }

  ctx.out_key = out_key;
  ctx.out_certs = out_certs;
  if (!ascii_to_ucs2(password, password ? strlen(password) : 0, &ctx.password,
                     &ctx.password_len)) {
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_DECODE_ERROR);
    goto err;
  }

  /* Verify the MAC. */
  {
    CBS mac, hash_type_seq, hash_oid, salt, expected_mac;
    uint64_t iterations;
    int hash_nid;
    const EVP_MD *md;
    uint8_t hmac_key[EVP_MAX_MD_SIZE];
    uint8_t hmac[EVP_MAX_MD_SIZE];
    unsigned hmac_len;

    if (!CBS_get_asn1(&mac_data, &mac, CBS_ASN1_SEQUENCE) ||
        !CBS_get_asn1(&mac, &hash_type_seq, CBS_ASN1_SEQUENCE) ||
        !CBS_get_asn1(&hash_type_seq, &hash_oid, CBS_ASN1_OBJECT) ||
        !CBS_get_asn1(&mac, &expected_mac, CBS_ASN1_OCTETSTRING) ||
        !CBS_get_asn1(&mac_data, &salt, CBS_ASN1_OCTETSTRING)) {
      OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_BAD_PKCS12_DATA);
      goto err;
    }

    /* The iteration count is optional and the default is one. */
    iterations = 1;
    if (CBS_len(&mac_data) > 0) {
      if (!CBS_get_asn1_uint64(&mac_data, &iterations) ||
          iterations > UINT_MAX) {
        OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_BAD_PKCS12_DATA);
        goto err;
      }
    }

    hash_nid = OBJ_cbs2nid(&hash_oid);
    if (hash_nid == NID_undef ||
        (md = EVP_get_digestbynid(hash_nid)) == NULL) {
      OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_UNKNOWN_HASH);
      goto err;
    }

    if (!pkcs12_key_gen_raw(ctx.password, ctx.password_len, CBS_data(&salt),
                            CBS_len(&salt), PKCS12_MAC_ID, iterations,
                            EVP_MD_size(md), hmac_key, md)) {
      goto err;
    }

    if (NULL == HMAC(md, hmac_key, EVP_MD_size(md), CBS_data(&authsafes),
                     CBS_len(&authsafes), hmac, &hmac_len)) {
      goto err;
    }

    if (!CBS_mem_equal(&expected_mac, hmac, hmac_len)) {
      OPENSSL_PUT_ERROR(PKCS8, PKCS8_R_INCORRECT_PASSWORD);
      goto err;
    }
  }

  /* authsafes contains a series of PKCS#7 ContentInfos. */
  if (!PKCS12_handle_sequence(&authsafes, &ctx, PKCS12_handle_content_info)) {
    goto err;
  }

  ret = 1;

err:
  OPENSSL_free(ctx.password);
  OPENSSL_free(der_bytes);
  if (!ret) {
    EVP_PKEY_free(*out_key);
    *out_key = NULL;
    while (sk_X509_num(out_certs) > original_out_certs_len) {
      X509 *x509 = sk_X509_pop(out_certs);
      X509_free(x509);
    }
  }

  return ret;
}

void PKCS12_PBE_add(void) {}

struct pkcs12_st {
  uint8_t *ber_bytes;
  size_t ber_len;
};

PKCS12 *d2i_PKCS12(PKCS12 **out_p12, const uint8_t **ber_bytes,
                   size_t ber_len) {
  PKCS12 *p12;

  p12 = OPENSSL_malloc(sizeof(PKCS12));
  if (!p12) {
    return NULL;
  }

  p12->ber_bytes = OPENSSL_malloc(ber_len);
  if (!p12->ber_bytes) {
    OPENSSL_free(p12);
    return NULL;
  }

  OPENSSL_memcpy(p12->ber_bytes, *ber_bytes, ber_len);
  p12->ber_len = ber_len;
  *ber_bytes += ber_len;

  if (out_p12) {
    PKCS12_free(*out_p12);

    *out_p12 = p12;
  }

  return p12;
}

PKCS12* d2i_PKCS12_bio(BIO *bio, PKCS12 **out_p12) {
  size_t used = 0;
  BUF_MEM *buf;
  const uint8_t *dummy;
  static const size_t kMaxSize = 256 * 1024;
  PKCS12 *ret = NULL;

  buf = BUF_MEM_new();
  if (buf == NULL) {
    return NULL;
  }
  if (BUF_MEM_grow(buf, 8192) == 0) {
    goto out;
  }

  for (;;) {
    int n = BIO_read(bio, &buf->data[used], buf->length - used);
    if (n < 0) {
      if (used == 0) {
        goto out;
      }
      /* Workaround a bug in node.js. It uses a memory BIO for this in the wrong
       * mode. */
      n = 0;
    }

    if (n == 0) {
      break;
    }
    used += n;

    if (used < buf->length) {
      continue;
    }

    if (buf->length > kMaxSize ||
        BUF_MEM_grow(buf, buf->length * 2) == 0) {
      goto out;
    }
  }

  dummy = (uint8_t*) buf->data;
  ret = d2i_PKCS12(out_p12, &dummy, used);

out:
  BUF_MEM_free(buf);
  return ret;
}

PKCS12* d2i_PKCS12_fp(FILE *fp, PKCS12 **out_p12) {
  BIO *bio;
  PKCS12 *ret;

  bio = BIO_new_fp(fp, 0 /* don't take ownership */);
  if (!bio) {
    return NULL;
  }

  ret = d2i_PKCS12_bio(bio, out_p12);
  BIO_free(bio);
  return ret;
}

int PKCS12_parse(const PKCS12 *p12, const char *password, EVP_PKEY **out_pkey,
                 X509 **out_cert, STACK_OF(X509) **out_ca_certs) {
  CBS ber_bytes;
  STACK_OF(X509) *ca_certs = NULL;
  char ca_certs_alloced = 0;

  if (out_ca_certs != NULL && *out_ca_certs != NULL) {
    ca_certs = *out_ca_certs;
  }

  if (!ca_certs) {
    ca_certs = sk_X509_new_null();
    if (ca_certs == NULL) {
      OPENSSL_PUT_ERROR(PKCS8, ERR_R_MALLOC_FAILURE);
      return 0;
    }
    ca_certs_alloced = 1;
  }

  CBS_init(&ber_bytes, p12->ber_bytes, p12->ber_len);
  if (!PKCS12_get_key_and_certs(out_pkey, ca_certs, &ber_bytes, password)) {
    if (ca_certs_alloced) {
      sk_X509_free(ca_certs);
    }
    return 0;
  }

  *out_cert = NULL;
  if (sk_X509_num(ca_certs) > 0) {
    *out_cert = sk_X509_shift(ca_certs);
  }

  if (out_ca_certs) {
    *out_ca_certs = ca_certs;
  } else {
    sk_X509_pop_free(ca_certs, X509_free);
  }

  return 1;
}

int PKCS12_verify_mac(const PKCS12 *p12, const char *password,
                      int password_len) {
  if (password == NULL) {
    if (password_len != 0) {
      return 0;
    }
  } else if (password_len != -1 &&
             (password[password_len] != 0 ||
              OPENSSL_memchr(password, 0, password_len) != NULL)) {
    return 0;
  }

  EVP_PKEY *pkey = NULL;
  X509 *cert = NULL;
  if (!PKCS12_parse(p12, password, &pkey, &cert, NULL)) {
    ERR_clear_error();
    return 0;
  }

  EVP_PKEY_free(pkey);
  X509_free(cert);

  return 1;
}

void PKCS12_free(PKCS12 *p12) {
  if (p12 == NULL) {
    return;
  }
  OPENSSL_free(p12->ber_bytes);
  OPENSSL_free(p12);
}
