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

#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/cipher.h>
#include <openssl/digest.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/x509.h>

#include "../evp/internal.h"


#define PKCS12_KEY_ID 1
#define PKCS12_IV_ID 2

static int ascii_to_ucs2(const char *ascii, size_t ascii_len,
                              uint8_t **out, size_t *out_len) {
  uint8_t *unitmp;
  size_t ulen, i;

  ulen = ascii_len * 2 + 2;
  if (ulen < ascii_len) {
    return 0;
  }
  unitmp = OPENSSL_malloc(ulen);
  if (unitmp == NULL) {
    return 0;
  }
  for (i = 0; i < ulen - 2; i += 2) {
    unitmp[i] = 0;
    unitmp[i + 1] = ascii[i >> 1];
  }

  /* Make result double null terminated */
  unitmp[ulen - 2] = 0;
  unitmp[ulen - 1] = 0;
  *out_len = ulen;
  *out = unitmp;
  return 1;
}

static int pkcs12_key_gen_uni(uint8_t *pass, size_t pass_len, uint8_t *salt,
                              size_t salt_len, int id, int iterations,
                              size_t out_len, uint8_t *out,
                              const EVP_MD *md_type) {
  uint8_t *B, *D, *I, *p, *Ai;
  int Slen, Plen, Ilen, Ijlen;
  int i, j, v;
  size_t u;
  int ret = 0;
  BIGNUM *Ij, *Bpl1; /* These hold Ij and B + 1 */
  EVP_MD_CTX ctx;

  EVP_MD_CTX_init(&ctx);
  v = EVP_MD_block_size(md_type);
  u = EVP_MD_size(md_type);
  D = OPENSSL_malloc(v);
  Ai = OPENSSL_malloc(u);
  B = OPENSSL_malloc(v + 1);
  Slen = v * ((salt_len + v - 1) / v);
  if (pass_len)
    Plen = v * ((pass_len + v - 1) / v);
  else
    Plen = 0;
  Ilen = Slen + Plen;
  I = OPENSSL_malloc(Ilen);
  Ij = BN_new();
  Bpl1 = BN_new();
  if (!D || !Ai || !B || !I || !Ij || !Bpl1)
    goto err;
  for (i = 0; i < v; i++)
    D[i] = id;
  p = I;
  for (i = 0; i < Slen; i++)
    *p++ = salt[i % salt_len];
  for (i = 0; i < Plen; i++)
    *p++ = pass[i % pass_len];
  for (;;) {
    if (!EVP_DigestInit_ex(&ctx, md_type, NULL) ||
        !EVP_DigestUpdate(&ctx, D, v) ||
        !EVP_DigestUpdate(&ctx, I, Ilen) ||
        !EVP_DigestFinal_ex(&ctx, Ai, NULL)) {
      goto err;
    }
    for (j = 1; j < iterations; j++) {
      if (!EVP_DigestInit_ex(&ctx, md_type, NULL) ||
          !EVP_DigestUpdate(&ctx, Ai, u) ||
          !EVP_DigestFinal_ex(&ctx, Ai, NULL)) {
        goto err;
      }
    }
    memcpy(out, Ai, out_len < u ? out_len : u);
    if (u >= out_len) {
      ret = 1;
      goto end;
    }
    out_len -= u;
    out += u;
    for (j = 0; j < v; j++)
      B[j] = Ai[j % u];
    /* Work out B + 1 first then can use B as tmp space */
    if (!BN_bin2bn(B, v, Bpl1))
      goto err;
    if (!BN_add_word(Bpl1, 1))
      goto err;
    for (j = 0; j < Ilen; j += v) {
      if (!BN_bin2bn(I + j, v, Ij))
        goto err;
      if (!BN_add(Ij, Ij, Bpl1))
        goto err;
      if (!BN_bn2bin(Ij, B))
        goto err;
      Ijlen = BN_num_bytes(Ij);
      /* If more than 2^(v*8) - 1 cut off MSB */
      if (Ijlen > v) {
        if (!BN_bn2bin(Ij, B))
          goto err;
        memcpy(I + j, B + 1, v);
        /* If less than v bytes pad with zeroes */
      } else if (Ijlen < v) {
        memset(I + j, 0, v - Ijlen);
        if (!BN_bn2bin(Ij, I + j + v - Ijlen))
          goto err;
      } else if (!BN_bn2bin(Ij, I + j)) {
        goto err;
      }
    }
  }

err:
  OPENSSL_PUT_ERROR(PKCS8, pkcs12_key_gen_uni, ERR_R_MALLOC_FAILURE);

end:
  OPENSSL_free(Ai);
  OPENSSL_free(B);
  OPENSSL_free(D);
  OPENSSL_free(I);
  BN_free(Ij);
  BN_free(Bpl1);
  EVP_MD_CTX_cleanup(&ctx);

  return ret;
}

static int pkcs12_key_gen_asc(const char *pass, size_t pass_len, uint8_t *salt,
                              size_t salt_len, int id, int iterations,
                              int out_len, uint8_t *out,
                              const EVP_MD *md_type) {
  int ret;
  uint8_t *ucs2_pass = NULL;
  size_t ucs2_pass_len = 0;

  if (pass && !ascii_to_ucs2(pass, pass_len, &ucs2_pass, &ucs2_pass_len)) {
    OPENSSL_PUT_ERROR(PKCS8, pkcs12_key_gen_asc, PKCS8_R_DECODE_ERROR);
    return 0;
  }
  ret = pkcs12_key_gen_uni(ucs2_pass, ucs2_pass_len, salt, salt_len, id,
                           iterations, out_len, out, md_type);

  if (ucs2_pass) {
    OPENSSL_cleanse(ucs2_pass, ucs2_pass_len);
    OPENSSL_free(ucs2_pass);
  }

  return ret;
}

static int pkcs12_pbe_keyivgen(EVP_CIPHER_CTX *ctx, const char *pass,
                               size_t pass_len, ASN1_TYPE *param,
                               const EVP_CIPHER *cipher, const EVP_MD *md,
                               int is_encrypt) {
  PBEPARAM *pbe;
  int salt_len, iterations, ret;
  uint8_t *salt;
  const uint8_t *pbuf;
  uint8_t key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];

  /* Extract useful info from parameter */
  if (param == NULL || param->type != V_ASN1_SEQUENCE ||
      param->value.sequence == NULL) {
    OPENSSL_PUT_ERROR(PKCS8, pkcs12_pbe_keyivgen, PKCS8_R_DECODE_ERROR);
    return 0;
  }

  pbuf = param->value.sequence->data;
  pbe = d2i_PBEPARAM(NULL, &pbuf, param->value.sequence->length);
  if (pbe == NULL) {
    OPENSSL_PUT_ERROR(PKCS8, pkcs12_pbe_keyivgen, PKCS8_R_DECODE_ERROR);
    return 0;
  }

  if (!pbe->iter) {
    iterations = 1;
  } else {
    iterations = ASN1_INTEGER_get(pbe->iter);
  }
  salt = pbe->salt->data;
  salt_len = pbe->salt->length;
  if (!pkcs12_key_gen_asc(pass, pass_len, salt, salt_len, PKCS12_KEY_ID,
                          iterations, EVP_CIPHER_key_length(cipher), key, md)) {
    OPENSSL_PUT_ERROR(PKCS8, pkcs12_pbe_keyivgen, PKCS8_R_KEY_GEN_ERROR);
    PBEPARAM_free(pbe);
    return 0;
  }
  if (!pkcs12_key_gen_asc(pass, pass_len, salt, salt_len, PKCS12_IV_ID,
                          iterations, EVP_CIPHER_iv_length(cipher), iv, md)) {
    OPENSSL_PUT_ERROR(PKCS8, pkcs12_pbe_keyivgen, PKCS8_R_KEY_GEN_ERROR);
    PBEPARAM_free(pbe);
    return 0;
  }
  PBEPARAM_free(pbe);
  ret = EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, is_encrypt);
  OPENSSL_cleanse(key, EVP_MAX_KEY_LENGTH);
  OPENSSL_cleanse(iv, EVP_MAX_IV_LENGTH);
  return ret;
}

typedef int (*keygen_func)(EVP_CIPHER_CTX *ctx, const char *pass,
                           size_t pass_len, ASN1_TYPE *param,
                           const EVP_CIPHER *cipher, const EVP_MD *md,
                           int is_encrypt);

struct pbe_suite {
  int pbe_nid;
  int cipher_nid;
  int md_nid;
  keygen_func keygen;
};

static const struct pbe_suite kBuiltinPBE[] = {
    {
     NID_pbe_WithSHA1And128BitRC4, NID_rc4, NID_sha1, pkcs12_pbe_keyivgen,
    },
    {
     NID_pbe_WithSHA1And3_Key_TripleDES_CBC, NID_des_ede3_cbc, NID_sha1,
     pkcs12_pbe_keyivgen,
    },
};

static int pbe_cipher_init(ASN1_OBJECT *pbe_obj, const char *pass,
                           size_t pass_len, ASN1_TYPE *param,
                           EVP_CIPHER_CTX *ctx, int is_encrypt) {
  const EVP_CIPHER *cipher;
  const EVP_MD *md;
  unsigned i;

  const struct pbe_suite *suite = NULL;
  const int pbe_nid = OBJ_obj2nid(pbe_obj);

  for (i = 0; i < sizeof(kBuiltinPBE) / sizeof(struct pbe_suite); i++) {
    suite = &kBuiltinPBE[i];
    if (suite->pbe_nid == pbe_nid) {
      break;
    }
  }

  if (suite == NULL) {
    char obj_str[80];
    OPENSSL_PUT_ERROR(PKCS8, pbe_cipher_init, PKCS8_R_UNKNOWN_ALGORITHM);
    if (!pbe_obj) {
      strncpy(obj_str, "NULL", sizeof(obj_str));
    } else {
      i2t_ASN1_OBJECT(obj_str, sizeof(obj_str), pbe_obj);
    }
    ERR_add_error_data(2, "TYPE=", obj_str);
    return 0;
  }

  if (suite->cipher_nid == -1) {
    cipher = NULL;
  } else {
    cipher = EVP_get_cipherbynid(suite->cipher_nid);
    if (!cipher) {
      OPENSSL_PUT_ERROR(PKCS8, pbe_cipher_init, PKCS8_R_UNKNOWN_CIPHER);
      return 0;
    }
  }

  if (suite->md_nid == -1) {
    md = NULL;
  } else {
    md = EVP_get_digestbynid(suite->md_nid);
    if (!md) {
      OPENSSL_PUT_ERROR(PKCS8, pbe_cipher_init, PKCS8_R_UNKNOWN_DIGEST);
      return 0;
    }
  }

  if (!suite->keygen(ctx, pass, pass_len, param, cipher, md, is_encrypt)) {
    OPENSSL_PUT_ERROR(PKCS8, pbe_cipher_init, PKCS8_R_KEYGEN_FAILURE);
    return 0;
  }

  return 1;
}

static int pbe_crypt(const X509_ALGOR *algor, const char *pass, size_t pass_len,
                     uint8_t *in, size_t in_len, uint8_t **out, size_t *out_len,
                     int is_encrypt) {
  uint8_t *buf;
  int n, ret = 0;
  EVP_CIPHER_CTX ctx;
  unsigned block_size;

  EVP_CIPHER_CTX_init(&ctx);

  if (!pbe_cipher_init(algor->algorithm, pass, pass_len, algor->parameter, &ctx,
                       is_encrypt)) {
    OPENSSL_PUT_ERROR(PKCS8, pbe_crypt, PKCS8_R_UNKNOWN_CIPHER_ALGORITHM);
    return 0;
  }
  block_size = EVP_CIPHER_CTX_block_size(&ctx);

  if (in_len + block_size < in_len) {
    OPENSSL_PUT_ERROR(PKCS8, pbe_crypt, PKCS8_R_TOO_LONG);
    goto err;
  }

  buf = OPENSSL_malloc(in_len + block_size);
  if (buf == NULL) {
    OPENSSL_PUT_ERROR(PKCS8, pbe_crypt, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  if (!EVP_CipherUpdate(&ctx, buf, &n, in, in_len)) {
    OPENSSL_free(buf);
    OPENSSL_PUT_ERROR(PKCS8, pbe_crypt, ERR_R_EVP_LIB);
    goto err;
  }
  *out_len = n;

  if (!EVP_CipherFinal_ex(&ctx, buf + n, &n)) {
    OPENSSL_free(buf);
    OPENSSL_PUT_ERROR(PKCS8, pbe_crypt, ERR_R_EVP_LIB);
    goto err;
  }
  *out_len += n;
  *out = buf;
  ret = 1;

err:
  EVP_CIPHER_CTX_cleanup(&ctx);
  return ret;
}

static void *pkcs12_item_decrypt_d2i(X509_ALGOR *algor, const ASN1_ITEM *it,
                                     const char *pass, size_t pass_len,
                                     ASN1_OCTET_STRING *oct) {
  uint8_t *out;
  const uint8_t *p;
  void *ret;
  size_t out_len;

  if (!pbe_crypt(algor, pass, pass_len, oct->data, oct->length, &out, &out_len,
                 0 /* decrypt */)) {
    OPENSSL_PUT_ERROR(PKCS8, pkcs12_item_decrypt_d2i, PKCS8_R_CRYPT_ERROR);
    return NULL;
  }
  p = out;
  ret = ASN1_item_d2i(NULL, &p, out_len, it);
  OPENSSL_cleanse(out, out_len);
  if (!ret) {
    OPENSSL_PUT_ERROR(PKCS8, pkcs12_item_decrypt_d2i, PKCS8_R_DECODE_ERROR);
  }
  OPENSSL_free(out);
  return ret;
}

PKCS8_PRIV_KEY_INFO *PKCS8_decrypt(X509_SIG *pkcs8, const char *pass,
                                   int pass_len) {
  if (pass && pass_len == -1) {
    pass_len = strlen(pass);
  }
  return pkcs12_item_decrypt_d2i(pkcs8->algor,
                                 ASN1_ITEM_rptr(PKCS8_PRIV_KEY_INFO), pass,
                                 pass_len, pkcs8->digest);
}

static ASN1_OCTET_STRING *pkcs12_item_i2d_encrypt(X509_ALGOR *algor,
                                                  const ASN1_ITEM *it,
                                                  const char *pass,
                                                  size_t passlen, void *obj) {
  ASN1_OCTET_STRING *oct;
  uint8_t *in = NULL;
  int in_len;
  size_t crypt_len;

  oct = M_ASN1_OCTET_STRING_new();
  if (oct == NULL) {
    OPENSSL_PUT_ERROR(PKCS8, pkcs12_item_i2d_encrypt, ERR_R_MALLOC_FAILURE);
    return NULL;
  }
  in_len = ASN1_item_i2d(obj, &in, it);
  if (!in) {
    OPENSSL_PUT_ERROR(PKCS8, pkcs12_item_i2d_encrypt, PKCS8_R_ENCODE_ERROR);
    return NULL;
  }
  if (!pbe_crypt(algor, pass, passlen, in, in_len, &oct->data, &crypt_len,
                 1 /* encrypt */)) {
    OPENSSL_PUT_ERROR(PKCS8, pkcs12_item_i2d_encrypt, PKCS8_R_ENCRYPT_ERROR);
    OPENSSL_free(in);
    return NULL;
  }
  oct->length = crypt_len;
  OPENSSL_cleanse(in, in_len);
  OPENSSL_free(in);
  return oct;
}

X509_SIG *PKCS8_encrypt(int pbe_nid, const EVP_CIPHER *cipher, const char *pass,
                        int pass_len, uint8_t *salt, size_t salt_len,
                        int iterations, PKCS8_PRIV_KEY_INFO *p8inf) {
  X509_SIG *pkcs8 = NULL;
  X509_ALGOR *pbe;

  if (pass && pass_len == -1) {
    pass_len = strlen(pass);
  }

  pkcs8 = X509_SIG_new();
  if (pkcs8 == NULL) {
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_encrypt, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  if (pbe_nid == -1) {
    pbe = PKCS5_pbe2_set(cipher, iterations, salt, salt_len);
  } else {
    pbe = PKCS5_pbe_set(pbe_nid, iterations, salt, salt_len);
  }

  if (!pbe) {
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_encrypt, ERR_R_ASN1_LIB);
    goto err;
  }

  X509_ALGOR_free(pkcs8->algor);
  pkcs8->algor = pbe;
  M_ASN1_OCTET_STRING_free(pkcs8->digest);
  pkcs8->digest = pkcs12_item_i2d_encrypt(
      pbe, ASN1_ITEM_rptr(PKCS8_PRIV_KEY_INFO), pass, pass_len, p8inf);
  if (!pkcs8->digest) {
    OPENSSL_PUT_ERROR(PKCS8, PKCS8_encrypt, PKCS8_R_ENCRYPT_ERROR);
    goto err;
  }

  return pkcs8;

err:
  X509_SIG_free(pkcs8);
  return NULL;
}

EVP_PKEY *EVP_PKCS82PKEY(PKCS8_PRIV_KEY_INFO *p8) {
  EVP_PKEY *pkey = NULL;
  ASN1_OBJECT *algoid;
  char obj_tmp[80];

  if (!PKCS8_pkey_get0(&algoid, NULL, NULL, NULL, p8))
    return NULL;

  pkey = EVP_PKEY_new();
  if (pkey == NULL) {
    OPENSSL_PUT_ERROR(PKCS8, EVP_PKCS82PKEY, ERR_R_MALLOC_FAILURE);
    return NULL;
  }

  if (!EVP_PKEY_set_type(pkey, OBJ_obj2nid(algoid))) {
    OPENSSL_PUT_ERROR(PKCS8, EVP_PKCS82PKEY,
                      PKCS8_R_UNSUPPORTED_PRIVATE_KEY_ALGORITHM);
    i2t_ASN1_OBJECT(obj_tmp, 80, algoid);
    ERR_add_error_data(2, "TYPE=", obj_tmp);
    goto error;
  }

  if (pkey->ameth->priv_decode) {
    if (!pkey->ameth->priv_decode(pkey, p8)) {
      OPENSSL_PUT_ERROR(PKCS8, EVP_PKCS82PKEY, PKCS8_R_PRIVATE_KEY_DECODE_ERROR);
      goto error;
    }
  } else {
    OPENSSL_PUT_ERROR(PKCS8, EVP_PKCS82PKEY, PKCS8_R_METHOD_NOT_SUPPORTED);
    goto error;
  }

  return pkey;

error:
  EVP_PKEY_free(pkey);
  return NULL;
}

PKCS8_PRIV_KEY_INFO *EVP_PKEY2PKCS8(EVP_PKEY *pkey) {
  PKCS8_PRIV_KEY_INFO *p8;

  p8 = PKCS8_PRIV_KEY_INFO_new();
  if (p8 == NULL) {
    OPENSSL_PUT_ERROR(PKCS8, EVP_PKEY2PKCS8, ERR_R_MALLOC_FAILURE);
    return NULL;
  }
  p8->broken = PKCS8_OK;

  if (pkey->ameth) {
    if (pkey->ameth->priv_encode) {
      if (!pkey->ameth->priv_encode(p8, pkey)) {
        OPENSSL_PUT_ERROR(PKCS8, EVP_PKEY2PKCS8,
                          PKCS8_R_PRIVATE_KEY_ENCODE_ERROR);
        goto error;
      }
    } else {
      OPENSSL_PUT_ERROR(PKCS8, EVP_PKEY2PKCS8, PKCS8_R_METHOD_NOT_SUPPORTED);
      goto error;
    }
  } else {
    OPENSSL_PUT_ERROR(PKCS8, EVP_PKEY2PKCS8,
                      PKCS8_R_UNSUPPORTED_PRIVATE_KEY_ALGORITHM);
    goto error;
  }
  return p8;

error:
  PKCS8_PRIV_KEY_INFO_free(p8);
  return NULL;
}
