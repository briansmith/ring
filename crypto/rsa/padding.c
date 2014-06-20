/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project 2005.
 */
/* ====================================================================
 * Copyright (c) 2005 The OpenSSL Project.  All rights reserved.
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

#include <openssl/digest.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include "internal.h"

/* TODO(fork): don't the check functions have to be constant time? */

int RSA_padding_add_PKCS1_type_1(uint8_t *to, unsigned tlen,
                                 const uint8_t *from, unsigned flen) {
  unsigned j;
  uint8_t *p;

  if (flen > (tlen - RSA_PKCS1_PADDING_SIZE)) {
    OPENSSL_PUT_ERROR(RSA, RSA_padding_add_PKCS1_type_1,
                      RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
    return 0;
  }

  p = (uint8_t *)to;

  *(p++) = 0;
  *(p++) = 1; /* Private Key BT (Block Type) */

  /* pad out with 0xff data */
  j = tlen - 3 - flen;
  memset(p, 0xff, j);
  p += j;
  *(p++) = 0;
  memcpy(p, from, (unsigned int)flen);
  return 1;
}

int RSA_padding_check_PKCS1_type_1(uint8_t *to, unsigned tlen, const uint8_t *from,
                                   unsigned flen, unsigned num) {
  unsigned i, j;
  const uint8_t *p;

  if (flen == 0) {
    OPENSSL_PUT_ERROR(RSA, RSA_padding_check_PKCS1_type_1,
                      RSA_R_EMPTY_PUBLIC_KEY);
    return -1;
  }

  p = from;
  if ((num != (flen + 1)) || (*(p++) != 1)) {
    OPENSSL_PUT_ERROR(RSA, RSA_padding_check_PKCS1_type_1,
                      RSA_R_BLOCK_TYPE_IS_NOT_01);
    return -1;
  }

  /* scan over padding data */
  j = flen - 1; /* one for type. */
  for (i = 0; i < j; i++) {
    if (*p != 0xff) /* should decrypt to 0xff */
    {
      if (*p == 0) {
        p++;
        break;
      } else {
        OPENSSL_PUT_ERROR(RSA, RSA_padding_check_PKCS1_type_1,
                          RSA_R_BAD_FIXED_HEADER_DECRYPT);
        return -1;
      }
    }
    p++;
  }

  if (i == j) {
    OPENSSL_PUT_ERROR(RSA, RSA_padding_check_PKCS1_type_1,
                      RSA_R_NULL_BEFORE_BLOCK_MISSING);
    return -1;
  }

  if (i < 8) {
    OPENSSL_PUT_ERROR(RSA, RSA_padding_check_PKCS1_type_1,
                      RSA_R_BAD_PAD_BYTE_COUNT);
    return -1;
  }
  i++; /* Skip over the '\0' */
  j -= i;
  if (j > tlen) {
    OPENSSL_PUT_ERROR(RSA, RSA_padding_check_PKCS1_type_1,
                      RSA_R_DATA_TOO_LARGE);
    return -1;
  }
  memcpy(to, p, j);

  return j;
}

int RSA_padding_add_PKCS1_type_2(uint8_t *to, unsigned tlen,
                                 const uint8_t *from, unsigned flen) {
  unsigned i, j;
  uint8_t *p;

  if (flen > (tlen - 11)) {
    OPENSSL_PUT_ERROR(RSA, RSA_padding_add_PKCS1_type_2,
                      RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
    return 0;
  }

  p = (unsigned char *)to;

  *(p++) = 0;
  *(p++) = 2; /* Public Key BT (Block Type) */

  /* pad out with non-zero random data */
  j = tlen - 3 - flen;

  if (RAND_pseudo_bytes(p, j) <= 0) {
    return 0;
  }

  for (i = 0; i < j; i++) {
    if (*p == 0) {
      do {
        if (RAND_pseudo_bytes(p, 1) <= 0) {
          return 0;
        }
      } while (*p == 0);
    }
    p++;
  }

  *(p++) = 0;

  memcpy(p, from, (unsigned int)flen);
  return 1;
}

/* constant_time_byte_eq returns 1 if x == y and 0 otherwise. */
static int constant_time_byte_eq(unsigned char a, unsigned char b) {
  unsigned char z = ~(a ^ b);
  z &= z >> 4;
  z &= z >> 2;
  z &= z >> 1;

  return z;
}

/* constant_time_select returns x if v is 1 and y if v is 0.
 * Its behavior is undefined if v takes any other value. */
static int constant_time_select(int v, int x, int y) {
  return ((~(v - 1)) & x) | ((v - 1) & y);
}

/* constant_time_le returns 1 if x < y and 0 otherwise.
 * x and y must be positive. */
static int constant_time_le(int x, int y) {
  return ((x - y - 1) >> (sizeof(int) * 8 - 1)) & 1;
}

int RSA_padding_check_PKCS1_type_2(uint8_t *to, unsigned tlen, const uint8_t *from,
                                   unsigned flen, unsigned num) {
  size_t i;
  unsigned char *em = NULL;
  int ret = -1;
  int first_byte_is_zero, second_byte_is_two, looking_for_index;
  int valid_index, zero_index = 0, msg_index;

  if (flen == 0) {
    OPENSSL_PUT_ERROR(RSA, RSA_padding_check_PKCS1_type_2,
                      RSA_R_EMPTY_PUBLIC_KEY);
    return -1;
  }

  /* PKCS#1 v1.5 decryption. See "PKCS #1 v2.2: RSA Cryptography
   * Standard", section 7.2.2. */

  if (flen > num) {
    goto err;
  }

  if (num < 11) {
    goto err;
  }


  em = OPENSSL_malloc(num);
  if (em == NULL) {
    OPENSSL_PUT_ERROR(RSA, RSA_padding_check_PKCS1_type_2,
                      ERR_R_MALLOC_FAILURE);
    return -1;
  }

  memset(em, 0, num);
  /* This unavoidably leaks timing information about |flen| because we
   * cannot have a constant memory access pattern without accessing
   * outside the bounds of |from|. */
  memcpy(em + num - flen, from, flen);

  first_byte_is_zero = constant_time_byte_eq(em[0], 0);
  second_byte_is_two = constant_time_byte_eq(em[1], 2);

  looking_for_index = 1;
  for (i = 2; i < num; i++) {
    int equals0 = constant_time_byte_eq(em[i], 0);
    zero_index =
        constant_time_select(looking_for_index & equals0, i, zero_index);
    looking_for_index = constant_time_select(equals0, 0, looking_for_index);
  }

  /* PS must be at least 8 bytes long, and it starts two bytes into |em|. */
  valid_index = constant_time_le(2 + 8, zero_index);
  /* Skip the zero byte. */
  msg_index = zero_index + 1;
  valid_index &= constant_time_le(num - msg_index, tlen);

  if (!(first_byte_is_zero & second_byte_is_two & ~looking_for_index &
        valid_index)) {
    goto err;
  }

  ret = num - msg_index;
  memcpy(to, &em[msg_index], ret);

err:
  if (em != NULL) {
    OPENSSL_free(em);
  }
  if (ret == -1) {
    OPENSSL_PUT_ERROR(RSA, RSA_padding_check_PKCS1_type_2,
                      RSA_R_PKCS_DECODING_ERROR);
  }
  return ret;
}

int RSA_padding_add_none(uint8_t *to, unsigned tlen, const uint8_t *from, unsigned flen) {
  if (flen > tlen) {
    OPENSSL_PUT_ERROR(RSA, RSA_padding_add_none,
                      RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
    return 0;
  }

  if (flen < tlen) {
    OPENSSL_PUT_ERROR(RSA, RSA_padding_add_none,
                      RSA_R_DATA_TOO_SMALL_FOR_KEY_SIZE);
    return 0;
  }

  memcpy(to, from, (unsigned int)flen);
  return 1;
}

int RSA_padding_check_none(uint8_t *to, unsigned tlen, const uint8_t *from,
                           unsigned flen, unsigned num) {
  if (flen > tlen) {
    OPENSSL_PUT_ERROR(RSA, RSA_padding_check_none, RSA_R_DATA_TOO_LARGE);
    return -1;
  }

  memset(to, 0, tlen - flen);
  memcpy(to + tlen - flen, from, flen);
  return tlen;
}

int RSA_padding_add_SSLv23(uint8_t *to, unsigned tlen, const uint8_t *from,
                           unsigned flen) {
  unsigned i, j;
  uint8_t *p;

  if (flen > (tlen - 11)) {
    OPENSSL_PUT_ERROR(RSA, RSA_padding_add_SSLv23,
                      RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
    return 0;
  }

  p = to;

  *(p++) = 0;
  *(p++) = 2; /* Public Key BT (Block Type) */

  /* pad out with non-zero random data */
  j = tlen - 3 - 8 - flen;

  if (RAND_pseudo_bytes(p, j) <= 0) {
    return 0;
  }

  for (i = 0; i < j; i++) {
    if (*p == '\0') {
      do {
        if (RAND_pseudo_bytes(p, 1) <= 0)
          return 0;
      } while (*p == '\0');
    }
    p++;
  }

  memset(p, 3, 8);
  p += 8;
  *(p++) = '\0';

  memcpy(p, from, flen);
  return 1;
}

int RSA_padding_check_SSLv23(uint8_t *to, unsigned tlen, const uint8_t *from,
                             unsigned flen, unsigned num) {
  unsigned i, j, k;
  const uint8_t *p;

  p = from;
  if (flen < 10) {
    OPENSSL_PUT_ERROR(RSA, RSA_padding_check_SSLv23, RSA_R_DATA_TOO_SMALL);
    return -1;
  }
  if ((num != (flen + 1)) || (*(p++) != 02)) {
    OPENSSL_PUT_ERROR(RSA, RSA_padding_check_SSLv23,
                      RSA_R_BLOCK_TYPE_IS_NOT_02);
    return -1;
  }

  /* scan over padding data */
  j = flen - 1; /* one for type */
  for (i = 0; i < j; i++) {
    if (*(p++) == 0) {
      break;
    }
  }

  if ((i == j) || (i < 8)) {
    OPENSSL_PUT_ERROR(RSA, RSA_padding_check_SSLv23,
                      RSA_R_NULL_BEFORE_BLOCK_MISSING);
    return -1;
  }

  for (k = -9; k < -1; k++) {
    if (p[k] != 0x03) {
      break;
    }
  }

  if (k == -1) {
    OPENSSL_PUT_ERROR(RSA, RSA_padding_check_SSLv23,
                      RSA_R_SSLV3_ROLLBACK_ATTACK);
    return -1;
  }

  i++; /* Skip over the '\0' */
  j -= i;
  if (j > tlen) {
    OPENSSL_PUT_ERROR(RSA, RSA_padding_check_SSLv23, RSA_R_DATA_TOO_LARGE);
    return -1;
  }
  memcpy(to, p, (unsigned int)j);

  return j;
}

int PKCS1_MGF1(uint8_t *mask, unsigned len, const uint8_t *seed,
               unsigned seedlen, const EVP_MD *dgst) {
  unsigned outlen = 0;
  uint32_t i;
  uint8_t cnt[4];
  EVP_MD_CTX c;
  uint8_t md[EVP_MAX_MD_SIZE];
  unsigned mdlen;
  int ret = -1;

  EVP_MD_CTX_init(&c);
  mdlen = EVP_MD_size(dgst);

  for (i = 0; outlen < len; i++) {
    cnt[0] = (uint8_t)((i >> 24) & 255);
    cnt[1] = (uint8_t)((i >> 16) & 255);
    cnt[2] = (uint8_t)((i >> 8)) & 255;
    cnt[3] = (uint8_t)(i & 255);
    if (!EVP_DigestInit_ex(&c, dgst, NULL) ||
        !EVP_DigestUpdate(&c, seed, seedlen) || !EVP_DigestUpdate(&c, cnt, 4)) {
      goto err;
    }

    if (outlen + mdlen <= len) {
      if (!EVP_DigestFinal_ex(&c, mask + outlen, NULL)) {
        goto err;
      }
      outlen += mdlen;
    } else {
      if (!EVP_DigestFinal_ex(&c, md, NULL)) {
        goto err;
      }
      memcpy(mask + outlen, md, len - outlen);
      outlen = len;
    }
  }
  ret = 0;

err:
  EVP_MD_CTX_cleanup(&c);
  return ret;
}

int RSA_padding_add_PKCS1_OAEP_mgf1(uint8_t *to, unsigned tlen,
                                    const uint8_t *from, unsigned flen,
                                    const uint8_t *param, unsigned plen,
                                    const EVP_MD *md, const EVP_MD *mgf1md) {
  unsigned i, emlen = tlen - 1, mdlen;
  uint8_t *db, *seed;
  uint8_t *dbmask = NULL, seedmask[SHA_DIGEST_LENGTH];
  int ret = 0;

  if (md == NULL) {
    md = EVP_sha1();
  }
  if (mgf1md == NULL) {
    mgf1md = md;
  }

  mdlen = EVP_MD_size(md);

  if (flen > emlen - 2 * mdlen - 1) {
    OPENSSL_PUT_ERROR(RSA, RSA_padding_add_PKCS1_OAEP_mgf1,
                      RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
    return 0;
  }

  if (emlen < 2 * mdlen + 1) {
    OPENSSL_PUT_ERROR(RSA, RSA_padding_add_PKCS1_OAEP_mgf1,
                      RSA_R_KEY_SIZE_TOO_SMALL);
    return 0;
  }

  to[0] = 0;
  seed = to + 1;
  db = to + mdlen + 1;

  if (!EVP_Digest((void *)param, plen, db, NULL, md, NULL)) {
    return 0;
  }
  memset(db + mdlen, 0, emlen - flen - 2 * mdlen - 1);
  db[emlen - flen - mdlen - 1] = 0x01;
  memcpy(db + emlen - flen - mdlen, from, (unsigned int)flen);
  if (RAND_pseudo_bytes(seed, mdlen) <= 0) {
    return 0;
  }

  dbmask = OPENSSL_malloc(emlen - mdlen);
  if (dbmask == NULL) {
    OPENSSL_PUT_ERROR(RSA, RSA_padding_add_PKCS1_OAEP_mgf1,
                      ERR_R_MALLOC_FAILURE);
    return 0;
  }

  if (PKCS1_MGF1(dbmask, emlen - mdlen, seed, mdlen, mgf1md) < 0) {
    goto out;
  }
  for (i = 0; i < emlen - mdlen; i++) {
    db[i] ^= dbmask[i];
  }

  if (PKCS1_MGF1(seedmask, mdlen, db, emlen - mdlen, mgf1md) < 0) {
    goto out;
  }
  for (i = 0; i < SHA_DIGEST_LENGTH; i++) {
    seed[i] ^= seedmask[i];
  }
  ret = 1;

out:
  if (dbmask != NULL) {
    OPENSSL_free(dbmask);
  }
  return ret;
}

int RSA_padding_check_PKCS1_OAEP_mgf1(uint8_t *to, unsigned tlen,
                                      const uint8_t *from, unsigned flen,
                                      unsigned num, const uint8_t *param,
                                      unsigned plen, const EVP_MD *md,
                                      const EVP_MD *mgf1md) {
  unsigned i, dblen, mlen = -1, bad, mdlen;
  const uint8_t *maskeddb;
  unsigned lzero;
  uint8_t *db = NULL, seed[SHA_DIGEST_LENGTH], phash[SHA_DIGEST_LENGTH];
  uint8_t *padded_from;

  if (md == NULL) {
    md = EVP_sha1();
  }
  if (mgf1md == NULL) {
    mgf1md = md;
  }

  mdlen = EVP_MD_size(md);

  if (--num < 2 * mdlen + 1) {
    /* 'num' is the length of the modulus, i.e. does not depend on the
     * particular ciphertext. */
    goto decoding_err;
  }

  /* TODO(fork): this code differs significantly between 1.0.1 and 1.0.2. We
   * need to understand why and pick the best one. */

  /* lzero is the number of leading zeros. We must not leak in the case
   * that this is negative. See James H. Manger, "A Chosen Ciphertext
   * Attack on RSA Optimal Asymmetric Encryption Padding (OAEP) [...]",
   * CRYPTO 2001). */
  lzero = num - flen;
  /* If lzero is negative then the MSB will be set and this arithmetic
   * right shift will set bad to all ones. Otherwise it'll be all
   * zeros. */
  bad = ((int)lzero) >> (sizeof(int) * 8 - 1);
  lzero &= ~bad;
  flen = (bad & num) | (~bad & flen);

  dblen = num - mdlen;
  db = OPENSSL_malloc(dblen + num);
  if (db == NULL) {
    OPENSSL_PUT_ERROR(RSA, RSA_padding_check_PKCS1_OAEP_mgf1,
                      ERR_R_MALLOC_FAILURE);
    return -1;
  }

  /* Always do this zero-padding copy (even when lzero == 0) to avoid
   * leaking timing info about the value of lzero. This sadly leaks
   * side-channel information, but it's not possible to have a fixed
   * memory access pattern since we can't read out of the bounds of
   * |from|. */
  padded_from = db + dblen;
  memset(padded_from, 0, num);
  memcpy(padded_from + lzero, from, flen);

  maskeddb = padded_from + mdlen;

  if (PKCS1_MGF1(seed, mdlen, maskeddb, dblen, mgf1md)) {
    return -1;
  }
  for (i = 0; i < mdlen; i++) {
    seed[i] ^= padded_from[i];
  }

  if (PKCS1_MGF1(db, dblen, seed, mdlen, mgf1md)) {
    return -1;
  }
  for (i = 0; i < dblen; i++) {
    db[i] ^= maskeddb[i];
  }

  if (!EVP_Digest((void *)param, plen, phash, NULL, md, NULL)) {
    return -1;
  }

  if (CRYPTO_memcmp(db, phash, mdlen) != 0 || bad) {
    goto decoding_err;
  } else {
    /* At this point we consider timing side-channels to be moot
     * because the plaintext contained the correct phash. */
    for (i = mdlen; i < dblen; i++) {
      if (db[i] != 0x00) {
        break;
      }
    }

    if (i == dblen || db[i] != 0x01) {
      goto decoding_err;
    } else {
      /* everything looks OK */

      mlen = dblen - ++i;
      if (tlen < mlen) {
        OPENSSL_PUT_ERROR(RSA, RSA_padding_check_PKCS1_OAEP_mgf1,
                          RSA_R_DATA_TOO_LARGE);
        mlen = -1;
      } else {
        memcpy(to, db + i, mlen);
      }
    }
  }

  OPENSSL_free(db);
  return mlen;

decoding_err:
  /* to avoid chosen ciphertext attacks, the error message should not reveal
   * which kind of decoding error happened */
  OPENSSL_PUT_ERROR(RSA, RSA_padding_check_PKCS1_OAEP_mgf1,
                    RSA_R_OAEP_DECODING_ERROR);
  if (db != NULL) {
    OPENSSL_free(db);
  }
  return -1;
}

int RSA_padding_add_PKCS1_OAEP(uint8_t *to, unsigned tlen,
                               const uint8_t *from, unsigned flen,
                               const uint8_t *param, unsigned plen) {
  return RSA_padding_add_PKCS1_OAEP_mgf1(to, tlen, from, flen, param, plen,
                                         NULL, NULL);
}

int RSA_padding_check_PKCS1_OAEP(uint8_t *to, unsigned tlen,
                                 const uint8_t *from, unsigned flen,
                                 unsigned num, const uint8_t *param,
                                 unsigned plen) {
  return RSA_padding_check_PKCS1_OAEP_mgf1(to, tlen, from, flen, num, param,
                                           plen, NULL, NULL);
}

static const unsigned char zeroes[] = {0,0,0,0,0,0,0,0};

int RSA_verify_PKCS1_PSS_mgf1(RSA *rsa, const uint8_t *mHash,
                              const EVP_MD *Hash, const EVP_MD *mgf1Hash,
                              const uint8_t *EM, int sLen) {
  int i;
  int ret = 0;
  int maskedDBLen, MSBits, emLen;
  size_t hLen;
  const uint8_t *H;
  uint8_t *DB = NULL;
  EVP_MD_CTX ctx;
  uint8_t H_[EVP_MAX_MD_SIZE];
  EVP_MD_CTX_init(&ctx);

  if (mgf1Hash == NULL) {
    mgf1Hash = Hash;
  }

  hLen = EVP_MD_size(Hash);

  /* Negative sLen has special meanings:
   *	-1	sLen == hLen
   *	-2	salt length is autorecovered from signature
   *	-N	reserved */
  if (sLen == -1) {
    sLen = hLen;
  } else if (sLen == -2) {
    sLen = -2;
  } else if (sLen < -2) {
    OPENSSL_PUT_ERROR(RSA, RSA_verify_PKCS1_PSS_mgf1, RSA_R_SLEN_CHECK_FAILED);
    goto err;
  }

  MSBits = (BN_num_bits(rsa->n) - 1) & 0x7;
  emLen = RSA_size(rsa);
  if (EM[0] & (0xFF << MSBits)) {
    OPENSSL_PUT_ERROR(RSA, RSA_verify_PKCS1_PSS_mgf1,
                      RSA_R_FIRST_OCTET_INVALID);
    goto err;
  }
  if (MSBits == 0) {
    EM++;
    emLen--;
  }
  if (emLen < ((int)hLen + sLen + 2)) {
    /* sLen can be small negative */
    OPENSSL_PUT_ERROR(RSA, RSA_verify_PKCS1_PSS_mgf1, RSA_R_DATA_TOO_LARGE);
    goto err;
  }
  if (EM[emLen - 1] != 0xbc) {
    OPENSSL_PUT_ERROR(RSA, RSA_verify_PKCS1_PSS_mgf1, RSA_R_LAST_OCTET_INVALID);
    goto err;
  }
  maskedDBLen = emLen - hLen - 1;
  H = EM + maskedDBLen;
  DB = OPENSSL_malloc(maskedDBLen);
  if (!DB) {
    OPENSSL_PUT_ERROR(RSA, RSA_verify_PKCS1_PSS_mgf1, ERR_R_MALLOC_FAILURE);
    goto err;
  }
  if (PKCS1_MGF1(DB, maskedDBLen, H, hLen, mgf1Hash) < 0) {
    goto err;
  }
  for (i = 0; i < maskedDBLen; i++) {
    DB[i] ^= EM[i];
  }
  if (MSBits) {
    DB[0] &= 0xFF >> (8 - MSBits);
  }
  for (i = 0; DB[i] == 0 && i < (maskedDBLen - 1); i++)
    ;
  if (DB[i++] != 0x1) {
    OPENSSL_PUT_ERROR(RSA, RSA_verify_PKCS1_PSS_mgf1,
                      RSA_R_SLEN_RECOVERY_FAILED);
    goto err;
  }
  if (sLen >= 0 && (maskedDBLen - i) != sLen) {
    OPENSSL_PUT_ERROR(RSA, RSA_verify_PKCS1_PSS_mgf1, RSA_R_SLEN_CHECK_FAILED);
    goto err;
  }
  if (!EVP_DigestInit_ex(&ctx, Hash, NULL) ||
      !EVP_DigestUpdate(&ctx, zeroes, sizeof zeroes) ||
      !EVP_DigestUpdate(&ctx, mHash, hLen)) {
    goto err;
  }
  if (maskedDBLen - i) {
    if (!EVP_DigestUpdate(&ctx, DB + i, maskedDBLen - i)) {
      goto err;
    }
  }
  if (!EVP_DigestFinal_ex(&ctx, H_, NULL)) {
    goto err;
  }
  if (memcmp(H_, H, hLen)) {
    OPENSSL_PUT_ERROR(RSA, RSA_verify_PKCS1_PSS_mgf1, RSA_R_BAD_SIGNATURE);
    ret = 0;
  } else {
    ret = 1;
  }

err:
  if (DB) {
    OPENSSL_free(DB);
  }
  EVP_MD_CTX_cleanup(&ctx);

  return ret;
}

int RSA_padding_add_PKCS1_PSS_mgf1(RSA *rsa, unsigned char *EM,
                                   const unsigned char *mHash,
                                   const EVP_MD *Hash, const EVP_MD *mgf1Hash,
                                   int sLen) {
  int i;
  int ret = 0;
  int maskedDBLen, MSBits, emLen;
  size_t hLen;
  unsigned char *H, *salt = NULL, *p;
  EVP_MD_CTX ctx;

  if (mgf1Hash == NULL) {
    mgf1Hash = Hash;
  }

  hLen = EVP_MD_size(Hash);

  /* Negative sLen has special meanings:
   *	-1	sLen == hLen
   *	-2	salt length is maximized
   *	-N	reserved */
  if (sLen == -1) {
    sLen = hLen;
  } else if (sLen == -2) {
    sLen = -2;
  } else if (sLen < -2) {
    OPENSSL_PUT_ERROR(RSA, RSA_padding_add_PKCS1_PSS_mgf1,
                      RSA_R_SLEN_CHECK_FAILED);
    goto err;
  }

  MSBits = (BN_num_bits(rsa->n) - 1) & 0x7;
  emLen = RSA_size(rsa);
  if (MSBits == 0) {
    *EM++ = 0;
    emLen--;
  }
  if (sLen == -2) {
    sLen = emLen - hLen - 2;
  } else if (emLen < (hLen + sLen + 2)) {
    OPENSSL_PUT_ERROR(RSA, RSA_padding_add_PKCS1_PSS_mgf1,
                      RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
    goto err;
  }
  if (sLen > 0) {
    salt = OPENSSL_malloc(sLen);
    if (!salt) {
      OPENSSL_PUT_ERROR(RSA, RSA_padding_add_PKCS1_PSS_mgf1,
                        ERR_R_MALLOC_FAILURE);
      goto err;
    }
    if (RAND_pseudo_bytes(salt, sLen) <= 0) {
      goto err;
    }
  }
  maskedDBLen = emLen - hLen - 1;
  H = EM + maskedDBLen;
  EVP_MD_CTX_init(&ctx);
  if (!EVP_DigestInit_ex(&ctx, Hash, NULL) ||
      !EVP_DigestUpdate(&ctx, zeroes, sizeof zeroes) ||
      !EVP_DigestUpdate(&ctx, mHash, hLen)) {
    goto err;
  }
  if (sLen && !EVP_DigestUpdate(&ctx, salt, sLen)) {
    goto err;
  }
  if (!EVP_DigestFinal_ex(&ctx, H, NULL)) {
    goto err;
  }
  EVP_MD_CTX_cleanup(&ctx);

  /* Generate dbMask in place then perform XOR on it */
  if (PKCS1_MGF1(EM, maskedDBLen, H, hLen, mgf1Hash)) {
    goto err;
  }

  p = EM;

  /* Initial PS XORs with all zeroes which is a NOP so just update
   * pointer. Note from a test above this value is guaranteed to
   * be non-negative. */
  p += emLen - sLen - hLen - 2;
  *p++ ^= 0x1;
  if (sLen > 0) {
    for (i = 0; i < sLen; i++) {
      *p++ ^= salt[i];
    }
  }
  if (MSBits) {
    EM[0] &= 0xFF >> (8 - MSBits);
  }

  /* H is already in place so just set final 0xbc */

  EM[emLen - 1] = 0xbc;

  ret = 1;

err:
  if (salt) {
    OPENSSL_free(salt);
  }

  return ret;
}
