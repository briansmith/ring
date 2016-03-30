/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.] */

#include <openssl/rsa.h>

#include <assert.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/mem.h>

#include "internal.h"
#include "../internal.h"


static int mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa, BN_CTX *ctx);
static int rsa_private_transform(RSA *rsa, uint8_t *out, const uint8_t *in,
                                 size_t len);

static int check_modulus_and_exponent_sizes(const BIGNUM *n, const BIGNUM *e,
                                            size_t min_bits, size_t max_bits) {
  unsigned rsa_bits = BN_num_bits(n);

  if (rsa_bits < min_bits) {
    OPENSSL_PUT_ERROR(RSA, RSA_R_KEY_SIZE_TOO_SMALL);
    return 0;
  }
  if (rsa_bits > 16 * 1024 || rsa_bits > max_bits) {
    OPENSSL_PUT_ERROR(RSA, RSA_R_MODULUS_TOO_LARGE);
    return 0;
  }

  /* Mitigate DoS attacks by limiting the exponent size. 33 bits was chosen as
   * the limit based on the recommendations in [1] and [2]. Windows CryptoAPI
   * doesn't support values larger than 32 bits [3], so it is unlikely that
   * exponents larger than 32 bits are being used for anything Windows commonly
   * does.
   *
   * [1] https://www.imperialviolet.org/2012/03/16/rsae.html
   * [2] https://www.imperialviolet.org/2012/03/17/rsados.html
   * [3] https://msdn.microsoft.com/en-us/library/aa387685(VS.85).aspx */
  static const unsigned kMaxExponentBits = 33;

  if (BN_num_bits(e) > kMaxExponentBits) {
    OPENSSL_PUT_ERROR(RSA, RSA_R_BAD_E_VALUE);
    return 0;
  }

  /* Verify |n > e|. Comparing |rsa_bits| to |kMaxExponentBits| is a small
   * shortcut to comparing |n| and |e| directly. In reality, |kMaxExponentBits|
   * is much smaller than the minimum RSA key size that any application should
   * accept. */
  if (rsa_bits <= kMaxExponentBits) {
    OPENSSL_PUT_ERROR(RSA, RSA_R_KEY_SIZE_TOO_SMALL);
    return 0;
  }
  assert(BN_ucmp(n, e) > 0);

  return 1;
}

unsigned RSA_size(const RSA *rsa) {
  return BN_num_bytes(rsa->n);
}

int RSA_encrypt(const BIGNUM *n, const BIGNUM *e, size_t *out_len, uint8_t *out,
                size_t max_out, const uint8_t *in, size_t in_len, int padding) {
  const unsigned rsa_size = BN_num_bytes(n); /* RSA_size((n, e)) */
  BIGNUM *f, *result;
  uint8_t *buf = NULL;
  BN_CTX *ctx = NULL;
  int i, ret = 0;

  if (max_out < rsa_size) {
    OPENSSL_PUT_ERROR(RSA, RSA_R_OUTPUT_BUFFER_TOO_SMALL);
    return 0;
  }

  /* XXX: |min_bits| should be much higer than 256, but this is what is needed
   * to get the rsa_test.cc tests to pass. */
  if (!check_modulus_and_exponent_sizes(n, e, 256, 16 * 1024)) {
    return 0;
  }

  ctx = BN_CTX_new();
  if (ctx == NULL) {
    return 0;
  }

  BN_CTX_start(ctx);
  f = BN_CTX_get(ctx);
  result = BN_CTX_get(ctx);
  buf = OPENSSL_malloc(rsa_size);
  if (!f || !result || !buf) {
    OPENSSL_PUT_ERROR(RSA, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  switch (padding) {
    case RSA_PKCS1_PADDING:
      i = RSA_padding_add_PKCS1_type_2(buf, rsa_size, in, in_len);
      break;
    case RSA_NO_PADDING:
      i = RSA_padding_add_none(buf, rsa_size, in, in_len);
      break;
    case RSA_PKCS1_OAEP_PADDING:
      /* ring: BoringSSL supports |RSA_PKCS1_OAEP_PADDING| here, defaulting
       * to SHA-1 for both digest algorithms, and no label. *ring* doesn't
       * support this (yet) because it doesn't want have a hard-coded
       * dependency on SHA-1. Also, *ring* it doesn't want to depend on the
       * |EVP_MD| API, so the calculation of OAEP padding needs to be redone
       * using |ring::digest|. */
      /* fall through */
    default:
      OPENSSL_PUT_ERROR(RSA, RSA_R_UNKNOWN_PADDING_TYPE);
      goto err;
  }

  if (i <= 0) {
    goto err;
  }

  if (BN_bin2bn(buf, rsa_size, f) == NULL) {
    goto err;
  }

  if (BN_ucmp(f, n) >= 0) {
    /* usually the padding functions would catch this */
    OPENSSL_PUT_ERROR(RSA, RSA_R_DATA_TOO_LARGE_FOR_MODULUS);
    goto err;
  }

  /* TODO: This should be a constant-time operation, no? */
  if (!BN_mod_exp_mont(result, f, e, n, ctx, NULL)) {
    goto err;
  }

  /* put in leading 0 bytes if the number is less than the length of the
   * modulus */
  if (!BN_bn2bin_padded(out, rsa_size, result)) {
    OPENSSL_PUT_ERROR(RSA, ERR_R_INTERNAL_ERROR);
    goto err;
  }

  *out_len = rsa_size;
  ret = 1;

err:
  BN_CTX_end(ctx);
  BN_CTX_free(ctx);
  OPENSSL_free(buf);
  return ret;
}

/* MAX_BLINDINGS_PER_RSA defines the maximum number of cached BN_BLINDINGs per
 * RSA*. Then this limit is exceeded, BN_BLINDING objects will be created and
 * destroyed as needed. */
#define MAX_BLINDINGS_PER_RSA 1024

/* rsa_blinding_get returns a BN_BLINDING to use with |rsa|. It does this by
 * allocating one of the cached BN_BLINDING objects in |rsa->blindings|. If
 * none are free, the cache will be extended by a extra element and the new
 * BN_BLINDING is returned.
 *
 * On success, the index of the assigned BN_BLINDING is written to
 * |*index_used| and must be passed to |rsa_blinding_release| when finished. */
static BN_BLINDING *rsa_blinding_get(RSA *rsa, unsigned *index_used) {
  assert(rsa->mont_n != NULL);

  BN_BLINDING *ret = NULL;
  BN_BLINDING **new_blindings;
  uint8_t *new_blindings_inuse;
  char overflow = 0;

  CRYPTO_MUTEX_lock_write(&rsa->lock);

  unsigned i;
  for (i = 0; i < rsa->num_blindings; i++) {
    if (rsa->blindings_inuse[i] == 0) {
      rsa->blindings_inuse[i] = 1;
      ret = rsa->blindings[i];
      *index_used = i;
      break;
    }
  }

  if (ret != NULL) {
    CRYPTO_MUTEX_unlock(&rsa->lock);
    return ret;
  }

  overflow = rsa->num_blindings >= MAX_BLINDINGS_PER_RSA;

  /* We didn't find a free BN_BLINDING to use so increase the length of
   * the arrays by one and use the newly created element. */

  CRYPTO_MUTEX_unlock(&rsa->lock);
  ret = BN_BLINDING_new();
  if (ret == NULL) {
    return NULL;
  }

  if (overflow) {
    /* We cannot add any more cached BN_BLINDINGs so we use |ret|
     * and mark it for destruction in |rsa_blinding_release|. */
    *index_used = MAX_BLINDINGS_PER_RSA;
    return ret;
  }

  CRYPTO_MUTEX_lock_write(&rsa->lock);

  new_blindings =
      OPENSSL_malloc(sizeof(BN_BLINDING *) * (rsa->num_blindings + 1));
  if (new_blindings == NULL) {
    goto err1;
  }
  memcpy(new_blindings, rsa->blindings,
         sizeof(BN_BLINDING *) * rsa->num_blindings);
  new_blindings[rsa->num_blindings] = ret;

  new_blindings_inuse = OPENSSL_malloc(rsa->num_blindings + 1);
  if (new_blindings_inuse == NULL) {
    goto err2;
  }
  memcpy(new_blindings_inuse, rsa->blindings_inuse, rsa->num_blindings);
  new_blindings_inuse[rsa->num_blindings] = 1;
  *index_used = rsa->num_blindings;

  OPENSSL_free(rsa->blindings);
  rsa->blindings = new_blindings;
  OPENSSL_free(rsa->blindings_inuse);
  rsa->blindings_inuse = new_blindings_inuse;
  rsa->num_blindings++;

  CRYPTO_MUTEX_unlock(&rsa->lock);
  return ret;

err2:
  OPENSSL_free(new_blindings);

err1:
  CRYPTO_MUTEX_unlock(&rsa->lock);
  BN_BLINDING_free(ret);
  return NULL;
}

/* rsa_blinding_release marks the cached BN_BLINDING at the given index as free
 * for other threads to use. */
static void rsa_blinding_release(RSA *rsa, BN_BLINDING *blinding,
                                 unsigned blinding_index) {
  if (blinding_index == MAX_BLINDINGS_PER_RSA) {
    /* This blinding wasn't cached. */
    BN_BLINDING_free(blinding);
    return;
  }

  CRYPTO_MUTEX_lock_write(&rsa->lock);
  rsa->blindings_inuse[blinding_index] = 0;
  CRYPTO_MUTEX_unlock(&rsa->lock);
}

/* signing */
int RSA_sign_raw(RSA *rsa, size_t *out_len, uint8_t *out, size_t max_out,
                 const uint8_t *in, size_t in_len, int padding) {
  const unsigned rsa_size = RSA_size(rsa);
  uint8_t *buf = NULL;
  int i, ret = 0;

  if (max_out < rsa_size) {
    OPENSSL_PUT_ERROR(RSA, RSA_R_OUTPUT_BUFFER_TOO_SMALL);
    return 0;
  }

  buf = OPENSSL_malloc(rsa_size);
  if (buf == NULL) {
    OPENSSL_PUT_ERROR(RSA, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  switch (padding) {
    case RSA_PKCS1_PADDING:
      i = RSA_padding_add_PKCS1_type_1(buf, rsa_size, in, in_len);
      break;
    case RSA_NO_PADDING:
      i = RSA_padding_add_none(buf, rsa_size, in, in_len);
      break;
    default:
      OPENSSL_PUT_ERROR(RSA, RSA_R_UNKNOWN_PADDING_TYPE);
      goto err;
  }

  if (i <= 0) {
    goto err;
  }

  if (!rsa_private_transform(rsa, out, buf, rsa_size)) {
    goto err;
  }

  *out_len = rsa_size;
  ret = 1;

err:
  OPENSSL_free(buf);
  return ret;
}

int RSA_decrypt(RSA *rsa, size_t *out_len, uint8_t *out, size_t max_out,
                const uint8_t *in, size_t in_len, int padding) {
  const unsigned rsa_size = RSA_size(rsa);
  int r = -1;
  uint8_t *buf = NULL;
  int ret = 0;

  if (max_out < rsa_size) {
    OPENSSL_PUT_ERROR(RSA, RSA_R_OUTPUT_BUFFER_TOO_SMALL);
    return 0;
  }

  if (padding == RSA_NO_PADDING) {
    buf = out;
  } else {
    /* Allocate a temporary buffer to hold the padded plaintext. */
    buf = OPENSSL_malloc(rsa_size);
    if (buf == NULL) {
      OPENSSL_PUT_ERROR(RSA, ERR_R_MALLOC_FAILURE);
      goto err;
    }
  }

  if (in_len != rsa_size) {
    OPENSSL_PUT_ERROR(RSA, RSA_R_DATA_LEN_NOT_EQUAL_TO_MOD_LEN);
    goto err;
  }

  if (!rsa_private_transform(rsa, buf, in, rsa_size)) {
    goto err;
  }

  switch (padding) {
    case RSA_PKCS1_PADDING:
      r = RSA_padding_check_PKCS1_type_2(out, rsa_size, buf, rsa_size);
      break;
    case RSA_NO_PADDING:
      r = rsa_size;
      break;
    case RSA_PKCS1_OAEP_PADDING:
      /* ring: BoringSSL supports |RSA_PKCS1_OAEP_PADDING| here, defaulting
       * to SHA-1 for both digest algorithms, and no label. *ring* doesn't
       * support this (yet) because it doesn't want have a hard-coded
       * dependency on SHA-1. Also, *ring* it doesn't want to depend on the
       * |EVP_MD| API, so the calculation of OAEP padding needs to be redone
       * using |ring::digest|. */
      /* fall through */
    default:
      OPENSSL_PUT_ERROR(RSA, RSA_R_UNKNOWN_PADDING_TYPE);
      goto err;
  }

  if (r < 0) {
    OPENSSL_PUT_ERROR(RSA, RSA_R_PADDING_CHECK_FAILED);
  } else {
    *out_len = r;
    ret = 1;
  }

err:
  if (padding != RSA_NO_PADDING) {
    OPENSSL_free(buf);
  }

  return ret;
}

/* rsa_public_decrypt decrypts the RSA signature |in| using the public key with
 * modulus |n| and exponent |e|, leaving the decrypted signature in |out|.
 * |out_len| and |in_len| must both be equal to |RSA_size(rsa)|. |min_bits| and
 * |max_bits| are the minimum and maximum allowed public key modulus sizes, in
 * bits. It returns one on success and zero on failure.
 *
 * When |rsa_public_decrypt| succeeds, the caller must then check the
 * signature value (and padding) left in |out|. */
int rsa_public_decrypt(const BIGNUM *n, const BIGNUM *e, uint8_t *out,
                       size_t out_len, const uint8_t *in, size_t in_len,
                       size_t min_bits, size_t max_bits) {
  unsigned rsa_size = BN_num_bytes(n); /* RSA_size((n, e)); */
  BIGNUM *f, *result;
  int ret = 0;
  BN_CTX *ctx = NULL;

  if (out_len != rsa_size) {
    OPENSSL_PUT_ERROR(RSA, RSA_R_OUTPUT_BUFFER_TOO_SMALL);
    return 0;
  }
  if (in_len != rsa_size) {
    OPENSSL_PUT_ERROR(RSA, RSA_R_DATA_LEN_NOT_EQUAL_TO_MOD_LEN);
    return 0;
  }
  if (!check_modulus_and_exponent_sizes(n, e, min_bits, max_bits)) {
    return 0;
  }

  ctx = BN_CTX_new();
  if (ctx == NULL) {
    goto err;
  }

  BN_CTX_start(ctx);
  f = BN_CTX_get(ctx);
  result = BN_CTX_get(ctx);
  if (f == NULL || result == NULL) {
    OPENSSL_PUT_ERROR(RSA, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  if (BN_bin2bn(in, in_len, f) == NULL) {
    goto err;
  }

  if (BN_ucmp(f, n) >= 0) {
    OPENSSL_PUT_ERROR(RSA, RSA_R_DATA_TOO_LARGE_FOR_MODULUS);
    goto err;
  }

  if (!BN_mod_exp_mont(result, f, e, n, ctx, NULL)) {
    goto err;
  }

  if (!BN_bn2bin_padded(out, out_len, result)) {
    OPENSSL_PUT_ERROR(RSA, ERR_R_INTERNAL_ERROR);
    goto err;
  }

  ret = 1;

err:
  if (ctx != NULL) {
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
  }
  return ret;
}

/* rsa_private_transform takes a big-endian integer from |in|, calculates the
 * d'th power of it, modulo the RSA modulus and writes the result as a
 * big-endian integer to |out|. Both |in| and |out| are |len| bytes long and
 * |len| is always equal to |RSA_size(rsa)|. If the result of the transform can
 * be represented in fewer than |len| bytes, then |out| must be zero padded on
 * the left.
 *
 * It returns one on success and zero otherwise.
 */
static int rsa_private_transform(RSA *rsa, uint8_t *out, const uint8_t *in,
                                 size_t len) {
  BIGNUM *f, *result;
  BN_CTX *ctx = NULL;
  unsigned blinding_index = 0;
  BN_BLINDING *blinding = NULL;

  ctx = BN_CTX_new();
  if (ctx == NULL) {
    return 0;
  }

  int ret = 0;

  BN_CTX_start(ctx);

  f = BN_CTX_get(ctx);
  result = BN_CTX_get(ctx);
  if (f == NULL || result == NULL) {
    OPENSSL_PUT_ERROR(RSA, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  if (BN_bin2bn(in, len, f) == NULL) {
    goto err;
  }

  if (BN_ucmp(f, rsa->n) >= 0) {
    /* Usually the padding functions would catch this. */
    OPENSSL_PUT_ERROR(RSA, RSA_R_DATA_TOO_LARGE_FOR_MODULUS);
    goto err;
  }

  blinding = rsa_blinding_get(rsa, &blinding_index);
  if (blinding == NULL ||
      !BN_BLINDING_convert(f, blinding, rsa, ctx) ||
      !mod_exp(result, f, rsa, ctx) ||
      !BN_BLINDING_invert(result, blinding, rsa->mont_n, ctx) ||
      !BN_bn2bin_padded(out, len, result)) {
    OPENSSL_PUT_ERROR(RSA, ERR_R_INTERNAL_ERROR);
    goto err;
  }

  ret = 1;

err:
  BN_CTX_end(ctx);
  BN_CTX_free(ctx);
  if (blinding != NULL) {
    rsa_blinding_release(rsa, blinding, blinding_index);
  }

  return ret;
}

static int mod_exp(BIGNUM *r0, const BIGNUM *I, RSA *rsa, BN_CTX *ctx) {
  assert(ctx != NULL);

  BIGNUM *r1, *m1, *vrfy;
  int ret = 0;

  BN_CTX_start(ctx);
  r1 = BN_CTX_get(ctx);
  m1 = BN_CTX_get(ctx);
  vrfy = BN_CTX_get(ctx);
  if (r1 == NULL ||
      m1 == NULL ||
      vrfy == NULL) {
    goto err;
  }

  /* compute I mod q */
  assert(BN_get_flags(rsa->q, BN_FLG_CONSTTIME));
  if (!BN_mod(r1, I, rsa->q, ctx)) {
    goto err;
  }

  /* compute r1^dmq1 mod q */
  assert(BN_get_flags(rsa->dmq1, BN_FLG_CONSTTIME));
  if (!BN_mod_exp_mont_consttime(m1, r1, rsa->dmq1, rsa->q, ctx, rsa->mont_q)) {
    goto err;
  }

  /* compute I mod p */
  assert(BN_get_flags(rsa->p, BN_FLG_CONSTTIME));
  if (!BN_mod(r1, I, rsa->p, ctx)) {
    goto err;
  }

  /* compute r1^dmp1 mod p */
  assert(BN_get_flags(rsa->dmp1, BN_FLG_CONSTTIME));
  if (!BN_mod_exp_mont_consttime(r0, r1, rsa->dmp1, rsa->p, ctx, rsa->mont_p)) {
    goto err;
  }

  if (!BN_sub(r0, r0, m1)) {
    goto err;
  }
  /* This will help stop the size of r0 increasing, which does
   * affect the multiply if it optimised for a power of 2 size */
  if (BN_is_negative(r0)) {
    if (!BN_add(r0, r0, rsa->p)) {
      goto err;
    }
  }

  if (!BN_mul(r1, r0, rsa->iqmp, ctx)) {
    goto err;
  }

  assert(BN_get_flags(rsa->p, BN_FLG_CONSTTIME));
  if (!BN_mod(r0, r1, rsa->p, ctx)) {
    goto err;
  }

  /* If p < q it is occasionally possible for the correction of
   * adding 'p' if r0 is negative above to leave the result still
   * negative. This can break the private key operations: the following
   * second correction should *always* correct this rare occurrence.
   * This will *never* happen with OpenSSL generated keys because
   * they ensure p > q [steve] */
  if (BN_is_negative(r0)) {
    if (!BN_add(r0, r0, rsa->p)) {
      goto err;
    }
  }
  if (!BN_mul(r1, r0, rsa->q, ctx)) {
    goto err;
  }
  if (!BN_add(r0, r1, m1)) {
    goto err;
  }

  if (!BN_mod_exp_mont(vrfy, r0, rsa->e, rsa->n, ctx, rsa->mont_n)) {
    goto err;
  }
  /* If 'I' was greater than (or equal to) rsa->n, the operation
   * will be equivalent to using 'I mod n'. However, the result of
   * the verify will *always* be less than 'n' so we don't check
   * for absolute equality, just congruency. */
  if (!BN_sub(vrfy, vrfy, I)) {
    goto err;
  }
  if (!BN_mod(vrfy, vrfy, rsa->n, ctx)) {
    goto err;
  }
  if (BN_is_negative(vrfy)) {
    if (!BN_add(vrfy, vrfy, rsa->n)) {
      goto err;
    }
  }
  if (!BN_is_zero(vrfy)) {
    /* 'I' and 'vrfy' aren't congruent mod n. Don't leak miscalculated CRT
     * output, just do a raw (slower) mod_exp and return that instead. */
    assert(BN_get_flags(rsa->d, BN_FLG_CONSTTIME));
    if (!BN_mod_exp_mont_consttime(r0, I, rsa->d, rsa->n, ctx, rsa->mont_n)) {
      goto err;
    }
  }

  ret = 1;

err:
  BN_CTX_end(ctx);
  return ret;
}

RSA *RSA_generate(int bits, uint32_t e, BN_GENCB *cb) {
  RSA *rsa = rsa_new_begin();
  if (rsa == NULL) {
    OPENSSL_PUT_ERROR(RSA, ERR_R_MALLOC_FAILURE)
    return NULL;
  }

  BIGNUM *r0 = NULL, *r1 = NULL, *r2 = NULL, *r3 = NULL, *tmp;
  int bitsp, bitsq, ok = -1, n = 0;
  BN_CTX *ctx = NULL;

  ctx = BN_CTX_new();
  if (ctx == NULL) {
    goto err;
  }
  BN_CTX_start(ctx);
  r0 = BN_CTX_get(ctx);
  r1 = BN_CTX_get(ctx);
  r2 = BN_CTX_get(ctx);
  r3 = BN_CTX_get(ctx);
  if (r0 == NULL || r1 == NULL || r2 == NULL || r3 == NULL) {
    goto err;
  }

  bitsp = (bits + 1) / 2;
  bitsq = bits - bitsp;

  rsa->e = BN_new();
  if (rsa->e == NULL ||
      !BN_set_word(rsa->e, e)) {
    goto err;
  }

  /* generate p and q */
  rsa->p = BN_new();
  rsa->q = BN_new();
  if (rsa->p == NULL ||
      rsa->q == NULL) {
    goto err;
  }
  for (;;) {
    if (!BN_generate_prime_ex(rsa->p, bitsp, cb) ||
        !BN_sub(r2, rsa->p, BN_value_one()) ||
        !BN_gcd(r1, r2, rsa->e, ctx)) {
      goto err;
    }
    if (BN_is_one(r1)) {
      break;
    }
    if (!BN_GENCB_call(cb, 2, n++)) {
      goto err;
    }
  }
  if (!BN_GENCB_call(cb, 3, 0)) {
    goto err;
  }
  for (;;) {
    /* When generating ridiculously small keys, we can get stuck
     * continually regenerating the same prime values. Check for
     * this and bail if it happens 3 times. */
    unsigned int degenerate = 0;
    do {
      if (!BN_generate_prime_ex(rsa->q, bitsq, cb)) {
        goto err;
      }
    } while ((BN_cmp(rsa->p, rsa->q) == 0) && (++degenerate < 3));
    if (degenerate == 3) {
      ok = 0; /* we set our own err */
      OPENSSL_PUT_ERROR(RSA, RSA_R_KEY_SIZE_TOO_SMALL);
      goto err;
    }
    if (!BN_sub(r2, rsa->q, BN_value_one()) ||
        !BN_gcd(r1, r2, rsa->e, ctx)) {
      goto err;
    }
    if (BN_is_one(r1)) {
      break;
    }
    if (!BN_GENCB_call(cb, 2, n++)) {
      goto err;
    }
  }
  if (!BN_GENCB_call(cb, 3, 1)) {
    goto err;
  }
  if (BN_cmp(rsa->p, rsa->q) < 0) {
    tmp = rsa->p;
    rsa->p = rsa->q;
    rsa->q = tmp;
  }
  BN_set_flags(rsa->p, BN_FLG_CONSTTIME);
  BN_set_flags(rsa->q, BN_FLG_CONSTTIME);

  /* calculate n */
  rsa->n = BN_new();
  if (rsa->n == NULL) {
    goto err;
  }
  if (!BN_mul(rsa->n, rsa->p, rsa->q, ctx)) {
    goto err;
  }

  /* calculate d */
  if (!BN_sub(r1, rsa->p, BN_value_one())) {
    goto err; /* p-1 */
  }
  if (!BN_sub(r2, rsa->q, BN_value_one())) {
    goto err; /* q-1 */
  }
  if (!BN_mul(r0, r1, r2, ctx)) {
    goto err; /* (p-1)(q-1) */
  }
  rsa->d = BN_new();
  if (rsa->d == NULL) {
    goto err;
  }
  BN_set_flags(r0, BN_FLG_CONSTTIME);
  if (!BN_mod_inverse(rsa->d, rsa->e, r0, ctx)) {
    goto err; /* d */
  }
  BN_set_flags(rsa->d, BN_FLG_CONSTTIME);

  /* calculate d mod (p-1) */
  rsa->dmp1 = BN_new();
  if (rsa->dmp1 == NULL) {
    goto err;
  }
  if (!BN_mod(rsa->dmp1, rsa->d, r1, ctx)) {
    goto err;
  }
  BN_set_flags(rsa->dmp1, BN_FLG_CONSTTIME);

  /* calculate d mod (q-1) */
  rsa->dmq1 = BN_new();
  if (rsa->dmq1 == NULL) {
    goto err;
  }
  if (!BN_mod(rsa->dmq1, rsa->d, r2, ctx)) {
    goto err;
  }
  BN_set_flags(rsa->dmq1, BN_FLG_CONSTTIME);

  /* calculate inverse of q mod p */
  rsa->iqmp = BN_new();
  if (rsa->iqmp == NULL) {
    goto err;
  }
  if (!BN_mod_inverse(rsa->iqmp, rsa->q, rsa->p, ctx)) {
    goto err;
  }
  BN_set_flags(rsa->iqmp, BN_FLG_CONSTTIME);

  if (!rsa_new_end(rsa, ctx)) {
    goto err;
  }

  ok = 1;

err:
  if (ok == -1) {
    OPENSSL_PUT_ERROR(RSA, ERR_LIB_BN);
    ok = 0;
  }
  if (ctx != NULL) {
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
  }
  if (!ok) {
    RSA_free(rsa);
    return NULL;
  }

  return rsa;
}
