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


/* Declarations to avoid -Wmissing-prototypes warnings. */
int GFp_rsa_private_transform(RSA *rsa, uint8_t *inout, size_t len,
                              BN_BLINDING *blinding, RAND *rng);


static int check_modulus_and_exponent(const BIGNUM *n, const BIGNUM *e,
                                      size_t min_bits, size_t max_bits) {
  unsigned rsa_bits = BN_num_bits(n);

  if (rsa_bits < min_bits) {
    OPENSSL_PUT_ERROR(RSA, RSA_R_KEY_SIZE_TOO_SMALL);
    return 0;
  }
  /* XXX: There's may be another check for the maximum length in rsa.rs that
   * subsumes this; check that when investigating the code coverage. */
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

  unsigned e_bits = BN_num_bits(e);

  if (e_bits < 2) {
    OPENSSL_PUT_ERROR(RSA, RSA_R_BAD_E_VALUE);
    return 0;
  }
  if (e_bits > kMaxExponentBits) {
    OPENSSL_PUT_ERROR(RSA, RSA_R_BAD_E_VALUE);
    return 0;
  }
  if (!BN_is_odd(e)) {
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

size_t RSA_size(const RSA *rsa) {
  return BN_num_bytes(rsa->n);
}


/* GFp_rsa_public_decrypt decrypts the RSA signature |in| using the public key
 * with modulus |public_key_n| and exponent |public_key_e|, leaving the
 * decrypted signature in |out|. |out_len| and |in_len| must both be equal to
 * |RSA_size(rsa)|. |min_bits| and |max_bits| are the minimum and maximum
 * allowed public key modulus sizes, in bits. It returns one on success and
 * zero on failure.
 *
 * When |rsa_public_decrypt| succeeds, the caller must then check the
 * signature value (and padding) left in |out|. */
int GFp_rsa_public_decrypt(uint8_t *out, size_t out_len,
                           const uint8_t *public_key_n, size_t public_key_n_len,
                           const uint8_t *public_key_e, size_t public_key_e_len,
                           const uint8_t *in, size_t in_len, size_t min_bits,
                           size_t max_bits) {
  BIGNUM n;
  BN_init(&n);

  BIGNUM e;
  BN_init(&e);

  BIGNUM f;
  BN_init(&f);

  BIGNUM result;
  BN_init(&result);

  BN_CTX *ctx = NULL;

  int ret = 0;

  if (BN_bin2bn(public_key_n, public_key_n_len, &n) == NULL ||
      BN_bin2bn(public_key_e, public_key_e_len, &e) == NULL) {
    OPENSSL_PUT_ERROR(RSA, ERR_R_INTERNAL_ERROR);
    goto err;
  }

  unsigned rsa_size = BN_num_bytes(&n); /* RSA_size((n, e)); */

  if (out_len != rsa_size) {
    OPENSSL_PUT_ERROR(RSA, RSA_R_OUTPUT_BUFFER_TOO_SMALL);
    goto err;
  }

  if (in_len != rsa_size) {
    OPENSSL_PUT_ERROR(RSA, RSA_R_DATA_LEN_NOT_EQUAL_TO_MOD_LEN);
    goto err;
  }

  if (!check_modulus_and_exponent(&n, &e, min_bits, max_bits)) {
    goto err;
  }

  if (BN_bin2bn(in, in_len, &f) == NULL) {
    OPENSSL_PUT_ERROR(RSA, ERR_R_INTERNAL_ERROR);
    goto err;
  }

  if (BN_ucmp(&f, &n) >= 0) {
    OPENSSL_PUT_ERROR(RSA, RSA_R_DATA_TOO_LARGE_FOR_MODULUS);
    goto err;
  }

  ctx = BN_CTX_new();
  if (ctx == NULL) {
    goto err;
  }

  if (!BN_mod_exp_mont(&result, &f, &e, &n, ctx, NULL) ||
      !BN_bn2bin_padded(out, out_len, &result)) {
    OPENSSL_PUT_ERROR(RSA, ERR_R_INTERNAL_ERROR);
    goto err;
  }

  ret = 1;

err:
  BN_free(&n);
  BN_free(&e);
  BN_free(&f);
  BN_free(&result);
  BN_CTX_free(ctx);
  return ret;
}

/* GFp_rsa_private_transform takes a big-endian integer from |inout|,
 * calculates the d'th power of it, modulo the RSA modulus and writes the
 * result as a big-endian integer back to |inout|. |inout| is |len| bytes long
 * and |len| is always equal to |RSA_size(rsa)|. If the result of the transform
 * can be represented in fewer than |len| bytes, then |out| must be zero padded
 * on the left.
 *
 * It returns one on success and zero otherwise.
 */
int GFp_rsa_private_transform(RSA *rsa, uint8_t *inout, size_t len,
                              BN_BLINDING *blinding, RAND *rng) {
  BN_CTX *ctx = BN_CTX_new();
  if (ctx == NULL) {
    return 0;
  }

  int ret = 0;

  BIGNUM base, r, tmp, mp, mq, vrfy;
  BN_init(&base);
  BN_init(&r);
  BN_init(&tmp);
  BN_init(&mp);
  BN_init(&mq);
  BN_init(&vrfy);

  if (BN_bin2bn(inout, len, &base) == NULL) {
    goto err;
  }

  if (BN_ucmp(&base, rsa->n) >= 0) {
    /* Usually the padding functions would catch this. */
    OPENSSL_PUT_ERROR(RSA, RSA_R_DATA_TOO_LARGE_FOR_MODULUS);
    goto err;
  }

  if (!BN_BLINDING_convert(&base, blinding, rsa, rng, ctx)) {
    OPENSSL_PUT_ERROR(RSA, ERR_R_INTERNAL_ERROR);
    goto err;
  }

  /* Extra reductions would be required if |p < q| and |p == q| is just plain
   * wrong. */
  assert(BN_cmp(rsa->q, rsa->p) < 0);

  /* mp := base^dmp1 mod p.
   *
   * |p * q == n| and |p > q| implies |p < n < p**2|. Thus, the base is just
   * reduced mod |p|. */
  assert(BN_get_flags(rsa->p, BN_FLG_CONSTTIME));
  assert(BN_get_flags(rsa->dmp1, BN_FLG_CONSTTIME));
  if (!BN_reduce_montgomery(&tmp, &base, rsa->mont_p, ctx) ||
      !BN_mod_exp_mont_consttime(&mp, &tmp, rsa->dmp1, rsa->p, ctx,
                                 rsa->mont_p)) {
    OPENSSL_PUT_ERROR(RSA, ERR_R_INTERNAL_ERROR);
    goto err;
  }

  /* mq := base^dmq1 mod q.
   *
   * |p * q == n| and |p > q| implies |q < q**2 < n < q**3|. Thus, |base| is
   * first reduced mod |q**2| and then reduced mod |q|. */
  assert(BN_get_flags(rsa->q, BN_FLG_CONSTTIME));
  assert(BN_get_flags(rsa->dmq1, BN_FLG_CONSTTIME));
  if (!BN_reduce_montgomery(&tmp, &base, rsa->mont_qq, ctx) ||
      !BN_reduce_montgomery(&tmp, &tmp, rsa->mont_q, ctx) ||
      !BN_mod_exp_mont_consttime(&mq, &tmp, rsa->dmq1, rsa->q, ctx,
                                 rsa->mont_q)) {
    OPENSSL_PUT_ERROR(RSA, ERR_R_INTERNAL_ERROR);
    goto err;
  }

  /* Combine them with Garner's algorithm.
   *
   * |0 <= mq < q < p| and |0 <= mp < p| implies |(-q) < (mp - mq) < p|, so
   * |BN_mod_sub_quick| can be used.
   *
   * In each multiplication, the Montgomery factor cancels out because |tmp| is
   * not Montgomery-encoded but the second input is.
   *
   * In the last multiplication, the reduction mod |n| isn't necessary because
   * |tmp < p| and |p * q == n| implies |tmp * q < n|. Montgomery
   * multiplication is used purely because it is implemented more efficiently.
   */
  if (!BN_mod_sub_quick(&tmp, &mp, &mq, rsa->p) ||
      !BN_mod_mul_montgomery(&tmp, &tmp, rsa->iqmp_mont, rsa->mont_p, ctx) ||
      !BN_mod_mul_montgomery(&tmp, &tmp, rsa->qmn_mont, rsa->mont_n, ctx) ||
      !BN_add(&r, &tmp, &mq)) {
    OPENSSL_PUT_ERROR(RSA, ERR_R_INTERNAL_ERROR);
    goto err;
  }

  /* Verify the result to protect against fault attacks as described in the
   * 1997 paper "On the Importance of Checking Cryptographic Protocols for
   * Faults" by Dan Boneh, Richard A. DeMillo, and Richard J. Lipton. Some
   * implementations do this only when the CRT is used, but we do it in all
   * cases. Section 6 of the aforementioned paper describes an attack that
   * works when the CRT isn't used. That attack is much less likely to succeed
   * than the CRT attack, but there have likely been improvements since 1997.
   *
   * This check is very cheap assuming |e| is small, which it almost always is. */
  if (!BN_mod_exp_mont(&vrfy, &r, rsa->e, rsa->n, ctx, rsa->mont_n)) {
    OPENSSL_PUT_ERROR(RSA, ERR_R_INTERNAL_ERROR);
    goto err;
  }
  if (vrfy.top != base.top ||
      CRYPTO_memcmp(vrfy.d, base.d, (size_t)vrfy.top * sizeof(vrfy.d[0])) != 0) {
    OPENSSL_PUT_ERROR(RSA, ERR_R_INTERNAL_ERROR);
    goto err;
  }

  if (!BN_BLINDING_invert(&r, blinding, rsa->mont_n, ctx) ||
      !BN_bn2bin_padded(inout, len, &r)) {
    OPENSSL_PUT_ERROR(RSA, ERR_R_INTERNAL_ERROR);
    goto err;
  }

  ret = 1;

err:
  BN_CTX_free(ctx);
  BN_free(&r);
  BN_free(&tmp);
  BN_free(&mp);
  BN_free(&mq);
  BN_free(&vrfy);

  return ret;
}
