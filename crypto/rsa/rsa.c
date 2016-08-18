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

#include <limits.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/mem.h>

#include "internal.h"
#include "../internal.h"


/* Prototypes to avoid -Wmissing-prototypes warnings. */
int rsa_new_end(RSA *rsa, const BIGNUM *d, const BIGNUM *n, const BIGNUM *p,
                const BIGNUM *q);

static int rsa_check_key(const RSA *rsa, const BIGNUM *d, BN_CTX *ctx);


int rsa_new_end(RSA *rsa, const BIGNUM *n, const BIGNUM *d, const BIGNUM *p,
                const BIGNUM *q) {
  assert(rsa->e != NULL);
  assert(rsa->dmp1 != NULL);
  assert(rsa->dmq1 != NULL);
  assert(rsa->iqmp != NULL);

  BN_CTX *ctx = BN_CTX_new();
  if (ctx == NULL) {
    return 0;
  }

  int ret = 0;

  BIGNUM qq;
  BN_init(&qq);

  rsa->mont_n = BN_MONT_CTX_new();
  rsa->mont_p = BN_MONT_CTX_new();
  rsa->mont_q = BN_MONT_CTX_new();
  rsa->mont_qq = BN_MONT_CTX_new();
  rsa->qmn_mont = BN_new();
  rsa->iqmp_mont = BN_new();
  if (rsa->mont_n == NULL ||
      rsa->mont_p == NULL ||
      rsa->mont_q == NULL ||
      rsa->mont_qq == NULL ||
      rsa->qmn_mont == NULL ||
      rsa->iqmp_mont == NULL ||
      !BN_MONT_CTX_set(rsa->mont_n, n, ctx) ||
      !BN_MONT_CTX_set(rsa->mont_p, p, ctx) ||
      !BN_MONT_CTX_set(rsa->mont_q, q, ctx) ||
      !BN_mod_mul_montgomery(&qq, q, q, rsa->mont_n, ctx) ||
      !BN_to_montgomery(&qq, &qq, rsa->mont_n, ctx) ||
      !BN_MONT_CTX_set(rsa->mont_qq, &qq, ctx) ||
      !BN_to_montgomery(rsa->qmn_mont, q, rsa->mont_n, ctx) ||
      /* Assumes p > q. */
      !BN_to_montgomery(rsa->iqmp_mont, rsa->iqmp, rsa->mont_p, ctx)) {
    goto err;
  }

  ret = rsa_check_key(rsa, d, ctx);

err:
  BN_free(&qq);
  BN_CTX_free(ctx);
  return ret;
}

static int rsa_check_key(const RSA *key, const BIGNUM *d, BN_CTX *ctx) {
  assert(ctx);

  BIGNUM n, pm1, qm1, dmp1, dmq1, iqmp_times_q;
  int ok = 0;

  BN_init(&n);
  BN_init(&pm1);
  BN_init(&qm1);
  BN_init(&dmp1);
  BN_init(&dmq1);
  BN_init(&iqmp_times_q);

  /* The public modulus must be large enough. |RSAPublicKey::sign| depends on
   * this; without it, |RSAPublicKey::sign| would generate padding that is
   * invalid (too few 0xFF bytes) for very small keys.
   *
   * XXX: The maximum limit of 4096 bits is primarily due to lack of testing
   * of larger key sizes; see, in particular,
   * https://www.mail-archive.com/openssl-dev@openssl.org/msg44586.html and
   * https://www.mail-archive.com/openssl-dev@openssl.org/msg44759.html. Also,
   * this limit might help with memory management decisions later. */
  if (!GFp_rsa_check_modulus_and_exponent(&key->mont_n->N, key->e, 2048, 4096)) {
    OPENSSL_PUT_ERROR(RSA, RSA_R_BAD_RSA_PARAMETERS);
    goto out;
  }

  /* Technically |p < q| may be legal, but the implementation of |mod_exp| has
   * been optimized such that it is now required that |p > q|. |p == q| is
   * definitely *not* OK. To support keys with |p < q| in the future, we can
   * provide a function that swaps |p| and |q| and recalculates the CRT
   * parameters via the currently-deleted |RSA_recover_crt_params|. Or we can
   * just avoid using the CRT when |p < q|. */
  if (BN_cmp(&key->mont_p->N, &key->mont_q->N) <= 0) {
    OPENSSL_PUT_ERROR(RSA, RSA_R_BAD_RSA_PARAMETERS);
    goto out;
  }

  if (/* n = pq */
      !BN_mul(&n, &key->mont_p->N, &key->mont_q->N, ctx)) {
    OPENSSL_PUT_ERROR(RSA, ERR_LIB_BN);
    goto out;
  }

  if (BN_cmp(&n, &key->mont_n->N) != 0) {
    OPENSSL_PUT_ERROR(RSA, RSA_R_N_NOT_EQUAL_P_Q);
    goto out;
  }

  /* In a valid key, |d*e mod lcm(p-1, q-1) == 1|. We don't check this because
   * we decided to omit the code that would be used to compute least common
   * multiples. Instead, we check that |p| and |q| are consistent with
   * |n| above and with |d| below. We never use |d| for any actual
   * computations. When we actually do a private key operation, we verify that
   * the result computed using all of these variables is correct using |e|.
   * Further, above we verify that the |e| is small. */

  if (/* dmp1 = d mod (p-1) */
      !BN_sub(&pm1, &key->mont_p->N, BN_value_one()) ||
      !BN_mod(&dmp1, d, &pm1, ctx) ||
      /* dmq1 = d mod (q-1) */
      !BN_sub(&qm1, &key->mont_q->N, BN_value_one()) ||
      !BN_mod(&dmq1, d, &qm1, ctx)) {
    OPENSSL_PUT_ERROR(RSA, ERR_LIB_BN);
    goto out;
  }

  if (BN_cmp(key->iqmp, &key->mont_p->N) >= 0) {
    OPENSSL_PUT_ERROR(RSA, RSA_R_CRT_VALUES_INCORRECT);
    goto out;
  }

  /* iqmp = q^-1 mod p. Assumes p > q. */
  if (!BN_mod_mul_montgomery(&iqmp_times_q, key->iqmp, &key->mont_q->N, key->mont_p,
                             ctx) ||
      !BN_to_montgomery(&iqmp_times_q, &iqmp_times_q, key->mont_p, ctx)) {
    OPENSSL_PUT_ERROR(RSA, ERR_LIB_BN);
    goto out;
  }

  if (BN_cmp(&dmp1, key->dmp1) != 0 ||
      BN_cmp(&dmq1, key->dmq1) != 0 ||
      !BN_is_one(&iqmp_times_q)) {
    OPENSSL_PUT_ERROR(RSA, RSA_R_CRT_VALUES_INCORRECT);
    goto out;
  }

  ok = 1;

out:
  BN_free(&n);
  BN_free(&pm1);
  BN_free(&qm1);
  BN_free(&dmp1);
  BN_free(&dmq1);
  BN_free(&iqmp_times_q);

  return ok;
}
