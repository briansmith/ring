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
int GFp_rsa_new_end(RSA *rsa, const BIGNUM *d);

static int rsa_check_key(const RSA *rsa, const BIGNUM *d);


int GFp_rsa_new_end(RSA *rsa, const BIGNUM *d) {
  assert(rsa->e != NULL);
  assert(GFp_BN_is_odd(rsa->e));
  assert(rsa->dmp1 != NULL);
  assert(rsa->dmq1 != NULL);
  assert(rsa->mont_n != NULL);
  assert(rsa->mont_p != NULL);
  assert(rsa->mont_q != NULL);
  assert(rsa->mont_qq != NULL);
  assert(rsa->qmn_mont != NULL);
  assert(rsa->iqmp_mont != NULL);

  const BIGNUM *n = &rsa->mont_n->N;
  const BIGNUM *p = &rsa->mont_p->N;
  const BIGNUM *q = &rsa->mont_q->N;

  assert(GFp_BN_is_odd(rsa->e));
  assert(GFp_BN_cmp(rsa->e, n) < 0);
  assert(GFp_BN_cmp(d, n) < 0);
  assert(GFp_BN_cmp(p, n) < 0);
  assert(GFp_BN_cmp(q, p) < 0);

  return rsa_check_key(rsa, d);
}

static int rsa_check_key(const RSA *key, const BIGNUM *d) {
  BIGNUM pm1, qm1, dmp1, dmq1;
  int ok = 0;

  GFp_BN_init(&pm1);
  GFp_BN_init(&qm1);
  GFp_BN_init(&dmp1);
  GFp_BN_init(&dmq1);

  /* In a valid key, |d*e mod lcm(p-1, q-1) == 1|. We don't check this because
   * we decided to omit the code that would be used to compute least common
   * multiples. Instead, we check that |p| and |q| are consistent with
   * |n| above and with |d| below. We never use |d| for any actual
   * computations. When we actually do a private key operation, we verify that
   * the result computed using all of these variables is correct using |e|.
   * Further, above we verify that the |e| is small. */

  if (/* dmp1 = d mod (p-1) */
      !GFp_BN_sub(&pm1, &key->mont_p->N, GFp_BN_value_one()) ||
      !GFp_BN_mod(&dmp1, d, &pm1) ||
      /* dmq1 = d mod (q-1) */
      !GFp_BN_sub(&qm1, &key->mont_q->N, GFp_BN_value_one()) ||
      !GFp_BN_mod(&dmq1, d, &qm1)) {
    OPENSSL_PUT_ERROR(RSA, ERR_LIB_BN);
    goto out;
  }

  if (GFp_BN_cmp(&dmp1, key->dmp1) != 0 ||
      GFp_BN_cmp(&dmq1, key->dmq1) != 0) {
    OPENSSL_PUT_ERROR(RSA, RSA_R_CRT_VALUES_INCORRECT);
    goto out;
  }

  ok = 1;

out:
  GFp_BN_free(&pm1);
  GFp_BN_free(&qm1);
  GFp_BN_free(&dmp1);
  GFp_BN_free(&dmq1);

  return ok;
}
