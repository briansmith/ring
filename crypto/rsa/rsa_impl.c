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
int GFp_rsa_private_transform(const RSA *rsa, /*inout*/ BIGNUM *base,
                              BN_BLINDING *blinding, RAND *rng);



/* GFp_rsa_private_transform takes a big-endian integer in |base| and raises it
 * to the d'th power modulo the public modulus. The caller must ensure that
 * |base| is less than |n|.
 *
 * It returns one on success and zero otherwise.
 */
int GFp_rsa_private_transform(const RSA *rsa, /*inout*/ BIGNUM *base,
                              BN_BLINDING *blinding, RAND *rng) {
  assert(GFp_BN_cmp(base, &rsa->mont_n->N) < 0);
  assert(!GFp_BN_is_zero(rsa->e));
  assert(!GFp_BN_is_zero(rsa->dmp1));
  assert(!GFp_BN_is_zero(rsa->dmq1));

  int ret = 0;

  BIGNUM r, tmp, mp, mq, vrfy;
  GFp_BN_init(&r);
  GFp_BN_init(&tmp);
  GFp_BN_init(&mp);
  GFp_BN_init(&mq);
  GFp_BN_init(&vrfy);

  if (!GFp_BN_BLINDING_convert(base, blinding, rsa, rng)) {
    OPENSSL_PUT_ERROR(RSA, ERR_R_INTERNAL_ERROR);
    goto err;
  }

  const BIGNUM *p = &rsa->mont_p->N;

  /* Extra reductions would be required if |p < q| and |p == q| is just plain
   * wrong. */
  assert(GFp_BN_cmp(&rsa->mont_q->N, p) < 0);

  /* mp := base^dmp1 mod p.
   *
   * |p * q == n| and |p > q| implies |p < n < p**2|. Thus, the base is just
   * reduced mod |p|. */
  if (!GFp_BN_reduce_mont(&tmp, base, rsa->mont_p) ||
      !GFp_BN_mod_exp_mont_consttime(&mp, &tmp, rsa->dmp1, rsa->mont_p)) {
    OPENSSL_PUT_ERROR(RSA, ERR_R_INTERNAL_ERROR);
    goto err;
  }

  /* mq := base^dmq1 mod q.
   *
   * |p * q == n| and |p > q| implies |q < q**2 < n < q**3|. Thus, |base| is
   * first reduced mod |q**2| and then reduced mod |q|. */
  if (!GFp_BN_reduce_mont(&tmp, base, rsa->mont_qq) ||
      !GFp_BN_reduce_mont(&tmp, &tmp, rsa->mont_q) ||
      !GFp_BN_mod_exp_mont_consttime(&mq, &tmp, rsa->dmq1, rsa->mont_q)) {
    OPENSSL_PUT_ERROR(RSA, ERR_R_INTERNAL_ERROR);
    goto err;
  }

  /* Combine them with Garner's algorithm.
   *
   * |0 <= mq < q < p| and |0 <= mp < p| implies |(-q) < (mp - mq) < p|, so
   * |GFp_BN_mod_sub_quick| can be used.
   *
   * In each multiplication, the Montgomery factor cancels out because |tmp| is
   * not Montgomery-encoded but the second input is.
   *
   * In the last multiplication, the reduction mod |n| isn't necessary because
   * |tmp < p| and |p * q == n| implies |tmp * q < n|. Montgomery
   * multiplication is used purely because it is implemented more efficiently.
   */
  if (!GFp_BN_mod_sub_quick(&tmp, &mp, &mq, p) ||
      !GFp_BN_mod_mul_mont(&tmp, &tmp, rsa->iqmp_mont, rsa->mont_p) ||
      !GFp_BN_mod_mul_mont(&tmp, &tmp, rsa->qmn_mont, rsa->mont_n) ||
      !GFp_BN_add(&r, &tmp, &mq)) {
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
   * This check is very cheap assuming |e| is small, which it almost always is.
   * Note that this is the only validation of |e| that is done other than
   * basic checks on its size, oddness, and minimum value, as |RSA_check_key|
   * doesn't validate its mathematical relations to |d| or |p| or |q|. */
  if (!GFp_BN_mod_exp_mont_vartime(&vrfy, &r, rsa->e, rsa->mont_n)) {
    OPENSSL_PUT_ERROR(RSA, ERR_R_INTERNAL_ERROR);
    goto err;
  }
  if (vrfy.top != base->top ||
      GFp_memcmp(vrfy.d, base->d, (size_t)vrfy.top * sizeof(vrfy.d[0])) != 0) {
    OPENSSL_PUT_ERROR(RSA, ERR_R_INTERNAL_ERROR);
    goto err;
  }

  if (!GFp_BN_BLINDING_invert(base, &r, blinding, rsa->mont_n)) {
    OPENSSL_PUT_ERROR(RSA, ERR_R_INTERNAL_ERROR);
    goto err;
  }

  ret = 1;

err:
  GFp_BN_free(&r);
  GFp_BN_free(&tmp);
  GFp_BN_free(&mp);
  GFp_BN_free(&mq);
  GFp_BN_free(&vrfy);

  return ret;
}
