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
 * [including the GNU Public Licence.]
 */
/* ====================================================================
 * Copyright (c) 1998-2006 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
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

#include <openssl/bn.h>

#include <assert.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/type_check.h>

#include "internal.h"
#include "../internal.h"


OPENSSL_COMPILE_ASSERT(BN_MONT_CTX_N0_LIMBS == 1 || BN_MONT_CTX_N0_LIMBS == 2,
                       BN_MONT_CTX_N0_LIMBS_VALUE_INVALID);
OPENSSL_COMPILE_ASSERT(sizeof(BN_ULONG) * BN_MONT_CTX_N0_LIMBS ==
                       sizeof(uint64_t), BN_MONT_CTX_set_64_bit_mismatch);

int GFp_BN_MONT_CTX_set(BN_MONT_CTX *mont, const BIGNUM *mod) {
  if (GFp_BN_is_zero(mod)) {
    OPENSSL_PUT_ERROR(BN, BN_R_DIV_BY_ZERO);
    return 0;
  }
  if (!GFp_BN_is_odd(mod)) {
    OPENSSL_PUT_ERROR(BN, BN_R_CALLED_WITH_EVEN_MODULUS);
    return 0;
  }
  if (GFp_BN_is_negative(mod)) {
    OPENSSL_PUT_ERROR(BN, BN_R_NEGATIVE_NUMBER);
    return 0;
  }

  /* Save the modulus. */
  if (!GFp_BN_copy(&mont->N, mod)) {
    OPENSSL_PUT_ERROR(BN, ERR_R_INTERNAL_ERROR);
    return 0;
  }

  /* Find n0 such that n0 * N == -1 (mod r).
   *
   * Only certain BN_BITS2<=32 platforms actually make use of n0[1]. For the
   * others, we could use a shorter R value and use faster |BN_ULONG|-based
   * math instead of |uint64_t|-based math, which would be double-precision.
   * However, currently only the assembler files know which is which. */
  uint64_t n0 = GFp_bn_mont_n0(mod);
  mont->n0[0] = (BN_ULONG)n0;
#if BN_MONT_CTX_N0_LIMBS == 2
  mont->n0[1] = (BN_ULONG)(n0 >> BN_BITS2);
#else
  mont->n0[1] = 0;
#endif

  /* Save RR = R**2 (mod N). R is the smallest power of 2**BN_BITS such that R
   * > mod. Even though the assembly on some 32-bit platforms works with 64-bit
   * values, using |BN_BITS2| here, rather than |BN_MONT_CTX_N0_LIMBS *
   * BN_BITS2|, is correct because R**2 will still be a multiple of the latter
   * as |BN_MONT_CTX_N0_LIMBS| is either one or two.
   *
   * XXX: This is not constant time with respect to |mont->N|, but it should
   * be. */
  unsigned lgBigR =
      (GFp_BN_num_bits(mod) + (BN_BITS2 - 1)) / BN_BITS2 * BN_BITS2;
  if (!GFp_bn_mod_exp_base_2_vartime(&mont->RR, lgBigR * 2, &mont->N)) {
    return 0;
  }

  return 1;
}

int GFp_BN_to_mont(BIGNUM *ret, const BIGNUM *a, const BN_MONT_CTX *mont) {
  return GFp_BN_mod_mul_mont(ret, a, &mont->RR, mont);
}

static int GFp_BN_from_montgomery_word(BIGNUM *ret, BIGNUM *r,
                                   const BN_MONT_CTX *mont) {
  assert(ret != r);

  BN_ULONG *ap, *np, *rp, n0, v, carry;
  int nl, max, i;

  const BIGNUM *n = &mont->N;
  nl = n->top;
  if (nl == 0) {
    ret->top = 0;
    return 1;
  }

  max = (2 * nl); /* carry is stored separately */
  if (GFp_bn_wexpand(r, max) == NULL) {
    return 0;
  }

  r->neg ^= n->neg;
  np = n->d;
  rp = r->d;

  /* clear the top words of T */
  if (max > r->top) {
    memset(&rp[r->top], 0, (max - r->top) * sizeof(BN_ULONG));
  }

  r->top = max;
  n0 = mont->n0[0];

  for (carry = 0, i = 0; i < nl; i++, rp++) {
    v = GFp_bn_mul_add_words(rp, np, nl, (rp[0] * n0) & BN_MASK2);
    v = (v + carry + rp[nl]) & BN_MASK2;
    carry |= (v != rp[nl]);
    carry &= (v <= rp[nl]);
    rp[nl] = v;
  }

  if (GFp_bn_wexpand(ret, nl) == NULL) {
    return 0;
  }
  ret->top = nl;
  ret->neg = r->neg;

  rp = ret->d;
  ap = &(r->d[nl]);

  {
    BN_ULONG *nrp;
    uintptr_t m;

    v = GFp_bn_sub_words(rp, ap, np, nl) - carry;
    /* if subtraction result is real, then trick unconditional memcpy below to
     * perform in-place "refresh" instead of actual copy. */
    m = (0u - (uintptr_t)v);
    nrp = (BN_ULONG *)(((uintptr_t)rp & ~m) | ((uintptr_t)ap & m));

    for (i = 0, nl -= 4; i < nl; i += 4) {
      BN_ULONG t1, t2, t3, t4;

      t1 = nrp[i + 0];
      t2 = nrp[i + 1];
      t3 = nrp[i + 2];
      ap[i + 0] = 0;
      t4 = nrp[i + 3];
      ap[i + 1] = 0;
      rp[i + 0] = t1;
      ap[i + 2] = 0;
      rp[i + 1] = t2;
      ap[i + 3] = 0;
      rp[i + 2] = t3;
      rp[i + 3] = t4;
    }

    for (nl += 4; i < nl; i++) {
      rp[i] = nrp[i], ap[i] = 0;
    }
  }

  GFp_bn_correct_top(r);
  GFp_bn_correct_top(ret);

  return 1;
}

int GFp_BN_from_mont(BIGNUM *r, const BIGNUM *a, const BN_MONT_CTX *mont) {
  BIGNUM tmp;
  GFp_BN_init(&tmp);

  int ret = 0;

  if (!GFp_BN_copy(&tmp, a) ||
      !GFp_BN_from_montgomery_word(r, &tmp, mont)) {
    goto err;
  }

  ret = 1;

err:
  GFp_BN_free(&tmp);

  return ret;
}

int GFp_BN_mod_mul_mont(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                    const BN_MONT_CTX *mont) {
  int num = mont->N.top;

  /* GFp_bn_mul_mont requires at least four limbs, at least for x86. */
  if (num >= 4 && a->top == num && b->top == num) {
    if (GFp_bn_wexpand(r, num) == NULL) {
      return 0;
    }
    GFp_bn_mul_mont(r->d, a->d, b->d, mont->N.d, mont->n0, num);
    r->neg = a->neg ^ b->neg;
    r->top = num;
    GFp_bn_correct_top(r);
    return 1;
  }

  BIGNUM tmp;
  GFp_BN_init(&tmp);

  int ret = 0;

  if (!GFp_BN_mul_no_alias(&tmp, a, b) ||
      !GFp_BN_from_montgomery_word(r, &tmp, mont)) {
    goto err;
  }

  ret = 1;

err:
  GFp_BN_free(&tmp);

  return ret;
}

int GFp_BN_reduce_mont(BIGNUM *r, const BIGNUM *a, const BN_MONT_CTX *mont) {
  BIGNUM tmp;
  GFp_BN_init(&tmp);
  if (!GFp_BN_copy(&tmp, a)) {
    OPENSSL_PUT_ERROR(BN, ERR_R_INTERNAL_ERROR);
    return 0;
  }

  int ret = 0;

  if (!GFp_BN_from_montgomery_word(r, &tmp, mont) ||
      !GFp_BN_to_mont(r, r, mont)) {
    goto err;
  }

  ret = 1;

err:
  GFp_BN_free(&tmp);
  return ret;
}
