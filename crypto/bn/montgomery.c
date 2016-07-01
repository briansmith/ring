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

#include <string.h>

#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/type_check.h>

#include "internal.h"
#include "../internal.h"


OPENSSL_COMPILE_ASSERT(BN_MONT_CTX_N0_LIMBS == 1 || BN_MONT_CTX_N0_LIMBS == 2,
                       BN_MONT_CTX_N0_LIMBS_VALUE_INVALID);

BN_MONT_CTX *BN_MONT_CTX_new(void) {
  BN_MONT_CTX *ret = OPENSSL_malloc(sizeof(BN_MONT_CTX));

  if (ret == NULL) {
    return NULL;
  }

  memset(ret, 0, sizeof(BN_MONT_CTX));
  BN_init(&ret->RR);
  BN_init(&ret->N);

  return ret;
}

void BN_MONT_CTX_free(BN_MONT_CTX *mont) {
  if (mont == NULL) {
    return;
  }

  BN_free(&mont->RR);
  BN_free(&mont->N);
  OPENSSL_free(mont);
}

int BN_MONT_CTX_set(BN_MONT_CTX *mont, const BIGNUM *mod, BN_CTX *ctx) {
  int ret = 0;
  BIGNUM *Ri, *R;
  BIGNUM tmod;
  BN_ULONG buf[2];

  if (BN_is_zero(mod)) {
    OPENSSL_PUT_ERROR(BN, BN_R_DIV_BY_ZERO);
    return 0;
  }

  BN_CTX_start(ctx);
  Ri = BN_CTX_get(ctx);
  if (Ri == NULL) {
    goto err;
  }
  R = &mont->RR; /* grab RR as a temp */
  if (!BN_copy(&mont->N, mod)) {
    goto err; /* Set N */
  }
  if (BN_get_flags(mod, BN_FLG_CONSTTIME)) {
    BN_set_flags(&mont->N, BN_FLG_CONSTTIME);
  }

  mont->N.neg = 0;

  BN_init(&tmod);
  tmod.d = buf;
  tmod.dmax = 2;
  tmod.neg = 0;

  BN_zero(R);
  if (!BN_set_bit(R, BN_MONT_CTX_N0_LIMBS * BN_BITS2)) {
    goto err;
  }

  tmod.top = 0;
  buf[0] = mod->d[0];
  if (buf[0] != 0) {
    tmod.top = 1;
  }

  buf[1] = 0;
  if (BN_MONT_CTX_N0_LIMBS == 2 && mod->top > 1 && mod->d[1] != 0) {
    buf[1] = mod->d[1];
    tmod.top = 2;
  }

  if (BN_mod_inverse(Ri, R, &tmod, ctx) == NULL) {
    goto err;
  }
  if (!BN_lshift(Ri, Ri, BN_MONT_CTX_N0_LIMBS * BN_BITS2)) {
    goto err; /* R*Ri */
  }
  const BIGNUM *Ri_dividend;
  if (!BN_is_zero(Ri)) {
    if (!BN_sub_word(Ri, 1)) {
      goto err;
    }
    Ri_dividend = Ri;
  } else {
    /* Ri == 0 so Ri - 1 == -1. -1 % tmod == 0xff..ff. */
    static const BN_ULONG kMinusOneLimbs[BN_MONT_CTX_N0_LIMBS] = {
      BN_MASK2,
#if BN_MONT_CTX_N0_LIMBS == 2
      BN_MASK2
#endif
    };
    STATIC_BIGNUM_DIAGNOSTIC_PUSH
    static const BIGNUM kMinusOne = STATIC_BIGNUM(kMinusOneLimbs);
    STATIC_BIGNUM_DIAGNOSTIC_POP
    Ri_dividend = &kMinusOne;
  }

  if (!BN_div(Ri, NULL, Ri_dividend, &tmod, ctx)) {
    goto err;
  }

  mont->n0[0] = 0;
  if (Ri->top > 0) {
    mont->n0[0] = Ri->d[0];
  }
  mont->n0[1] = 0;
  if (BN_MONT_CTX_N0_LIMBS == 2 && Ri->top > 1) {
    mont->n0[1] = Ri->d[1];
  }

  /* RR = (2^ri)^2 == 2^(ri*2) == 1 << (ri*2), which has its (ri*2)th bit set. */
  int ri = (BN_num_bits(mod) + (BN_BITS2 - 1)) / BN_BITS2 * BN_BITS2;
  BN_zero(&(mont->RR));
  if (!BN_set_bit(&(mont->RR), ri * 2)) {
    goto err;
  }
  if (!BN_mod(&(mont->RR), &(mont->RR), &(mont->N), ctx)) {
    goto err;
  }

  ret = 1;

err:
  BN_CTX_end(ctx);
  return ret;
}

int BN_to_montgomery(BIGNUM *ret, const BIGNUM *a, const BN_MONT_CTX *mont,
                     BN_CTX *ctx) {
  return BN_mod_mul_montgomery(ret, a, &mont->RR, mont, ctx);
}

static int BN_from_montgomery_word(BIGNUM *ret, BIGNUM *r,
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
  if (bn_wexpand(r, max) == NULL) {
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
    v = bn_mul_add_words(rp, np, nl, (rp[0] * n0) & BN_MASK2);
    v = (v + carry + rp[nl]) & BN_MASK2;
    carry |= (v != rp[nl]);
    carry &= (v <= rp[nl]);
    rp[nl] = v;
  }

  if (bn_wexpand(ret, nl) == NULL) {
    return 0;
  }
  ret->top = nl;
  ret->neg = r->neg;

  rp = ret->d;
  ap = &(r->d[nl]);

  {
    BN_ULONG *nrp;
    uintptr_t m;

    v = bn_sub_words(rp, ap, np, nl) - carry;
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

  bn_correct_top(r);
  bn_correct_top(ret);

  return 1;
}

int BN_from_montgomery(BIGNUM *r, const BIGNUM *a, const BN_MONT_CTX *mont,
                       BN_CTX *ctx) {
  int ret = 0;
  BIGNUM *t;

  BN_CTX_start(ctx);
  t = BN_CTX_get(ctx);
  if (t == NULL ||
      !BN_copy(t, a)) {
    goto err;
  }

  ret = BN_from_montgomery_word(r, t, mont);

err:
  BN_CTX_end(ctx);

  return ret;
}

int BN_mod_mul_montgomery(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                          const BN_MONT_CTX *mont, BN_CTX *ctx) {
  BIGNUM *tmp;
  int ret = 0;

  int num = mont->N.top;

  /* bn_mul_mont requires at least four limbs, at least for x86. */
  if (num >= 4 && a->top == num && b->top == num) {
    if (bn_wexpand(r, num) == NULL) {
      return 0;
    }
    bn_mul_mont(r->d, a->d, b->d, mont->N.d, mont->n0, num);
    r->neg = a->neg ^ b->neg;
    r->top = num;
    bn_correct_top(r);
    return 1;
  }

  BN_CTX_start(ctx);
  tmp = BN_CTX_get(ctx);
  if (tmp == NULL) {
    goto err;
  }

  if (a == b) {
    if (!BN_sqr(tmp, a, ctx)) {
      goto err;
    }
  } else {
    if (!BN_mul(tmp, a, b, ctx)) {
      goto err;
    }
  }

  /* reduce from aRR to aR */
  if (!BN_from_montgomery_word(r, tmp, mont)) {
    goto err;
  }

  ret = 1;

err:
  BN_CTX_end(ctx);
  return ret;
}

int BN_reduce_montgomery(BIGNUM *r, const BIGNUM *a,
                         const BN_MONT_CTX *mod_mont, BN_CTX *ctx) {
  BIGNUM tmp;
  BN_init(&tmp);
  if (!BN_copy(&tmp, a)) {
    OPENSSL_PUT_ERROR(BN, ERR_R_INTERNAL_ERROR);
    return 0;
  }

  int ret = 0;

  if (!BN_from_montgomery_word(r, &tmp, mod_mont) ||
      !BN_to_montgomery(r, r, mod_mont, ctx)) {
    goto err;
  }

  ret = 1;

err:
  BN_free(&tmp);
  return ret;
}
