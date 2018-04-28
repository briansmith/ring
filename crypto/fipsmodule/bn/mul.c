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

#include <GFp/bn.h>

#include <assert.h>
#include <string.h>

#include "internal.h"


static void GFp_bn_mul_normal(BN_ULONG *r, BN_ULONG *a, int na, BN_ULONG *b,
                              int nb) {
  assert(r != a);
  assert(r != b);

  BN_ULONG *rr;

  if (na < nb) {
    int itmp;
    BN_ULONG *ltmp;

    itmp = na;
    na = nb;
    nb = itmp;
    ltmp = a;
    a = b;
    b = ltmp;
  }
  rr = &(r[na]);
  if (nb <= 0) {
    (void)GFp_bn_mul_words(r, a, na, 0);
    return;
  } else {
    rr[0] = GFp_bn_mul_words(r, a, na, b[0]);
  }

  for (;;) {
    if (--nb <= 0) {
      return;
    }
    rr[1] = GFp_bn_mul_add_words(&(r[1]), a, na, b[1]);
    if (--nb <= 0) {
      return;
    }
    rr[2] = GFp_bn_mul_add_words(&(r[2]), a, na, b[2]);
    if (--nb <= 0) {
      return;
    }
    rr[3] = GFp_bn_mul_add_words(&(r[3]), a, na, b[3]);
    if (--nb <= 0) {
      return;
    }
    rr[4] = GFp_bn_mul_add_words(&(r[4]), a, na, b[4]);
    rr += 4;
    r += 4;
    b += 4;
  }
}

int GFp_BN_mul_no_alias(BIGNUM *r, const BIGNUM *a, const BIGNUM *b) {
  assert(r != a);
  assert(r != b);

  int ret = 0;
  int top, al, bl;

  al = a->top;
  bl = b->top;

  if ((al == 0) || (bl == 0)) {
    GFp_BN_zero(r);
    return 1;
  }
  top = al + bl;

  if (!GFp_bn_wexpand(r, top)) {
    goto err;
  }
  r->top = top;
  GFp_bn_mul_normal(r->d, a->d, al, b->d, bl);

  GFp_bn_correct_top(r);
  ret = 1;

err:
  return ret;
}
