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
 * Copyright (c) 1998-2005 The OpenSSL Project.  All rights reserved.
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

#include <openssl/cpu.h>
#include <openssl/err.h>
#include <openssl/mem.h>

#include "internal.h"


#if !defined(OPENSSL_NO_ASM) && defined(OPENSSL_X86_64)
#define OPENSSL_BN_ASM_MONT5
#define RSAZ_ENABLED

#include "rsaz_exp.h"

void bn_mul_mont_gather5(BN_ULONG *rp, const BN_ULONG *ap, const void *table,
                         const BN_ULONG *np, const BN_ULONG *n0, int num,
                         int power);
void bn_scatter5(const BN_ULONG *inp, size_t num, void *table, size_t power);
void bn_gather5(BN_ULONG *out, size_t num, void *table, size_t power);
void bn_power5(BN_ULONG *rp, const BN_ULONG *ap, const void *table,
               const BN_ULONG *np, const BN_ULONG *n0, int num, int power);
int bn_from_montgomery(BN_ULONG *rp, const BN_ULONG *ap,
                       const BN_ULONG *not_used, const BN_ULONG *np,
                       const BN_ULONG *n0, int num);
#endif

/* BN_exp was moved to bn_test_lib.c. */

/* maximum precomputation table size for *variable* sliding windows */
#define TABLE_SIZE 32

/* BN_window_bits_for_exponent_size -- macro for sliding window mod_exp
 * functions
 *
 * For window size 'w' (w >= 2) and a random 'b' bits exponent, the number of
 * multiplications is a constant plus on average
 *
 *    2^(w-1) + (b-w)/(w+1);
 *
 * here 2^(w-1)  is for precomputing the table (we actually need entries only
 * for windows that have the lowest bit set), and (b-w)/(w+1)  is an
 * approximation for the expected number of w-bit windows, not counting the
 * first one.
 *
 * Thus we should use
 *
 *    w >= 6  if        b > 671
 *     w = 5  if  671 > b > 239
 *     w = 4  if  239 > b >  79
 *     w = 3  if   79 > b >  23
 *    w <= 2  if   23 > b
 *
 * (with draws in between).  Very small exponents are often selected
 * with low Hamming weight, so we use  w = 1  for b <= 23. */
#define BN_window_bits_for_exponent_size(b) \
		((b) > 671 ? 6 : \
		 (b) > 239 ? 5 : \
		 (b) >  79 ? 4 : \
		 (b) >  23 ? 3 : 1)

int BN_mod_exp_mont(BIGNUM *rr, const BIGNUM *a, const BIGNUM *p,
                    const BIGNUM *m, BN_CTX *ctx, const BN_MONT_CTX *mont) {
  int i, j, bits, ret = 0, wstart, window;
  int start = 1;
  BIGNUM *d, *r;
  const BIGNUM *aa;
  /* Table of variables obtained from 'ctx' */
  BIGNUM *val[TABLE_SIZE];
  BN_MONT_CTX *new_mont = NULL;

  if (BN_get_flags(p, BN_FLG_CONSTTIME) != 0) {
    return BN_mod_exp_mont_consttime(rr, a, p, m, ctx, mont);
  }

  if (!BN_is_odd(m)) {
    OPENSSL_PUT_ERROR(BN, BN_R_CALLED_WITH_EVEN_MODULUS);
    return 0;
  }
  bits = BN_num_bits(p);
  if (bits == 0) {
    /* x**0 mod 1 is still zero. */
    if (BN_is_one(m)) {
      BN_zero(rr);
      return 1;
    }
    return BN_one(rr);
  }

  BN_CTX_start(ctx);
  d = BN_CTX_get(ctx);
  r = BN_CTX_get(ctx);
  val[0] = BN_CTX_get(ctx);
  if (!d || !r || !val[0]) {
    goto err;
  }

  /* Allocate a montgomery context if it was not supplied by the caller. */
  if (mont == NULL) {
    new_mont = BN_MONT_CTX_new();
    if (new_mont == NULL || !BN_MONT_CTX_set(new_mont, m, ctx)) {
      goto err;
    }
    mont = new_mont;
  }

  if (a->neg || BN_ucmp(a, m) >= 0) {
    if (!BN_nnmod(val[0], a, m, ctx)) {
      goto err;
    }
    aa = val[0];
  } else {
    aa = a;
  }

  if (BN_is_zero(aa)) {
    BN_zero(rr);
    ret = 1;
    goto err;
  }
  if (!BN_to_montgomery(val[0], aa, mont, ctx)) {
    goto err; /* 1 */
  }

  window = BN_window_bits_for_exponent_size(bits);
  if (window > 1) {
    if (!BN_mod_mul_montgomery(d, val[0], val[0], mont, ctx)) {
      goto err; /* 2 */
    }
    j = 1 << (window - 1);
    for (i = 1; i < j; i++) {
      if (((val[i] = BN_CTX_get(ctx)) == NULL) ||
          !BN_mod_mul_montgomery(val[i], val[i - 1], d, mont, ctx)) {
        goto err;
      }
    }
  }

  start = 1; /* This is used to avoid multiplication etc
              * when there is only the value '1' in the
              * buffer. */
  wstart = bits - 1; /* The top bit of the window */

  j = m->top; /* borrow j */
  if (m->d[j - 1] & (((BN_ULONG)1) << (BN_BITS2 - 1))) {
    if (bn_wexpand(r, j) == NULL) {
      goto err;
    }
    /* 2^(top*BN_BITS2) - m */
    r->d[0] = (0 - m->d[0]) & BN_MASK2;
    for (i = 1; i < j; i++) {
      r->d[i] = (~m->d[i]) & BN_MASK2;
    }
    r->top = j;
    /* Upper words will be zero if the corresponding words of 'm'
     * were 0xfff[...], so decrement r->top accordingly. */
    bn_correct_top(r);
  } else if (!BN_to_montgomery(r, BN_value_one(), mont, ctx)) {
    goto err;
  }

  for (;;) {
    int wvalue; /* The 'value' of the window */
    int wend; /* The bottom bit of the window */

    if (BN_is_bit_set(p, wstart) == 0) {
      if (!start && !BN_mod_mul_montgomery(r, r, r, mont, ctx)) {
        goto err;
      }
      if (wstart == 0) {
        break;
      }
      wstart--;
      continue;
    }

    /* We now have wstart on a 'set' bit, we now need to work out how bit a
     * window to do.  To do this we need to scan forward until the last set bit
     * before the end of the window */
    wvalue = 1;
    wend = 0;
    for (i = 1; i < window; i++) {
      if (wstart - i < 0) {
        break;
      }
      if (BN_is_bit_set(p, wstart - i)) {
        wvalue <<= (i - wend);
        wvalue |= 1;
        wend = i;
      }
    }

    /* wend is the size of the current window */
    j = wend + 1;
    /* add the 'bytes above' */
    if (!start) {
      for (i = 0; i < j; i++) {
        if (!BN_mod_mul_montgomery(r, r, r, mont, ctx)) {
          goto err;
        }
      }
    }

    /* wvalue will be an odd number < 2^window */
    if (!BN_mod_mul_montgomery(r, r, val[wvalue >> 1], mont, ctx)) {
      goto err;
    }

    /* move the 'window' down further */
    wstart -= wend + 1;
    start = 0;
    if (wstart < 0) {
      break;
    }
  }

  if (!BN_from_montgomery(rr, r, mont, ctx)) {
    goto err;
  }
  ret = 1;

err:
  BN_MONT_CTX_free(new_mont);
  BN_CTX_end(ctx);
  return ret;
}

/* BN_mod_exp_mont_consttime() stores the precomputed powers in a specific
 * layout so that accessing any of these table values shows the same access
 * pattern as far as cache lines are concerned. The following functions are
 * used to transfer a BIGNUM from/to that table. */
static int copy_to_prebuf(const BIGNUM *b, int top, unsigned char *buf, int idx,
                          int width) {
  size_t i, j;

  if (top > b->top) {
    top = b->top; /* this works because 'buf' is explicitly zeroed */
  }
  for (i = 0, j = idx; i < top * sizeof b->d[0]; i++, j += width) {
    buf[j] = ((unsigned char *)b->d)[i];
  }

  return 1;
}

static int copy_from_prebuf(BIGNUM *b, int top, unsigned char *buf, int idx,
                            int width) {
  size_t i, j;

  if (bn_wexpand(b, top) == NULL) {
    return 0;
  }

  for (i = 0, j = idx; i < top * sizeof b->d[0]; i++, j += width) {
    ((unsigned char *)b->d)[i] = buf[j];
  }

  b->top = top;
  bn_correct_top(b);
  return 1;
}

/* BN_mod_exp_mont_conttime is based on the assumption that the L1 data cache
 * line width of the target processor is at least the following value. */
#define MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH (64)
#define MOD_EXP_CTIME_MIN_CACHE_LINE_MASK \
  (MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH - 1)

/* Window sizes optimized for fixed window size modular exponentiation
 * algorithm (BN_mod_exp_mont_consttime).
 *
 * To achieve the security goals of BN_mode_exp_mont_consttime, the maximum
 * size of the window must not exceed
 * log_2(MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH). 
 *
 * Window size thresholds are defined for cache line sizes of 32 and 64, cache
 * line sizes where log_2(32)=5 and log_2(64)=6 respectively. A window size of
 * 7 should only be used on processors that have a 128 byte or greater cache
 * line size. */
#if MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH == 64

#define BN_window_bits_for_ctime_exponent_size(b) \
  ((b) > 937 ? 6 : (b) > 306 ? 5 : (b) > 89 ? 4 : (b) > 22 ? 3 : 1)
#define BN_MAX_WINDOW_BITS_FOR_CTIME_EXPONENT_SIZE (6)

#elif MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH == 32

#define BN_window_bits_for_ctime_exponent_size(b) \
  ((b) > 306 ? 5 : (b) > 89 ? 4 : (b) > 22 ? 3 : 1)
#define BN_MAX_WINDOW_BITS_FOR_CTIME_EXPONENT_SIZE (5)

#endif

/* Given a pointer value, compute the next address that is a cache line
 * multiple. */
#define MOD_EXP_CTIME_ALIGN(x_)          \
  ((unsigned char *)(x_) +               \
   (MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH - \
    (((uintptr_t)(x_)) & (MOD_EXP_CTIME_MIN_CACHE_LINE_MASK))))

/* This variant of BN_mod_exp_mont() uses fixed windows and the special
 * precomputation memory layout to limit data-dependency to a minimum
 * to protect secret exponents (cf. the hyper-threading timing attacks
 * pointed out by Colin Percival,
 * http://www.daemonology.net/hyperthreading-considered-harmful/)
 */
int BN_mod_exp_mont_consttime(BIGNUM *rr, const BIGNUM *a, const BIGNUM *p,
                              const BIGNUM *m, BN_CTX *ctx,
                              const BN_MONT_CTX *mont) {
  int i, bits, ret = 0, window, wvalue;
  int top;
  BN_MONT_CTX *new_mont = NULL;

  int numPowers;
  unsigned char *powerbufFree = NULL;
  int powerbufLen = 0;
  unsigned char *powerbuf = NULL;
  BIGNUM tmp, am;

  if (!BN_is_odd(m)) {
    OPENSSL_PUT_ERROR(BN, BN_R_CALLED_WITH_EVEN_MODULUS);
    return 0;
  }

  top = m->top;

  bits = BN_num_bits(p);
  if (bits == 0) {
    /* x**0 mod 1 is still zero. */
    if (BN_is_one(m)) {
      BN_zero(rr);
      return 1;
    }
    return BN_one(rr);
  }

  BN_CTX_start(ctx);

  /* Allocate a montgomery context if it was not supplied by the caller. */
  if (mont == NULL) {
    new_mont = BN_MONT_CTX_new();
    if (new_mont == NULL || !BN_MONT_CTX_set(new_mont, m, ctx)) {
      goto err;
    }
    mont = new_mont;
  }

#ifdef RSAZ_ENABLED
  /* If the size of the operands allow it, perform the optimized
   * RSAZ exponentiation. For further information see
   * crypto/bn/rsaz_exp.c and accompanying assembly modules. */
  if ((16 == a->top) && (16 == p->top) && (BN_num_bits(m) == 1024) &&
      rsaz_avx2_eligible()) {
    if (NULL == bn_wexpand(rr, 16)) {
      goto err;
    }
    RSAZ_1024_mod_exp_avx2(rr->d, a->d, p->d, m->d, mont->RR.d, mont->n0[0]);
    rr->top = 16;
    rr->neg = 0;
    bn_correct_top(rr);
    ret = 1;
    goto err;
  }
#endif

  /* Get the window size to use with size of p. */
  window = BN_window_bits_for_ctime_exponent_size(bits);
#if defined(OPENSSL_BN_ASM_MONT5)
  if (window >= 5) {
    window = 5; /* ~5% improvement for RSA2048 sign, and even for RSA4096 */
    if ((top & 7) == 0) {
      powerbufLen += 2 * top * sizeof(m->d[0]);
    }
  }
#endif

  /* Allocate a buffer large enough to hold all of the pre-computed
   * powers of am, am itself and tmp.
   */
  numPowers = 1 << window;
  powerbufLen +=
      sizeof(m->d[0]) *
      (top * numPowers + ((2 * top) > numPowers ? (2 * top) : numPowers));
#ifdef alloca
  if (powerbufLen < 3072) {
    powerbufFree = alloca(powerbufLen + MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH);
  } else
#endif
  {
    if ((powerbufFree = (unsigned char *)OPENSSL_malloc(
            powerbufLen + MOD_EXP_CTIME_MIN_CACHE_LINE_WIDTH)) == NULL) {
      goto err;
    }
  }

  powerbuf = MOD_EXP_CTIME_ALIGN(powerbufFree);
  memset(powerbuf, 0, powerbufLen);

#ifdef alloca
  if (powerbufLen < 3072) {
    powerbufFree = NULL;
  }
#endif

  /* lay down tmp and am right after powers table */
  tmp.d = (BN_ULONG *)(powerbuf + sizeof(m->d[0]) * top * numPowers);
  am.d = tmp.d + top;
  tmp.top = am.top = 0;
  tmp.dmax = am.dmax = top;
  tmp.neg = am.neg = 0;
  tmp.flags = am.flags = BN_FLG_STATIC_DATA;

/* prepare a^0 in Montgomery domain */
/* by Shay Gueron's suggestion */
  if (m->d[top - 1] & (((BN_ULONG)1) << (BN_BITS2 - 1))) {
    /* 2^(top*BN_BITS2) - m */
    tmp.d[0] = (0 - m->d[0]) & BN_MASK2;
    for (i = 1; i < top; i++) {
      tmp.d[i] = (~m->d[i]) & BN_MASK2;
    }
    tmp.top = top;
  } else if (!BN_to_montgomery(&tmp, BN_value_one(), mont, ctx)) {
    goto err;
  }

  /* prepare a^1 in Montgomery domain */
  if (a->neg || BN_ucmp(a, m) >= 0) {
    if (!BN_mod(&am, a, m, ctx) ||
        !BN_to_montgomery(&am, &am, mont, ctx)) {
      goto err;
    }
  } else if (!BN_to_montgomery(&am, a, mont, ctx)) {
    goto err;
  }

#if defined(OPENSSL_BN_ASM_MONT5)
  /* This optimization uses ideas from http://eprint.iacr.org/2011/239,
   * specifically optimization of cache-timing attack countermeasures
   * and pre-computation optimization. */

  /* Dedicated window==4 case improves 512-bit RSA sign by ~15%, but as
   * 512-bit RSA is hardly relevant, we omit it to spare size... */
  if (window == 5 && top > 1) {
    const BN_ULONG *np = mont->N.d, *n0 = mont->n0, *np2;

    /* BN_to_montgomery can contaminate words above .top
     * [in BN_DEBUG[_DEBUG] build]... */
    for (i = am.top; i < top; i++) {
      am.d[i] = 0;
    }
    for (i = tmp.top; i < top; i++) {
      tmp.d[i] = 0;
    }

    if (top & 7) {
      np2 = np;
    } else {
      BN_ULONG *np_double = am.d + top;
      for (i = 0; i < top; i++) {
        np_double[2 * i] = np[i];
      }
      np2 = np_double;
    }

    bn_scatter5(tmp.d, top, powerbuf, 0);
    bn_scatter5(am.d, am.top, powerbuf, 1);
    bn_mul_mont(tmp.d, am.d, am.d, np, n0, top);
    bn_scatter5(tmp.d, top, powerbuf, 2);

    /* same as above, but uses squaring for 1/2 of operations */
    for (i = 4; i < 32; i *= 2) {
      bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
      bn_scatter5(tmp.d, top, powerbuf, i);
    }
    for (i = 3; i < 8; i += 2) {
      int j;
      bn_mul_mont_gather5(tmp.d, am.d, powerbuf, np2, n0, top, i - 1);
      bn_scatter5(tmp.d, top, powerbuf, i);
      for (j = 2 * i; j < 32; j *= 2) {
        bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
        bn_scatter5(tmp.d, top, powerbuf, j);
      }
    }
    for (; i < 16; i += 2) {
      bn_mul_mont_gather5(tmp.d, am.d, powerbuf, np2, n0, top, i - 1);
      bn_scatter5(tmp.d, top, powerbuf, i);
      bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
      bn_scatter5(tmp.d, top, powerbuf, 2 * i);
    }
    for (; i < 32; i += 2) {
      bn_mul_mont_gather5(tmp.d, am.d, powerbuf, np2, n0, top, i - 1);
      bn_scatter5(tmp.d, top, powerbuf, i);
    }

    bits--;
    for (wvalue = 0, i = bits % 5; i >= 0; i--, bits--) {
      wvalue = (wvalue << 1) + BN_is_bit_set(p, bits);
    }
    bn_gather5(tmp.d, top, powerbuf, wvalue);

    /* At this point |bits| is 4 mod 5 and at least -1. (|bits| is the first bit
     * that has not been read yet.) */
    assert(bits >= -1 && (bits == -1 || bits % 5 == 4));

    /* Scan the exponent one window at a time starting from the most
     * significant bits.
     */
    if (top & 7) {
      while (bits >= 0) {
        for (wvalue = 0, i = 0; i < 5; i++, bits--) {
          wvalue = (wvalue << 1) + BN_is_bit_set(p, bits);
        }

        bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
        bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
        bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
        bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
        bn_mul_mont(tmp.d, tmp.d, tmp.d, np, n0, top);
        bn_mul_mont_gather5(tmp.d, tmp.d, powerbuf, np, n0, top, wvalue);
      }
    } else {
      const uint8_t *p_bytes = (const uint8_t *)p->d;
      int max_bits = p->top * BN_BITS2;
      assert(bits < max_bits);
      /* |p = 0| has been handled as a special case, so |max_bits| is at least
       * one word. */
      assert(max_bits >= 64);

      /* If the first bit to be read lands in the last byte, unroll the first
       * iteration to avoid reading past the bounds of |p->d|. (After the first
       * iteration, we are guaranteed to be past the last byte.) Note |bits|
       * here is the top bit, inclusive. */
      if (bits - 4 >= max_bits - 8) {
        /* Read five bits from |bits-4| through |bits|, inclusive. */
        wvalue = p_bytes[p->top * BN_BYTES - 1];
        wvalue >>= (bits - 4) & 7;
        wvalue &= 0x1f;
        bits -= 5;
        bn_power5(tmp.d, tmp.d, powerbuf, np2, n0, top, wvalue);
      }
      while (bits >= 0) {
        /* Read five bits from |bits-4| through |bits|, inclusive. */
        int first_bit = bits - 4;
        wvalue = *(const uint16_t *) (p_bytes + (first_bit >> 3));
        wvalue >>= first_bit & 7;
        wvalue &= 0x1f;
        bits -= 5;
        bn_power5(tmp.d, tmp.d, powerbuf, np2, n0, top, wvalue);
      }
    }

    ret = bn_from_montgomery(tmp.d, tmp.d, NULL, np2, n0, top);
    tmp.top = top;
    bn_correct_top(&tmp);
    if (ret) {
      if (!BN_copy(rr, &tmp)) {
        ret = 0;
      }
      goto err; /* non-zero ret means it's not error */
    }
  } else
#endif
  {
    if (!copy_to_prebuf(&tmp, top, powerbuf, 0, numPowers) ||
        !copy_to_prebuf(&am, top, powerbuf, 1, numPowers)) {
      goto err;
    }

    /* If the window size is greater than 1, then calculate
     * val[i=2..2^winsize-1]. Powers are computed as a*a^(i-1)
     * (even powers could instead be computed as (a^(i/2))^2
     * to use the slight performance advantage of sqr over mul).
     */
    if (window > 1) {
      if (!BN_mod_mul_montgomery(&tmp, &am, &am, mont, ctx) ||
          !copy_to_prebuf(&tmp, top, powerbuf, 2, numPowers)) {
        goto err;
      }
      for (i = 3; i < numPowers; i++) {
        /* Calculate a^i = a^(i-1) * a */
        if (!BN_mod_mul_montgomery(&tmp, &am, &tmp, mont, ctx) ||
            !copy_to_prebuf(&tmp, top, powerbuf, i, numPowers)) {
          goto err;
        }
      }
    }

    bits--;
    for (wvalue = 0, i = bits % window; i >= 0; i--, bits--) {
      wvalue = (wvalue << 1) + BN_is_bit_set(p, bits);
    }
    if (!copy_from_prebuf(&tmp, top, powerbuf, wvalue, numPowers)) {
      goto err;
    }

    /* Scan the exponent one window at a time starting from the most
     * significant bits.
     */
    while (bits >= 0) {
      wvalue = 0; /* The 'value' of the window */

      /* Scan the window, squaring the result as we go */
      for (i = 0; i < window; i++, bits--) {
        if (!BN_mod_mul_montgomery(&tmp, &tmp, &tmp, mont, ctx)) {
          goto err;
        }
        wvalue = (wvalue << 1) + BN_is_bit_set(p, bits);
      }

      /* Fetch the appropriate pre-computed value from the pre-buf */
      if (!copy_from_prebuf(&am, top, powerbuf, wvalue, numPowers)) {
        goto err;
      }

      /* Multiply the result into the intermediate result */
      if (!BN_mod_mul_montgomery(&tmp, &tmp, &am, mont, ctx)) {
        goto err;
      }
    }
  }

  /* Convert the final result from montgomery to standard format */
  if (!BN_from_montgomery(rr, &tmp, mont, ctx)) {
    goto err;
  }
  ret = 1;

err:
  BN_MONT_CTX_free(new_mont);
  if (powerbuf != NULL) {
    OPENSSL_cleanse(powerbuf, powerbufLen);
    OPENSSL_free(powerbufFree);
  }
  BN_CTX_end(ctx);
  return (ret);
}

int BN_mod_exp_mont_word(BIGNUM *rr, BN_ULONG a, const BIGNUM *p,
                         const BIGNUM *m, BN_CTX *ctx,
                         const BN_MONT_CTX *mont) {
  BN_MONT_CTX *new_mont = NULL;
  int b, bits, ret = 0;
  int r_is_one;
  BN_ULONG w, next_w;
  BIGNUM *d, *r, *t;
  BIGNUM *swap_tmp;
#define BN_MOD_MUL_WORD(r, w, m)   \
  (BN_mul_word(r, (w)) &&          \
   (/* BN_ucmp(r, (m)) < 0 ? 1 :*/ \
    (BN_mod(t, r, m, ctx) && (swap_tmp = r, r = t, t = swap_tmp, 1))))
  /* BN_MOD_MUL_WORD is only used with 'w' large, so the BN_ucmp test is
   * probably more overhead than always using BN_mod (which uses BN_copy if a
   * similar test returns true). We can use BN_mod and do not need BN_nnmod
   * because our accumulator is never negative (the result of BN_mod does not
   * depend on the sign of the modulus). */
#define BN_TO_MONTGOMERY_WORD(r, w, mont) \
  (BN_set_word(r, (w)) && BN_to_montgomery(r, r, (mont), ctx))

  if (BN_get_flags(p, BN_FLG_CONSTTIME) != 0) {
    /* BN_FLG_CONSTTIME only supported by BN_mod_exp_mont() */
    OPENSSL_PUT_ERROR(BN, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
    return 0;
  }

  if (!BN_is_odd(m)) {
    OPENSSL_PUT_ERROR(BN, BN_R_CALLED_WITH_EVEN_MODULUS);
    return 0;
  }

  if (m->top == 1) {
    a %= m->d[0]; /* make sure that 'a' is reduced */
  }

  bits = BN_num_bits(p);
  if (bits == 0) {
    /* x**0 mod 1 is still zero. */
    if (BN_is_one(m)) {
      BN_zero(rr);
      return 1;
    }
    return BN_one(rr);
  }
  if (a == 0) {
    BN_zero(rr);
    return 1;
  }

  BN_CTX_start(ctx);
  d = BN_CTX_get(ctx);
  r = BN_CTX_get(ctx);
  t = BN_CTX_get(ctx);
  if (d == NULL || r == NULL || t == NULL) {
    goto err;
  }

  /* Allocate a montgomery context if it was not supplied by the caller. */
  if (mont == NULL) {
    new_mont = BN_MONT_CTX_new();
    if (new_mont == NULL || !BN_MONT_CTX_set(new_mont, m, ctx)) {
      goto err;
    }
    mont = new_mont;
  }

  r_is_one = 1; /* except for Montgomery factor */

  /* bits-1 >= 0 */

  /* The result is accumulated in the product r*w. */
  w = a; /* bit 'bits-1' of 'p' is always set */
  for (b = bits - 2; b >= 0; b--) {
    /* First, square r*w. */
    next_w = w * w;
    if ((next_w / w) != w) {
      /* overflow */
      if (r_is_one) {
        if (!BN_TO_MONTGOMERY_WORD(r, w, mont)) {
          goto err;
        }
        r_is_one = 0;
      } else {
        if (!BN_MOD_MUL_WORD(r, w, m)) {
          goto err;
        }
      }
      next_w = 1;
    }

    w = next_w;
    if (!r_is_one) {
      if (!BN_mod_mul_montgomery(r, r, r, mont, ctx)) {
        goto err;
      }
    }

    /* Second, multiply r*w by 'a' if exponent bit is set. */
    if (BN_is_bit_set(p, b)) {
      next_w = w * a;
      if ((next_w / a) != w) {
        /* overflow */
        if (r_is_one) {
          if (!BN_TO_MONTGOMERY_WORD(r, w, mont)) {
            goto err;
          }
          r_is_one = 0;
        } else {
          if (!BN_MOD_MUL_WORD(r, w, m)) {
            goto err;
          }
        }
        next_w = a;
      }
      w = next_w;
    }
  }

  /* Finally, set r:=r*w. */
  if (w != 1) {
    if (r_is_one) {
      if (!BN_TO_MONTGOMERY_WORD(r, w, mont)) {
        goto err;
      }
      r_is_one = 0;
    } else {
      if (!BN_MOD_MUL_WORD(r, w, m)) {
        goto err;
      }
    }
  }

  if (r_is_one) {
    /* can happen only if a == 1*/
    if (!BN_one(rr)) {
      goto err;
    }
  } else {
    if (!BN_from_montgomery(rr, r, mont, ctx)) {
      goto err;
    }
  }
  ret = 1;

err:
  BN_MONT_CTX_free(new_mont);
  BN_CTX_end(ctx);
  return ret;
}
