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

#include "internal.h"
#include "../../internal.h"

#include "../../limbs/limbs.h"
#include "../../limbs/limbs.inl"

OPENSSL_STATIC_ASSERT(BN_MONT_CTX_N0_LIMBS == 1 || BN_MONT_CTX_N0_LIMBS == 2,
  "BN_MONT_CTX_N0_LIMBS value is invalid");
OPENSSL_STATIC_ASSERT(
  sizeof(BN_ULONG) * BN_MONT_CTX_N0_LIMBS == sizeof(uint64_t),
  "uint64_t is insufficient precision for n0");

int bn_from_montgomery_in_place(BN_ULONG r[], size_t num_r, BN_ULONG a[],
                                    size_t num_a, const BN_ULONG n[],
                                    size_t num_n,
                                    const BN_ULONG n0_[BN_MONT_CTX_N0_LIMBS]) {
  if (num_n == 0 || num_r != num_n || num_a != 2 * num_n) {
    return 0;
  }

  // Add multiples of |n| to |r| until R = 2^(nl * BN_BITS2) divides it. On
  // input, we had |r| < |n| * R, so now |r| < 2 * |n| * R. Note that |r|
  // includes |carry| which is stored separately.
  BN_ULONG n0 = n0_[0];
  BN_ULONG carry = 0;
  for (size_t i = 0; i < num_n; i++) {
    BN_ULONG v = limbs_mul_add_limb(a + i, n, a[i] * n0, num_n);
    v += carry + a[i + num_n];
    carry |= (v != a[i + num_n]);
    carry &= (v <= a[i + num_n]);
    a[i + num_n] = v;
  }

  // Shift |num_n| words to divide by R. We have |a| < 2 * |n|. Note that |a|
  // includes |carry| which is stored separately.
  a += num_n;

  // |a| thus requires at most one additional subtraction |n| to be reduced.
  // Subtract |n| and select the answer in constant time.
  BN_ULONG v = limbs_sub(r, a, n, num_n) - carry;
  // |v| is one if |a| - |n| underflowed or zero if it did not. Note |v| cannot
  // be -1. That would imply the subtraction did not fit in |num_n| words, and
  // we know at most one subtraction is needed.
  v = 0u - v;
  for (size_t i = 0; i < num_n; i++) {
    r[i] = constant_time_select_w(v, a[i], r[i]);
    a[i] = 0;
  }
  return 1;
}

# ifdef OPENSSL_NO_ASM

#   include <alloca.h>

#  define BN_BITS4        32
#  define BN_MASK2        (0xffffffffffffffffL)
#  define BN_MASK2l       (0xffffffffL)
#  define BN_MASK2h       (0xffffffff00000000L)
#  define BN_MASK2h1      (0xffffffff80000000L)
#  define BN_DEC_CONV     (10000000000000000000UL)
#  define BN_DEC_NUM      19
#  define BN_DEC_FMT1     "%lu"
#  define BN_DEC_FMT2     "%019lu"

BN_ULONG bn_sub_words(BN_ULONG *r, const BN_ULONG *a, const BN_ULONG *b,
                      size_t n)
{
    BN_ULONG t1, t2;
    BN_ULONG c = 0;

    if (n <= 0)
        return (BN_ULONG)0;

#ifndef OPENSSL_SMALL_FOOTPRINT
    while ((int)n & ~3) {
        t1 = a[0];
        t2 = b[0];
        r[0] = (t1 - t2 - c) & BN_MASK2;
        if (t1 != t2)
            c = (t1 < t2);
        t1 = a[1];
        t2 = b[1];
        r[1] = (t1 - t2 - c) & BN_MASK2;
        if (t1 != t2)
            c = (t1 < t2);
        t1 = a[2];
        t2 = b[2];
        r[2] = (t1 - t2 - c) & BN_MASK2;
        if (t1 != t2)
            c = (t1 < t2);
        t1 = a[3];
        t2 = b[3];
        r[3] = (t1 - t2 - c) & BN_MASK2;
        if (t1 != t2)
            c = (t1 < t2);
        a += 4;
        b += 4;
        r += 4;
        n -= 4;
    }
#endif
    while (n) {
        t1 = a[0];
        t2 = b[0];
        r[0] = (t1 - t2 - c) & BN_MASK2;
        if (t1 != t2)
            c = (t1 < t2);
        a++;
        b++;
        r++;
        n--;
    }
    return c;
}

#  define Lw(t)    (((BN_ULONG)(t))&BN_MASK2)
#  define Hw(t)    (((BN_ULONG)((t)>>BN_BITS2))&BN_MASK2)

#   define BN_UMULT_HIGH(a,b)          (((uint128_t)(a)*(b))>>64)
#   define BN_UMULT_LOHI(low,high,a,b) ({       \
        uint128_t ret=(uint128_t)(a)*(b);   \
        (high)=ret>>64; (low)=ret;      })

#  define mul_add(r,a,w,c) {              \
        BN_ULONG high,low,ret,tmp=(a);  \
        ret =  (r);                     \
        high=  (BN_ULONG)BN_UMULT_HIGH(w,tmp);   \
        ret += (c);                     \
        low =  (w) * tmp;               \
        (c) =  (ret<(c))?1:0;           \
        (c) += high;                    \
        ret += low;                     \
        (c) += (ret<low)?1:0;           \
        (r) =  ret;                     \
        }

#  define mul(r,a,w,c)    {               \
        BN_ULONG high,low,ret,ta=(a);   \
        low =  (w) * ta;                \
        high=  (BN_ULONG)BN_UMULT_HIGH(w,ta);    \
        ret =  low + (c);               \
        (c) =  high;                    \
        (c) += (ret<low)?1:0;           \
        (r) =  ret;                     \
        }

#  define sqr(r0,r1,a)    {               \
        BN_ULONG tmp=(a);               \
        (r0) = tmp * tmp;               \
        (r1) = BN_UMULT_HIGH(tmp,tmp);  \
        }


#endif

/*
 * This is essentially reference implementation, which may or may not
 * result in performance improvement. E.g. on IA-32 this routine was
 * observed to give 40% faster rsa1024 private key operations and 10%
 * faster rsa4096 ones, while on AMD64 it improves rsa1024 sign only
 * by 10% and *worsens* rsa4096 sign by 15%. Once again, it's a
 * reference implementation, one to be used as starting point for
 * platform-specific assembler. Mentioned numbers apply to compiler
 * generated code compiled with and without -DOPENSSL_BN_ASM_MONT and
 * can vary not only from platform to platform, but even for compiler
 * versions. Assembler vs. assembler improvement coefficients can
 * [and are known to] differ and are to be documented elsewhere.
 */
void bn_mul_mont(BN_ULONG *rp, const BN_ULONG *ap, const BN_ULONG *bp,
                const BN_ULONG *np, const BN_ULONG *n0p, size_t num)
{
    BN_ULONG c0, c1, ml, *tp, n0;
#   ifdef mul64
    BN_ULONG mh;
#   endif
    volatile BN_ULONG *vp;
    size_t i = 0, j;

#   if 0                        /* template for platform-specific
                                 * implementation */
    if (ap == bp)
        return bn_sqr_mont(rp, ap, np, n0p, num);
#   endif
    vp = tp = alloca((num + 2) * sizeof(BN_ULONG));

    n0 = *n0p;

    c0 = 0;
    ml = bp[0];
#   ifdef mul64
    mh = HBITS(ml);
    ml = LBITS(ml);
    for (j = 0; j < num; ++j)
        mul(tp[j], ap[j], ml, mh, c0);
#   else
    for (j = 0; j < num; ++j)
        mul(tp[j], ap[j], ml, c0);
#   endif

    tp[num] = c0;
    tp[num + 1] = 0;
    goto enter;

    for (i = 0; i < num; i++) {
        c0 = 0;
        ml = bp[i];
#   ifdef mul64
        mh = HBITS(ml);
        ml = LBITS(ml);
        for (j = 0; j < num; ++j)
            mul_add(tp[j], ap[j], ml, mh, c0);
#   else
        for (j = 0; j < num; ++j)
            mul_add(tp[j], ap[j], ml, c0);
#   endif
        c1 = (tp[num] + c0) & BN_MASK2;
        tp[num] = c1;
        tp[num + 1] = (c1 < c0 ? 1 : 0);
 enter:
        c1 = tp[0];
        ml = (c1 * n0) & BN_MASK2;
        c0 = 0;
#   ifdef mul64
        mh = HBITS(ml);
        ml = LBITS(ml);
        mul_add(c1, np[0], ml, mh, c0);
#   else
        mul_add(c1, ml, np[0], c0);
#   endif
        for (j = 1; j < num; j++) {
            c1 = tp[j];
#   ifdef mul64
            mul_add(c1, np[j], ml, mh, c0);
#   else
            mul_add(c1, ml, np[j], c0);
#   endif
            tp[j - 1] = c1 & BN_MASK2;
        }
        c1 = (tp[num] + c0) & BN_MASK2;
        tp[num - 1] = c1;
        tp[num] = tp[num + 1] + (c1 < c0 ? 1 : 0);
    }

    if (tp[num] != 0 || tp[num - 1] >= np[num - 1]) {
        c0 = bn_sub_words(rp, tp, np, num);
        if (tp[num] != 0 || c0 == 0) {
            for (i = 0; i < num + 2; i++)
                vp[i] = 0;
            return;
        }
    }
    for (i = 0; i < num; i++)
        rp[i] = tp[i], vp[i] = 0;
    vp[num] = 0;
    vp[num + 1] = 0;
    return;
}
