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

#include <openssl/bn.h>

#include <assert.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/type_check.h>

#include "internal.h"
#include "../../internal.h"


#define BN_MUL_RECURSIVE_SIZE_NORMAL 16
#define BN_SQR_RECURSIVE_SIZE_NORMAL BN_MUL_RECURSIVE_SIZE_NORMAL


static void bn_abs_sub_words(BN_ULONG *r, const BN_ULONG *a, const BN_ULONG *b,
                             size_t num, BN_ULONG *tmp) {
  BN_ULONG borrow = bn_sub_words(tmp, a, b, num);
  bn_sub_words(r, b, a, num);
  bn_select_words(r, 0 - borrow, r /* tmp < 0 */, tmp /* tmp >= 0 */, num);
}

static void bn_mul_normal(BN_ULONG *r, const BN_ULONG *a, size_t na,
                          const BN_ULONG *b, size_t nb) {
  if (na < nb) {
    size_t itmp = na;
    na = nb;
    nb = itmp;
    const BN_ULONG *ltmp = a;
    a = b;
    b = ltmp;
  }
  BN_ULONG *rr = &(r[na]);
  if (nb == 0) {
    OPENSSL_memset(r, 0, na * sizeof(BN_ULONG));
    return;
  }
  rr[0] = bn_mul_words(r, a, na, b[0]);

  for (;;) {
    if (--nb == 0) {
      return;
    }
    rr[1] = bn_mul_add_words(&(r[1]), a, na, b[1]);
    if (--nb == 0) {
      return;
    }
    rr[2] = bn_mul_add_words(&(r[2]), a, na, b[2]);
    if (--nb == 0) {
      return;
    }
    rr[3] = bn_mul_add_words(&(r[3]), a, na, b[3]);
    if (--nb == 0) {
      return;
    }
    rr[4] = bn_mul_add_words(&(r[4]), a, na, b[4]);
    rr += 4;
    r += 4;
    b += 4;
  }
}

#if !defined(OPENSSL_X86) || defined(OPENSSL_NO_ASM)
// Here follows specialised variants of bn_add_words() and bn_sub_words(). They
// have the property performing operations on arrays of different sizes. The
// sizes of those arrays is expressed through cl, which is the common length (
// basicall, min(len(a),len(b)) ), and dl, which is the delta between the two
// lengths, calculated as len(a)-len(b). All lengths are the number of
// BN_ULONGs...  For the operations that require a result array as parameter,
// it must have the length cl+abs(dl). These functions should probably end up
// in bn_asm.c as soon as there are assembler counterparts for the systems that
// use assembler files.

static BN_ULONG bn_sub_part_words(BN_ULONG *r, const BN_ULONG *a,
                                  const BN_ULONG *b, int cl, int dl) {
  BN_ULONG c, t;

  assert(cl >= 0);
  c = bn_sub_words(r, a, b, cl);

  if (dl == 0) {
    return c;
  }

  r += cl;
  a += cl;
  b += cl;

  if (dl < 0) {
    for (;;) {
      t = b[0];
      r[0] = 0 - t - c;
      if (t != 0) {
        c = 1;
      }
      if (++dl >= 0) {
        break;
      }

      t = b[1];
      r[1] = 0 - t - c;
      if (t != 0) {
        c = 1;
      }
      if (++dl >= 0) {
        break;
      }

      t = b[2];
      r[2] = 0 - t - c;
      if (t != 0) {
        c = 1;
      }
      if (++dl >= 0) {
        break;
      }

      t = b[3];
      r[3] = 0 - t - c;
      if (t != 0) {
        c = 1;
      }
      if (++dl >= 0) {
        break;
      }

      b += 4;
      r += 4;
    }
  } else {
    int save_dl = dl;
    while (c) {
      t = a[0];
      r[0] = t - c;
      if (t != 0) {
        c = 0;
      }
      if (--dl <= 0) {
        break;
      }

      t = a[1];
      r[1] = t - c;
      if (t != 0) {
        c = 0;
      }
      if (--dl <= 0) {
        break;
      }

      t = a[2];
      r[2] = t - c;
      if (t != 0) {
        c = 0;
      }
      if (--dl <= 0) {
        break;
      }

      t = a[3];
      r[3] = t - c;
      if (t != 0) {
        c = 0;
      }
      if (--dl <= 0) {
        break;
      }

      save_dl = dl;
      a += 4;
      r += 4;
    }
    if (dl > 0) {
      if (save_dl > dl) {
        switch (save_dl - dl) {
          case 1:
            r[1] = a[1];
            if (--dl <= 0) {
              break;
            }
            OPENSSL_FALLTHROUGH;
          case 2:
            r[2] = a[2];
            if (--dl <= 0) {
              break;
            }
            OPENSSL_FALLTHROUGH;
          case 3:
            r[3] = a[3];
            if (--dl <= 0) {
              break;
            }
        }
        a += 4;
        r += 4;
      }
    }

    if (dl > 0) {
      for (;;) {
        r[0] = a[0];
        if (--dl <= 0) {
          break;
        }
        r[1] = a[1];
        if (--dl <= 0) {
          break;
        }
        r[2] = a[2];
        if (--dl <= 0) {
          break;
        }
        r[3] = a[3];
        if (--dl <= 0) {
          break;
        }

        a += 4;
        r += 4;
      }
    }
  }

  return c;
}
#else
// On other platforms the function is defined in asm.
BN_ULONG bn_sub_part_words(BN_ULONG *r, const BN_ULONG *a, const BN_ULONG *b,
                           int cl, int dl);
#endif

// bn_abs_sub_part_words computes |r| = |a| - |b|, storing the absolute value
// and returning a mask of all ones if the result was negative and all zeros if
// the result was positive. |cl| and |dl| follow the |bn_sub_part_words| calling
// convention.
//
// TODO(davidben): Make this take |size_t|. The |cl| + |dl| calling convention
// is confusing. The trouble is 32-bit x86 implements |bn_sub_part_words| in
// assembly, but we can probably just delete it?
static BN_ULONG bn_abs_sub_part_words(BN_ULONG *r, const BN_ULONG *a,
                                      const BN_ULONG *b, int cl, int dl,
                                      BN_ULONG *tmp) {
  BN_ULONG borrow = bn_sub_part_words(tmp, a, b, cl, dl);
  bn_sub_part_words(r, b, a, cl, -dl);
  int r_len = cl + (dl < 0 ? -dl : dl);
  borrow = 0 - borrow;
  bn_select_words(r, borrow, r /* tmp < 0 */, tmp /* tmp >= 0 */, r_len);
  return borrow;
}

// Karatsuba recursive multiplication algorithm
// (cf. Knuth, The Art of Computer Programming, Vol. 2)

// bn_mul_recursive sets |r| to |a| * |b|, using |t| as scratch space. |r| has
// length 2*|n2|, |a| has length |n2| + |dna|, |b| has length |n2| + |dnb|, and
// |t| has length 4*|n2|. |n2| must be a power of two. Finally, we must have
// -|BN_MUL_RECURSIVE_SIZE_NORMAL|/2 <= |dna| <= 0 and
// -|BN_MUL_RECURSIVE_SIZE_NORMAL|/2 <= |dnb| <= 0.
//
// TODO(davidben): Simplify and |size_t| the calling convention around lengths
// here.
static void bn_mul_recursive(BN_ULONG *r, const BN_ULONG *a, const BN_ULONG *b,
                             int n2, int dna, int dnb, BN_ULONG *t) {
  // |n2| is a power of two.
  assert(n2 != 0 && (n2 & (n2 - 1)) == 0);
  // Check |dna| and |dnb| are in range.
  assert(-BN_MUL_RECURSIVE_SIZE_NORMAL/2 <= dna && dna <= 0);
  assert(-BN_MUL_RECURSIVE_SIZE_NORMAL/2 <= dnb && dnb <= 0);

  // Only call bn_mul_comba 8 if n2 == 8 and the
  // two arrays are complete [steve]
  if (n2 == 8 && dna == 0 && dnb == 0) {
    bn_mul_comba8(r, a, b);
    return;
  }

  // Else do normal multiply
  if (n2 < BN_MUL_RECURSIVE_SIZE_NORMAL) {
    bn_mul_normal(r, a, n2 + dna, b, n2 + dnb);
    if (dna + dnb < 0) {
      OPENSSL_memset(&r[2 * n2 + dna + dnb], 0,
                     sizeof(BN_ULONG) * -(dna + dnb));
    }
    return;
  }

  // Split |a| and |b| into a0,a1 and b0,b1, where a0 and b0 have size |n|.
  // Split |t| into t0,t1,t2,t3, each of size |n|, with the remaining 4*|n| used
  // for recursive calls.
  // Split |r| into r0,r1,r2,r3. We must contribute a0*b0 to r0,r1, a0*a1+b0*b1
  // to r1,r2, and a1*b1 to r2,r3. The middle term we will compute as:
  //
  //   a0*a1 + b0*b1 = (a0 - a1)*(b1 - b0) + a1*b1 + a0*b0
  //
  // Note that we know |n| >= |BN_MUL_RECURSIVE_SIZE_NORMAL|/2 above, so
  // |tna| and |tnb| are non-negative.
  int n = n2 / 2, tna = n + dna, tnb = n + dnb;

  // t0 = a0 - a1 and t1 = b1 - b0. The result will be multiplied, so we XOR
  // their sign masks, giving the sign of (a0 - a1)*(b1 - b0). t0 and t1
  // themselves store the absolute value.
  BN_ULONG neg = bn_abs_sub_part_words(t, a, &a[n], tna, n - tna, &t[n2]);
  neg ^= bn_abs_sub_part_words(&t[n], &b[n], b, tnb, tnb - n, &t[n2]);

  // Compute:
  // t2,t3 = t0 * t1 = |(a0 - a1)*(b1 - b0)|
  // r0,r1 = a0 * b0
  // r2,r3 = a1 * b1
  if (n == 4 && dna == 0 && dnb == 0) {
    bn_mul_comba4(&t[n2], t, &t[n]);

    bn_mul_comba4(r, a, b);
    bn_mul_comba4(&r[n2], &a[n], &b[n]);
  } else if (n == 8 && dna == 0 && dnb == 0) {
    bn_mul_comba8(&t[n2], t, &t[n]);

    bn_mul_comba8(r, a, b);
    bn_mul_comba8(&r[n2], &a[n], &b[n]);
  } else {
    BN_ULONG *p = &t[n2 * 2];
    bn_mul_recursive(&t[n2], t, &t[n], n, 0, 0, p);
    bn_mul_recursive(r, a, b, n, 0, 0, p);
    bn_mul_recursive(&r[n2], &a[n], &b[n], n, dna, dnb, p);
  }

  // t0,t1,c = r0,r1 + r2,r3 = a0*b0 + a1*b1
  BN_ULONG c = bn_add_words(t, r, &r[n2], n2);

  // t2,t3,c = t0,t1,c + neg*t2,t3 = (a0 - a1)*(b1 - b0) + a1*b1 + a0*b0.
  // The second term is stored as the absolute value, so we do this with a
  // constant-time select.
  BN_ULONG c_neg = c - bn_sub_words(&t[n2 * 2], t, &t[n2], n2);
  BN_ULONG c_pos = c + bn_add_words(&t[n2], t, &t[n2], n2);
  bn_select_words(&t[n2], neg, &t[n2 * 2], &t[n2], n2);
  OPENSSL_COMPILE_ASSERT(sizeof(BN_ULONG) <= sizeof(crypto_word_t),
                         crypto_word_t_too_small);
  c = constant_time_select_w(neg, c_neg, c_pos);

  // We now have our three components. Add them together.
  // r1,r2,c = r1,r2 + t2,t3,c
  c += bn_add_words(&r[n], &r[n], &t[n2], n2);

  // Propagate the carry bit to the end.
  for (int i = n + n2; i < n2 + n2; i++) {
    BN_ULONG old = r[i];
    r[i] = old + c;
    c = r[i] < old;
  }

  // The product should fit without carries.
  assert(c == 0);
}

// n+tn is the word length
// t needs to be n*4 is size, as does r
// tnX may not be negative but less than n
static void bn_mul_part_recursive(BN_ULONG *r, const BN_ULONG *a,
                                  const BN_ULONG *b, int n, int tna, int tnb,
                                  BN_ULONG *t) {
  int i, j, n2 = n * 2;
  int c1, c2, neg;
  BN_ULONG ln, lo, *p;

  if (n < 8) {
    bn_mul_normal(r, a, n + tna, b, n + tnb);
    return;
  }

  // TODO(davidben): This function is not constant-time, but should be. See
  // https://crbug.com/boringssl/234.

  // r=(a[0]-a[1])*(b[1]-b[0])
  c1 = bn_cmp_part_words(a, &(a[n]), tna, n - tna);
  c2 = bn_cmp_part_words(&(b[n]), b, tnb, tnb - n);
  neg = 0;
  switch (c1 * 3 + c2) {
    case -4:
      bn_sub_part_words(t, &(a[n]), a, tna, tna - n);        // -
      bn_sub_part_words(&(t[n]), b, &(b[n]), tnb, n - tnb);  // -
      break;
    case -3:
      // break;
    case -2:
      bn_sub_part_words(t, &(a[n]), a, tna, tna - n);        // -
      bn_sub_part_words(&(t[n]), &(b[n]), b, tnb, tnb - n);  // +
      neg = 1;
      break;
    case -1:
    case 0:
    case 1:
      // break;
    case 2:
      bn_sub_part_words(t, a, &(a[n]), tna, n - tna);        // +
      bn_sub_part_words(&(t[n]), b, &(b[n]), tnb, n - tnb);  // -
      neg = 1;
      break;
    case 3:
      // break;
    case 4:
      bn_sub_part_words(t, a, &(a[n]), tna, n - tna);
      bn_sub_part_words(&(t[n]), &(b[n]), b, tnb, tnb - n);
      break;
  }

  if (n == 8) {
    bn_mul_comba8(&(t[n2]), t, &(t[n]));
    bn_mul_comba8(r, a, b);
    bn_mul_normal(&(r[n2]), &(a[n]), tna, &(b[n]), tnb);
    OPENSSL_memset(&(r[n2 + tna + tnb]), 0, sizeof(BN_ULONG) * (n2 - tna - tnb));
  } else {
    p = &(t[n2 * 2]);
    bn_mul_recursive(&(t[n2]), t, &(t[n]), n, 0, 0, p);
    bn_mul_recursive(r, a, b, n, 0, 0, p);
    i = n / 2;
    // If there is only a bottom half to the number,
    // just do it
    if (tna > tnb) {
      j = tna - i;
    } else {
      j = tnb - i;
    }

    if (j == 0) {
      bn_mul_recursive(&(r[n2]), &(a[n]), &(b[n]), i, tna - i, tnb - i, p);
      OPENSSL_memset(&(r[n2 + i * 2]), 0, sizeof(BN_ULONG) * (n2 - i * 2));
    } else if (j > 0) {
      // eg, n == 16, i == 8 and tn == 11
      bn_mul_part_recursive(&(r[n2]), &(a[n]), &(b[n]), i, tna - i, tnb - i, p);
      OPENSSL_memset(&(r[n2 + tna + tnb]), 0,
                     sizeof(BN_ULONG) * (n2 - tna - tnb));
    } else {
      // (j < 0) eg, n == 16, i == 8 and tn == 5
      OPENSSL_memset(&(r[n2]), 0, sizeof(BN_ULONG) * n2);
      if (tna < BN_MUL_RECURSIVE_SIZE_NORMAL &&
          tnb < BN_MUL_RECURSIVE_SIZE_NORMAL) {
        bn_mul_normal(&(r[n2]), &(a[n]), tna, &(b[n]), tnb);
      } else {
        for (;;) {
          i /= 2;
          // these simplified conditions work
          // exclusively because difference
          // between tna and tnb is 1 or 0
          if (i < tna || i < tnb) {
            bn_mul_part_recursive(&(r[n2]), &(a[n]), &(b[n]), i, tna - i,
                                  tnb - i, p);
            break;
          } else if (i == tna || i == tnb) {
            bn_mul_recursive(&(r[n2]), &(a[n]), &(b[n]), i, tna - i, tnb - i,
                             p);
            break;
          }
        }
      }
    }
  }

  // t[32] holds (a[0]-a[1])*(b[1]-b[0]), c1 is the sign
  // r[10] holds (a[0]*b[0])
  // r[32] holds (b[1]*b[1])

  c1 = (int)(bn_add_words(t, r, &(r[n2]), n2));

  if (neg) {
    // if t[32] is negative
    c1 -= (int)(bn_sub_words(&(t[n2]), t, &(t[n2]), n2));
  } else {
    // Might have a carry
    c1 += (int)(bn_add_words(&(t[n2]), &(t[n2]), t, n2));
  }

  // t[32] holds (a[0]-a[1])*(b[1]-b[0])+(a[0]*b[0])+(a[1]*b[1])
  // r[10] holds (a[0]*b[0])
  // r[32] holds (b[1]*b[1])
  // c1 holds the carry bits
  c1 += (int)(bn_add_words(&(r[n]), &(r[n]), &(t[n2]), n2));
  if (c1) {
    p = &(r[n + n2]);
    lo = *p;
    ln = lo + c1;
    *p = ln;

    // The overflow will stop before we over write
    // words we should not overwrite
    if (ln < (BN_ULONG)c1) {
      do {
        p++;
        lo = *p;
        ln = lo + 1;
        *p = ln;
      } while (ln == 0);
    }
  }
}

// bn_mul_impl implements |BN_mul| and |bn_mul_fixed|. Note this function breaks
// |BIGNUM| invariants and may return a negative zero. This is handled by the
// callers.
static int bn_mul_impl(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                       BN_CTX *ctx) {
  int ret = 0;
  int top, al, bl;
  BIGNUM *rr;
  int i;
  BIGNUM *t = NULL;
  int j = 0, k;

  al = a->width;
  bl = b->width;

  if ((al == 0) || (bl == 0)) {
    BN_zero(r);
    return 1;
  }
  top = al + bl;

  BN_CTX_start(ctx);
  if ((r == a) || (r == b)) {
    if ((rr = BN_CTX_get(ctx)) == NULL) {
      goto err;
    }
  } else {
    rr = r;
  }
  rr->neg = a->neg ^ b->neg;

  i = al - bl;
  if (i == 0) {
    if (al == 8) {
      if (!bn_wexpand(rr, 16)) {
        goto err;
      }
      rr->width = 16;
      bn_mul_comba8(rr->d, a->d, b->d);
      goto end;
    }
  }

  static const int kMulNormalSize = 16;
  if (al >= kMulNormalSize && bl >= kMulNormalSize) {
    if (i >= -1 && i <= 1) {
      /* Find out the power of two lower or equal
         to the longest of the two numbers */
      if (i >= 0) {
        j = BN_num_bits_word((BN_ULONG)al);
      }
      if (i == -1) {
        j = BN_num_bits_word((BN_ULONG)bl);
      }
      j = 1 << (j - 1);
      assert(j <= al || j <= bl);
      k = j + j;
      t = BN_CTX_get(ctx);
      if (t == NULL) {
        goto err;
      }
      if (al > j || bl > j) {
        if (!bn_wexpand(t, k * 4)) {
          goto err;
        }
        if (!bn_wexpand(rr, k * 4)) {
          goto err;
        }
        bn_mul_part_recursive(rr->d, a->d, b->d, j, al - j, bl - j, t->d);
      } else {
        // al <= j || bl <= j
        if (!bn_wexpand(t, k * 2)) {
          goto err;
        }
        if (!bn_wexpand(rr, k * 2)) {
          goto err;
        }
        bn_mul_recursive(rr->d, a->d, b->d, j, al - j, bl - j, t->d);
      }
      rr->width = top;
      goto end;
    }
  }

  if (!bn_wexpand(rr, top)) {
    goto err;
  }
  rr->width = top;
  bn_mul_normal(rr->d, a->d, al, b->d, bl);

end:
  if (r != rr && !BN_copy(r, rr)) {
    goto err;
  }
  ret = 1;

err:
  BN_CTX_end(ctx);
  return ret;
}

int BN_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx) {
  if (!bn_mul_impl(r, a, b, ctx)) {
    return 0;
  }

  // This additionally fixes any negative zeros created by |bn_mul_impl|.
  bn_set_minimal_width(r);
  return 1;
}

int bn_mul_fixed(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx) {
  // Prevent negative zeros.
  if (a->neg || b->neg) {
    OPENSSL_PUT_ERROR(BN, BN_R_NEGATIVE_NUMBER);
    return 0;
  }

  return bn_mul_impl(r, a, b, ctx);
}

int bn_mul_small(BN_ULONG *r, size_t num_r, const BN_ULONG *a, size_t num_a,
                 const BN_ULONG *b, size_t num_b) {
  if (num_r != num_a + num_b) {
    OPENSSL_PUT_ERROR(BN, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
    return 0;
  }
  // TODO(davidben): Should this call |bn_mul_comba4| too? |BN_mul| does not
  // hit that code.
  if (num_a == 8 && num_b == 8) {
    bn_mul_comba8(r, a, b);
  } else {
    bn_mul_normal(r, a, num_a, b, num_b);
  }
  return 1;
}

// tmp must have 2*n words
static void bn_sqr_normal(BN_ULONG *r, const BN_ULONG *a, size_t n,
                          BN_ULONG *tmp) {
  if (n == 0) {
    return;
  }

  size_t max = n * 2;
  const BN_ULONG *ap = a;
  BN_ULONG *rp = r;
  rp[0] = rp[max - 1] = 0;
  rp++;

  // Compute the contribution of a[i] * a[j] for all i < j.
  if (n > 1) {
    ap++;
    rp[n - 1] = bn_mul_words(rp, ap, n - 1, ap[-1]);
    rp += 2;
  }
  if (n > 2) {
    for (size_t i = n - 2; i > 0; i--) {
      ap++;
      rp[i] = bn_mul_add_words(rp, ap, i, ap[-1]);
      rp += 2;
    }
  }

  // The final result fits in |max| words, so none of the following operations
  // will overflow.

  // Double |r|, giving the contribution of a[i] * a[j] for all i != j.
  bn_add_words(r, r, r, max);

  // Add in the contribution of a[i] * a[i] for all i.
  bn_sqr_words(tmp, a, n);
  bn_add_words(r, r, tmp, max);
}

// bn_sqr_recursive sets |r| to |a|^2, using |t| as scratch space. |r| has
// length 2*|n2|, |a| has length |n2|, and |t| has length 4*|n2|. |n2| must be
// a power of two.
static void bn_sqr_recursive(BN_ULONG *r, const BN_ULONG *a, size_t n2,
                             BN_ULONG *t) {
  // |n2| is a power of two.
  assert(n2 != 0 && (n2 & (n2 - 1)) == 0);

  if (n2 == 4) {
    bn_sqr_comba4(r, a);
    return;
  }
  if (n2 == 8) {
    bn_sqr_comba8(r, a);
    return;
  }
  if (n2 < BN_SQR_RECURSIVE_SIZE_NORMAL) {
    bn_sqr_normal(r, a, n2, t);
    return;
  }

  // Split |a| into a0,a1, each of size |n|.
  // Split |t| into t0,t1,t2,t3, each of size |n|, with the remaining 4*|n| used
  // for recursive calls.
  // Split |r| into r0,r1,r2,r3. We must contribute a0^2 to r0,r1, 2*a0*a1 to
  // r1,r2, and a1^2 to r2,r3.
  size_t n = n2 / 2;
  BN_ULONG *t_recursive = &t[n2 * 2];

  // t0 = |a0 - a1|.
  bn_abs_sub_words(t, a, &a[n], n, &t[n]);
  // t2,t3 = t0^2 = |a0 - a1|^2 = a0^2 - 2*a0*a1 + a1^2
  bn_sqr_recursive(&t[n2], t, n, t_recursive);

  // r0,r1 = a0^2
  bn_sqr_recursive(r, a, n, t_recursive);

  // r2,r3 = a1^2
  bn_sqr_recursive(&r[n2], &a[n], n, t_recursive);

  // t0,t1,c = r0,r1 + r2,r3 = a0^2 + a1^2
  BN_ULONG c = bn_add_words(t, r, &r[n2], n2);
  // t2,t3,c = t0,t1,c - t2,t3 = 2*a0*a1
  c -= bn_sub_words(&t[n2], t, &t[n2], n2);

  // We now have our three components. Add them together.
  // r1,r2,c = r1,r2 + t2,t3,c
  c += bn_add_words(&r[n], &r[n], &t[n2], n2);

  // Propagate the carry bit to the end.
  for (size_t i = n + n2; i < n2 + n2; i++) {
    BN_ULONG old = r[i];
    r[i] = old + c;
    c = r[i] < old;
  }

  // The square should fit without carries.
  assert(c == 0);
}

int BN_mul_word(BIGNUM *bn, BN_ULONG w) {
  if (!bn->width) {
    return 1;
  }

  if (w == 0) {
    BN_zero(bn);
    return 1;
  }

  BN_ULONG ll = bn_mul_words(bn->d, bn->d, bn->width, w);
  if (ll) {
    if (!bn_wexpand(bn, bn->width + 1)) {
      return 0;
    }
    bn->d[bn->width++] = ll;
  }

  return 1;
}

int bn_sqr_fixed(BIGNUM *r, const BIGNUM *a, BN_CTX *ctx) {
  int al = a->width;
  if (al <= 0) {
    r->width = 0;
    r->neg = 0;
    return 1;
  }

  int ret = 0;
  BN_CTX_start(ctx);
  BIGNUM *rr = (a != r) ? r : BN_CTX_get(ctx);
  BIGNUM *tmp = BN_CTX_get(ctx);
  if (!rr || !tmp) {
    goto err;
  }

  int max = 2 * al;  // Non-zero (from above)
  if (!bn_wexpand(rr, max)) {
    goto err;
  }

  if (al == 4) {
    bn_sqr_comba4(rr->d, a->d);
  } else if (al == 8) {
    bn_sqr_comba8(rr->d, a->d);
  } else {
    if (al < BN_SQR_RECURSIVE_SIZE_NORMAL) {
      BN_ULONG t[BN_SQR_RECURSIVE_SIZE_NORMAL * 2];
      bn_sqr_normal(rr->d, a->d, al, t);
    } else {
      // If |al| is a power of two, we can use |bn_sqr_recursive|.
      if (al != 0 && (al & (al - 1)) == 0) {
        if (!bn_wexpand(tmp, al * 4)) {
          goto err;
        }
        bn_sqr_recursive(rr->d, a->d, al, tmp->d);
      } else {
        if (!bn_wexpand(tmp, max)) {
          goto err;
        }
        bn_sqr_normal(rr->d, a->d, al, tmp->d);
      }
    }
  }

  rr->neg = 0;
  rr->width = max;

  if (rr != r && !BN_copy(r, rr)) {
    goto err;
  }
  ret = 1;

err:
  BN_CTX_end(ctx);
  return ret;
}

int BN_sqr(BIGNUM *r, const BIGNUM *a, BN_CTX *ctx) {
  if (!bn_sqr_fixed(r, a, ctx)) {
    return 0;
  }

  bn_set_minimal_width(r);
  return 1;
}

int bn_sqr_small(BN_ULONG *r, size_t num_r, const BN_ULONG *a, size_t num_a) {
  if (num_r != 2 * num_a || num_a > BN_SMALL_MAX_WORDS) {
    OPENSSL_PUT_ERROR(BN, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
    return 0;
  }
  if (num_a == 4) {
    bn_sqr_comba4(r, a);
  } else if (num_a == 8) {
    bn_sqr_comba8(r, a);
  } else {
    BN_ULONG tmp[2 * BN_SMALL_MAX_WORDS];
    bn_sqr_normal(r, a, num_a, tmp);
    OPENSSL_cleanse(tmp, 2 * num_a * sizeof(BN_ULONG));
  }
  return 1;
}
