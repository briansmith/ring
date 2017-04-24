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

#include <limits.h>
#include <string.h>

#include <GFp/err.h>
#include <GFp/mem.h>

#include "internal.h"


/* Avoid -Wmissing-prototypes warnings. */

uint64_t GFp_BN_get_positive_u64(const BIGNUM *bn);


void GFp_BN_init(BIGNUM *bn) {
  memset(bn, 0, sizeof(BIGNUM));
}

void GFp_BN_free(BIGNUM *bn) {
  /* Keep this in sync with the |Drop| impl for |BIGNUM| in
   * |ring::rsa::bigint|. */

  if (bn == NULL) {
    return;
  }

  if ((bn->flags & BN_FLG_STATIC_DATA) == 0) {
    OPENSSL_free(bn->d);
  }

  if (bn->flags & BN_FLG_MALLOCED) {
    OPENSSL_free(bn);
  } else {
    bn->d = NULL;
  }
}

int GFp_BN_copy(BIGNUM *dest, const BIGNUM *src) {
  if (src == dest) {
    return 1;
  }

  if (!GFp_bn_wexpand(dest, src->top)) {
    return 0;
  }

  if (src->top > 0) {
    memcpy(dest->d, src->d, sizeof(src->d[0]) * src->top);
  }

  dest->top = src->top;
  dest->neg = src->neg;
  return 1;
}

/* GFp_BN_num_bits_word returns the minimum number of bits needed to represent
 * the value in |l|. */
unsigned GFp_BN_num_bits_word(BN_ULONG l) {
  static const unsigned char bits[256] = {
      0, 1, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5,
      5, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6,
      6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 7, 7, 7, 7, 7, 7, 7, 7,
      7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
      7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
      7, 7, 7, 7, 7, 7, 7, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
      8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
      8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
      8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
      8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
      8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8};

#if defined(OPENSSL_64_BIT)
  if (l & 0xffffffff00000000L) {
    if (l & 0xffff000000000000L) {
      if (l & 0xff00000000000000L) {
        return (bits[(int)(l >> 56)] + 56);
      } else {
        return (bits[(int)(l >> 48)] + 48);
      }
    } else {
      if (l & 0x0000ff0000000000L) {
        return (bits[(int)(l >> 40)] + 40);
      } else {
        return (bits[(int)(l >> 32)] + 32);
      }
    }
  } else
#endif
  {
    if (l & 0xffff0000L) {
      if (l & 0xff000000L) {
        return (bits[(int)(l >> 24L)] + 24);
      } else {
        return (bits[(int)(l >> 16L)] + 16);
      }
    } else {
      if (l & 0xff00L) {
        return (bits[(int)(l >> 8)] + 8);
      } else {
        return (bits[(int)(l)]);
      }
    }
  }
}

unsigned GFp_BN_num_bits(const BIGNUM *bn) {
  const int max = bn->top - 1;

  if (GFp_BN_is_zero(bn)) {
    return 0;
  }

  return max*BN_BITS2 + GFp_BN_num_bits_word(bn->d[max]);
}

void GFp_BN_zero(BIGNUM *bn) {
  bn->top = bn->neg = 0;
}

/* GFp_BN_get_positive_u64 returns the value of |bn| if the value is in
 * [1, 2**64). Otherwise it returns 0 to indicate an error occurred. */
uint64_t GFp_BN_get_positive_u64(const BIGNUM *bn) {
  if (bn->top > 64 / BN_BITS2) {
    return 0;
  }
  uint64_t r = 0;
  if (bn->top > 0) {
    r = bn->d[0];
  }
#if BN_BITS2 == 32
  if (bn->top > 1) {
    r |= ((uint64_t)bn->d[1]) << BN_BITS2;
  }
#elif BN_BITS2 != 64
#error BN_BITS2 is not 32 or 64.
#endif
  return r;
}

int GFp_BN_set_word(BIGNUM *bn, BN_ULONG value) {
  if (value == 0) {
    GFp_BN_zero(bn);
    return 1;
  }

  if (!GFp_bn_wexpand(bn, 1)) {
    return 0;
  }

  bn->neg = 0;
  bn->d[0] = value;
  bn->top = 1;
  return 1;
}

int GFp_BN_is_negative(const BIGNUM *bn) {
  return bn->neg != 0;
}

int GFp_bn_wexpand(BIGNUM *bn, size_t words) {
  BN_ULONG *a;

  if (words <= (size_t)bn->dmax) {
    return 1;
  }

  if (words > (INT_MAX / (4 * BN_BITS2))) {
    OPENSSL_PUT_ERROR(BN, BN_R_BIGNUM_TOO_LONG);
    return 0;
  }

  if (bn->flags & BN_FLG_STATIC_DATA) {
    OPENSSL_PUT_ERROR(BN, BN_R_EXPAND_ON_STATIC_BIGNUM_DATA);
    return 0;
  }

  a = OPENSSL_malloc(sizeof(BN_ULONG) * words);
  if (a == NULL) {
    OPENSSL_PUT_ERROR(BN, ERR_R_MALLOC_FAILURE);
    return 0;
  }

  memcpy(a, bn->d, sizeof(BN_ULONG) * bn->top);

  OPENSSL_free(bn->d);
  bn->d = a;
  bn->dmax = (int)words;

  return 1;
}

void GFp_bn_correct_top(BIGNUM *bn) {
  BN_ULONG *ftl;
  int tmp_top = bn->top;

  if (tmp_top > 0) {
    for (ftl = &(bn->d[tmp_top - 1]); tmp_top > 0; tmp_top--) {
      if (*(ftl--)) {
        break;
      }
    }
    bn->top = tmp_top;
  }

  if (bn->top == 0) {
    bn->neg = 0;
  }
}
