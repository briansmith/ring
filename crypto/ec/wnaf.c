/* Originally written by Bodo Moeller for the OpenSSL project.
 * ====================================================================
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
 * Hudson (tjh@cryptsoft.com).
 *
 */
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 *
 * Portions of the attached software ("Contribution") are developed by
 * SUN MICROSYSTEMS, INC., and are contributed to the OpenSSL project.
 *
 * The Contribution is licensed pursuant to the OpenSSL open source
 * license provided above.
 *
 * The elliptic curve binary polynomial software is originally written by
 * Sheueling Chang Shantz and Douglas Stebila of Sun Microsystems
 * Laboratories. */

#include <openssl/bn.h>

#include "../internal.h"
#include "../bn/internal.h"

/* This file implements the wNAF-based interleaving multi-exponentation method
 * (<URL:http://www.informatik.tu-darmstadt.de/TI/Mitarbeiter/moeller.html#multiexp>);
 * */


/* Prototypes to avoid -Wmissing-prototypes warnings. */
size_t GFp_suite_b_wnaf(int8_t *r, const BN_ULONG *scalar, size_t scalar_limbs,
                        int w);


static int is_bit_set(const BN_ULONG *scalar, size_t bit) {
  BN_ULONG limb = scalar[bit / BN_BITS2];
  size_t bit_within_limb = bit % BN_BITS2;
  int ret = (limb >> bit_within_limb) & 1;
  return ret;
}

/* Determine the modified width-(w+1) Non-Adjacent Form (wNAF) of 'scalar'.
 * This is an array  r[]  of values that are either zero or odd with an
 * absolute value less than  2^w  satisfying
 *     scalar = \sum_j r[j]*2^j
 * where at most one of any  w+1  consecutive digits is non-zero
 * with the exception that the most significant digit may be only
 * w-1 zeros away from that next non-zero digit.
 */
size_t GFp_suite_b_wnaf(int8_t *r, const BN_ULONG scalar[],
                        size_t scalar_limbs, int w) {
  /* 'int8_t' can represent integers with absolute values less than 2^7 */
  assert(1 <= w);
  assert(w <= 7);

  int window_val;
  int bit, next_bit, mask;
  size_t j;

  size_t len = scalar_limbs * BN_BITS2;
  for (;;) {
    if (len == 0) {
      r[0] = 0;
      return 1;
    }
    if (is_bit_set(scalar, len - 1)) {
      break;
    }
    --len;
  }

  bit = 1 << w;        /* at most 128 */
  next_bit = bit << 1; /* at most 256 */
  mask = next_bit - 1; /* at most 255 */

  window_val = scalar[0] & mask;
  j = 0;
  while ((window_val != 0) ||
         (j + w + 1 < len)) /* if j+w+1 >= len, window_val will not increase */
  {
    int digit = 0;

    /* 0 <= window_val <= 2^(w+1) */

    if (window_val & 1) {
      /* 0 < window_val < 2^(w+1) */

      if (window_val & bit) {
        digit = window_val - next_bit; /* -2^w < digit < 0 */

#if 1 /* modified wNAF */
        if (j + w + 1 >= len) {
          /* special case for generating modified wNAFs:
           * no new bits will be added into window_val,
           * so using a positive digit here will decrease
           * the total length of the representation */

          digit = window_val & (mask >> 1); /* 0 < digit < 2^w */
        }
#endif
      } else {
        digit = window_val; /* 0 < digit < 2^w */
      }

      assert(!(digit <= -bit || digit >= bit || !(digit & 1)));

      window_val -= digit;

      /* now window_val is 0 or 2^(w+1) in standard wNAF generation;
       * for modified window NAFs, it may also be 2^w
       */
      assert(!(window_val != 0 && window_val != next_bit && window_val != bit));
    }

    r[j++] = digit;

    window_val >>= 1;
    if (j + w < len && is_bit_set(scalar, j + w)) {
      window_val += bit;
    }

    assert(!(window_val > next_bit));
  }

  assert(!(j > len + 1));
  return j;
}
