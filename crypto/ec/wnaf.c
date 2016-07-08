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

#include <openssl/ec.h>

#include <string.h>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/mem.h>

#include "internal.h"
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


/* TODO: table should be optimised for the wNAF-based implementation,
 *       sometimes smaller windows will give better performance
 *       (thus the boundaries should be increased)
 */
#define EC_window_bits_for_scalar_size(b)                                      \
  ((size_t)((b) >= 2000 ? 6 : (b) >= 800 ? 5 : (b) >= 300                      \
                                                   ? 4                         \
                                                   : (b) >= 70 ? 3 : (b) >= 20 \
                                                                         ? 2   \
                                                                         : 1))

static signed char *compute_wNAF(const BIGNUM *scalar, int w, size_t *ret_len) {
  if (BN_is_negative(scalar)) {
    OPENSSL_PUT_ERROR(EC, ERR_R_INTERNAL_ERROR);
    return NULL;

  }
  if (w <= 0 || w > 7) /* 'signed char' can represent integers with absolute
                       values less than 2^7 */
  {
    OPENSSL_PUT_ERROR(EC, ERR_R_INTERNAL_ERROR);
    return NULL;
  }

  unsigned len = BN_num_bits(scalar);
  signed char *r = OPENSSL_malloc(len + 1);
  if (r == NULL) {
    OPENSSL_PUT_ERROR(EC, ERR_R_MALLOC_FAILURE);
    return NULL;
  }
  *ret_len = GFp_suite_b_wnaf(r, scalar->d, (size_t)scalar->top, w);
  return r;
}

static EC_POINT *make_point(const EC_GROUP *group, const BN_ULONG p_x[],
                            const BN_ULONG p_y[]) {
  EC_POINT *result = EC_POINT_new(group);
  if (result == NULL) {
    return NULL;
  }

  int ok = 0;

  size_t num_limbs =
    (ec_GFp_simple_group_get_degree(group) + (BN_BITS2 - 1)) / BN_BITS2;

  if (!bn_set_words(&result->X, p_x, num_limbs) ||
      !bn_set_words(&result->Y, p_y, num_limbs) ||
      !BN_copy(&result->Z, &group->one)) {
    goto err;
  }

  ok = 1;

err:
  if (!ok) {
    EC_POINT_free(result);
    result = NULL;
  }
  return result;
}


int ec_wNAF_mul(const EC_GROUP *group, BN_ULONG r_xyz[],
                const BN_ULONG g_scalar_[], const BN_ULONG p_scalar_[],
                const BN_ULONG p_x[], const BN_ULONG p_y[]) {
  assert((p_scalar_ == NULL) == (p_x == NULL));
  assert((p_scalar_ == NULL) == (p_y == NULL));

  BN_CTX *ctx = NULL;
  const EC_POINT *generator = NULL;
  EC_POINT *tmp = NULL;
  size_t total_num;
  size_t i, j;
  int k;
  int r_is_inverted = 0;
  int r_is_at_infinity = 1;
  size_t *wsize = NULL;      /* individual window sizes */
  signed char **wNAF = NULL; /* individual wNAFs */
  size_t *wNAF_len = NULL;
  size_t max_len = 0;
  size_t num_val;
  EC_POINT **val = NULL; /* precomputation */
  EC_POINT **v;
  EC_POINT ***val_sub = NULL; /* pointers to sub-arrays of 'val' */
  int ret = 0;

  EC_POINT *r = NULL;
  BIGNUM *g_scalar = NULL;
  EC_POINT *p_new = NULL;
  const BIGNUM *p_scalar = NULL;
  const EC_POINT *p = NULL;

  ctx = BN_CTX_new();
  if (ctx == NULL) {
    return 0;
  }

  r = EC_POINT_new(group);
  if (r == NULL) {
    goto err;
  }

  size_t num_limbs =
    (ec_GFp_simple_group_get_degree(group) + (BN_BITS2 - 1)) / BN_BITS2;

  if (g_scalar_ != NULL) {
    g_scalar = BN_CTX_get(ctx);
    if (g_scalar == NULL ||
        !bn_set_words(g_scalar, g_scalar_, num_limbs)) {
      goto err;
    }
  }

  if (p_scalar_ != NULL) {
    BIGNUM *p_scalar_new = BN_CTX_get(ctx);
    if (p_scalar_new == NULL ||
        !bn_set_words(p_scalar_new, p_scalar_, num_limbs)) {
      goto err;
    }
    p_scalar = p_scalar_new;
    p_new = make_point(group, p_x, p_y);
    if (p_new == NULL) {
      goto err;
    }
    p = p_new;
  }

  /* TODO: This function used to take |points| and |scalars| as arrays of
   * |num| elements. The code below should be simplified to work in terms of |p|
   * and |p_scalar|. */
  size_t num = p != NULL ? 1 : 0;
  const EC_POINT **points = p != NULL ? &p : NULL;
  const BIGNUM **scalars = p != NULL ? &p_scalar : NULL;

  total_num = num;

  if (g_scalar != NULL) {
    generator = EC_GROUP_get0_generator(group);
    if (generator == NULL) {
      OPENSSL_PUT_ERROR(EC, EC_R_UNDEFINED_GENERATOR);
      goto err;
    }

    ++total_num; /* treat 'g_scalar' like 'num'-th element of 'scalars' */
  }


  wsize = OPENSSL_malloc(total_num * sizeof wsize[0]);
  wNAF_len = OPENSSL_malloc(total_num * sizeof wNAF_len[0]);
  wNAF = OPENSSL_malloc((total_num + 1) *
                        sizeof wNAF[0]); /* includes space for pivot */
  val_sub = OPENSSL_malloc(total_num * sizeof val_sub[0]);

  /* Ensure wNAF is initialised in case we end up going to err. */
  if (wNAF) {
    wNAF[0] = NULL; /* preliminary pivot */
  }

  if (!wsize || !wNAF_len || !wNAF || !val_sub) {
    OPENSSL_PUT_ERROR(EC, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  /* num_val will be the total number of temporarily precomputed points */
  num_val = 0;

  for (i = 0; i < total_num; i++) {
    size_t bits;

    bits = i < num ? BN_num_bits(scalars[i]) : BN_num_bits(g_scalar);
    wsize[i] = EC_window_bits_for_scalar_size(bits);
    num_val += (size_t)1 << (wsize[i] - 1);
    wNAF[i + 1] = NULL; /* make sure we always have a pivot */
    wNAF[i] =
        compute_wNAF((i < num ? scalars[i] : g_scalar), wsize[i], &wNAF_len[i]);
    if (wNAF[i] == NULL) {
      goto err;
    }
    if (wNAF_len[i] > max_len) {
      max_len = wNAF_len[i];
    }
  }

  /* All points we precompute now go into a single array 'val'. 'val_sub[i]' is
   * a pointer to the subarray for the i-th point. */
  val = OPENSSL_malloc((num_val + 1) * sizeof val[0]);
  if (val == NULL) {
    OPENSSL_PUT_ERROR(EC, ERR_R_MALLOC_FAILURE);
    goto err;
  }
  val[num_val] = NULL; /* pivot element */

  /* allocate points for precomputation */
  v = val;
  for (i = 0; i < total_num; i++) {
    val_sub[i] = v;
    for (j = 0; j < ((size_t)1 << (wsize[i] - 1)); j++) {
      *v = EC_POINT_new(group);
      if (*v == NULL) {
        goto err;
      }
      v++;
    }
  }
  if (!(v == val + num_val)) {
    OPENSSL_PUT_ERROR(EC, ERR_R_INTERNAL_ERROR);
    goto err;
  }

  if (!(tmp = EC_POINT_new(group))) {
    goto err;
  }

  /* prepare precomputed values:
   *    val_sub[i][0] :=     points[i]
   *    val_sub[i][1] := 3 * points[i]
   *    val_sub[i][2] := 5 * points[i]
   *    ...
   */
  for (i = 0; i < total_num; i++) {
    if (i < num) {
      if (!ec_GFp_simple_point_copy(val_sub[i][0], points[i])) {
        goto err;
      }
    } else if (!ec_GFp_simple_point_copy(val_sub[i][0], generator)) {
      goto err;
    }

    if (wsize[i] > 1) {
      if (!ec_GFp_simple_dbl(group, tmp, val_sub[i][0], ctx)) {
        goto err;
      }
      for (j = 1; j < ((size_t)1 << (wsize[i] - 1)); j++) {
        if (!ec_GFp_simple_add(group, val_sub[i][j], val_sub[i][j - 1], tmp,
                               ctx)) {
          goto err;
        }
      }
    }
  }

  r_is_at_infinity = 1;

  for (k = max_len - 1; k >= 0; k--) {
    if (!r_is_at_infinity && !ec_GFp_simple_dbl(group, r, r, ctx)) {
      goto err;
    }

    for (i = 0; i < total_num; i++) {
      if (wNAF_len[i] > (size_t)k) {
        int digit = wNAF[i][k];
        int is_neg;

        if (digit) {
          is_neg = digit < 0;

          if (is_neg) {
            digit = -digit;
          }

          if (is_neg != r_is_inverted) {
            if (!r_is_at_infinity && !ec_GFp_simple_invert(group, r)) {
              goto err;
            }
            r_is_inverted = !r_is_inverted;
          }

          /* digit > 0 */

          if (r_is_at_infinity) {
            if (!ec_GFp_simple_point_copy(r, val_sub[i][digit >> 1])) {
              goto err;
            }
            r_is_at_infinity = 0;
          } else {
            if (!ec_GFp_simple_add(group, r, r, val_sub[i][digit >> 1], ctx)) {
              goto err;
            }
          }
        }
      }
    }
  }

  if (r_is_at_infinity) {
    if (!EC_POINT_set_to_infinity(group, r)) {
      goto err;
    }
  } else if (r_is_inverted && !ec_GFp_simple_invert(group, r)) {
    goto err;
  }

  BN_ULONG *x_out = r_xyz;
  BN_ULONG *y_out = x_out + num_limbs;
  BN_ULONG *z_out = y_out + num_limbs;
  if (!bn_get_words(x_out, &r->X, num_limbs) ||
      !bn_get_words(y_out, &r->Y, num_limbs) ||
      !bn_get_words(z_out, &r->Z, num_limbs)) {
    goto err;
  }

  ret = 1;

err:
  EC_POINT_free(r);
  EC_POINT_free(p_new);
  BN_CTX_free(ctx);
  EC_POINT_free(tmp);
  OPENSSL_free(wsize);
  OPENSSL_free(wNAF_len);
  if (wNAF != NULL) {
    signed char **w;

    for (w = wNAF; *w != NULL; w++) {
      OPENSSL_free(*w);
    }

    OPENSSL_free(wNAF);
  }
  if (val != NULL) {
    for (v = val; *v != NULL; v++) {
      ec_GFp_simple_point_finish(*v);
      OPENSSL_free(*v);
    }

    OPENSSL_free(val);
  }
  OPENSSL_free(val_sub);
  return ret;
}
