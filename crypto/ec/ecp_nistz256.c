/* Copyright (c) 2014, Intel Corporation.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

/* Developers and authors:
 * Shay Gueron (1, 2), and Vlad Krasnov (1)
 * (1) Intel Corporation, Israel Development Center
 * (2) University of Haifa
 * Reference:
 *   Shay Gueron and Vlad Krasnov
 *   "Fast Prime Field Elliptic Curve Cryptography with 256 Bit Primes"
 *   http://eprint.iacr.org/2013/816 */

#include <openssl/ec.h>

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/err.h>

#include "ecp_nistz256.h"
#include "../bn/internal.h"
#include "../ec/internal.h"
#include "../internal.h"


typedef P256_POINT_AFFINE PRECOMP256_ROW[64];

/* Functions implemented in assembly */

/* Modular neg: res = -a mod P */
void ecp_nistz256_neg(BN_ULONG res[P256_LIMBS], const BN_ULONG a[P256_LIMBS]);

/* One converted into the Montgomery domain */
static const BN_ULONG ONE[P256_LIMBS] = {
    TOBN(0x00000000, 0x00000001), TOBN(0xffffffff, 0x00000000),
    TOBN(0xffffffff, 0xffffffff), TOBN(0x00000000, 0xfffffffe),
};

/* Precomputed tables for the default generator */
#include "ecp_nistz256_table.inl"

/* Recode window to a signed digit. See util-64.c for details. */
static unsigned booth_recode_w5(unsigned in) {
  unsigned s, d;

  s = ~((in >> 5) - 1);
  d = (1 << 6) - in - 1;
  d = (d & s) | (in & ~s);
  d = (d >> 1) + (d & 1);

  return (d << 1) + (s & 1);
}

static unsigned booth_recode_w7(unsigned in) {
  unsigned s, d;

  s = ~((in >> 7) - 1);
  d = (1 << 8) - in - 1;
  d = (d & s) | (in & ~s);
  d = (d >> 1) + (d & 1);

  return (d << 1) + (s & 1);
}

static void copy_conditional(BN_ULONG dst[P256_LIMBS],
                             const BN_ULONG src[P256_LIMBS], BN_ULONG move) {
  BN_ULONG mask1 = ((BN_ULONG)0) - move;
  BN_ULONG mask2 = ~mask1;

  dst[0] = (src[0] & mask1) ^ (dst[0] & mask2);
  dst[1] = (src[1] & mask1) ^ (dst[1] & mask2);
  dst[2] = (src[2] & mask1) ^ (dst[2] & mask2);
  dst[3] = (src[3] & mask1) ^ (dst[3] & mask2);
  if (P256_LIMBS == 8) {
    dst[4] = (src[4] & mask1) ^ (dst[4] & mask2);
    dst[5] = (src[5] & mask1) ^ (dst[5] & mask2);
    dst[6] = (src[6] & mask1) ^ (dst[6] & mask2);
    dst[7] = (src[7] & mask1) ^ (dst[7] & mask2);
  }
}

void ecp_nistz256_point_double(P256_POINT *r, const P256_POINT *a);
void ecp_nistz256_point_add(P256_POINT *r, const P256_POINT *a,
                            const P256_POINT *b);
void ecp_nistz256_point_add_affine(P256_POINT *r, const P256_POINT *a,
                                   const P256_POINT_AFFINE *b);


/* ecp_nistz256_bignum_to_field_elem copies the contents of |in| to |out| and
 * returns one if it fits. Otherwise it returns zero. */
static int ecp_nistz256_bignum_to_field_elem(BN_ULONG out[P256_LIMBS],
                                             const BIGNUM *in) {
  if ((size_t)in->top > P256_LIMBS) {
    return 0;
  }

  memset(out, 0, sizeof(BN_ULONG) * P256_LIMBS);
  memcpy(out, in->d, sizeof(BN_ULONG) * in->top);
  return 1;
}

/* r = p * p_scalar */
static int ecp_nistz256_windowed_mul(P256_POINT *r, const EC_POINT *p,
                                     const BIGNUM *p_scalar) {
  assert(p != NULL);
  assert(p_scalar != NULL);

  static const unsigned kWindowSize = 5;
  static const unsigned kMask = (1 << (5 /* kWindowSize */ + 1)) - 1;

  /* A |P256_POINT| is (3 * 32) = 96 bytes, and the 64-byte alignment should
   * add no more than 63 bytes of overhead. Thus, |table| should require
   * ~1599 ((96 * 16) + 63) bytes of stack space. */
  alignas(64) P256_POINT table[16];
  uint8_t p_str[33];

  int j;
  for (j = 0; j < p_scalar->top * BN_BYTES; j += BN_BYTES) {
    BN_ULONG d = p_scalar->d[j / BN_BYTES];

    p_str[j + 0] = d & 0xff;
    p_str[j + 1] = (d >> 8) & 0xff;
    p_str[j + 2] = (d >> 16) & 0xff;
    p_str[j + 3] = (d >>= 24) & 0xff;
    if (BN_BYTES == 8) {
      d >>= 8;
      p_str[j + 4] = d & 0xff;
      p_str[j + 5] = (d >> 8) & 0xff;
      p_str[j + 6] = (d >> 16) & 0xff;
      p_str[j + 7] = (d >> 24) & 0xff;
    }
  }

  for (; j < 33; j++) {
    p_str[j] = 0;
  }

  /* table[0] is implicitly (0,0,0) (the point at infinity), therefore it is
   * not stored. All other values are actually stored with an offset of -1 in
   * table. */
  P256_POINT *row = table;

  if (!ecp_nistz256_bignum_to_field_elem(row[1 - 1].X, &p->X) ||
      !ecp_nistz256_bignum_to_field_elem(row[1 - 1].Y, &p->Y) ||
      !ecp_nistz256_bignum_to_field_elem(row[1 - 1].Z, &p->Z)) {
    OPENSSL_PUT_ERROR(EC, EC_R_COORDINATES_OUT_OF_RANGE);
    return 0;
  }

  ecp_nistz256_point_double(&row[2 - 1], &row[1 - 1]);
  ecp_nistz256_point_add(&row[3 - 1], &row[2 - 1], &row[1 - 1]);
  ecp_nistz256_point_double(&row[4 - 1], &row[2 - 1]);
  ecp_nistz256_point_double(&row[6 - 1], &row[3 - 1]);
  ecp_nistz256_point_double(&row[8 - 1], &row[4 - 1]);
  ecp_nistz256_point_double(&row[12 - 1], &row[6 - 1]);
  ecp_nistz256_point_add(&row[5 - 1], &row[4 - 1], &row[1 - 1]);
  ecp_nistz256_point_add(&row[7 - 1], &row[6 - 1], &row[1 - 1]);
  ecp_nistz256_point_add(&row[9 - 1], &row[8 - 1], &row[1 - 1]);
  ecp_nistz256_point_add(&row[13 - 1], &row[12 - 1], &row[1 - 1]);
  ecp_nistz256_point_double(&row[14 - 1], &row[7 - 1]);
  ecp_nistz256_point_double(&row[10 - 1], &row[5 - 1]);
  ecp_nistz256_point_add(&row[15 - 1], &row[14 - 1], &row[1 - 1]);
  ecp_nistz256_point_add(&row[11 - 1], &row[10 - 1], &row[1 - 1]);
  ecp_nistz256_point_add(&row[16 - 1], &row[15 - 1], &row[1 - 1]);

  BN_ULONG tmp[P256_LIMBS];
  alignas(32) P256_POINT h;
  unsigned index = 255;
  unsigned wvalue = p_str[(index - 1) / 8];
  wvalue = (wvalue >> ((index - 1) % 8)) & kMask;

  ecp_nistz256_select_w5(r, table, booth_recode_w5(wvalue) >> 1);

  while (index >= 5) {
    if (index != 255) {
      unsigned off = (index - 1) / 8;

      wvalue = p_str[off] | p_str[off + 1] << 8;
      wvalue = (wvalue >> ((index - 1) % 8)) & kMask;

      wvalue = booth_recode_w5(wvalue);

      ecp_nistz256_select_w5(&h, table, wvalue >> 1);

      ecp_nistz256_neg(tmp, h.Y);
      copy_conditional(h.Y, tmp, (wvalue & 1));

      ecp_nistz256_point_add(r, r, &h);
    }

    index -= kWindowSize;

    ecp_nistz256_point_double(r, r);
    ecp_nistz256_point_double(r, r);
    ecp_nistz256_point_double(r, r);
    ecp_nistz256_point_double(r, r);
    ecp_nistz256_point_double(r, r);
  }

  /* Final window */
  wvalue = p_str[0];
  wvalue = (wvalue << 1) & kMask;

  wvalue = booth_recode_w5(wvalue);

  ecp_nistz256_select_w5(&h, table, wvalue >> 1);

  ecp_nistz256_neg(tmp, h.Y);
  copy_conditional(h.Y, tmp, wvalue & 1);

  ecp_nistz256_point_add(r, r, &h);

  return 1;
}

static int ecp_nistz256_points_mul(
    const EC_GROUP *group, EC_POINT *r, const BIGNUM *g_scalar,
    const EC_POINT *p_, const BIGNUM *p_scalar, BN_CTX *ctx) {
  (void)ctx;

  assert((p_ != NULL) == (p_scalar != NULL));
  assert(p_scalar == NULL || BN_cmp(p_scalar, EC_GROUP_get0_order(group)) < 0);

  static const unsigned kWindowSize = 7;
  static const unsigned kMask = (1 << (7 /* kWindowSize */ + 1)) - 1;

  alignas(32) union {
    P256_POINT p;
    P256_POINT_AFFINE a;
  } t, p;


  if (g_scalar != NULL) {
#if defined(NDEBUG)
    (void)group;
#endif
    assert(BN_cmp(g_scalar, EC_GROUP_get0_order(group)) < 0);
    uint8_t p_str[33] = {0};
    int i;
    for (i = 0; i < g_scalar->top * BN_BYTES; i += BN_BYTES) {
      BN_ULONG d = g_scalar->d[i / BN_BYTES];

      p_str[i + 0] = d & 0xff;
      p_str[i + 1] = (d >> 8) & 0xff;
      p_str[i + 2] = (d >> 16) & 0xff;
      p_str[i + 3] = (d >>= 24) & 0xff;
      if (BN_BYTES == 8) {
        d >>= 8;
        p_str[i + 4] = d & 0xff;
        p_str[i + 5] = (d >> 8) & 0xff;
        p_str[i + 6] = (d >> 16) & 0xff;
        p_str[i + 7] = (d >> 24) & 0xff;
      }
    }

    for (; i < (int) sizeof(p_str); i++) {
      p_str[i] = 0;
    }

    /* First window */
    unsigned wvalue = (p_str[0] << 1) & kMask;
    unsigned index = kWindowSize;

    wvalue = booth_recode_w7(wvalue);

    const PRECOMP256_ROW *const precomputed_table =
        (const PRECOMP256_ROW *)ecp_nistz256_precomputed;
    ecp_nistz256_select_w7(&p.a, precomputed_table[0], wvalue >> 1);

    ecp_nistz256_neg(p.p.Z, p.p.Y);
    copy_conditional(p.p.Y, p.p.Z, wvalue & 1);

    memcpy(p.p.Z, ONE, sizeof(ONE));

    for (i = 1; i < 37; i++) {
      unsigned off = (index - 1) / 8;
      wvalue = p_str[off] | p_str[off + 1] << 8;
      wvalue = (wvalue >> ((index - 1) % 8)) & kMask;
      index += kWindowSize;

      wvalue = booth_recode_w7(wvalue);

      ecp_nistz256_select_w7(&t.a, precomputed_table[i], wvalue >> 1);

      ecp_nistz256_neg(t.p.Z, t.a.Y);
      copy_conditional(t.a.Y, t.p.Z, wvalue & 1);

      ecp_nistz256_point_add_affine(&p.p, &p.p, &t.a);
    }
  }

  const int p_is_infinity = g_scalar == NULL;
  if (p_scalar != NULL) {
    P256_POINT *out = &t.p;
    if (p_is_infinity) {
      out = &p.p;
    }

    if (!ecp_nistz256_windowed_mul(out, p_, p_scalar)) {
      return 0;
    }

    if (!p_is_infinity) {
      ecp_nistz256_point_add(&p.p, &p.p, out);
    }
  }

  /* Not constant-time, but we're only operating on the public output. */
  if (!bn_set_words(&r->X, p.p.X, P256_LIMBS) ||
      !bn_set_words(&r->Y, p.p.Y, P256_LIMBS) ||
      !bn_set_words(&r->Z, p.p.Z, P256_LIMBS)) {
    return 0;
  }

  return 1;
}

const EC_METHOD EC_GFp_nistz256_method = {
  ecp_nistz256_points_mul,
  ec_GFp_mont_field_mul,
  ec_GFp_mont_field_sqr,
};
