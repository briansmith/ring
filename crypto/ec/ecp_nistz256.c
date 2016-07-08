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

#include "ecp_nistz.h"
#include "ecp_nistz256.h"
#include "../bn/internal.h"
#include "../ec/internal.h"
#include "../internal.h"


typedef P256_POINT_AFFINE PRECOMP256_ROW[64];


/* Prototypes to avoid -Wmissing-prototypes warnings. */
void ecp_nistz256_point_mul_base(P256_POINT *r,
                                 const BN_ULONG g_scalar[P256_LIMBS]);
void ecp_nistz256_point_mul(P256_POINT *r, const BN_ULONG p_scalar[P256_LIMBS],
                            const BN_ULONG p_x[P256_LIMBS],
                            const BN_ULONG p_y[P256_LIMBS]);


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

static void copy_conditional(BN_ULONG dst[P256_LIMBS],
                             const BN_ULONG src[P256_LIMBS], BN_ULONG move) {
  BN_ULONG mask1 = move;
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


/* r = p * p_scalar */
void ecp_nistz256_point_mul(P256_POINT *r, const BN_ULONG p_scalar[P256_LIMBS],
                            const BN_ULONG p_x[P256_LIMBS],
                            const BN_ULONG p_y[P256_LIMBS]) {
  static const unsigned kWindowSize = 5;
  static const unsigned kMask = (1 << (5 /* kWindowSize */ + 1)) - 1;

  uint8_t p_str[(P256_LIMBS * BN_BYTES) + 1];
  gfp_little_endian_bytes_from_scalar(p_str, sizeof(p_str) / sizeof(p_str[0]),
                                      p_scalar, P256_LIMBS);

  /* A |P256_POINT| is (3 * 32) = 96 bytes, and the 64-byte alignment should
   * add no more than 63 bytes of overhead. Thus, |table| should require
   * ~1599 ((96 * 16) + 63) bytes of stack space. */
  alignas(64) P256_POINT table[16];

  /* table[0] is implicitly (0,0,0) (the point at infinity), therefore it is
   * not stored. All other values are actually stored with an offset of -1 in
   * table. */
  P256_POINT *row = table;

  memcpy(row[1 - 1].X, p_x, P256_LIMBS * BN_BYTES);
  memcpy(row[1 - 1].Y, p_y, P256_LIMBS * BN_BYTES);
  memcpy(row[1 - 1].Z, ONE, P256_LIMBS * BN_BYTES);

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

  unsigned raw_wvalue;
  BN_ULONG recoded_is_negative;
  unsigned recoded;

  raw_wvalue = p_str[(index - 1) / 8];
  raw_wvalue = (raw_wvalue >> ((index - 1) % 8)) & kMask;

  booth_recode(&recoded_is_negative, &recoded, raw_wvalue, kWindowSize);
  assert(!recoded_is_negative);
  ecp_nistz256_select_w5(r, table, recoded);

  while (index >= kWindowSize) {
    if (index != 255) {
      unsigned off = (index - 1) / 8;

      raw_wvalue = p_str[off] | p_str[off + 1] << 8;
      raw_wvalue = (raw_wvalue >> ((index - 1) % 8)) & kMask;
      booth_recode(&recoded_is_negative, &recoded, raw_wvalue, kWindowSize);

      ecp_nistz256_select_w5(&h, table, recoded);
      ecp_nistz256_neg(tmp, h.Y);
      copy_conditional(h.Y, tmp, recoded_is_negative);

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
  raw_wvalue = p_str[0];
  raw_wvalue = (raw_wvalue << 1) & kMask;

  booth_recode(&recoded_is_negative, &recoded, raw_wvalue, kWindowSize);
  ecp_nistz256_select_w5(&h, table, recoded);
  ecp_nistz256_neg(tmp, h.Y);
  copy_conditional(h.Y, tmp, recoded_is_negative);
  ecp_nistz256_point_add(r, r, &h);
}

void ecp_nistz256_point_mul_base(P256_POINT *r,
                                 const BN_ULONG g_scalar[P256_LIMBS]) {
#if !defined(NDEBUG)
  int is_g_scalar_zero = 1;
  for (size_t i = 0; i < P256_LIMBS; ++i) {
    if (g_scalar[i] != 0) {
      is_g_scalar_zero = 0;
      break;
    }
  }
  assert(!is_g_scalar_zero);
#endif

  static const unsigned kWindowSize = 7;
  static const unsigned kMask = (1 << (7 /* kWindowSize */ + 1)) - 1;

  uint8_t p_str[(P256_LIMBS * BN_BYTES) + 1];
  gfp_little_endian_bytes_from_scalar(p_str, sizeof(p_str) / sizeof(p_str[0]),
                                      g_scalar, P256_LIMBS);

  typedef union {
    P256_POINT p;
    P256_POINT_AFFINE a;
  } P256_POINT_UNION;

  alignas(32) P256_POINT_UNION p;
  alignas(32) P256_POINT_UNION t;

  /* First window */
  unsigned index = kWindowSize;

  unsigned raw_wvalue;
  BN_ULONG recoded_is_negative;
  unsigned recoded;

  raw_wvalue = (p_str[0] << 1) & kMask;

  booth_recode(&recoded_is_negative, &recoded, raw_wvalue, kWindowSize);
  const PRECOMP256_ROW *const precomputed_table =
      (const PRECOMP256_ROW *)ecp_nistz256_precomputed;
  ecp_nistz256_select_w7(&p.a, precomputed_table[0], recoded);
  ecp_nistz256_neg(p.p.Z, p.p.Y);
  copy_conditional(p.p.Y, p.p.Z, recoded_is_negative);

  memcpy(p.p.Z, ONE, sizeof(ONE));

  for (size_t i = 1; i < 37; i++) {
    unsigned off = (index - 1) / 8;
    raw_wvalue = p_str[off] | p_str[off + 1] << 8;
    raw_wvalue = (raw_wvalue >> ((index - 1) % 8)) & kMask;
    index += kWindowSize;

    booth_recode(&recoded_is_negative, &recoded, raw_wvalue, kWindowSize);
    ecp_nistz256_select_w7(&t.a, precomputed_table[i], recoded);
    ecp_nistz256_neg(t.p.Z, t.a.Y);
    copy_conditional(t.a.Y, t.p.Z, recoded_is_negative);
    ecp_nistz256_point_add_affine(&p.p, &p.p, &t.a);
  }

  memcpy(r, &p.p, sizeof(p.p));
}

/* MSVC warns us that it's dangerous to rely on the precondition that one or
 * both of |g_scalar| or |p_scalar} must be non-NULL. But, we rely on it
 * anyway. */
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable:4701)
#endif

static int ecp_nistz256_points_mul(const EC_GROUP *group, BN_ULONG r_xyz[],
                                   const BN_ULONG g_scalar[P256_LIMBS],
                                   const BN_ULONG p_scalar[P256_LIMBS],
                                   const BN_ULONG p_x[P256_LIMBS],
                                   const BN_ULONG p_y[P256_LIMBS]) {
  (void)group;

  assert((g_scalar != NULL) || (p_scalar != NULL));
  assert((p_scalar != NULL) == (p_x != NULL));
  assert((p_scalar != NULL) == (p_y != NULL));

  alignas(32) P256_POINT p;
  alignas(32) P256_POINT t;

  if (g_scalar != NULL) {
    ecp_nistz256_point_mul_base(&p, g_scalar);
  }

  const int p_is_infinity = g_scalar == NULL;
  if (p_scalar != NULL) {
    P256_POINT *out = &t;
    if (p_is_infinity) {
      out = &p;
    }

    ecp_nistz256_point_mul(out, p_scalar, p_x, p_y);

    if (!p_is_infinity) {
      ecp_nistz256_point_add(&p, &p, out);
    }
  }

  memcpy(r_xyz, &p, sizeof(p));

  return 1;
}

#if defined(_MSC_VER)
#pragma warning(pop)
#endif


const EC_METHOD EC_GFp_nistz256_method = {
  ecp_nistz256_points_mul,
  ec_GFp_mont_field_mul,
  ec_GFp_mont_field_sqr,
};
