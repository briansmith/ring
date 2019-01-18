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

#include "ecp_nistz256.h"

#include <string.h>

#include "ecp_nistz.h"
#include "../bn/internal.h"
#include "../../limbs/limbs.inl"

#if defined(__GNUC__)
#pragma GCC diagnostic ignored "-Wsign-conversion"
#endif

typedef P256_POINT_AFFINE PRECOMP256_ROW[64];


/* Prototypes to avoid -Wmissing-prototypes warnings. */
void GFp_nistz256_point_mul_base(P256_POINT *r,
                                 const Limb g_scalar[P256_LIMBS]);
void GFp_nistz256_point_mul(P256_POINT *r, const Limb p_scalar[P256_LIMBS],
                            const Limb p_x[P256_LIMBS],
                            const Limb p_y[P256_LIMBS]);


/* Functions implemented in assembly */
/* Modular neg: res = -a mod P */
void GFp_nistz256_neg(Limb res[P256_LIMBS], const Limb a[P256_LIMBS]);


/* One converted into the Montgomery domain */
static const Limb ONE[P256_LIMBS] = {
    TOBN(0x00000000, 0x00000001), TOBN(0xffffffff, 0x00000000),
    TOBN(0xffffffff, 0xffffffff), TOBN(0x00000000, 0xfffffffe),
};

/* Precomputed tables for the default generator */
#include "ecp_nistz256_table.inl"

/* This assumes that |x| and |y| have been each been reduced to their minimal
 * unique representations. */
static Limb is_infinity(const Limb x[P256_LIMBS],
                            const Limb y[P256_LIMBS]) {
  Limb acc = 0;
  for (size_t i = 0; i < P256_LIMBS; ++i) {
    acc |= x[i] | y[i];
  }
  return constant_time_is_zero_w(acc);
}

static void copy_conditional(Limb dst[P256_LIMBS],
                             const Limb src[P256_LIMBS], Limb move) {
  Limb mask1 = move;
  Limb mask2 = ~mask1;

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

void GFp_nistz256_point_double(P256_POINT *r, const P256_POINT *a);
void GFp_nistz256_point_add(P256_POINT *r, const P256_POINT *a,
                            const P256_POINT *b);
void GFp_nistz256_point_add_affine(P256_POINT *r, const P256_POINT *a,
                                   const P256_POINT_AFFINE *b);


/* r = p * p_scalar */
void GFp_nistz256_point_mul(P256_POINT *r, const Limb p_scalar[P256_LIMBS],
                            const Limb p_x[P256_LIMBS],
                            const Limb p_y[P256_LIMBS]) {
  static const unsigned kWindowSize = 5;
  static const unsigned kMask = (1 << (5 /* kWindowSize */ + 1)) - 1;

  uint8_t p_str[(P256_LIMBS * sizeof(Limb)) + 1];
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

  limbs_copy(row[1 - 1].X, p_x, P256_LIMBS);
  limbs_copy(row[1 - 1].Y, p_y, P256_LIMBS);
  limbs_copy(row[1 - 1].Z, ONE, P256_LIMBS);

  GFp_nistz256_point_double(&row[2 - 1], &row[1 - 1]);
  GFp_nistz256_point_add(&row[3 - 1], &row[2 - 1], &row[1 - 1]);
  GFp_nistz256_point_double(&row[4 - 1], &row[2 - 1]);
  GFp_nistz256_point_double(&row[6 - 1], &row[3 - 1]);
  GFp_nistz256_point_double(&row[8 - 1], &row[4 - 1]);
  GFp_nistz256_point_double(&row[12 - 1], &row[6 - 1]);
  GFp_nistz256_point_add(&row[5 - 1], &row[4 - 1], &row[1 - 1]);
  GFp_nistz256_point_add(&row[7 - 1], &row[6 - 1], &row[1 - 1]);
  GFp_nistz256_point_add(&row[9 - 1], &row[8 - 1], &row[1 - 1]);
  GFp_nistz256_point_add(&row[13 - 1], &row[12 - 1], &row[1 - 1]);
  GFp_nistz256_point_double(&row[14 - 1], &row[7 - 1]);
  GFp_nistz256_point_double(&row[10 - 1], &row[5 - 1]);
  GFp_nistz256_point_add(&row[15 - 1], &row[14 - 1], &row[1 - 1]);
  GFp_nistz256_point_add(&row[11 - 1], &row[10 - 1], &row[1 - 1]);
  GFp_nistz256_point_double(&row[16 - 1], &row[8 - 1]);

  Limb tmp[P256_LIMBS];
  alignas(32) P256_POINT h;
  static const unsigned START_INDEX = 256 - 1;
  unsigned index = START_INDEX;

  unsigned raw_wvalue;
  Limb recoded_is_negative;
  unsigned recoded;

  raw_wvalue = p_str[(index - 1) / 8];
  raw_wvalue = (raw_wvalue >> ((index - 1) % 8)) & kMask;

  booth_recode(&recoded_is_negative, &recoded, raw_wvalue, kWindowSize);
  assert(!recoded_is_negative);
  GFp_nistz256_select_w5(r, table, recoded);

  while (index >= kWindowSize) {
    if (index != START_INDEX) {
      unsigned off = (index - 1) / 8;

      raw_wvalue = p_str[off] | p_str[off + 1] << 8;
      raw_wvalue = (raw_wvalue >> ((index - 1) % 8)) & kMask;
      booth_recode(&recoded_is_negative, &recoded, raw_wvalue, kWindowSize);

      GFp_nistz256_select_w5(&h, table, recoded);
      GFp_nistz256_neg(tmp, h.Y);
      copy_conditional(h.Y, tmp, recoded_is_negative);

      GFp_nistz256_point_add(r, r, &h);
    }

    index -= kWindowSize;

    GFp_nistz256_point_double(r, r);
    GFp_nistz256_point_double(r, r);
    GFp_nistz256_point_double(r, r);
    GFp_nistz256_point_double(r, r);
    GFp_nistz256_point_double(r, r);
  }

  /* Final window */
  raw_wvalue = p_str[0];
  raw_wvalue = (raw_wvalue << 1) & kMask;

  booth_recode(&recoded_is_negative, &recoded, raw_wvalue, kWindowSize);
  GFp_nistz256_select_w5(&h, table, recoded);
  GFp_nistz256_neg(tmp, h.Y);
  copy_conditional(h.Y, tmp, recoded_is_negative);
  GFp_nistz256_point_add(r, r, &h);
}

void GFp_nistz256_point_mul_base(P256_POINT *r,
                                 const Limb g_scalar[P256_LIMBS]) {
  static const unsigned kWindowSize = 7;
  static const unsigned kMask = (1 << (7 /* kWindowSize */ + 1)) - 1;

  uint8_t p_str[(P256_LIMBS * sizeof(Limb)) + 1];
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
  Limb recoded_is_negative;
  unsigned recoded;

  raw_wvalue = (p_str[0] << 1) & kMask;

  booth_recode(&recoded_is_negative, &recoded, raw_wvalue, kWindowSize);
  const PRECOMP256_ROW *const precomputed_table =
      (const PRECOMP256_ROW *)GFp_nistz256_precomputed;
  GFp_nistz256_select_w7(&p.a, precomputed_table[0], recoded);
  GFp_nistz256_neg(p.p.Z, p.p.Y);
  copy_conditional(p.p.Y, p.p.Z, recoded_is_negative);

  limbs_copy(p.p.Z, ONE, P256_LIMBS);
  /* If it is at the point at infinity then p.p.X will be zero. */
  copy_conditional(p.p.Z, p.p.X, is_infinity(p.p.X, p.p.Y));

  for (size_t i = 1; i < 37; i++) {
    unsigned off = (index - 1) / 8;
    raw_wvalue = p_str[off] | p_str[off + 1] << 8;
    raw_wvalue = (raw_wvalue >> ((index - 1) % 8)) & kMask;
    index += kWindowSize;

    booth_recode(&recoded_is_negative, &recoded, raw_wvalue, kWindowSize);
    GFp_nistz256_select_w7(&t.a, precomputed_table[i], recoded);
    GFp_nistz256_neg(t.p.Z, t.a.Y);
    copy_conditional(t.a.Y, t.p.Z, recoded_is_negative);
    GFp_nistz256_point_add_affine(&p.p, &p.p, &t.a);
  }

  limbs_copy(r->X, p.p.X, P256_LIMBS);
  limbs_copy(r->Y, p.p.Y, P256_LIMBS);
  limbs_copy(r->Z, p.p.Z, P256_LIMBS);
}
