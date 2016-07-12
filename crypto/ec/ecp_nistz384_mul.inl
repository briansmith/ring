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

#include "ecp_nistz.h"


/* Prototypes to avoid -Wmissing-prototypes warnings. */
void ecp_nistz384_point_mul(P384_POINT *r, const BN_ULONG p_scalar[P384_LIMBS],
                            const BN_ULONG p_x[P384_LIMBS],
                            const BN_ULONG p_y[P384_LIMBS]);


static void add_precomputed_w5(P384_POINT *r, unsigned wvalue,
                               const P384_POINT table[16]) {
  BN_ULONG recoded_is_negative;
  unsigned int recoded;
  booth_recode(&recoded_is_negative, &recoded, wvalue, 5);

  alignas(64) P384_POINT h;
  gfp_p384_point_select_w5(&h, table, recoded);

  alignas(64) BN_ULONG tmp[P384_LIMBS];
  GFp_p384_elem_neg(tmp, h.Y);
  copy_conditional(h.Y, tmp, recoded_is_negative);

  ecp_nistz384_point_add(r, r, &h);
}

/* r = p * p_scalar */
void ecp_nistz384_point_mul(P384_POINT *r, const BN_ULONG p_scalar[P384_LIMBS],
                            const BN_ULONG p_x[P384_LIMBS],
                            const BN_ULONG p_y[P384_LIMBS]) {
  static const unsigned kWindowSize = 5;
  static const unsigned kMask = (1 << (5 /* kWindowSize */ + 1)) - 1;

  uint8_t p_str[(P384_LIMBS * BN_BYTES) + 1];
  gfp_little_endian_bytes_from_scalar(p_str, sizeof(p_str) / sizeof(p_str[0]),
                                      p_scalar, P384_LIMBS);

  /* A |P384_POINT| is (3 * 48) = 144 bytes, and the 64-byte alignment should
   * add no more than 63 bytes of overhead. Thus, |table| should require
   * ~2367 ((144 * 16) + 63) bytes of stack space. */
  alignas(64) P384_POINT table[16];

  /* table[0] is implicitly (0,0,0) (the point at infinity), therefore it is
   * not stored. All other values are actually stored with an offset of -1 in
   * table. */
  P384_POINT *row = table;

  memcpy(row[1 - 1].X, p_x, P384_LIMBS * BN_BYTES);
  memcpy(row[1 - 1].Y, p_y, P384_LIMBS * BN_BYTES);
  memcpy(row[1 - 1].Z, ONE, P384_LIMBS * BN_BYTES);

  ecp_nistz384_point_double(&row[2 - 1], &row[1 - 1]);
  ecp_nistz384_point_add(&row[3 - 1], &row[2 - 1], &row[1 - 1]);
  ecp_nistz384_point_double(&row[4 - 1], &row[2 - 1]);
  ecp_nistz384_point_double(&row[6 - 1], &row[3 - 1]);
  ecp_nistz384_point_double(&row[8 - 1], &row[4 - 1]);
  ecp_nistz384_point_double(&row[12 - 1], &row[6 - 1]);
  ecp_nistz384_point_add(&row[5 - 1], &row[4 - 1], &row[1 - 1]);
  ecp_nistz384_point_add(&row[7 - 1], &row[6 - 1], &row[1 - 1]);
  ecp_nistz384_point_add(&row[9 - 1], &row[8 - 1], &row[1 - 1]);
  ecp_nistz384_point_add(&row[13 - 1], &row[12 - 1], &row[1 - 1]);
  ecp_nistz384_point_double(&row[14 - 1], &row[7 - 1]);
  ecp_nistz384_point_double(&row[10 - 1], &row[5 - 1]);
  ecp_nistz384_point_add(&row[15 - 1], &row[14 - 1], &row[1 - 1]);
  ecp_nistz384_point_add(&row[11 - 1], &row[10 - 1], &row[1 - 1]);
  ecp_nistz384_point_add(&row[16 - 1], &row[15 - 1], &row[1 - 1]);

  static const unsigned START_INDEX = 384 - 4;
  unsigned index = START_INDEX;

  BN_ULONG recoded_is_negative;
  unsigned recoded;

  unsigned wvalue = p_str[(index - 1) / 8];
  wvalue = (wvalue >> ((index - 1) % 8)) & kMask;

  booth_recode(&recoded_is_negative, &recoded, wvalue, 5);
  assert(!recoded_is_negative);

  gfp_p384_point_select_w5(r, table, recoded);

  while (index >= kWindowSize) {
    if (index != START_INDEX) {
      unsigned off = (index - 1) / 8;

      wvalue = p_str[off] | p_str[off + 1] << 8;
      wvalue = (wvalue >> ((index - 1) % 8)) & kMask;
      add_precomputed_w5(r, wvalue, table);
    }

    index -= kWindowSize;

    ecp_nistz384_point_double(r, r);
    ecp_nistz384_point_double(r, r);
    ecp_nistz384_point_double(r, r);
    ecp_nistz384_point_double(r, r);
    ecp_nistz384_point_double(r, r);
  }

  /* Final window */
  wvalue = p_str[0];
  wvalue = (wvalue << 1) & kMask;
  add_precomputed_w5(r, wvalue, table);
}
