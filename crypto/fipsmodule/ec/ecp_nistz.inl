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
#include "gfp.h"

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#endif

#define point_add(prefix, bits) RENAME_FUNC(prefix, bits, point_add)
#define point_double(prefix, bits) RENAME_FUNC(prefix, bits, point_double)
#define point_mul(prefix, bits) RENAME_FUNC(prefix, bits, point_mul)

/* Point double: r = 2*a */
static void point_double(nistz, BITS)(NIST_POINT *r, const NIST_POINT *a) {
  BN_ULONG S[FE_LIMBS];
  BN_ULONG M[FE_LIMBS];
  BN_ULONG Zsqr[FE_LIMBS];
  BN_ULONG tmp0[FE_LIMBS];

  const BN_ULONG *in_x = a->X;
  const BN_ULONG *in_y = a->Y;
  const BN_ULONG *in_z = a->Z;

  BN_ULONG *res_x = r->X;
  BN_ULONG *res_y = r->Y;
  BN_ULONG *res_z = r->Z;

  elem_mul_by_2(S, in_y);

  elem_sqr_mont(Zsqr, in_z);

  elem_sqr_mont(S, S);

  elem_mul_mont(res_z, in_z, in_y);
  elem_mul_by_2(res_z, res_z);

  elem_add(M, in_x, Zsqr);
  elem_sub(Zsqr, in_x, Zsqr);

  elem_sqr_mont(res_y, S);
  elem_div_by_2(res_y, res_y);

  elem_mul_mont(M, M, Zsqr);
  elem_mul_by_3(M, M);

  elem_mul_mont(S, S, in_x);
  elem_mul_by_2(tmp0, S);

  elem_sqr_mont(res_x, M);

  elem_sub(res_x, res_x, tmp0);
  elem_sub(S, S, res_x);

  elem_mul_mont(S, S, M);
  elem_sub(res_y, S, res_y);
}

/* Point addition: r = a+b */
static void point_add(nistz, BITS)(NIST_POINT *r, const NIST_POINT *a,
                                   const NIST_POINT *b) {
  BN_ULONG U2[FE_LIMBS], S2[FE_LIMBS];
  BN_ULONG U1[FE_LIMBS], S1[FE_LIMBS];
  BN_ULONG Z1sqr[FE_LIMBS];
  BN_ULONG Z2sqr[FE_LIMBS];
  BN_ULONG H[FE_LIMBS], R[FE_LIMBS];
  BN_ULONG Hsqr[FE_LIMBS];
  BN_ULONG Rsqr[FE_LIMBS];
  BN_ULONG Hcub[FE_LIMBS];

  BN_ULONG res_x[FE_LIMBS];
  BN_ULONG res_y[FE_LIMBS];
  BN_ULONG res_z[FE_LIMBS];

  const BN_ULONG *in1_x = a->X;
  const BN_ULONG *in1_y = a->Y;
  const BN_ULONG *in1_z = a->Z;

  const BN_ULONG *in2_x = b->X;
  const BN_ULONG *in2_y = b->Y;
  const BN_ULONG *in2_z = b->Z;

  BN_ULONG in1infty = is_zero(a->Z);
  BN_ULONG in2infty = is_zero(b->Z);

  elem_sqr_mont(Z2sqr, in2_z); /* Z2^2 */
  elem_sqr_mont(Z1sqr, in1_z); /* Z1^2 */

  elem_mul_mont(S1, Z2sqr, in2_z); /* S1 = Z2^3 */
  elem_mul_mont(S2, Z1sqr, in1_z); /* S2 = Z1^3 */

  elem_mul_mont(S1, S1, in1_y); /* S1 = Y1*Z2^3 */
  elem_mul_mont(S2, S2, in2_y); /* S2 = Y2*Z1^3 */
  elem_sub(R, S2, S1);          /* R = S2 - S1 */

  elem_mul_mont(U1, in1_x, Z2sqr); /* U1 = X1*Z2^2 */
  elem_mul_mont(U2, in2_x, Z1sqr); /* U2 = X2*Z1^2 */
  elem_sub(H, U2, U1);             /* H = U2 - U1 */

  BN_ULONG is_exceptional = is_equal(U1, U2) & ~in1infty & ~in2infty;
  if (is_exceptional) {
    if (is_equal(S1, S2)) {
      point_double(nistz, BITS)(r, a);
    } else {
      limbs_zero(r->X, FE_LIMBS);
      limbs_zero(r->Y, FE_LIMBS);
      limbs_zero(r->Z, FE_LIMBS);
    }
    return;
  }

  elem_sqr_mont(Rsqr, R);             /* R^2 */
  elem_mul_mont(res_z, H, in1_z);     /* Z3 = H*Z1*Z2 */
  elem_sqr_mont(Hsqr, H);             /* H^2 */
  elem_mul_mont(res_z, res_z, in2_z); /* Z3 = H*Z1*Z2 */
  elem_mul_mont(Hcub, Hsqr, H);       /* H^3 */

  elem_mul_mont(U2, U1, Hsqr); /* U1*H^2 */
  elem_mul_by_2(Hsqr, U2);     /* 2*U1*H^2 */

  elem_sub(res_x, Rsqr, Hsqr);
  elem_sub(res_x, res_x, Hcub);

  elem_sub(res_y, U2, res_x);

  elem_mul_mont(S2, S1, Hcub);
  elem_mul_mont(res_y, R, res_y);
  elem_sub(res_y, res_y, S2);

  copy_conditional(res_x, in2_x, in1infty);
  copy_conditional(res_y, in2_y, in1infty);
  copy_conditional(res_z, in2_z, in1infty);

  copy_conditional(res_x, in1_x, in2infty);
  copy_conditional(res_y, in1_y, in2infty);
  copy_conditional(res_z, in1_z, in2infty);

  limbs_copy(r->X, res_x, FE_LIMBS);
  limbs_copy(r->Y, res_y, FE_LIMBS);
  limbs_copy(r->Z, res_z, FE_LIMBS);
}

static void add_precomputed_w(NIST_POINT *r, crypto_word_t wvalue,
                              const NIST_POINT table[TBL_SZ]) {
  crypto_word_t recoded_is_negative;
  crypto_word_t recoded;
  booth_recode(&recoded_is_negative, &recoded, wvalue, W_BITS);

  alignas(64) NIST_POINT h;
  NIST_POINT_select_w(&h, table, recoded);

  alignas(64) BN_ULONG tmp[FE_LIMBS];
  elem_neg(tmp, h.Y);
  copy_conditional(h.Y, tmp, recoded_is_negative);

  point_add(nistz, BITS)(r, r, &h);
}

/* r = p * p_scalar */
static void point_mul(nistz, BITS)(NIST_POINT *r, const BN_ULONG p_scalar[FE_LIMBS],
                                   const BN_ULONG p_x[FE_LIMBS],
                                   const BN_ULONG p_y[FE_LIMBS]) {
  uint8_t p_str[(FE_LIMBS * sizeof(Limb)) + 1];
  little_endian_bytes_from_scalar(p_str, sizeof(p_str) / sizeof(p_str[0]),
                                  p_scalar, FE_LIMBS);

  /* A |NIST_POINT| is (3 * 48) = 144 bytes, and the 64-byte alignment should
  * add no more than 63 bytes of overhead. Thus, |table| should require
  * ~2367 ((144 * 16) + 63) bytes of stack space. */
  alignas(64) NIST_POINT table[TBL_SZ];

  /* table[0] is implicitly (0,0,0) (the point at infinity), therefore it is
  * not stored. All other values are actually stored with an offset of -1 in
  * table. */
  NIST_POINT *row = table;

  limbs_copy(row[0].X, p_x, FE_LIMBS);
  limbs_copy(row[0].Y, p_y, FE_LIMBS);
  limbs_copy(row[0].Z, ONE, FE_LIMBS);

  point_double(nistz, BITS)(&row[1], &row[0]);

  for (int i = 2; i < TBL_SZ; i += 2) {
    point_add(nistz, BITS)(&row[i], &row[i - 1], &row[0]);
    point_double(nistz, BITS)(&row[i + 1], &row[i / 2]);
  }

  static const size_t ROUND_SIZE = (BITS + W_BITS - 1) / W_BITS * W_BITS;
  size_t START_INDEX = ROUND_SIZE == BITS + 1 ? ROUND_SIZE - W_BITS: ROUND_SIZE;
  size_t index = START_INDEX;

  BN_ULONG recoded_is_negative;
  crypto_word_t recoded;

  crypto_word_t wvalue = p_str[(index - 1) / 8];
  wvalue = (wvalue >> ((index - 1) % 8)) & W_MASK;

  booth_recode(&recoded_is_negative, &recoded, wvalue, W_BITS);
  dev_assert_secret(!recoded_is_negative);

  NIST_POINT_select_w(r, table, recoded);

  while (index >= W_BITS) {
    if (index != START_INDEX) {
      size_t off = (index - 1) / 8;

      wvalue = p_str[off] | p_str[off + 1] << 8;
      wvalue = (wvalue >> ((index - 1) % 8)) & W_MASK;
      add_precomputed_w(r, wvalue, table);
    }

    index -= W_BITS;

    for (int i = 0; i < W_BITS; i++) {
      point_double(nistz, BITS)(r, r);
    }
  }

  /* Final window */
  wvalue = p_str[0];
  wvalue = (wvalue << 1) & W_MASK;
  add_precomputed_w(r, wvalue, table);
}

void point_double(p, BITS)(Limb r[3][FE_LIMBS], const Limb a[3][FE_LIMBS])
{
  NIST_POINT t;
  limbs_copy(t.X, a[0], FE_LIMBS);
  limbs_copy(t.Y, a[1], FE_LIMBS);
  limbs_copy(t.Z, a[2], FE_LIMBS);
  point_double(nistz, BITS)(&t, &t);
  limbs_copy(r[0], t.X, FE_LIMBS);
  limbs_copy(r[1], t.Y, FE_LIMBS);
  limbs_copy(r[2], t.Z, FE_LIMBS);
}

void point_add(p, BITS)(Limb r[3][FE_LIMBS],
                        const Limb a[3][FE_LIMBS],
                        const Limb b[3][FE_LIMBS])
{
  NIST_POINT t1;
  limbs_copy(t1.X, a[0], FE_LIMBS);
  limbs_copy(t1.Y, a[1], FE_LIMBS);
  limbs_copy(t1.Z, a[2], FE_LIMBS);

  NIST_POINT t2;
  limbs_copy(t2.X, b[0], FE_LIMBS);
  limbs_copy(t2.Y, b[1], FE_LIMBS);
  limbs_copy(t2.Z, b[2], FE_LIMBS);

  point_add(nistz, BITS)(&t1, &t1, &t2);

  limbs_copy(r[0], t1.X, FE_LIMBS);
  limbs_copy(r[1], t1.Y, FE_LIMBS);
  limbs_copy(r[2], t1.Z, FE_LIMBS);
}

void point_mul(p, BITS)(Limb r[3][FE_LIMBS],
                        const BN_ULONG p_scalar[FE_LIMBS],
                        const Limb p_x[FE_LIMBS],
                        const Limb p_y[FE_LIMBS])
{
  alignas(64) NIST_POINT acc;
  point_mul(nistz, BITS)(&acc, p_scalar, p_x, p_y);
  limbs_copy(r[0], acc.X, FE_LIMBS);
  limbs_copy(r[1], acc.Y, FE_LIMBS);
  limbs_copy(r[2], acc.Z, FE_LIMBS);
}

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
