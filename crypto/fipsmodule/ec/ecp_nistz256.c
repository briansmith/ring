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

#include "ecp_nistz.h"
#include "../bn/internal.h"
#include "../../limbs/limbs.inl"

#if defined(__GNUC__)
#pragma GCC diagnostic ignored "-Wsign-conversion"
#endif

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

#ifndef OPENSSL_MIPS64
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
#endif

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
#ifndef OPENSSL_MIPS64
void GFp_nistz256_point_add_affine(P256_POINT *r, const P256_POINT *a,
                                   const P256_POINT_AFFINE *b);
#endif
#if defined(OPENSSL_X86_64)
void GFp_nistz256_point_add(P256_POINT *r, const P256_POINT *a,
                            const P256_POINT *b);
#else

static const BN_ULONG Q[P256_LIMBS] = {
  TOBN(0xffffffff, 0xffffffff),
  TOBN(0x00000000, 0xffffffff),
  TOBN(0x00000000, 0x00000000),
  TOBN(0xffffffff, 0x00000001),
};

static inline Limb is_equal(const Limb a[P256_LIMBS], const Limb b[P256_LIMBS]) {
  return LIMBS_equal(a, b, P256_LIMBS);
}

static inline Limb is_zero(const BN_ULONG a[P256_LIMBS]) {
  return LIMBS_are_zero(a, P256_LIMBS);
}

static inline void elem_mul_by_2(Limb r[P256_LIMBS], const Limb a[P256_LIMBS]) {
  LIMBS_shl_mod(r, a, Q, P256_LIMBS);
}

static inline void elem_mul_mont(Limb r[P256_LIMBS], const Limb a[P256_LIMBS],
                                 const Limb b[P256_LIMBS]) {
  GFp_nistz256_mul_mont(r, a, b);
}

static inline void elem_sqr_mont(Limb r[P256_LIMBS], const Limb a[P256_LIMBS]) {
  GFp_nistz256_sqr_mont(r, a);
}

static inline void elem_sub(Limb r[P256_LIMBS], const Limb a[P256_LIMBS],
                            const Limb b[P256_LIMBS]) {
  LIMBS_sub_mod(r, a, b, Q, P256_LIMBS);
}

/* Point addition: r = a+b */
void GFp_nistz256_point_add(P256_POINT *r, const P256_POINT *a, const P256_POINT *b) {
  BN_ULONG U2[P256_LIMBS], S2[P256_LIMBS];
  BN_ULONG U1[P256_LIMBS], S1[P256_LIMBS];
  BN_ULONG Z1sqr[P256_LIMBS];
  BN_ULONG Z2sqr[P256_LIMBS];
  BN_ULONG H[P256_LIMBS], R[P256_LIMBS];
  BN_ULONG Hsqr[P256_LIMBS];
  BN_ULONG Rsqr[P256_LIMBS];
  BN_ULONG Hcub[P256_LIMBS];

  BN_ULONG res_x[P256_LIMBS];
  BN_ULONG res_y[P256_LIMBS];
  BN_ULONG res_z[P256_LIMBS];

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
      GFp_nistz256_point_double(r, a);
    } else {
      limbs_zero(r->X, P256_LIMBS);
      limbs_zero(r->Y, P256_LIMBS);
      limbs_zero(r->Z, P256_LIMBS);
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

  limbs_copy(r->X, res_x, P256_LIMBS);
  limbs_copy(r->Y, res_y, P256_LIMBS);
  limbs_copy(r->Z, res_z, P256_LIMBS);
}

/* Include more reference implementation code for arches lacking assembly
 * optimizations */
#ifdef OPENSSL_MIPS64

static inline void elem_add(Limb r[P256_LIMBS], const Limb a[P256_LIMBS],
                            const Limb b[P256_LIMBS]) {
  LIMBS_add_mod(r, a, b, Q, P256_LIMBS);
}

static inline void elem_mul_by_3(Limb r[P256_LIMBS], const Limb a[P256_LIMBS]) {
  Limb tmp[P256_LIMBS];
  elem_mul_by_2(tmp, a);
  LIMBS_add_mod(r, tmp, a, Q, P256_LIMBS);
}

static inline void elem_div_by_2(Limb r[P256_LIMBS], const Limb a[P256_LIMBS]) {
  /* Consider the case where `a` is even. Then we can shift `a` right one bit
   * and the result will still be valid because we didn't lose any bits and so
   * `(a >> 1) * 2 == a (mod q)`, which is the invariant we must satisfy.
   *
   * The remainder of this comment is considering the case where `a` is odd.
   *
   * Since `a` is odd, it isn't the case that `(a >> 1) * 2 == a (mod q)`
   * because the lowest bit is lost during the shift. For example, consider:
   *
   * ```python
   * q = 2**384 - 2**128 - 2**96 + 2**32 - 1
   * a = 2**383
   * two_a = a * 2 % q
   * assert two_a == 0x100000000ffffffffffffffff00000001
   * ```
   *
   * Notice there how `(2 * a) % q` wrapped around to a smaller odd value. When
   * we divide `two_a` by two (mod q), we need to get the value `2**383`, which
   * we obviously can't get with just a right shift.
   *
   * `q` is odd, and `a` is odd, so `a + q` is even. We could calculate
   * `(a + q) >> 1` and then reduce it mod `q`. However, then we would have to
   * keep track of an extra most significant bit. We can avoid that by instead
   * calculating `(a >> 1) + ((q + 1) >> 1)`. The `1` in `q + 1` is the least
   * significant bit of `a`. `q + 1` is even, which means it can be shifted
   * without losing any bits. Since `q` is odd, `q - 1` is even, so the largest
   * odd field element is `q - 2`. Thus we know that `a <= q - 2`. We know
   * `(q + 1) >> 1` is `(q + 1) / 2` since (`q + 1`) is even. The value of
   * `a >> 1` is `(a - 1)/2` since the shift will drop the least significant
   * bit of `a`, which is 1. Thus:
   *
   * sum  =  ((q + 1) >> 1) + (a >> 1)
   * sum  =  (q + 1)/2 + (a >> 1)       (substituting (q + 1)/2)
   *     <=  (q + 1)/2 + (q - 2 - 1)/2  (substituting a <= q - 2)
   *     <=  (q + 1)/2 + (q - 3)/2      (simplifying)
   *     <=  (q + 1 + q - 3)/2          (factoring out the common divisor)
   *     <=  (2q - 2)/2                 (simplifying)
   *     <=  q - 1                      (simplifying)
   *
   * Thus, no reduction of the sum mod `q` is necessary. */

  Limb is_odd = constant_time_is_nonzero_w(a[0] & 1);

  /* r = a >> 1. */
  Limb carry = a[P256_LIMBS - 1] & 1;
  r[P256_LIMBS - 1] = a[P256_LIMBS - 1] >> 1;
  for (size_t i = 1; i < P256_LIMBS; ++i) {
    Limb new_carry = a[P256_LIMBS - i - 1];
    r[P256_LIMBS - i - 1] =
        (a[P256_LIMBS - i - 1] >> 1) | (carry << (LIMB_BITS - 1));
    carry = new_carry;
  }

  static const Limb Q_PLUS_1_SHR_1[P256_LIMBS] = {
    TOBN(0x00000000, 0x00000000), TOBN(0x00000000, 0x80000000),
    TOBN(0x80000000, 0x00000000), TOBN(0x7fffffff, 0x80000000),
  };

  Limb adjusted[P256_LIMBS];
  BN_ULONG carry2 = limbs_add(adjusted, r, Q_PLUS_1_SHR_1, P256_LIMBS);
#if defined(NDEBUG)
  (void)carry2;
#endif
  ASSERT(carry2 == 0);

  copy_conditional(r, adjusted, is_odd);
}

void GFp_nistz256_add(Limb r[P256_LIMBS], const Limb a[P256_LIMBS],
                      const Limb b[P256_LIMBS])
{
  elem_add(r, a, b);
}

/* Point double: r = 2*a */
void GFp_nistz256_point_double(P256_POINT *r, const P256_POINT *a)
{
  BN_ULONG S[P256_LIMBS];
  BN_ULONG M[P256_LIMBS];
  BN_ULONG Zsqr[P256_LIMBS];
  BN_ULONG tmp0[P256_LIMBS];

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
#endif
#endif

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
  ASSERT(!recoded_is_negative);
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

static const unsigned kWindowSize = 7;

static inline void select_precomputed(P256_POINT_AFFINE *p, size_t i,
                                      unsigned raw_wvalue) {
  Limb recoded_is_negative;
  unsigned recoded;
  booth_recode(&recoded_is_negative, &recoded, raw_wvalue, kWindowSize);
  GFp_nistz256_select_w7(p, GFp_nistz256_precomputed[i], recoded);
  Limb neg_y[P256_LIMBS];
  GFp_nistz256_neg(neg_y, p->Y);
  copy_conditional(p->Y, neg_y, recoded_is_negative);
}

#ifndef OPENSSL_MIPS64
void GFp_nistz256_point_mul_base(P256_POINT *r,
                                 const Limb g_scalar[P256_LIMBS]) {
  static const unsigned kMask = (1 << (7 /* kWindowSize */ + 1)) - 1;

  uint8_t p_str[(P256_LIMBS * sizeof(Limb)) + 1];
  gfp_little_endian_bytes_from_scalar(p_str, sizeof(p_str) / sizeof(p_str[0]),
                                      g_scalar, P256_LIMBS);

  /* First window */
  unsigned index = kWindowSize;

  alignas(32) P256_POINT_AFFINE t;

  unsigned raw_wvalue = (p_str[0] << 1) & kMask;
  select_precomputed(&t, 0, raw_wvalue);

  alignas(32) P256_POINT p;
  limbs_copy(p.X, t.X, P256_LIMBS);
  limbs_copy(p.Y, t.Y, P256_LIMBS);
  limbs_copy(p.Z, ONE, P256_LIMBS);
  /* If it is at the point at infinity then p.p.X will be zero. */
  copy_conditional(p.Z, p.X, is_infinity(p.X, p.Y));

  for (size_t i = 1; i < 37; i++) {
    unsigned off = (index - 1) / 8;
    raw_wvalue = p_str[off] | p_str[off + 1] << 8;
    raw_wvalue = (raw_wvalue >> ((index - 1) % 8)) & kMask;
    index += kWindowSize;
    select_precomputed(&t, i, raw_wvalue);
    GFp_nistz256_point_add_affine(&p, &p, &t);
  }

  limbs_copy(r->X, p.X, P256_LIMBS);
  limbs_copy(r->Y, p.Y, P256_LIMBS);
  limbs_copy(r->Z, p.Z, P256_LIMBS);
}
#endif
