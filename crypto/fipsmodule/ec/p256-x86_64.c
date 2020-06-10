/*
 * Copyright 2014-2016 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2014, Intel Corporation. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Originally written by Shay Gueron (1, 2), and Vlad Krasnov (1)
 * (1) Intel Corporation, Israel Development Center, Haifa, Israel
 * (2) University of Haifa, Israel
 *
 * Reference:
 * S.Gueron and V.Krasnov, "Fast Prime Field Elliptic Curve Cryptography with
 *                          256 Bit Primes"
 */

#include <GFp/base.h>

#include "../../limbs/limbs.inl"

#include <stdint.h>

#include "p256-x86_64.h"

#if defined(OPENSSL_USE_NISTZ256)

typedef P256_POINT_AFFINE PRECOMP256_ROW[64];

// One converted into the Montgomery domain
static const BN_ULONG ONE[P256_LIMBS] = {
    TOBN(0x00000000, 0x00000001), TOBN(0xffffffff, 0x00000000),
    TOBN(0xffffffff, 0xffffffff), TOBN(0x00000000, 0xfffffffe),
};

// Precomputed tables for the default generator
#include "p256-x86_64-table.h"

// Recode window to a signed digit, see |GFp_nistp_recode_scalar_bits| in
// util.c for details
static crypto_word booth_recode_w5(crypto_word in) {
  crypto_word s, d;

  s = ~((in >> 5) - 1);
  d = (1 << 6) - in - 1;
  d = (d & s) | (in & ~s);
  d = (d >> 1) + (d & 1);

  return (d << 1) + (s & 1);
}

static crypto_word booth_recode_w7(crypto_word in) {
  crypto_word s, d;

  s = ~((in >> 7) - 1);
  d = (1 << 8) - in - 1;
  d = (d & s) | (in & ~s);
  d = (d >> 1) + (d & 1);

  return (d << 1) + (s & 1);
}

// copy_conditional copies |src| to |dst| if |move| is one and leaves it as-is
// if |move| is zero.
//
// WARNING: this breaks the usual convention of constant-time functions
// returning masks.
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

// is_not_zero returns one iff in != 0 and zero otherwise.
//
// WARNING: this breaks the usual convention of constant-time functions
// returning masks.
//
// (define-fun is_not_zero ((in (_ BitVec 64))) (_ BitVec 64)
//   (bvlshr (bvor in (bvsub #x0000000000000000 in)) #x000000000000003f)
// )
//
// (declare-fun x () (_ BitVec 64))
//
// (assert (and (= x #x0000000000000000) (= (is_not_zero x) #x0000000000000001)))
// (check-sat)
//
// (assert (and (not (= x #x0000000000000000)) (= (is_not_zero x) #x0000000000000000)))
// (check-sat)
//
static BN_ULONG is_not_zero(BN_ULONG in) {
  in |= (0 - in);
  in >>= BN_BITS2 - 1;
  return in;
}


// r = p * p_scalar
static void ecp_nistz256_windowed_mul(P256_POINT *r,
                                      const BN_ULONG p_scalar[P256_LIMBS],
                                      const BN_ULONG p_x[P256_LIMBS],
                                      const BN_ULONG p_y[P256_LIMBS]) {
  debug_assert_nonsecret(r != NULL);
  debug_assert_nonsecret(p_scalar != NULL);
  debug_assert_nonsecret(p_x != NULL);
  debug_assert_nonsecret(p_y != NULL);

  static const size_t kWindowSize = 5;
  static const crypto_word kMask = (1 << (5 /* kWindowSize */ + 1)) - 1;

  // A |P256_POINT| is (3 * 32) = 96 bytes, and the 64-byte alignment should
  // add no more than 63 bytes of overhead. Thus, |table| should require
  // ~1599 ((96 * 16) + 63) bytes of stack space.
  alignas(64) P256_POINT table[16];
  P256_SCALAR_BYTES p_str;
  p256_scalar_bytes_from_limbs(p_str, p_scalar);

  // table[0] is implicitly (0,0,0) (the point at infinity), therefore it is
  // not stored. All other values are actually stored with an offset of -1 in
  // table.
  P256_POINT *row = table;

  limbs_copy(row[1 - 1].X, p_x, P256_LIMBS);
  limbs_copy(row[1 - 1].Y, p_y, P256_LIMBS);
  limbs_copy(row[1 - 1].Z, ONE, P256_LIMBS);

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
  ecp_nistz256_point_double(&row[16 - 1], &row[8 - 1]);

  BN_ULONG tmp[P256_LIMBS];
  alignas(32) P256_POINT h;
  size_t index = 255;
  crypto_word wvalue = p_str[(index - 1) / 8];
  wvalue = (wvalue >> ((index - 1) % 8)) & kMask;

  ecp_nistz256_select_w5(r, table, booth_recode_w5(wvalue) >> 1);

  while (index >= 5) {
    if (index != 255) {
      size_t off = (index - 1) / 8;

      wvalue = (crypto_word)p_str[off] | (crypto_word)p_str[off + 1] << 8;
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

  // Final window
  wvalue = p_str[0];
  wvalue = (wvalue << 1) & kMask;

  wvalue = booth_recode_w5(wvalue);

  ecp_nistz256_select_w5(&h, table, wvalue >> 1);

  ecp_nistz256_neg(tmp, h.Y);
  copy_conditional(h.Y, tmp, wvalue & 1);

  ecp_nistz256_point_add(r, r, &h);
}

typedef union {
  P256_POINT p;
  P256_POINT_AFFINE a;
} p256_point_union_t;

static crypto_word calc_first_wvalue(size_t *index, const uint8_t p_str[33]) {
  static const size_t kWindowSize = 7;
  static const crypto_word kMask = (1 << (7 /* kWindowSize */ + 1)) - 1;
  *index = kWindowSize;

  crypto_word wvalue = ((crypto_word)p_str[0] << 1) & kMask;
  return booth_recode_w7(wvalue);
}

static crypto_word calc_wvalue(size_t *index, const uint8_t p_str[33]) {
  static const size_t kWindowSize = 7;
  static const crypto_word kMask = (1 << (7 /* kWindowSize */ + 1)) - 1;

  const size_t off = (*index - 1) / 8;
  crypto_word wvalue =
      (crypto_word)p_str[off] | (crypto_word)p_str[off + 1] << 8;
  wvalue = (wvalue >> ((*index - 1) % 8)) & kMask;
  *index += kWindowSize;

  return booth_recode_w7(wvalue);
}

void GFp_p256_point_mul(P256_POINT *r, const Limb p_scalar[P256_LIMBS],
                        const Limb p_x[P256_LIMBS],
                        const Limb p_y[P256_LIMBS]) {
  alignas(32) P256_POINT out;
  ecp_nistz256_windowed_mul(&out, p_scalar, p_x, p_y);

  limbs_copy(r->X, out.X, P256_LIMBS);
  limbs_copy(r->Y, out.Y, P256_LIMBS);
  limbs_copy(r->Z, out.Z, P256_LIMBS);
}

void GFp_p256_point_mul_base(P256_POINT *r, const Limb scalar[P256_LIMBS]) {
  alignas(32) p256_point_union_t t, p;

  P256_SCALAR_BYTES p_str;
  p256_scalar_bytes_from_limbs(p_str, scalar);

  // First window
  size_t index = 0;
  crypto_word wvalue = calc_first_wvalue(&index, p_str);

  ecp_nistz256_select_w7(&p.a, ecp_nistz256_precomputed[0], wvalue >> 1);
  ecp_nistz256_neg(p.p.Z, p.p.Y);
  copy_conditional(p.p.Y, p.p.Z, wvalue & 1);

  // Convert |p| from affine to Jacobian coordinates. We set Z to zero if |p|
  // is infinity and |ONE| otherwise. |p| was computed from the table, so it
  // is infinity iff |wvalue >> 1| is zero.
  GFp_memset(p.p.Z, 0, sizeof(p.p.Z));
  copy_conditional(p.p.Z, ONE, is_not_zero(wvalue >> 1));

  for (int i = 1; i < 37; i++) {
    wvalue = calc_wvalue(&index, p_str);

    ecp_nistz256_select_w7(&t.a, ecp_nistz256_precomputed[i], wvalue >> 1);

    ecp_nistz256_neg(t.p.Z, t.a.Y);
    copy_conditional(t.a.Y, t.p.Z, wvalue & 1);

    // Note |ecp_nistz256_point_add_affine| does not work if |p.p| and |t.a|
    // are the same non-infinity point.
    ecp_nistz256_point_add_affine(&p.p, &p.p, &t.a);
  }

  limbs_copy(r->X, p.p.X, P256_LIMBS);
  limbs_copy(r->Y, p.p.Y, P256_LIMBS);
  limbs_copy(r->Z, p.p.Z, P256_LIMBS);
}

#endif /* defined(OPENSSL_USE_NISTZ256) */
