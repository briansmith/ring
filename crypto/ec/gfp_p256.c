/* Copyright 2016 Brian Smith.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include "ecp_nistz256.h"
#include "gfp_internal.h"

#include <string.h>

#include "../internal.h"
#include "../bn/internal.h"


typedef GFp_Limb Elem[P256_LIMBS];
typedef GFp_Limb ScalarMont[P256_LIMBS];
typedef GFp_Limb Scalar[P256_LIMBS];


void ecp_nistz256_ord_mul_mont(ScalarMont r, const ScalarMont a,
                               const ScalarMont b);
void ecp_nistz256_ord_sqr_mont(ScalarMont r, const ScalarMont a, int rep);
/* Prototypes to avoid -Wmissing-prototypes warnings. */
void GFp_p256_elem_inv(Elem r, const Elem a);
void GFp_p256_scalar_inv_to_mont(ScalarMont r, const Scalar a);
void GFp_p256_scalar_mul_mont(ScalarMont r, const ScalarMont a,
                              const ScalarMont b);


#if defined(OPENSSL_ARM) || defined(OPENSSL_X86)
void ecp_nistz256_sqr_mont(Elem r, const Elem a) {
  /* XXX: Inefficient. TODO: optimize with dedicated squaring routine. */
  ecp_nistz256_mul_mont(r, a, a);
}
#endif

static inline void elem_mul_mont(Elem r, const Elem a, const Elem b) {
  ecp_nistz256_mul_mont(r, a, b);
}

static inline void elem_sqr_mont(Elem r, const Elem a) {
  ecp_nistz256_sqr_mont(r, a);
}

static inline void elem_sqr_mul_mont(Elem r, const Elem a, size_t squarings,
                                     const Elem b) {
  assert(squarings >= 1);
  ScalarMont tmp;
  elem_sqr_mont(tmp, a);
  for (size_t i = 1; i < squarings; ++i) {
    elem_sqr_mont(tmp, tmp);
  }
  elem_mul_mont(r, tmp, b);
}

void GFp_p256_elem_inv(Elem r, const Elem a) {
  /* Calculate the modular inverse of field element |a| using Fermat's Little
   * Theorem:
   *
   *    a**-1 (mod q) == a**(q - 2) (mod q)
   *
   * The exponent (q - 2) is:
   *
   *    0xffffffff00000001000000000000000000000000fffffffffffffffffffffffd
   */
  const GFp_Limb *b_1 = a;
  Elem b_11;     elem_sqr_mul_mont(b_11, b_1, 0 + 1, b_1);
  Elem f;        elem_sqr_mul_mont(f, b_11, 0 + 2, b_11);
  Elem ff;       elem_sqr_mul_mont(ff, f, 0 + 4, f);
  Elem ffff;     elem_sqr_mul_mont(ffff, ff, 0 + 8, ff);
  Elem ffffffff; elem_sqr_mul_mont(ffffffff, ffff, 0 + 16, ffff);

  Elem acc;

  /* ffffffff00000001 */
  elem_sqr_mul_mont(acc, ffffffff, 31 + 1, b_1);

  /* ffffffff00000001000000000000000000000000ffffffff */
  elem_sqr_mul_mont(acc, acc, 96 + 32, ffffffff);

  /* ffffffff00000001000000000000000000000000ffffffffffffffff */
  elem_sqr_mul_mont(acc, acc, 0 + 32, ffffffff);

  /* ffffffff00000001000000000000000000000000ffffffffffffffffffff */
  elem_sqr_mul_mont(acc, acc, 0 + 16, ffff);

  /* ffffffff00000001000000000000000000000000ffffffffffffffffffffff */
  elem_sqr_mul_mont(acc, acc, 0 + 8, ff);

  /* ffffffff00000001000000000000000000000000fffffffffffffffffffffff */
  elem_sqr_mul_mont(acc, acc, 0 + 4, f);

  /* ffffffff00000001000000000000000000000000fffffffffffffffffffffffd */
  elem_sqr_mul_mont(acc, acc, 0 + 2, b_11);
  elem_sqr_mul_mont(r, acc, 1 + 1, b_1);
}


#if !defined(OPENSSL_X86_64)
void ecp_nistz256_ord_mul_mont(ScalarMont r, const ScalarMont a,
                               const ScalarMont b) {
  static const BN_ULONG N[] = {
    TOBN(0xf3b9cac2, 0xfc632551),
    TOBN(0xbce6faad, 0xa7179e84),
    TOBN(0xffffffff, 0xffffffff),
    TOBN(0xffffffff, 0x00000000),
  };
  static const BN_ULONG N_N0[] = {
    BN_MONT_CTX_N0(0xccd1c8aa, 0xee00bc4f)
  };
  /* XXX: Inefficient. TODO: optimize with dedicated multiplication routine. */
  bn_mul_mont(r, a, b, N, N_N0, P256_LIMBS);
}
#endif

static inline void scalar_mul_mont(ScalarMont r, const ScalarMont a,
                                   const ScalarMont b) {
  ecp_nistz256_ord_mul_mont(r, a, b);
}

static inline void scalar_sqr_mont(ScalarMont r, const ScalarMont a) {
#if defined(OPENSSL_X86_64)
  ecp_nistz256_ord_sqr_mont(r, a, 1);
#else
  scalar_mul_mont(r, a, a);
#endif
}

static inline void scalar_to_mont(ScalarMont r, const Scalar a) {
  static const GFp_Limb N_RR[P256_LIMBS] = {
    TOBN(0x83244c95, 0xbe79eea2),
    TOBN(0x4699799c, 0x49bd6fa6),
    TOBN(0x2845b239, 0x2b6bec59),
    TOBN(0x66e12d94, 0xf3d95620),
  };
  scalar_mul_mont(r, a, N_RR);
}

static void scalar_sqr_mul_mont(ScalarMont r, const ScalarMont a,
                                size_t squarings, const ScalarMont b) {
  assert(squarings >= 1);
  ScalarMont tmp;
#if defined(OPENSSL_X86_64)
  ecp_nistz256_ord_sqr_mont(tmp, a, (int)squarings);
#else
  scalar_sqr_mont(tmp, a);
  for (size_t i = 1; i < squarings; ++i) {
    scalar_sqr_mont(tmp, tmp);
  }
#endif
  scalar_mul_mont(r, tmp, b);
}

void GFp_p256_scalar_inv_to_mont(ScalarMont r, const Scalar a) {
  /* Calculate the modular inverse of scalar |a| using Fermat's Little Theorem:
   *
   *    a**-1 (mod n) == a**(n - 2) (mod n)
   *
   * The exponent (n - 2) is:
   *
   *    0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254f
   */

  enum {
    b_1 = 0,
    b_10,
    b_11,
    b_101,
    b_111,
    b_1010,
    b_1111,
    b_10101,
    b_101111,
    INV_DIGIT_COUNT
  };

  ScalarMont d[INV_DIGIT_COUNT];

  scalar_to_mont     (d[b_1], a);
  scalar_sqr_mont    (d[b_10],   d[b_1]);
  scalar_mul_mont    (d[b_11],   d[b_10],        d[b_1]);
  scalar_sqr_mul_mont(d[b_101],  d[b_10], 0 + 1, d[b_1]);
  scalar_mul_mont    (d[b_111],  d[b_101],       d[b_10]);
  scalar_sqr_mont    (d[b_1010], d[b_101]);
  scalar_mul_mont    (d[b_1111], d[b_1010],      d[b_101]);

  /* These two fork off the main star chain. */
  scalar_sqr_mul_mont(d[b_10101],  d[b_1010],  0 + 1, d[b_1]);
  scalar_sqr_mul_mont(d[b_101111], d[b_10101], 0 + 1, d[b_101]);

  ScalarMont ff;       scalar_sqr_mul_mont(ff, d[b_1111], 0 + 4, d[b_1111]);
  ScalarMont ffff;     scalar_sqr_mul_mont(ffff, ff, 0 + 8, ff);
  ScalarMont ffffffff; scalar_sqr_mul_mont(ffffffff, ffff, 0 + 16, ffff);

  ScalarMont acc;

  /* ffffffff00000000ffffffff */
  scalar_sqr_mul_mont(acc, ffffffff, 32 + 32, ffffffff);

  /* ffffffff00000000ffffffffffffffff */
  scalar_sqr_mul_mont(acc, acc, 0 + 32, ffffffff);

  /* The rest of the exponent, in binary, is:
   *
   *    1011110011100110111110101010110110100111000101111001111010000100
   *    1111001110111001110010101100001011111100011000110010010101001111
   */

  struct {
    uint8_t squarings;
    uint8_t digit;
  } REMAINING_WINDOWS[] = {
    {     6, b_101111 },
    { 2 + 3, b_111 },
    { 2 + 2, b_11 },
    { 1 + 4, b_1111 },
    {     5, b_10101 },
    { 1 + 3, b_101 },
    { 0 + 3, b_101 },
    { 0 + 3, b_101 },
    { 2 + 3, b_111 },
    { 3 + 6, b_101111 },
    { 2 + 4, b_1111 },
    { 1 + 1, b_1 },
    { 4 + 1, b_1 },
    { 2 + 4, b_1111 },
    { 2 + 3, b_111 },
    { 1 + 3, b_111 },
    { 2 + 3, b_111 },
    { 2 + 3, b_101 },
    { 1 + 2, b_11 },
    { 4 + 6, b_101111 },
    {     2, b_11 },
    { 3 + 2, b_11 },
    { 3 + 2, b_11 },
    { 2 + 1, b_1 },
    { 2 + 5, b_10101 },
    { 2 + 4, b_1111 }
  };

  for (size_t i = 0;
       i < sizeof(REMAINING_WINDOWS) / sizeof(REMAINING_WINDOWS[0]); ++i) {
    scalar_sqr_mul_mont(acc, acc, REMAINING_WINDOWS[i].squarings,
                        d[REMAINING_WINDOWS[i].digit]);
  }

  memcpy(r, acc, sizeof(acc));
}

void GFp_p256_scalar_mul_mont(ScalarMont r, const ScalarMont a,
                              const ScalarMont b) {
  scalar_mul_mont(r, a, b);
}

#if !defined(OPENSSL_X86_64)

/* TODO(perf): Optimize these. */

OPENSSL_COMPILE_ASSERT(sizeof(size_t) == sizeof(GFp_Limb),
                       size_t_and_gfp_limb_are_different_sizes);


void ecp_nistz256_select_w5(P256_POINT *out, const P256_POINT table[16],
                            int index) {
  assert(index >= 0);
  size_t index_as_size_t = (size_t)index; /* XXX: constant time? */

  alignas(32) Elem x; memset(x, 0, sizeof(x));
  alignas(32) Elem y; memset(y, 0, sizeof(y));
  alignas(32) Elem z; memset(z, 0, sizeof(z));

  for (size_t i = 0; i < 16; ++i) {
    GFp_Limb mask = constant_time_eq_size_t(index_as_size_t, i + 1);
    for (size_t j = 0; j < P256_LIMBS; ++j) {
      x[j] |= table[i].X[j] & mask;
      y[j] |= table[i].Y[j] & mask;
      z[j] |= table[i].Z[j] & mask;
    }
  }

  memcpy(&out->X, x, sizeof(x));
  memcpy(&out->Y, y, sizeof(y));
  memcpy(&out->Z, z, sizeof(z));
}

void ecp_nistz256_select_w7(P256_POINT_AFFINE *out,
                            const P256_POINT_AFFINE table[64], int index) {
  assert(index >= 0);
  size_t index_as_size_t = (size_t)index; /* XXX: constant time? */

  alignas(32) Elem x; memset(x, 0, sizeof(x));
  alignas(32) Elem y; memset(y, 0, sizeof(y));

  for (size_t i = 0; i < 64; ++i) {
    GFp_Limb mask = constant_time_eq_size_t(index_as_size_t, i + 1);
    for (size_t j = 0; j < P256_LIMBS; ++j) {
      x[j] |= table[i].X[j] & mask;
      y[j] |= table[i].Y[j] & mask;
    }
  }

  memcpy(&out->X, x, sizeof(x));
  memcpy(&out->Y, y, sizeof(y));
}

#endif
