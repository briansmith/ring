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

#include "gfp_internal.h"

#include <string.h>

#include "../bn/internal.h"
#include "../internal.h"


typedef GFp_Limb Elem[P384_LIMBS];
typedef GFp_Limb ScalarMont[P384_LIMBS];
typedef GFp_Limb Scalar[P384_LIMBS];


/* Prototypes to avoid -Wmissing-prototypes warnings. */
void GFp_p384_elem_add(Elem r, const Elem a, const Elem b);
void GFp_p384_elem_inv(Elem r, const Elem a);
void GFp_p384_elem_mul_mont(Elem r, const Elem a, const Elem b);
void GFp_p384_scalar_inv_to_mont(ScalarMont r, const Scalar a);
void GFp_p384_scalar_mul_mont(ScalarMont r, const ScalarMont a,
                              const ScalarMont b);


static const BN_ULONG Q[P384_LIMBS] = {
  TOBN(0x00000000, 0xffffffff),
  TOBN(0xffffffff, 0x00000000),
  TOBN(0xffffffff, 0xfffffffe),
  TOBN(0xffffffff, 0xffffffff),
  TOBN(0xffffffff, 0xffffffff),
  TOBN(0xffffffff, 0xffffffff),
};

static const BN_ULONG N[P384_LIMBS] = {
  TOBN(0xecec196a, 0xccc52973),
  TOBN(0x581a0db2, 0x48b0a77a),
  TOBN(0xc7634d81, 0xf4372ddf),
  TOBN(0xffffffff, 0xffffffff),
  TOBN(0xffffffff, 0xffffffff),
  TOBN(0xffffffff, 0xffffffff),
};


static inline void elem_mul_mont(Elem r, const Elem a, const Elem b) {
  static const BN_ULONG Q_N0[] = {
    BN_MONT_CTX_N0(0x1, 0x1)
  };
  /* XXX: Not (clearly) constant-time; inefficient. TODO: Add a dedicated
   * squaring routine. */
  bn_mul_mont(r, a, b, Q, Q_N0, P384_LIMBS);
}

static inline void elem_sqr_mont(Elem r, const Elem a) {
  /* XXX: Inefficient. TODO: Add dedicated squaring routine. */
  elem_mul_mont(r, a, a);
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


void GFp_p384_elem_add(Elem r, const Elem a, const Elem b) {
  /* XXX: Not constant-time. */
  if (!bn_add_words(r, a, b, P384_LIMBS)) {
    if (bn_cmp_words(r, Q, P384_LIMBS) < 0) {
      return;
    }
  }
  /* Either the addition resulted in a carry requiring 1 bit more than would
   * fit in |P384_LIMBS| limbs, or the addition result fit in |P384_LIMBS|
   * limbs but it was not less than |q|. Either way, it needs to be reduced. */
  (void)bn_sub_words(r, r, Q, P384_LIMBS);
}

void GFp_p384_elem_inv(Elem r, const Elem a) {
  /* Calculate the modular inverse of field element |a| using Fermat's Little
   * Theorem:
   *
   *    a**-1 (mod q) == a**(q - 2) (mod q)
   *
   * The exponent (q - 2) is:
   *
   *    0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe\
   *      ffffffff0000000000000000fffffffd
   */

  const GFp_Limb *b_1 = a;

  Elem b_11;    elem_sqr_mul_mont(b_11, b_1, 0 + 1, b_1);
  Elem f;       elem_sqr_mul_mont(f, b_11, 0 + 2, b_11);
  Elem ff;      elem_sqr_mul_mont(ff, f, 0 + 4, f);
  Elem ffff;    elem_sqr_mul_mont(ffff, ff, 0 + 8, ff);
  Elem ffffff;  elem_sqr_mul_mont(ffffff, ffff, 0 + 8, ff);
  Elem fffffff; elem_sqr_mul_mont(fffffff, ffffff, 0 + 4, f);

  Elem ffffffffffffff;
  elem_sqr_mul_mont(ffffffffffffff, fffffff, 0 + 28, fffffff);

  Elem ffffffffffffffffffffffffffff;
  elem_sqr_mul_mont(ffffffffffffffffffffffffffff, ffffffffffffff, 0 + 56,
                    ffffffffffffff);

  Elem acc;

  /* ffffffffffffffffffffffffffffffffffffffffffffffffffffffff */
  elem_sqr_mul_mont(acc, ffffffffffffffffffffffffffff, 0 + 112,
                    ffffffffffffffffffffffffffff);

  /* fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff */
  elem_sqr_mul_mont(acc, acc, 0 + 28, fffffff);

  /* fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff[11] */
  elem_sqr_mul_mont(acc, acc, 0 + 2, b_11);

  /* fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff[111] */
  elem_sqr_mul_mont(acc, acc, 0 + 1, b_1);

  /* fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffff */
  elem_sqr_mul_mont(acc, acc, 1 + 28, fffffff);

  /* fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff */
  elem_sqr_mul_mont(acc, acc, 0 + 4, f);

  /* fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff
   * 0000000000000000fffffff */
  elem_sqr_mul_mont(acc, acc, 64 + 28, fffffff);

  /* fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff
   * 0000000000000000fffffffd */
  elem_sqr_mul_mont(acc, acc, 0 + 2, b_11);
  elem_sqr_mul_mont(r, acc, 1 + 1, b_1);
}

void GFp_p384_elem_mul_mont(Elem r, const Elem a, const Elem b) {
  elem_mul_mont(r, a, b);
}


static inline void scalar_mul_mont(ScalarMont r, const ScalarMont a,
                                   const ScalarMont b) {
  static const BN_ULONG N_N0[] = {
    BN_MONT_CTX_N0(0x6ed46089, 0xe88fdc45)
  };
  /* XXX: Inefficient. TODO: Add dedicated multiplication routine. */
  bn_mul_mont(r, a, b, N, N_N0, P384_LIMBS);
}

static inline void scalar_sqr_mont(ScalarMont r, const ScalarMont a) {
  /* XXX: Inefficient. TODO: Add dedicated squaring routine. */
  scalar_mul_mont(r, a, a);
}

static inline void scalar_to_mont(ScalarMont r, const ScalarMont a) {
  static const BN_ULONG N_RR[P384_LIMBS] = {
    TOBN(0x2d319b24, 0x19b409a9),
    TOBN(0xff3d81e5, 0xdf1aa419),
    TOBN(0xbc3e483a, 0xfcb82947),
    TOBN(0xd40d4917, 0x4aab1cc5),
    TOBN(0x3fb05b7a, 0x28266895),
    TOBN(0x0c84ee01, 0x2b39bf21),
  };
  scalar_mul_mont(r, a, N_RR);
}

static void scalar_sqr_mul_mont(ScalarMont r, const ScalarMont a,
                                size_t squarings, const ScalarMont b) {
  assert(squarings >= 1);
  ScalarMont tmp;
  scalar_sqr_mont(tmp, a);
  for (size_t i = 1; i < squarings; ++i) {
    scalar_sqr_mont(tmp, tmp);
  }
  scalar_mul_mont(r, tmp, b);
}

void GFp_p384_scalar_inv_to_mont(ScalarMont r, const Scalar a) {
  /* Calculate the modular inverse of scalar |a| using Fermat's Little Theorem:
   *
   *   a**-1 (mod n) == a**(n - 2) (mod n)
   *
   * The exponent (n - 2) is:
   *
   *     0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf\
   *       581a0db248b0a77aecec196accc52971.
   */

  /* XXX(perf): This hasn't been optimized at all. TODO: optimize. */

  enum {
    b_1 = 0,
    b_10,
    b_11,
    b_101,
    b_111,
    b_1111,
    INV_DIGIT_COUNT
  };

  ScalarMont d[INV_DIGIT_COUNT];

  scalar_to_mont     (d[b_1],    a);
  scalar_sqr_mont    (d[b_10],   d[b_1]);
  scalar_mul_mont    (d[b_11],   d[b_10],         d[b_1]);
  scalar_sqr_mul_mont(d[b_101],  d[b_10],  0 + 1, d[b_1]);
  scalar_mul_mont    (d[b_111],  d[b_101],        d[b_10]);
  scalar_sqr_mul_mont(d[b_1111], d[b_111], 0 + 1, d[b_1]);

  ScalarMont ff;       scalar_sqr_mul_mont(ff, d[b_1111], 0 + 4, d[b_1111]);
  ScalarMont ffff;     scalar_sqr_mul_mont(ffff, ff, 0 + 8, ff);
  ScalarMont ffffffff; scalar_sqr_mul_mont(ffffffff, ffff, 0 + 16, ffff);

  ScalarMont acc;

  /* ffffffffffffffff */
  scalar_sqr_mul_mont(acc, ffffffff, 0 + 32, ffffffff);

  /* ffffffffffffffffffffffff */
  scalar_sqr_mul_mont(acc, acc, 0 + 32, ffffffff);

  /* ffffffffffffffffffffffffffffffffffffffffffffffff */
  scalar_sqr_mul_mont(acc, acc, 0 + 96, acc);

  /* The rest of the exponent, in binary, is:
   *
   *    1100011101100011010011011000000111110100001101110010110111011111
   *    0101100000011010000011011011001001001000101100001010011101111010
   *    1110110011101100000110010110101011001100110001010010100101110001
   */

  struct {
    uint8_t squarings;
    uint8_t digit;
  } REMAINING_WINDOWS[] = {
    {     2, b_11 },
    { 3 + 3, b_111 },
    { 1 + 2, b_11 },
    { 3 + 2, b_11 },
    { 1 + 1, b_1 },
    { 2 + 2, b_11 },
    { 1 + 2, b_11 },
    { 6 + 4, b_1111 },
    {     3, b_101 },
    { 4 + 2, b_11 },
    { 1 + 3, b_111 },
    { 2 + 3, b_101 },
    {     1, b_1 },
    { 1 + 3, b_111 },
    { 1 + 4, b_1111 },
    {     3, b_101 },
    { 1 + 2, b_11 },
    { 6 + 2, b_11 },
    { 1 + 1, b_1 },
    { 5 + 2, b_11 },
    { 1 + 2, b_11 },
    { 1 + 2, b_11 },
    { 2 + 1, b_1 },
    { 2 + 1, b_1 },
    { 2 + 1, b_1 },
    { 3 + 1, b_1 },
    { 1 + 2, b_11 },
    { 4 + 1, b_1 },
    { 1 + 1, b_1 },
    { 2 + 3, b_111 },
    { 1 + 4, b_1111 },
    { 1 + 1, b_1 },
    { 1 + 3, b_111 },
    { 1 + 2, b_11 },
    { 2 + 3, b_111 },
    { 1 + 2, b_11 },
    { 5 + 2, b_11 },
    { 2 + 1, b_1 },
    { 1 + 2, b_11 },
    { 1 + 3, b_101 },
    { 1 + 2, b_11 },
    { 2 + 2, b_11 },
    { 2 + 2, b_11 },
    { 3 + 3, b_101 },
    { 2 + 3, b_101 },
    { 2 + 1, b_1 },
    { 1 + 3, b_111 },
    { 3 + 1, b_1 },
  };

  for (size_t i = 0;
       i < sizeof(REMAINING_WINDOWS) / sizeof(REMAINING_WINDOWS[0]); ++i) {
    scalar_sqr_mul_mont(acc, acc, REMAINING_WINDOWS[i].squarings,
                        d[REMAINING_WINDOWS[i].digit]);
  }

  memcpy(r, acc, sizeof(acc));
}

void GFp_p384_scalar_mul_mont(ScalarMont r, const ScalarMont a,
                              const ScalarMont b) {
  scalar_mul_mont(r, a, b);
}
