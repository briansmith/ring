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


#define P256_LIMBS (256u / GFp_LIMB_BITS)

typedef GFp_Limb Elem[P256_LIMBS];
typedef GFp_Limb ScalarMont[P256_LIMBS];
typedef GFp_Limb Scalar[P256_LIMBS];


void ecp_nistz256_mul_mont(Elem r, const Elem a, const Elem b);


/* Prototypes to avoid -Wmissing-prototypes warnings. */
#if defined(OPENSSL_ARM) || defined(OPENSSL_X86)
void ecp_nistz256_sqr_mont(Elem r, const Elem a);
#endif
void GFp_p256_scalar_inv_to_mont(ScalarMont r, const Scalar a);
void GFp_p256_scalar_mul_mont(ScalarMont r, const ScalarMont a,
                              const ScalarMont b);


#if defined(OPENSSL_ARM) || defined(OPENSSL_X86)
void ecp_nistz256_sqr_mont(Elem r, const Elem a) {
  /* XXX: Inefficient. TODO: optimize with dedicated squaring routine. */
  ecp_nistz256_mul_mont(r, a, a);
}
#endif


static void scalar_mul_mont(ScalarMont r, const ScalarMont a,
                            const ScalarMont b) {
  /* XXX: Inefficient. TODO: optimize with dedicated multiplication routine. */
  bn_mul_mont(r, a, b, EC_GROUP_P256.order_mont.N.d,
              EC_GROUP_P256.order_mont.n0, P256_LIMBS);
}

static inline void scalar_sqr_mont(ScalarMont r, const ScalarMont a) {
  /* XXX: Inefficient. TODO: optimize with dedicated squaring routine. */
  scalar_mul_mont(r, a, a);
}

static inline void scalar_to_mont(ScalarMont r, const GFp_Limb a[P256_LIMBS]) {
  scalar_mul_mont(r, a, EC_GROUP_P256.order_mont.RR.d);
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
