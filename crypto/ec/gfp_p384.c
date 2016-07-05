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

#include "ecp_nistz384.h"
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
void GFp_p384_select_w5(P384_POINT *out, const P384_POINT table[16],
                        int index);
void GFp_p384_select_w7(P384_POINT_AFFINE *out,
                        const P384_POINT_AFFINE table[64], int index);



OPENSSL_COMPILE_ASSERT(sizeof(size_t) == sizeof(GFp_Limb),
                       size_t_and_gfp_limb_are_different_sizes);

OPENSSL_COMPILE_ASSERT(sizeof(size_t) == sizeof(BN_ULONG),
                       size_t_and_bn_ulong_are_different_sizes);


/* XXX: MSVC for x86 warns when it fails to inline these functions it should
 * probably inline. */
#if defined(_MSC_VER)  && defined(OPENSSL_X86)
#define INLINE_IF_POSSIBLE __forceinline
#else
#define INLINE_IF_POSSIBLE inline
#endif


static INLINE_IF_POSSIBLE GFp_Limb is_equal(const Elem a, const Elem b) {
  GFp_Limb eq = constant_time_is_zero(0);
  for (size_t i = 1; i < P384_LIMBS; ++i) {
    eq =
        constant_time_select_size_t(eq, constant_time_eq_size_t(a[i], b[i]), 0);
  }
  return eq;
}

static INLINE_IF_POSSIBLE void copy_conditional(Elem r, const Elem a,
                                                const GFp_Limb condition) {
  for (size_t i = 0; i < P384_LIMBS; ++i) {
    r[i] = constant_time_select_size_t(condition, a[i], r[i]);
  }
}

static const BN_ULONG ONE[P384_LIMBS] = {
  TOBN(0xffffffff, 1), TOBN(0, 0xffffffff), TOBN(0, 1), TOBN(0, 0), TOBN(0, 0),
  TOBN(0, 0),
};

static void elem_add(Elem r, const Elem a, const Elem b) {
  GFp_Limb carry =
      constant_time_is_nonzero_size_t(bn_add_words(r, a, b, P384_LIMBS));
  Elem adjusted;
  GFp_Limb no_borrow = constant_time_is_zero_size_t(
      bn_sub_words(adjusted, r, EC_GROUP_P384.mont.N.d, P384_LIMBS));
  copy_conditional(r, adjusted,
                   constant_time_select_size_t(carry, carry, no_borrow));
}

static void elem_sub(Elem r, const Elem a, const Elem b) {
  /* TODO: simplify the boolean logic here, e..g. by adding a
   * `constant_time_is_nonzero_size_t`. */
  GFp_Limb no_borrow =
    constant_time_is_zero_size_t(bn_sub_words(r, a, b, P384_LIMBS));
  Elem adjusted;
  (void)bn_add_words(adjusted, r, EC_GROUP_P384.mont.N.d, P384_LIMBS);
  GFp_Limb adjust = constant_time_is_zero_size_t(no_borrow);
  copy_conditional(r, adjusted, adjust);
}

static inline void elem_mul_mont(Elem r, const Elem a, const Elem b) {
  /* XXX: Not (clearly) constant-time; inefficient. TODO: Add a dedicated
   * squaring routine. */
  bn_mul_mont(r, a, b, EC_GROUP_P384.mont.N.d, EC_GROUP_P384.mont.n0,
              P384_LIMBS);
}

static inline void elem_mul_by_2(Elem r, const Elem a) {
  elem_add(r, a, a);
}

static INLINE_IF_POSSIBLE void elem_mul_by_3(Elem r, const Elem a) {
  ///* XXX: inefficient. TODO: Replace with an integrated shift + add. */
  static const Elem THREE = {
    TOBN(0xfffffffd, 3),
    TOBN(2, 0xffffffff),
    TOBN(0, 3),
  };
  elem_mul_mont(r, a, THREE);
}

static inline void elem_div_by_2(Elem r, const Elem a) {
  /* XXX: inefficient. TODO: Replace with a shift. */
  static const Elem HALF = {
    TOBN(0, 0),
    TOBN(0, 0),
    TOBN(0, 0),
    TOBN(0, 0),
    TOBN(0, 0),
    TOBN(0x80000000, 0),
  };
  elem_mul_mont(r, a, HALF);
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
  elem_add(r, a, b);
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
  /* XXX: Inefficient. TODO: Add dedicated multiplication routine. */
  bn_mul_mont(r, a, b, EC_GROUP_P384.order_mont.N.d,
              EC_GROUP_P384.order_mont.n0, P384_LIMBS);
}

static inline void scalar_sqr_mont(ScalarMont r, const ScalarMont a) {
  /* XXX: Inefficient. TODO: Add dedicated squaring routine. */
  scalar_mul_mont(r, a, a);
}

static inline void scalar_to_mont(ScalarMont r, const ScalarMont a) {
  scalar_mul_mont(r, a, EC_GROUP_P384.order_mont.RR.d);
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


#include "ecp_nistz384.inl"
