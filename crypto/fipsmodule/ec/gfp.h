/* Copyright 2016-2024 Brian Smith.
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

#define RENAME_FUNC(prefix, bits, func) prefix ## bits ## _ ## func

typedef struct {
  Limb X[FE_LIMBS];
  Limb Y[FE_LIMBS];
  Limb Z[FE_LIMBS];
} NIST_POINT;

typedef struct {
  Limb X[FE_LIMBS];
  Limb Y[FE_LIMBS];
} NIST_POINT_AFFINE;

#define TBL_SZ (1 << (W_BITS - 1))
#define W_MASK ((1 << (W_BITS + 1)) - 1)

static inline Limb is_equal(const Elem a, const Elem b) {
  return LIMBS_equal(a, b, FE_LIMBS);
}

static inline Limb is_zero(const BN_ULONG a[FE_LIMBS]) {
  return LIMBS_are_zero(a, FE_LIMBS);
}

static inline void copy_conditional(Elem r, const Elem a,
                                                const Limb condition) {
  for (size_t i = 0; i < FE_LIMBS; ++i) {
    r[i] = constant_time_select_w(condition, a[i], r[i]);
  }
}

static inline void elem_add(Elem r, const Elem a, const Elem b) {
  LIMBS_add_mod(r, a, b, Q, FE_LIMBS);
}

static inline void elem_sub(Elem r, const Elem a, const Elem b) {
  LIMBS_sub_mod(r, a, b, Q, FE_LIMBS);
}

static void elem_div_by_2(Elem r, const Elem a) {
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
  Limb carry = a[FE_LIMBS - 1] & 1;
  r[FE_LIMBS - 1] = a[FE_LIMBS - 1] >> 1;
  for (size_t i = 1; i < FE_LIMBS; ++i) {
    Limb new_carry = a[FE_LIMBS - i - 1];
    r[FE_LIMBS - i - 1] =
        (a[FE_LIMBS - i - 1] >> 1) | (carry << (LIMB_BITS - 1));
    carry = new_carry;
  }

  Elem adjusted;
  BN_ULONG carry2 = limbs_add(adjusted, r, Q_PLUS_1_SHR_1, FE_LIMBS);
  dev_assert_secret(carry2 == 0);
  (void)carry2;
  copy_conditional(r, adjusted, is_odd);
}

static inline void elem_mul_mont(Elem r, const Elem a, const Elem b) {
  /* XXX: Not (clearly) constant-time; inefficient.*/
  bn_mul_mont(r, a, b, Q, Q_N0, FE_LIMBS);
}

static inline void elem_mul_by_2(Elem r, const Elem a) {
  LIMBS_shl_mod(r, a, Q, FE_LIMBS);
}

static INLINE_IF_POSSIBLE void elem_mul_by_3(Elem r, const Elem a) {
  /* XXX: inefficient. TODO: Replace with an integrated shift + add. */
  Elem doubled;
  elem_add(doubled, a, a);
  elem_add(r, doubled, a);
}

static inline void elem_sqr_mont(Elem r, const Elem a) {
  /* XXX: Inefficient. TODO: Add a dedicated squaring routine. */
  elem_mul_mont(r, a, a);
}

static void elem_neg(Elem r, const Elem a) {
  Limb is_zero = LIMBS_are_zero(a, FE_LIMBS);
  Carry borrow = limbs_sub(r, Q, a, FE_LIMBS);
  dev_assert_secret(borrow == 0);
  (void)borrow;
  for (size_t i = 0; i < FE_LIMBS; ++i) {
    r[i] = constant_time_select_w(is_zero, 0, r[i]);
  }
}

static void NIST_POINT_select_w(NIST_POINT *out,
                                const NIST_POINT table[TBL_SZ], size_t index) {
  Elem x; limbs_zero(x, FE_LIMBS);
  Elem y; limbs_zero(y, FE_LIMBS);
  Elem z; limbs_zero(z, FE_LIMBS);

  // TODO: Rewrite in terms of |limbs_select|.
  for (size_t i = 0; i < TBL_SZ; ++i) {
    crypto_word_t equal = constant_time_eq_w(index, (crypto_word_t)i + 1);
    for (size_t j = 0; j < FE_LIMBS; ++j) {
      x[j] = constant_time_select_w(equal, table[i].X[j], x[j]);
      y[j] = constant_time_select_w(equal, table[i].Y[j], y[j]);
      z[j] = constant_time_select_w(equal, table[i].Z[j], z[j]);
    }
  }

  limbs_copy(out->X, x, FE_LIMBS);
  limbs_copy(out->Y, y, FE_LIMBS);
  limbs_copy(out->Z, z, FE_LIMBS);
}

#define bits_elem_neg(prefix, bits) RENAME_FUNC(prefix, bits, elem_neg)
#define bits_elem_sub(prefix, bits) RENAME_FUNC(prefix, bits, elem_sub)
#define bits_elem_div_by_2(prefix, bits) RENAME_FUNC(prefix, bits, elem_div_by_2)
#define bits_elem_mul_mont(prefix, bits) RENAME_FUNC(prefix, bits, elem_mul_mont)
#define bits_scalar_mul_mont(prefix, bits) RENAME_FUNC(prefix, bits, scalar_mul_mont)

void bits_elem_neg(p, BITS)(Elem r, const Elem a) {
  elem_neg(r, a);
}

void bits_elem_sub(p, BITS)(Elem r, const Elem a, const Elem b) {
  elem_sub(r, a, b);
}

void bits_elem_div_by_2(p, BITS)(Elem r, const Elem a) {
  elem_div_by_2(r, a);
}

void bits_elem_mul_mont(p, BITS)(Elem r, const Elem a, const Elem b) {
  elem_mul_mont(r, a, b);
}

void bits_scalar_mul_mont(p, BITS)(ScalarMont r, const ScalarMont a,
                              const ScalarMont b) {
  /* XXX: Inefficient. TODO: Add dedicated multiplication routine. */
  bn_mul_mont(r, a, b, N, N_N0, FE_LIMBS);
}
