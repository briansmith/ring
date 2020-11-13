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
#include "../../limbs/limbs.h"

#include "../../internal.h"
#include "../bn/internal.h"
#include "../../limbs/limbs.inl"

typedef Limb Elem[P256_LIMBS];
typedef Limb ScalarMont[P256_LIMBS];
typedef Limb Scalar[P256_LIMBS];

void GFp_p256_scalar_sqr_rep_mont(ScalarMont r, const ScalarMont a, Limb rep);

#if defined(OPENSSL_ARM) || defined(OPENSSL_X86) || defined(OPENSSL_S390X)
void GFp_nistz256_sqr_mont(Elem r, const Elem a) {
  /* XXX: Inefficient. TODO: optimize with dedicated squaring routine. */
  GFp_nistz256_mul_mont(r, a, a);
}
#endif

#if !defined(OPENSSL_X86_64)
void GFp_p256_scalar_mul_mont(ScalarMont r, const ScalarMont a,
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
  GFp_bn_mul_mont(r, a, b, N, N_N0, P256_LIMBS);
}
#endif

#if defined(OPENSSL_X86_64)
void GFp_p256_scalar_sqr_mont(ScalarMont r, const ScalarMont a) {
  GFp_p256_scalar_sqr_rep_mont(r, a, 1);
}
#else
void GFp_p256_scalar_sqr_mont(ScalarMont r, const ScalarMont a) {
  GFp_p256_scalar_mul_mont(r, a, a);
}

void GFp_p256_scalar_sqr_rep_mont(ScalarMont r, const ScalarMont a, Limb rep) {
  dev_assert_secret(rep >= 1);
  GFp_p256_scalar_sqr_mont(r, a);
  for (Limb i = 1; i < rep; ++i) {
    GFp_p256_scalar_sqr_mont(r, r);
  }
}
#endif


#if !defined(OPENSSL_X86_64)

/* TODO(perf): Optimize these. */

void GFp_nistz256_select_w5(P256_POINT *out, const P256_POINT table[16],
                            crypto_word index) {
  dev_assert_secret(index >= 0);

  alignas(32) Elem x; limbs_zero(x, P256_LIMBS);
  alignas(32) Elem y; limbs_zero(y, P256_LIMBS);
  alignas(32) Elem z; limbs_zero(z, P256_LIMBS);

  // TODO: Rewrite in terms of |limbs_select|.
  for (size_t i = 0; i < 16; ++i) {
    crypto_word equal = constant_time_eq_w(index, (crypto_word)i + 1);
    for (size_t j = 0; j < P256_LIMBS; ++j) {
      x[j] = constant_time_select_w(equal, table[i].X[j], x[j]);
      y[j] = constant_time_select_w(equal, table[i].Y[j], y[j]);
      z[j] = constant_time_select_w(equal, table[i].Z[j], z[j]);
    }
  }

  limbs_copy(out->X, x, P256_LIMBS);
  limbs_copy(out->Y, y, P256_LIMBS);
  limbs_copy(out->Z, z, P256_LIMBS);
}

#if defined GFp_USE_LARGE_TABLE
void GFp_nistz256_select_w7(P256_POINT_AFFINE *out,
                            const PRECOMP256_ROW table, crypto_word index) {
  alignas(32) Limb xy[P256_LIMBS * 2];
  limbs_select(xy, table, P256_LIMBS * 2, 64, index - 1);
  limbs_copy(out->X, &xy[0], P256_LIMBS);
  limbs_copy(out->Y, &xy[P256_LIMBS], P256_LIMBS);
}
#endif

#endif

#ifdef OPENSSL_S390X

static const BN_ULONG Q[P256_LIMBS] = {
  TOBN(0xffffffff, 0xffffffff),
  TOBN(0x00000000, 0xffffffff),
  TOBN(0x00000000, 0x00000000),
  TOBN(0xffffffff, 0x00000001),
};

/* One converted into the Montgomery domain */
static const BN_ULONG ONE[P256_LIMBS] = {
  TOBN(0x00000000, 0x00000001),
  TOBN(0xffffffff, 0x00000000),
  TOBN(0xffffffff, 0xffffffff),
  TOBN(0x00000000, 0xfffffffe)
};

static inline Limb is_equal(const Elem a, const Elem b) {
  return LIMBS_equal(a, b, P256_LIMBS);
}

static inline void copy_conditional(Elem r, const Elem a,
                                    const Limb condition) {
  for (size_t i = 0; i < P256_LIMBS; ++i) {
    r[i] = constant_time_select_w(condition, a[i], r[i]);
  }
}

static inline void elem_add(Elem r, const Elem a, const Elem b) {
  LIMBS_add_mod(r, a, b, Q, P256_LIMBS);
}

static inline void elem_sub(Elem r, const Elem a, const Elem b) {
  LIMBS_sub_mod(r, a, b, Q, P256_LIMBS);
}

static void elem_div_by_2(Elem r, const Elem a) {
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

  static const Elem Q_PLUS_1_SHR_1 = {
    TOBN(0x00000000, 0x00000000),
    TOBN(0x00000000, 0x80000000),
    TOBN(0x80000000, 0x00000000),
    TOBN(0x7fffffff, 0x80000000),
  };

  Elem adjusted;
  BN_ULONG carry2 = limbs_add(adjusted, r, Q_PLUS_1_SHR_1, P256_LIMBS);
#if defined(NDEBUG)
  (void)carry2;
#endif
  assert(carry2 == 0);

  copy_conditional(r, adjusted, is_odd);
}

static inline void elem_mul_mont(Elem r, const Elem a, const Elem b) {
  static const BN_ULONG Q_N0[] = {
    BN_MONT_CTX_N0(0x0, 0x1)
  };
  /* XXX: Not (clearly) constant-time; inefficient.*/
  GFp_bn_mul_mont(r, a, b, Q, Q_N0, P256_LIMBS);
}

static inline void elem_mul_by_2(Elem r, const Elem a) {
  LIMBS_shl_mod(r, a, Q, P256_LIMBS);
}

static inline void elem_mul_by_3(Elem r, const Elem a) {
  /* XXX: inefficient. TODO: Replace with an integrated shift + add. */
  Elem doubled;
  elem_add(doubled, a, a);
  elem_add(r, doubled, a);
}

static inline void elem_sqr_mont(Elem r, const Elem a) {
  /* XXX: Inefficient. TODO: Add a dedicated squaring routine. */
  elem_mul_mont(r, a, a);
}

void GFp_nistz256_add(Elem r, const Elem a, const Elem b) {
  elem_add(r, a, b);
}

void GFp_nistz256_mul_mont(Elem r, const Elem a, const Elem b) {
  elem_mul_mont(r, a, b);
}

void GFp_nistz256_neg(Elem r, const Elem a) {
  Limb is_zero = LIMBS_are_zero(a, P256_LIMBS);
  Carry borrow = limbs_sub(r, Q, a, P256_LIMBS);
#if defined(NDEBUG)
  (void)borrow;
#endif
  assert(borrow == 0);
  for (size_t i = 0; i < P256_LIMBS; ++i) {
    r[i] = constant_time_select_w(is_zero, 0, r[i]);
  }
}

static BN_ULONG is_zero(const BN_ULONG a[P256_LIMBS]) {
  BN_ULONG acc = 0;
  for (size_t i = 0; i < P256_LIMBS; ++i) {
    acc |= a[i];
  }
  return constant_time_is_zero_w(acc);
}

/* Point double: r = 2*a */
void GFp_nistz256_point_double(P256_POINT *r, const P256_POINT *a) {
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

/* Point addition: r = a+b */
void GFp_nistz256_point_add(P256_POINT *r, const P256_POINT *a,
                            const P256_POINT *b) {
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

  /* This should not happen during sign/ecdh,
   * so no constant time violation */
  if (is_equal(U1, U2) && !in1infty && !in2infty) {
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

/* Point addition when b is known to be affine: r = a+b */
void GFp_nistz256_point_add_affine(P256_POINT *r, const P256_POINT *a,
                                   const P256_POINT_AFFINE *b) {
  BN_ULONG U2[P256_LIMBS], S2[P256_LIMBS];
  BN_ULONG Z1sqr[P256_LIMBS];
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

  BN_ULONG in1infty = is_zero(a->Z);
  BN_ULONG in2infty = is_zero(b->X) & is_zero(b->Y);

  elem_sqr_mont(Z1sqr, in1_z);        /* Z1^2 */

  elem_mul_mont(U2, in2_x, Z1sqr);    /* U2 = X2*Z1^2 */
  elem_sub(H, U2, in1_x);             /* H = U2 - U1 */

  elem_mul_mont(S2, Z1sqr, in1_z);    /* S2 = Z1^3 */

  elem_mul_mont(res_z, H, in1_z);     /* Z3 = H*Z1*Z2 */

  elem_mul_mont(S2, S2, in2_y);       /* S2 = Y2*Z1^3 */
  elem_sub(R, S2, in1_y);             /* R = S2 - S1 */

  elem_sqr_mont(Hsqr, H);             /* H^2 */
  elem_sqr_mont(Rsqr, R);             /* R^2 */
  elem_mul_mont(Hcub, Hsqr, H);       /* H^3 */

  elem_mul_mont(U2, in1_x, Hsqr);     /* U1*H^2 */
  elem_mul_by_2(Hsqr, U2);            /* 2*U1*H^2 */

  elem_sub(res_x, Rsqr, Hsqr);
  elem_sub(res_x, res_x, Hcub);
  elem_sub(H, U2, res_x);

  elem_mul_mont(S2, in1_y, Hcub);
  elem_mul_mont(H, H, R);
  elem_sub(res_y, H, S2);

  copy_conditional(res_x, in2_x, in1infty);
  copy_conditional(res_x, in1_x, in2infty);

  copy_conditional(res_y, in2_y, in1infty);
  copy_conditional(res_y, in1_y, in2infty);

  copy_conditional(res_z, ONE, in1infty);
  copy_conditional(res_z, in1_z, in2infty);

  limbs_copy(r->X, res_x, P256_LIMBS);
  limbs_copy(r->Y, res_y, P256_LIMBS);
  limbs_copy(r->Z, res_z, P256_LIMBS);
}

#endif

