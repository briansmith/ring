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

#include "./p256_shared.h"

#include "../../limbs/limbs.h"

#if !defined(OPENSSL_USE_NISTZ256)

typedef Limb ScalarMont[P256_LIMBS];
typedef Limb Scalar[P256_LIMBS];

#include "../bn/internal.h"

void GFp_p256_scalar_sqr_rep_mont(ScalarMont r, const ScalarMont a, Limb rep);

#if defined(OPENSSL_ARM) || defined(OPENSSL_X86) || defined(OPENSSL_MIPS64)
void GFp_nistz256_sqr_mont(Elem r, const Elem a) {
  /* XXX: Inefficient. TODO: optimize with dedicated squaring routine. */
  GFp_nistz256_mul_mont(r, a, a);
}
#endif

#if defined(OPENSSL_MIPS64)

static const BN_ULONG Q[P256_LIMBS] = {
  TOBN(0xffffffff, 0xffffffff),
  TOBN(0x00000000, 0xffffffff),
  TOBN(0x00000000, 0x00000000),
  TOBN(0xffffffff, 0x00000001),
};

void GFp_nistz256_neg(Elem r, const Elem a) {
  Limb is_zero = LIMBS_are_zero(a, P256_LIMBS);
  Carry borrow = limbs_sub(r, Q, a, P256_LIMBS);
#if defined(NDEBUG)
  (void)borrow;
#endif
  ASSERT(borrow == 0);
  for (size_t i = 0; i < P256_LIMBS; ++i) {
    r[i] = constant_time_select_w(is_zero, 0, r[i]);
  }
}

static inline void elem_mul_mont(Elem r, const Elem a, const Elem b) {
  static const BN_ULONG Q_N0[] = {
    BN_MONT_CTX_N0(0x0, 0x1)
  };
  /* XXX: Not (clearly) constant-time; inefficient.*/
  GFp_bn_mul_mont(r, a, b, Q, Q_N0, P256_LIMBS);
}

void GFp_nistz256_mul_mont(Elem r, const Elem a, const Elem b) {
  elem_mul_mont(r, a, b);
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

/* XXX: Inefficient. TODO: optimize with dedicated squaring routine. */
void GFp_p256_scalar_sqr_rep_mont(ScalarMont r, const ScalarMont a, Limb rep) {
  dev_assert_secret(rep >= 1);
  GFp_p256_scalar_mul_mont(r, a, a);
  for (Limb i = 1; i < rep; ++i) {
    GFp_p256_scalar_mul_mont(r, r, r);
  }
}
#endif

#endif
