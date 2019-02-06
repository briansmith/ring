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


/* Prototypes to avoid -Wmissing-prototypes warnings. */
void GFp_p256_scalar_mul_mont(ScalarMont r, const ScalarMont a,
                              const ScalarMont b);
void GFp_p256_scalar_sqr_mont(ScalarMont r, const ScalarMont a);
void GFp_p256_scalar_sqr_rep_mont(ScalarMont r, const ScalarMont a, Limb rep);


#if defined(OPENSSL_ARM) || defined(OPENSSL_X86)
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
  assert(rep >= 1);
  GFp_p256_scalar_sqr_mont(r, a);
  for (Limb i = 1; i < rep; ++i) {
    GFp_p256_scalar_sqr_mont(r, r);
  }
}
#endif


#if !defined(OPENSSL_X86_64)

#include <string.h>

/* TODO(perf): Optimize these. */

void GFp_nistz256_select_w5(P256_POINT *out, const P256_POINT table[16],
                            int index) {
  assert(index >= 0);
  size_t index_s = (size_t)index; /* XXX: constant time? */

  alignas(32) Elem x; memset(x, 0, sizeof(x));
  alignas(32) Elem y; memset(y, 0, sizeof(y));
  alignas(32) Elem z; memset(z, 0, sizeof(z));

  for (size_t i = 0; i < 16; ++i) {
    Limb mask = constant_time_eq_w(index_s, i + 1);
    for (size_t j = 0; j < P256_LIMBS; ++j) {
      x[j] |= table[i].X[j] & mask;
      y[j] |= table[i].Y[j] & mask;
      z[j] |= table[i].Z[j] & mask;
    }
  }

  limbs_copy(out->X, x, P256_LIMBS);
  limbs_copy(out->Y, y, P256_LIMBS);
  limbs_copy(out->Z, z, P256_LIMBS);
}

void GFp_nistz256_select_w7(P256_POINT_AFFINE *out,
                            const P256_POINT_AFFINE table[64], int index) {
  assert(index >= 0);
  size_t index_as_s = (size_t)index; /* XXX: constant time? */

  alignas(32) Elem x; memset(x, 0, sizeof(x));
  alignas(32) Elem y; memset(y, 0, sizeof(y));

  for (size_t i = 0; i < 64; ++i) {
    Limb mask = constant_time_eq_w(index_as_s, i + 1);
    for (size_t j = 0; j < P256_LIMBS; ++j) {
      x[j] |= table[i].X[j] & mask;
      y[j] |= table[i].Y[j] & mask;
    }
  }

  limbs_copy(out->X, x, P256_LIMBS);
  limbs_copy(out->Y, y, P256_LIMBS);
}

#endif
