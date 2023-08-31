
/* Copyright 2016-2023 Brian Smith.
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

#include "../../limbs/limbs.h"
#include "../bn/internal.h"
#include "../../internal.h"

#include "../../limbs/limbs.inl"

#define BITS 384

#define P384_LIMBS (384u / LIMB_BITS)

#define FE_LIMBS P384_LIMBS

typedef Limb Elem[FE_LIMBS];
typedef Limb ScalarMont[FE_LIMBS];
typedef Limb Scalar[FE_LIMBS];

static const Elem Q = {
#if defined(OPENSSL_64_BIT)
  0xffffffff, 0xffffffff00000000, 0xfffffffffffffffe, 0xffffffffffffffff,
  0xffffffffffffffff, 0xffffffffffffffff
#else
  0xffffffff, 0, 0, 0xffffffff, 0xfffffffe, 0xffffffff, 0xffffffff, 0xffffffff,
  0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff
#endif
};

static const Elem N = {
#if defined(OPENSSL_64_BIT)
  0xecec196accc52973, 0x581a0db248b0a77a, 0xc7634d81f4372ddf, 0xffffffffffffffff,
  0xffffffffffffffff, 0xffffffffffffffff
#else
  0xccc52973, 0xecec196a, 0x48b0a77a, 0x581a0db2, 0xf4372ddf, 0xc7634d81,
  0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff
#endif
};

static const Elem ONE = {
#if defined(OPENSSL_64_BIT)
  0xffffffff00000001, 0xffffffff, 1, 0, 0
#else
  1, 0xffffffff, 0xffffffff, 0, 1, 0, 0, 0, 0, 0
#endif
};

static const Elem Q_PLUS_1_SHR_1 = {
#if defined(OPENSSL_64_BIT)
  0x80000000, 0x7fffffff80000000, 0xffffffffffffffff, 0xffffffffffffffff,
  0xffffffffffffffff, 0x7fffffffffffffff
#else
  0x80000000, 0, 0x80000000, 0x7fffffff, 0xffffffff, 0xffffffff, 0xffffffff,
  0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0x7fffffff
#endif
};

static const BN_ULONG Q_N0[] = {
  BN_MONT_CTX_N0(1, 1)
};

static const BN_ULONG N_N0[] = {
  BN_MONT_CTX_N0(0x6ed46089, 0xe88fdc45)
};

/* XXX: MSVC for x86 warns when it fails to inline these functions it should
 * probably inline. */
#if defined(_MSC_VER) && !defined(__clang__) && defined(OPENSSL_X86)
#define INLINE_IF_POSSIBLE __forceinline
#else
#define INLINE_IF_POSSIBLE inline
#endif

/* Window values that are Ok for P384 (look at `ecp_nistz.h`): 2, 5, 6, 7 */
/* Window values that are Ok for P521 (look at `ecp_nistz.h`): 4 */
#define W_BITS 5

#include "ecp_nistz.inl"

