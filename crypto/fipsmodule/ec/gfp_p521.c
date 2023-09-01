
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

#define BITS 521

#define P521_LIMBS ((521 + LIMB_BITS - 1) / LIMB_BITS)

#define FE_LIMBS P521_LIMBS

typedef Limb Elem[FE_LIMBS];
typedef Limb ScalarMont[FE_LIMBS];
typedef Limb Scalar[FE_LIMBS];

static const Elem Q = {
#if defined(OPENSSL_64_BIT)
  0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
  0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
  0x1ff
#else
  0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
  0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
  0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0x1ff
#endif
};

static const Elem N = {
#if defined(OPENSSL_64_BIT)
  0xbb6fb71e91386409, 0x3bb5c9b8899c47ae, 0x7fcc0148f709a5d0, 0x51868783bf2f966b,
  0xfffffffffffffffa, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
  0x1ff
#else
  0x91386409, 0xbb6fb71e, 0x899c47ae, 0x3bb5c9b8, 0xf709a5d0, 0x7fcc0148,
  0xbf2f966b, 0x51868783, 0xfffffffa, 0xffffffff, 0xffffffff, 0xffffffff,
  0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0x1ff
#endif
};

static const Elem ONE = {
#if defined(OPENSSL_64_BIT)
  0x80000000000000, 0, 0, 0, 0, 0, 0, 0, 0
#else
  0x800000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
#endif
};

static const Elem Q_PLUS_1_SHR_1 = {
#if defined(OPENSSL_64_BIT)
  0, 0, 0, 0, 0, 0, 0, 0, 0x100
#else
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x100
#endif
};

static const BN_ULONG Q_N0[] = {
  BN_MONT_CTX_N0(0, 1)
};

static const BN_ULONG N_N0[] = {
  BN_MONT_CTX_N0(0x1d2f5ccd, 0x79a995c7)
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
#define W_BITS 4

#include "ecp_nistz.inl"

