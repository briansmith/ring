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

#if defined(_MSC_VER)
#include <intrin.h>
/* MSVC 2015 RC, when compiling for x86 with /Ox (at least), miscompiles
 * _addcarry_u32(c, 0, prod_hi, &x) like so:
 *
 *     add eax,esi ; The previous add that might have set the carry flag.
 *     xor esi,esi ; OOPS! Carry flag is now reset!
 *     mov dword ptr [edi-4],eax
 *     adc esi,dword ptr [prod_hi]
 *
 * We test with MSVC 2015 update 2, so make sure we're using a version at least
 * as new as that. */
#if _MSC_FULL_VER < 190023918
#error "MSVC 2015 or later is required."
#endif
typedef uint8_t GFp_Carry;
#if GFp_LIMB_BITS == 64
#pragma intrinsic(_subborrow_u64)
#define GFp_SUBBORROW_INTRINSIC _subborrow_u64
#elif GFp_LIMB_BITS == 32
#pragma intrinsic(_subborrow_u32)
#define GFp_SUBBORROW_INTRINSIC _subborrow_u32
typedef uint64_t GFp_DoubleLimb;
#endif
#else
typedef GFp_Limb GFp_Carry;
#if GFp_LIMB_BITS == 64
typedef __uint128_t GFp_DoubleLimb;
#elif GFp_LIMB_BITS == 32
typedef uint64_t GFp_DoubleLimb;
#endif
#endif

/* |*r = a - b - borrow_in|, returning the borrow out bit. |borrow_in| must be
 * 0 or 1. */
static inline GFp_Carry gfp_sbb(GFp_Limb *r, GFp_Limb a, GFp_Limb b,
                                GFp_Carry borrow_in) {
  assert(borrow_in == 0 || borrow_in == 1);
  GFp_Carry ret;
#if defined(GFp_SUBBORROW_INTRINSIC)
  ret = GFp_SUBBORROW_INTRINSIC(borrow_in, a, b, r);
#else
  GFp_DoubleLimb x = (GFp_DoubleLimb)a - b - borrow_in;
  *r = (GFp_Limb)x;
  ret = (GFp_Carry)((x >> GFp_LIMB_BITS) & 1);
#endif
  assert(ret == 0 || ret == 1);
  return ret;
}

/* |*r = a - b|, returning borrow bit. */
static inline GFp_Carry gfp_sub(GFp_Limb *r, GFp_Limb a, GFp_Limb b) {
  GFp_Carry ret;
#if defined(GFp_SUBBORROW_INTRINSIC)
  ret = GFp_SUBBORROW_INTRINSIC(0, a, b, r);
#else
  GFp_DoubleLimb x = (GFp_DoubleLimb)a - b;
  *r = (GFp_Limb)x;
  ret = (GFp_Carry)((x >> GFp_LIMB_BITS) & 1);
#endif
  assert(ret == 0 || ret == 1);
  return ret;
}
