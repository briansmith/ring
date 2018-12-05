/* Copyright (c) 2018, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include <assert.h>

#include "internal.h"


// The following functions use a Barrett reduction variant to avoid leaking the
// numerator. See http://ridiculousfish.com/blog/posts/labor-of-division-episode-i.html
//
// We use 32-bit numerator and 16-bit divisor for simplicity. This allows
// computing |m| and |q| without architecture-specific code.

// mod_u16 returns |n| mod |d|. |p| and |m| are the "magic numbers" for |d| (see
// reference). For proof of correctness in Coq, see
// https://github.com/davidben/fiat-crypto/blob/barrett/src/Arithmetic/BarrettReduction/RidiculousFish.v
// Note the Coq version of |mod_u16| additionally includes the computation of
// |p| and |m| from |bn_mod_u16_consttime| below.
static uint16_t mod_u16(uint32_t n, uint16_t d, uint32_t p, uint32_t m) {
  // Compute floor(n/d) per steps 3 through 5.
  uint32_t q = ((uint64_t)m * n) >> 32;
  // Note there is a typo in the reference. We right-shift by one, not two.
  uint32_t t = ((n - q) >> 1) + q;
  t = t >> (p - 1);

  // Multiply and subtract to get the remainder.
  n -= d * t;
  assert(n < d);
  return n;
}

// shift_and_add_mod_u16 returns |r| * 2^32 + |a| mod |d|. |p| and |m| are the
// "magic numbers" for |d| (see reference).
static uint16_t shift_and_add_mod_u16(uint16_t r, uint32_t a, uint16_t d,
                                      uint32_t p, uint32_t m) {
  // Incorporate |a| in two 16-bit chunks.
  uint32_t t = r;
  t <<= 16;
  t |= a >> 16;
  t = mod_u16(t, d, p, m);

  t <<= 16;
  t |= a & 0xffff;
  t = mod_u16(t, d, p, m);
  return t;
}


// Function taken from boringssl's bn.c file.
// BN_num_bits_word returns the minimum number of bits needed to represent the
// value in |l|.
static unsigned BN_num_bits_word(BN_ULONG l) {
  // |BN_num_bits| is often called on RSA prime factors. These have public bit
  // lengths, but all bits beyond the high bit are secret, so count bits in
  // constant time.
  BN_ULONG x, mask;
  int bits = (l != 0);

#if BN_BITS2 > 32
  // Look at the upper half of |x|. |x| is at most 64 bits long.
  x = l >> 32;
  // Set |mask| to all ones if |x| (the top 32 bits of |l|) is non-zero and all
  // all zeros otherwise.
  mask = 0u - x;
  mask = (0u - (mask >> (BN_BITS2 - 1)));
  // If |x| is non-zero, the lower half is included in the bit count in full,
  // and we count the upper half. Otherwise, we count the lower half.
  bits += 32 & mask;
  l ^= (x ^ l) & mask;  // |l| is |x| if |mask| and remains |l| otherwise.
#endif

  // The remaining blocks are analogous iterations at lower powers of two.
  x = l >> 16;
  mask = 0u - x;
  mask = (0u - (mask >> (BN_BITS2 - 1)));
  bits += 16 & mask;
  l ^= (x ^ l) & mask;

  x = l >> 8;
  mask = 0u - x;
  mask = (0u - (mask >> (BN_BITS2 - 1)));
  bits += 8 & mask;
  l ^= (x ^ l) & mask;

  x = l >> 4;
  mask = 0u - x;
  mask = (0u - (mask >> (BN_BITS2 - 1)));
  bits += 4 & mask;
  l ^= (x ^ l) & mask;

  x = l >> 2;
  mask = 0u - x;
  mask = (0u - (mask >> (BN_BITS2 - 1)));
  bits += 2 & mask;
  l ^= (x ^ l) & mask;

  x = l >> 1;
  mask = 0u - x;
  mask = (0u - (mask >> (BN_BITS2 - 1)));
  bits += 1 & mask;

  return bits;
}

uint16_t bn_mod_u16_consttime(const BN_ULONG bn[], size_t num_limbs, uint16_t d) {
  if (d <= 1) {
    return 0;
  }

  // Compute the "magic numbers" for |d|. See steps 1 and 2.
  // This computes p = ceil(log_2(d)).
  uint32_t p = BN_num_bits_word(d - 1);
  // This operation is not constant-time, but |p| and |d| are public values.
  // Note that |p| is at most 16, so the computation fits in |uint64_t|.
  assert(p <= 16);
  uint32_t m = ((UINT64_C(1) << (32 + p)) + d - 1) / d;

  uint16_t ret = 0;
  for (int i = num_limbs - 1; i >= 0; i--) {
#if BN_BITS2 == 32
    ret = shift_and_add_mod_u16(ret, bn[i], d, p, m);
#elif BN_BITS2 == 64
    ret = shift_and_add_mod_u16(ret, bn[i] >> 32, d, p, m);
    ret = shift_and_add_mod_u16(ret, bn[i] & 0xffffffff, d, p, m);
#else
#error "Unknown BN_ULONG size"
#endif
  }
  return ret;
}
