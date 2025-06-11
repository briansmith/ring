/* Copyright (c) 2014, Google Inc.
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

// This implementation of poly1305 is by Andrew Moon
// (https://github.com/floodyberry/poly1305-donna) and released as public
// domain.

#include <ring-core/base.h>

#include "../internal.h"
#include "ring-core/check.h"

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wconversion"
#endif

static uint64_t mul32x32_64(uint32_t a, uint32_t b) { return (uint64_t)a * b; }

// Keep in sync with `poly1305_state_st` in ffi_fallback.rs.
struct poly1305_state_st {
  alignas(64) uint32_t r0;
  uint32_t r1, r2, r3, r4;
  uint32_t s1, s2, s3, s4;
  uint32_t h0, h1, h2, h3, h4;
  uint8_t key[16];
};

static inline void poly1305_mul(struct poly1305_state_st *state);

// poly1305_blocks updates |state| given some amount of input data.
static void poly1305_update_16(
    struct poly1305_state_st *state, const uint8_t *in,
    size_t len) {
  debug_assert_nonsecret(len >= 16);
  debug_assert_nonsecret(len % 16 == 0);
  debug_assert_nonsecret((uintptr_t)state % 64 == 0);

  uint32_t t0, t1, t2, t3;

  do {
    t0 = CRYPTO_load_u32_le(in);
    t1 = CRYPTO_load_u32_le(in + 4);
    t2 = CRYPTO_load_u32_le(in + 8);
    t3 = CRYPTO_load_u32_le(in + 12);

    in += 16;
    len -= 16;

    state->h0 += t0 & 0x3ffffff;
    state->h1 += ((((uint64_t)t1 << 32) | t0) >> 26) & 0x3ffffff;
    state->h2 += ((((uint64_t)t2 << 32) | t1) >> 20) & 0x3ffffff;
    state->h3 += ((((uint64_t)t3 << 32) | t2) >> 14) & 0x3ffffff;
    state->h4 += (t3 >> 8) | (1 << 24);

    poly1305_mul(state);
  } while (len > 0);
}

static inline void poly1305_mul(struct poly1305_state_st *state) {
  uint64_t t[5];
  uint32_t b;
  uint64_t c;

  t[0] = mul32x32_64(state->h0, state->r0) + mul32x32_64(state->h1, state->s4) +
         mul32x32_64(state->h2, state->s3) + mul32x32_64(state->h3, state->s2) +
         mul32x32_64(state->h4, state->s1);
  t[1] = mul32x32_64(state->h0, state->r1) + mul32x32_64(state->h1, state->r0) +
         mul32x32_64(state->h2, state->s4) + mul32x32_64(state->h3, state->s3) +
         mul32x32_64(state->h4, state->s2);
  t[2] = mul32x32_64(state->h0, state->r2) + mul32x32_64(state->h1, state->r1) +
         mul32x32_64(state->h2, state->r0) + mul32x32_64(state->h3, state->s4) +
         mul32x32_64(state->h4, state->s3);
  t[3] = mul32x32_64(state->h0, state->r3) + mul32x32_64(state->h1, state->r2) +
         mul32x32_64(state->h2, state->r1) + mul32x32_64(state->h3, state->r0) +
         mul32x32_64(state->h4, state->s4);
  t[4] = mul32x32_64(state->h0, state->r4) + mul32x32_64(state->h1, state->r3) +
         mul32x32_64(state->h2, state->r2) + mul32x32_64(state->h3, state->r1) +
         mul32x32_64(state->h4, state->r0);

  state->h0 = (uint32_t)t[0] & 0x3ffffff;
  c = (t[0] >> 26);
  t[1] += c;
  state->h1 = (uint32_t)t[1] & 0x3ffffff;
  b = (uint32_t)(t[1] >> 26);
  t[2] += b;
  state->h2 = (uint32_t)t[2] & 0x3ffffff;
  b = (uint32_t)(t[2] >> 26);
  t[3] += b;
  state->h3 = (uint32_t)t[3] & 0x3ffffff;
  b = (uint32_t)(t[3] >> 26);
  t[4] += b;
  state->h4 = (uint32_t)t[4] & 0x3ffffff;
  b = (uint32_t)(t[4] >> 26);
  state->h0 += b * 5;
}

// final bytes
static void poly1305_update_final_atmost15bytes(
    struct poly1305_state_st *state, const uint8_t *in,
    size_t len) {
  debug_assert_nonsecret(len < 16);

  size_t j;
  uint32_t t0, t1, t2, t3;
  uint8_t mp[16];

  if (!len) {
    return;
  }

  for (j = 0; j < len; j++) {
    mp[j] = in[j];
  }
  mp[j++] = 1;
  for (; j < 16; j++) {
    mp[j] = 0;
  }
  len = 0;

  t0 = CRYPTO_load_u32_le(mp + 0);
  t1 = CRYPTO_load_u32_le(mp + 4);
  t2 = CRYPTO_load_u32_le(mp + 8);
  t3 = CRYPTO_load_u32_le(mp + 12);

  state->h0 += t0 & 0x3ffffff;
  state->h1 += ((((uint64_t)t1 << 32) | t0) >> 26) & 0x3ffffff;
  state->h2 += ((((uint64_t)t2 << 32) | t1) >> 20) & 0x3ffffff;
  state->h3 += ((((uint64_t)t3 << 32) | t2) >> 14) & 0x3ffffff;
  state->h4 += (t3 >> 8);

  poly1305_mul(state);
}

void CRYPTO_poly1305_update(struct poly1305_state_st *state, const uint8_t *in,
                            size_t in_len) {
  size_t remainder_len = in_len % 16;
  size_t whole_len = in_len - remainder_len;
  if (whole_len > 0) {
    poly1305_update_16(state, in, whole_len);
  }
  if (remainder_len > 0) {
    poly1305_update_final_atmost15bytes(state, in + whole_len, remainder_len);
  }
}
