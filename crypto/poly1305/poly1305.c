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

/* This implementation of poly1305 is by Andrew Moon
 * (https://github.com/floodyberry/poly1305-donna) and released as public
 * domain. */

#include <openssl/poly1305.h>

#include <assert.h>
#include <string.h>

#include <openssl/type_check.h>

#include "../internal.h"


#define POLY1305_BLOCK_STATE_SIZE 192

typedef void (*poly1305_blocks_t)(void *ctx, const uint8_t *in, size_t len,
                                  uint32_t padbit);
typedef void (*poly1305_emit_t)(void *ctx, uint8_t mac[16],
                                const uint32_t nonce[4]);

struct poly1305_state_st {
  alignas(8) uint8_t opaque[POLY1305_BLOCK_STATE_SIZE];
  uint32_t nonce[4];
  uint8_t buf[16];
  unsigned buf_used;
  struct {
    poly1305_blocks_t blocks;
    poly1305_emit_t emit;
  } func;
};

OPENSSL_COMPILE_ASSERT(sizeof(poly1305_state) >=
                           sizeof(struct poly1305_state_st),
                       poly1305_state_too_small);

/* We can assume little-endian. */
static uint32_t U8TO32_LE(const uint8_t *m) {
  uint32_t r;
  memcpy(&r, m, sizeof(r));
  return r;
}

#if !defined(OPENSSL_NO_ASM)
#if defined(OPENSSL_X86)
/* See comment above |_poly1305_init_sse2| in poly1305-x86.pl. */
OPENSSL_COMPILE_ASSERT(POLY1305_BLOCK_STATE_SIZE >= 4 * (5 + 1 + 4 + 2 + 4 * 9),
                       poly1305_block_state_too_small);
#define POLY1305_ASM
#elif defined(OPENSSL_X86_64)
/* See comment above |__poly1305_block| in poly1305-x86_64.pl. */
OPENSSL_COMPILE_ASSERT(POLY1305_BLOCK_STATE_SIZE >=
                           4 * (5 + 1 + 2 * 2 + 2 + 4 * 9),
                       poly1305_block_state_too_small);
#define POLY1305_ASM
#elif defined(OPENSSL_ARM)
/* TODO(davidben): Figure out the layout of the struct. For now,
 * |POLY1305_BLOCK_STATE_SIZE| is taken from OpenSSL. */
#define POLY1305_ASM
#elif defined(OPENSSL_AARCH64)
/* TODO(davidben): Figure out the layout of the struct. For now,
 * |POLY1305_BLOCK_STATE_SIZE| is taken from OpenSSL. */
#define POLY1305_ASM
#endif
#endif

#if defined(POLY1305_ASM)

int poly1305_init(void *ctx, const uint8_t key[16], void *out_func);
void poly1305_blocks(void *ctx, const uint8_t *in, size_t len,
                     uint32_t padbit);
void poly1305_emit(void *ctx, uint8_t mac[16], const uint32_t nonce[4]);

#else

struct poly1305_block_state_st {
  uint32_t r0, r1, r2, r3, r4;
  uint32_t s1, s2, s3, s4;
  uint32_t h0, h1, h2, h3, h4;
};

OPENSSL_COMPILE_ASSERT(POLY1305_BLOCK_STATE_SIZE >=
                           sizeof(struct poly1305_block_state_st),
                       poly1305_block_state_too_small);

/* We can assume little-endian. */
static void U32TO8_LE(uint8_t *m, uint32_t v) { memcpy(m, &v, sizeof(v)); }

static uint64_t mul32x32_64(uint32_t a, uint32_t b) { return (uint64_t)a * b; }

static int poly1305_init(void *ctx, const uint8_t key[16], void *out_func) {
  struct poly1305_block_state_st *state = (struct poly1305_block_state_st *)ctx;
  uint32_t t0, t1, t2, t3;

  t0 = U8TO32_LE(key + 0);
  t1 = U8TO32_LE(key + 4);
  t2 = U8TO32_LE(key + 8);
  t3 = U8TO32_LE(key + 12);

  /* precompute multipliers */
  state->r0 = t0 & 0x3ffffff;
  t0 >>= 26;
  t0 |= t1 << 6;
  state->r1 = t0 & 0x3ffff03;
  t1 >>= 20;
  t1 |= t2 << 12;
  state->r2 = t1 & 0x3ffc0ff;
  t2 >>= 14;
  t2 |= t3 << 18;
  state->r3 = t2 & 0x3f03fff;
  t3 >>= 8;
  state->r4 = t3 & 0x00fffff;

  state->s1 = state->r1 * 5;
  state->s2 = state->r2 * 5;
  state->s3 = state->r3 * 5;
  state->s4 = state->r4 * 5;

  /* init state */
  state->h0 = 0;
  state->h1 = 0;
  state->h2 = 0;
  state->h3 = 0;
  state->h4 = 0;

  return 0;
}

static void poly1305_blocks(void *ctx, const uint8_t *in, size_t len,
                            uint32_t padbit) {
  struct poly1305_block_state_st *state = (struct poly1305_block_state_st *)ctx;
  uint32_t t0, t1, t2, t3;
  uint64_t t[5];
  uint32_t b;
  uint64_t c;

  assert(len % 16 == 0);
  assert(padbit != 0 || len == 16);

  while (len >= 16) {
    t0 = U8TO32_LE(in);
    t1 = U8TO32_LE(in + 4);
    t2 = U8TO32_LE(in + 8);
    t3 = U8TO32_LE(in + 12);

    in += 16;
    len -= 16;

    state->h0 += t0 & 0x3ffffff;
    state->h1 += ((((uint64_t)t1 << 32) | t0) >> 26) & 0x3ffffff;
    state->h2 += ((((uint64_t)t2 << 32) | t1) >> 20) & 0x3ffffff;
    state->h3 += ((((uint64_t)t3 << 32) | t2) >> 14) & 0x3ffffff;
    state->h4 += (t3 >> 8) | (padbit << 24);

    t[0] =
        mul32x32_64(state->h0, state->r0) + mul32x32_64(state->h1, state->s4) +
        mul32x32_64(state->h2, state->s3) + mul32x32_64(state->h3, state->s2) +
        mul32x32_64(state->h4, state->s1);
    t[1] =
        mul32x32_64(state->h0, state->r1) + mul32x32_64(state->h1, state->r0) +
        mul32x32_64(state->h2, state->s4) + mul32x32_64(state->h3, state->s3) +
        mul32x32_64(state->h4, state->s2);
    t[2] =
        mul32x32_64(state->h0, state->r2) + mul32x32_64(state->h1, state->r1) +
        mul32x32_64(state->h2, state->r0) + mul32x32_64(state->h3, state->s4) +
        mul32x32_64(state->h4, state->s3);
    t[3] =
        mul32x32_64(state->h0, state->r3) + mul32x32_64(state->h1, state->r2) +
        mul32x32_64(state->h2, state->r1) + mul32x32_64(state->h3, state->r0) +
        mul32x32_64(state->h4, state->s4);
    t[4] =
        mul32x32_64(state->h0, state->r4) + mul32x32_64(state->h1, state->r3) +
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
}

static void poly1305_emit(void *ctx, uint8_t mac[16], const uint32_t nonce[4]) {
  struct poly1305_block_state_st *state = (struct poly1305_block_state_st *)ctx;
  uint64_t f0, f1, f2, f3;
  uint32_t g0, g1, g2, g3, g4;
  uint32_t b, nb;

  b = state->h0 >> 26;
  state->h0 = state->h0 & 0x3ffffff;
  state->h1 += b;
  b = state->h1 >> 26;
  state->h1 = state->h1 & 0x3ffffff;
  state->h2 += b;
  b = state->h2 >> 26;
  state->h2 = state->h2 & 0x3ffffff;
  state->h3 += b;
  b = state->h3 >> 26;
  state->h3 = state->h3 & 0x3ffffff;
  state->h4 += b;
  b = state->h4 >> 26;
  state->h4 = state->h4 & 0x3ffffff;
  state->h0 += b * 5;

  g0 = state->h0 + 5;
  b = g0 >> 26;
  g0 &= 0x3ffffff;
  g1 = state->h1 + b;
  b = g1 >> 26;
  g1 &= 0x3ffffff;
  g2 = state->h2 + b;
  b = g2 >> 26;
  g2 &= 0x3ffffff;
  g3 = state->h3 + b;
  b = g3 >> 26;
  g3 &= 0x3ffffff;
  g4 = state->h4 + b - (1 << 26);

  b = (g4 >> 31) - 1;
  nb = ~b;
  state->h0 = (state->h0 & nb) | (g0 & b);
  state->h1 = (state->h1 & nb) | (g1 & b);
  state->h2 = (state->h2 & nb) | (g2 & b);
  state->h3 = (state->h3 & nb) | (g3 & b);
  state->h4 = (state->h4 & nb) | (g4 & b);

  f0 = ((state->h0) | (state->h1 << 26)) + (uint64_t)nonce[0];
  f1 = ((state->h1 >> 6) | (state->h2 << 20)) + (uint64_t)nonce[1];
  f2 = ((state->h2 >> 12) | (state->h3 << 14)) + (uint64_t)nonce[2];
  f3 = ((state->h3 >> 18) | (state->h4 << 8)) + (uint64_t)nonce[3];

  U32TO8_LE(&mac[0], f0);
  f1 += (f0 >> 32);
  U32TO8_LE(&mac[4], f1);
  f2 += (f1 >> 32);
  U32TO8_LE(&mac[8], f2);
  f3 += (f2 >> 32);
  U32TO8_LE(&mac[12], f3);
}

#endif /* !POLY1305_ASM */

void CRYPTO_poly1305_init(poly1305_state *statep, const uint8_t key[32]) {
  struct poly1305_state_st *state = (struct poly1305_state_st *)statep;

  if (!poly1305_init(state->opaque, key, &state->func)) {
    state->func.blocks = poly1305_blocks;
    state->func.emit = poly1305_emit;
  }

  state->buf_used = 0;
  state->nonce[0] = U8TO32_LE(key + 16);
  state->nonce[1] = U8TO32_LE(key + 20);
  state->nonce[2] = U8TO32_LE(key + 24);
  state->nonce[3] = U8TO32_LE(key + 28);
}

void CRYPTO_poly1305_update(poly1305_state *statep, const uint8_t *in,
                            size_t in_len) {
  struct poly1305_state_st *state = (struct poly1305_state_st *)statep;

  if (state->buf_used != 0) {
    unsigned todo = 16 - state->buf_used;
    if (todo > in_len) {
      todo = in_len;
    }
    memcpy(state->buf + state->buf_used, in, todo);
    state->buf_used += todo;
    in_len -= todo;
    in += todo;

    if (state->buf_used == 16) {
      state->func.blocks(state->opaque, state->buf, 16, 1 /* pad */);
      state->buf_used = 0;
    }
  }

  if (in_len >= 16) {
    size_t todo = in_len & ~0xf;
    state->func.blocks(state->opaque, in, todo, 1 /* pad */);
    in += todo;
    in_len &= 0xf;
  }

  if (in_len != 0) {
    memcpy(state->buf, in, in_len);
    state->buf_used = in_len;
  }
}

void CRYPTO_poly1305_finish(poly1305_state *statep, uint8_t mac[16]) {
  struct poly1305_state_st *state = (struct poly1305_state_st *)statep;

  if (state->buf_used != 0) {
    state->buf[state->buf_used] = 1;
    memset(state->buf + state->buf_used + 1, 0, 16 - state->buf_used - 1);
    state->func.blocks(state->opaque, state->buf, 16, 0 /* already padded */);
  }

  state->func.emit(state->opaque, mac, state->nonce);
}
