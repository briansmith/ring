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


/* We can assume little-endian. */
static uint32_t U8TO32_LE(const uint8_t *m) {
  uint32_t r;
  memcpy(&r, m, sizeof(r));
  return r;
}

#if defined(OPENSSL_X86)
/* See comment above |_poly1305_init_sse2| in poly1305-x86.pl. */
OPENSSL_COMPILE_ASSERT(POLY1305_BLOCK_STATE_SIZE >= 4 * (5 + 1 + 4 + 2 + 4 * 9),
                       poly1305_block_state_too_small);
#elif defined(OPENSSL_X86_64)
/* See comment above |__poly1305_block| in poly1305-x86_64.pl. */
OPENSSL_COMPILE_ASSERT(POLY1305_BLOCK_STATE_SIZE >=
                           4 * (5 + 1 + 2 * 2 + 2 + 4 * 9),
                       poly1305_block_state_too_small);
#elif defined(OPENSSL_ARM)
/* TODO(davidben): Figure out the layout of the struct. For now,
 * |POLY1305_BLOCK_STATE_SIZE| is taken from OpenSSL. */
#elif defined(OPENSSL_AARCH64)
/* TODO(davidben): Figure out the layout of the struct. For now,
 * |POLY1305_BLOCK_STATE_SIZE| is taken from OpenSSL. */
#endif

int poly1305_init(void *ctx, const uint8_t key[16], void *out_func);
void poly1305_blocks(void *ctx, const uint8_t *in, size_t len,
                     uint32_t padbit);
void poly1305_emit(void *ctx, uint8_t mac[16], const uint32_t nonce[4]);

struct poly1305_state_st {
  alignas(8) uint8_t opaque[POLY1305_BLOCK_STATE_SIZE];
  uint32_t nonce[4];
  uint8_t buf[16];
  unsigned buf_used;
  struct {
    void (*blocks)(void *ctx, const uint8_t *in, size_t len, uint32_t padbit);
    void (*emit)(void *ctx, uint8_t mac[16], const uint32_t nonce[4]);
  } func;
};

OPENSSL_COMPILE_ASSERT(sizeof(poly1305_state) >=
                       sizeof(struct poly1305_state_st),
                       poly1305_state_too_small);


void CRYPTO_poly1305_init(poly1305_state *statep, const uint8_t key[32]) {
  struct poly1305_state_st state;

  if (!poly1305_init(state.opaque, key, &state.func)) {
    state.func.blocks = poly1305_blocks;
    state.func.emit = poly1305_emit;
  }

  state.buf_used = 0;
  state.nonce[0] = U8TO32_LE(key + 16);
  state.nonce[1] = U8TO32_LE(key + 20);
  state.nonce[2] = U8TO32_LE(key + 24);
  state.nonce[3] = U8TO32_LE(key + 28);

  memset(statep, 0, sizeof(*statep));
  memcpy(statep, &state, sizeof(state));
}

void CRYPTO_poly1305_update(poly1305_state *statep, const uint8_t *in,
                            size_t in_len) {
  struct poly1305_state_st state;
  memcpy(&state, statep, sizeof(state));

  if (state.buf_used != 0) {
    unsigned todo = 16 - state.buf_used;
    if (todo > in_len) {
      todo = in_len;
    }
    memcpy(state.buf + state.buf_used, in, todo);
    state.buf_used += todo;
    in_len -= todo;
    in += todo;

    if (state.buf_used == 16) {
      state.func.blocks(state.opaque, state.buf, 16, 1 /* pad */);
      state.buf_used = 0;
    }
  }

  if (in_len >= 16) {
    size_t todo = in_len & ~0xf;
    state.func.blocks(state.opaque, in, todo, 1 /* pad */);
    in += todo;
    in_len &= 0xf;
  }

  if (in_len != 0) {
    memcpy(state.buf, in, in_len);
    state.buf_used = in_len;
  }

  memcpy(statep, &state, sizeof(state));
}

void CRYPTO_poly1305_finish(poly1305_state *statep, uint8_t mac[16]) {
  struct poly1305_state_st state;
  memcpy(&state, statep, sizeof(state));

  if (state.buf_used != 0) {
    state.buf[state.buf_used] = 1;
    memset(state.buf + state.buf_used + 1, 0, 16 - state.buf_used - 1);
    state.func.blocks(state.opaque, state.buf, 16, 0 /* already padded */);
  }

  state.func.emit(state.opaque, mac, state.nonce);
}

const size_t CRYPTO_POLY1305_STATE_LEN = sizeof(struct poly1305_state_st);
