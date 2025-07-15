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

// This implementation was taken from the public domain, neon2 version in
// SUPERCOP by D. J. Bernstein and Peter Schwabe.

#include <ring-core/base.h>

#include "../internal.h"


#pragma GCC diagnostic ignored "-Wsign-conversion"

// Keep in sync with ffi_arm_neon.rs
typedef struct {
  uint32_t v[12];  // for alignment; only using 10
} fe1305x2;

void CRYPTO_poly1305_freeze(fe1305x2 *r) {
  int i;

  uint32_t x0 = r->v[0];
  uint32_t x1 = r->v[2];
  uint32_t x2 = r->v[4];
  uint32_t x3 = r->v[6];
  uint32_t x4 = r->v[8];
  uint32_t y0;
  uint32_t y1;
  uint32_t y2;
  uint32_t y3;
  uint32_t y4;
  uint32_t swap;

  for (i = 0; i < 3; ++i) {
    x1 += x0 >> 26;
    x0 &= 0x3ffffff;
    x2 += x1 >> 26;
    x1 &= 0x3ffffff;
    x3 += x2 >> 26;
    x2 &= 0x3ffffff;
    x4 += x3 >> 26;
    x3 &= 0x3ffffff;
    x0 += 5 * (x4 >> 26);
    x4 &= 0x3ffffff;
  }

  y0 = x0 + 5;
  y1 = x1 + (y0 >> 26);
  y0 &= 0x3ffffff;
  y2 = x2 + (y1 >> 26);
  y1 &= 0x3ffffff;
  y3 = x3 + (y2 >> 26);
  y2 &= 0x3ffffff;
  y4 = x4 + (y3 >> 26);
  y3 &= 0x3ffffff;
  swap = -(y4 >> 26);
  y4 &= 0x3ffffff;

  y0 ^= x0;
  y1 ^= x1;
  y2 ^= x2;
  y3 ^= x3;
  y4 ^= x4;

  y0 &= swap;
  y1 &= swap;
  y2 &= swap;
  y3 &= swap;
  y4 &= swap;

  y0 ^= x0;
  y1 ^= x1;
  y2 ^= x2;
  y3 ^= x3;
  y4 ^= x4;

  r->v[0] = y0;
  r->v[2] = y1;
  r->v[4] = y2;
  r->v[6] = y3;
  r->v[8] = y4;
}
