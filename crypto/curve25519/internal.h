/* Copyright (c) 2015, Google Inc.
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

#ifndef OPENSSL_HEADER_CURVE25519_INTERNAL_H
#define OPENSSL_HEADER_CURVE25519_INTERNAL_H

#include <GFp/base.h>

#include <stdint.h>


#if defined(__cplusplus)
extern "C" {
#endif


#if defined(OPENSSL_X86_64) && !defined(OPENSSL_SMALL) && \
    !defined(OPENSSL_WINDOWS) && !defined(OPENSSL_NO_ASM)
/* This isn't compatible with Windows because the asm code makes use of the red
 * zone, which Windows doesn't support. */
#define BORINGSSL_X25519_X86_64

void GFp_x25519_x86_64(uint8_t out[32], const uint8_t scalar[32],
                       const uint8_t point[32]);
#endif


#if defined(OPENSSL_ARM) && !defined(OPENSSL_NO_ASM)
#define BORINGSSL_X25519_NEON

/* x25519_NEON is defined in asm/x25519-arm.S. */
void GFp_x25519_NEON(uint8_t out[32], const uint8_t scalar[32],
                     const uint8_t point[32]);
#endif

/* fe means field element. Here the field is \Z/(2^255-19). An element t,
 * entries t[0]...t[9], represents the integer t[0]+2^26 t[1]+2^51 t[2]+2^77
 * t[3]+2^102 t[4]+...+2^230 t[9]. Bounds on each t[i] vary depending on
 * context.
 *
 * Keep in sync with `Elem` and `ELEM_LIMBS` in curve25519/ops.rs. */
typedef int32_t fe[10];

/* ge means group element.

 * Here the group is the set of pairs (x,y) of field elements (see fe.h)
 * satisfying -x^2 + y^2 = 1 + d x^2y^2
 * where d = -121665/121666.
 *
 * Representations:
 *   ge_p2 (projective): (X:Y:Z) satisfying x=X/Z, y=Y/Z
 *   ge_p3 (extended): (X:Y:Z:T) satisfying x=X/Z, y=Y/Z, XY=ZT
 *   ge_p1p1 (completed): ((X:Z),(Y:T)) satisfying x=X/Z, y=Y/T
 *   ge_precomp (Duif): (y+x,y-x,2dxy)
 */

/* Keep in sync with `Point` in curve25519/ops.rs. */
typedef struct {
  fe X;
  fe Y;
  fe Z;
} ge_p2;


/* Keep in sync with `ExtPoint` in curve25519/ops.rs. */
typedef struct {
  fe X;
  fe Y;
  fe Z;
  fe T;
} ge_p3;

typedef struct {
  fe X;
  fe Y;
  fe Z;
  fe T;
} ge_p1p1;

typedef struct {
  fe yplusx;
  fe yminusx;
  fe xy2d;
} ge_precomp;

typedef struct {
  fe YplusX;
  fe YminusX;
  fe Z;
  fe T2d;
} ge_cached;


#if defined(__cplusplus)
}  /* extern C */
#endif

#endif  /* OPENSSL_HEADER_CURVE25519_INTERNAL_H */
