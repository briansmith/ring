/* Copyright (c) 2014, Intel Corporation.
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

#ifndef OPENSSL_HEADER_EC_ECP_NISTZ384_H
#define OPENSSL_HEADER_EC_ECP_NISTZ384_H

#include <GFp/bn.h>

#include "../../limbs/limbs.h"

#if defined(__cplusplus)
extern "C" {
#endif

#define P384_LIMBS (384u / LIMB_BITS)

typedef struct {
  BN_ULONG X[P384_LIMBS];
  BN_ULONG Y[P384_LIMBS];
  BN_ULONG Z[P384_LIMBS];
} P384_POINT;

typedef struct {
  BN_ULONG X[P384_LIMBS];
  BN_ULONG Y[P384_LIMBS];
} P384_POINT_AFFINE;


// Prototypes to avoid -Wmissing-prototypes warnings.
void GFp_nistz384_point_double(P384_POINT *r, const P384_POINT *a);
void GFp_nistz384_point_add(P384_POINT *r, const P384_POINT *a,
                            const P384_POINT *b);


#if defined(__cplusplus)
}
#endif

#endif // OPENSSL_HEADER_EC_ECP_NISTZ384_H
