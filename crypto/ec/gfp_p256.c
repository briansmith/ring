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


#define P256_LIMBS (256u / GFp_LIMB_BITS)

typedef GFp_Limb Elem[P256_LIMBS];
typedef GFp_Limb ScalarMont[P256_LIMBS];


void ecp_nistz256_mul_mont(Elem r, const Elem a, const Elem b);


/* Prototypes to avoid -Wmissing-prototypes warnings. */
#if defined(OPENSSL_ARM) || defined(OPENSSL_X86)
void ecp_nistz256_sqr_mont(Elem r, const Elem a);
#endif


#if defined(OPENSSL_ARM) || defined(OPENSSL_X86)
void ecp_nistz256_sqr_mont(Elem r, const Elem a) {
  /* XXX: Inefficient. TODO: optimize with dedicated squaring routine. */
  ecp_nistz256_mul_mont(r, a, a);
}
#endif
