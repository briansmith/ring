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
#include "../bn/internal.h"
#include "../internal.h"


#define P384_LIMBS (384u / BN_BITS2)

typedef GFp_Limb Elem[P384_LIMBS];


 /* Prototypes to avoid -Wmissing-prototypes warnings. */
void GFp_p384_elem_add(Elem r, const Elem a, const Elem b);
void GFp_p384_elem_mul_mont(Elem r, const Elem a, const Elem b);


void GFp_p384_elem_add(Elem r, const Elem a, const Elem b) {
  /* XXX: Not constant-time. */
  if (!bn_add_words(r, a, b, P384_LIMBS)) {
    if (bn_cmp_words(r, EC_GROUP_P384.mont.N.d, P384_LIMBS) < 0) {
      return;
    }
  }
  /* Either the addition resulted in a carry requiring 1 bit more than would
   * fit in |P384_LIMBS| limbs, or the addition result fit in |P384_LIMBS|
   * limbs but it was not less than |q|. Either way, it needs to be reduced. */
  (void)bn_sub_words(r, r, EC_GROUP_P384.mont.N.d, P384_LIMBS);
}

void GFp_p384_elem_mul_mont(Elem r, const Elem a, const Elem b) {
  /* XXX: Not constant-time. */
  bn_mul_mont(r, a, b, EC_GROUP_P384.mont.N.d, EC_GROUP_P384.mont.n0,
              P384_LIMBS);
}
