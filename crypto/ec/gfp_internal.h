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

#ifndef GFp_INTERNAL_H
#define GFp_INTERNAL_H

#include <openssl/base.h>
#include <openssl/ec.h>

#include <stddef.h>

#include "internal.h"


typedef BN_ULONG GFp_Limb;

#define GFp_LIMB_BITS BN_BITS2

#define P256_LIMBS (256u / BN_BITS2)
#define P384_LIMBS (384u / BN_BITS2)

int GFp_suite_b_generate_private_key(const EC_GROUP *group,
                                     uint8_t *private_key_out, RAND *rng);

int GFp_suite_b_public_from_private(const EC_GROUP *group,
                                    uint8_t *public_key_out,
                                    const uint8_t *private_key);

int GFp_suite_b_ecdh(const EC_GROUP *group, uint8_t *out, size_t out_len,
                     const uint8_t *private_key,
                     const GFp_Limb *peer_public_key_x,
                     const GFp_Limb *peer_public_key_y);

EC_POINT *GFp_suite_b_make_point(const EC_GROUP *group,
                                 const GFp_Limb *peer_public_key_x,
                                 const GFp_Limb *peer_public_key_y);

void GFp_p256_elem_inv(GFp_Limb r[P256_LIMBS], const GFp_Limb a[P256_LIMBS]);


#endif /* GFp_INTERNAL_H */
