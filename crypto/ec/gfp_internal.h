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


#endif /* GFp_INTERNAL_H */
