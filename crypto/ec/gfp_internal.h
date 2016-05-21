/* Copyright 2016 Brian Smith.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#ifndef GFp_INTERNAL_H
#define GFp_INTERNAL_H

#include <openssl/base.h>
#include <openssl/ec.h>

#include <stddef.h>

#include "internal.h"


int GFp_nist_generate_private_key(const EC_GROUP *group, uint8_t *out,
                                  size_t out_len, RAND *rng);

int GFp_nist_public_from_private(const EC_GROUP *group,
                                 uint8_t *public_key_out,
                                 size_t public_key_out_len,
                                 const uint8_t *private_key,
                                 size_t private_key_len);

int GFp_nist_ecdh(const EC_GROUP *group, uint8_t *out, size_t out_len,
                  const uint8_t *private_key, size_t private_key_len,
                  const uint8_t *peer_public_key, size_t peer_public_key_len);


#endif /* GFp_INTERNAL_H */
