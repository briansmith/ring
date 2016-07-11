/* Copyright 2015-2016 Brian Smith.
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

#include <assert.h>
#include <stdint.h>
#include <openssl/ec.h>
#include <openssl/err.h>

#include "gfp_internal.h"
#include "../bn/internal.h"


#define CURVE_P256_EC_METHOD EC_GFp_nistz256_method
#define CURVE_P384_EC_METHOD EC_GFp_mont_method

/* Use C99 designated initializers + the -Wuninitialized warning to help keep
 * the initializations in sync with the definitions of |BN_MONT_CTX|,
 * |EC_GROUP|, etc. */
#if defined(_MSC_VER)
#define FIELD(x) /* MSVC doesn't support designated initializers */
#else
#define FIELD(x) x
#endif

#include "ec_curve_data.inl"
