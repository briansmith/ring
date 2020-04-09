/* Copyright (c) 2020, Google Inc.
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

#ifndef OPENSSL_HEADER_EC_EXTRA_INTERNAL_H
#define OPENSSL_HEADER_EC_EXTRA_INTERNAL_H

#include <openssl/ec.h>

#include "../fipsmodule/ec/internal.h"

#if defined(__cplusplus)
extern "C" {
#endif


// Hash-to-curve.
//
// The following functions implement primitives from
// draft-irtf-cfrg-hash-to-curve-06. We currently only implement a P-521 suite,
// but others can be added as needed.

// ec_hash_to_curve_p521_sha512_sswu hashes |msg| to a point on |group| and
// writes the result to |out|, implementing the P521_XMD:SHA-512_SSWU_RO_ suite.
// It returns one on success and zero on error. |dst| is the domain separation
// tag and must be unique for each protocol. See section 3.1 of
// draft-irtf-cfrg-hash-to-curve-06 for additional guidance on this parameter.
OPENSSL_EXPORT int ec_hash_to_curve_p521_xmd_sha512_sswu(
    const EC_GROUP *group, EC_RAW_POINT *out, const uint8_t *dst,
    size_t dst_len, const uint8_t *msg, size_t msg_len);

// ec_hash_to_curve_p521_xmd_sha512_sswu_ref_for_testing behaves like
// |ec_hash_to_curve_p521_sha512_sswu| but reproduces a spec issue reflected in
// the original test vectors.
//
// This function is exposed for test purposes and should not be used elsewhere.
OPENSSL_EXPORT int ec_hash_to_curve_p521_xmd_sha512_sswu_ref_for_testing(
    const EC_GROUP *group, EC_RAW_POINT *out, const uint8_t *dst,
    size_t dst_len, const uint8_t *msg, size_t msg_len);

// ec_hash_to_scalar_p521_xmd_sha512 hashes |msg| to a scalar on |group| and
// writes the result to |out|, using the hash_to_field operation from the
// P521_XMD:SHA-512_SSWU_RO_ suite, but generating a value modulo the group
// order rather than a field element. |dst| is the domain separation
// tag and must be unique for each protocol. See section 3.1 of
// draft-irtf-cfrg-hash-to-curve-06 for additional guidance on this parameter.
//
// Note the requirement to use a different tag for each encoding used in a
// protocol extends to this function. Protocols which use both this function and
// |ec_hash_to_scalar_p521_xmd_sha512| must use distinct values of |dst| for
// each use.
OPENSSL_EXPORT int ec_hash_to_scalar_p521_xmd_sha512(
    const EC_GROUP *group, EC_SCALAR *out, const uint8_t *dst, size_t dst_len,
    const uint8_t *msg, size_t msg_len);


#if defined(__cplusplus)
}  // extern C
#endif

#endif  // OPENSSL_HEADER_EC_EXTRA_INTERNAL_H
