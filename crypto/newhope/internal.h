/* Copyright (c) 2016, Google Inc.
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

#ifndef OPENSSL_HEADER_NEWHOPE_INTERNAL_H
#define OPENSSL_HEADER_NEWHOPE_INTERNAL_H

#include <openssl/newhope.h>
#include <openssl/sha.h>

#include "../internal.h"


/* The number of polynomial coefficients. */
#define PARAM_N 1024

/* The width the noise distribution. */
#define PARAM_K 16

/* Modulus. */
#define PARAM_Q 12289

/* KEY_LENGTH is the size of the result of the key agreement. This result is
 * not exposed to callers: instead, it is whitened with SHA-256, whose output
 * happens to be the same size. */
#define KEY_LENGTH 32

/* Polynomial coefficients in unpacked form. */
struct newhope_poly_st {
  alignas(32) uint16_t coeffs[PARAM_N];
};

/* The packed form is 14 bits per coefficient, or 1792 bytes. */
#define POLY_BYTES ((1024 * 14) / 8)

/* SEED_LENGTH is the length of the AES-CTR seed used to derive a polynomial. */
#define SEED_LENGTH 32

/* newhope_poly_uniform generates the polynomial |a| using AES-CTR mode with the
 * seed
 * |seed|. (In the reference implementation this was done with SHAKE-128.) */
void newhope_poly_uniform(NEWHOPE_POLY* a, const uint8_t* seed);

/* newhope_poly_getnoise sets |r| to a random polynomial where the coefficients
 * are
 * sampled from the noise distribution. (In the reference implementation, this
 * is given a random seed and a nonce.)*/
void newhope_poly_getnoise(NEWHOPE_POLY* r);

/* newhope_poly_frombytes unpacks the packed polynomial coefficients in |a| into
 * |r|. */
void newhope_poly_frombytes(NEWHOPE_POLY* r, const uint8_t* a);

/* newhope_poly_tobytes packs the polynomial |p| into the compact representation
 * |r|. */
void newhope_poly_tobytes(uint8_t* r, const NEWHOPE_POLY* p);

void newhope_helprec(NEWHOPE_POLY* c, const NEWHOPE_POLY* v);

/* newhope_reconcile performs the error-reconciliation step using the input |v|
 * and
 * reconciliation data |c|, writing the resulting key to |key|. */
void newhope_reconcile(uint8_t* key, const NEWHOPE_POLY* v,
                       const NEWHOPE_POLY* c);

/* newhope_poly_ntt performs NTT(r) in-place. */
void newhope_poly_ntt(NEWHOPE_POLY* r);

/* newhope_poly_invntt performs the inverse of NTT(r) in-place. */
void newhope_poly_invntt(NEWHOPE_POLY* r);

void newhope_poly_add(NEWHOPE_POLY* r, const NEWHOPE_POLY* a,
                      const NEWHOPE_POLY* b);
void newhope_poly_pointwise(NEWHOPE_POLY* r, const NEWHOPE_POLY* a,
                            const NEWHOPE_POLY* b);

uint16_t newhope_montgomery_reduce(uint32_t a);
uint16_t newhope_barrett_reduce(uint16_t a);

void newhope_bitrev_vector(uint16_t* poly);
void newhope_mul_coefficients(uint16_t* poly, const uint16_t* factors);
void newhope_ntt(uint16_t* poly, const uint16_t* omegas);


#endif /* OPENSSL_HEADER_NEWHOPE_INTERNAL_H */
