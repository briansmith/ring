/* Copyright 2015 Brian Smith.
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
#ifndef OPENSSL_HEADER_CHACHA_INTERNAL_H
#define OPENSSL_HEADER_CHACHA_INTERNAL_H

#include "../internal.h"

#include "string.h"

#if defined(__cplusplus)
extern "C" {
#endif

/* CRYPTO_chacha_96_bit_nonce_from_64_bit_nonce formats a nonce for use with
 * |CRYPTO_chacha_20| that is compatible with the formulation used in older
 * versions. Previously |CRYPTO_chacha_20| used a 64 bit counter and took a 64
 * bit nonce, whereas the current version uses a 32-bit counter and a 96-bit
 * nonce:
 *
 *       Old:     counter low || counter high || nonce low || nonce high
 *       New:  32-bit counter ||    nonce low || nonce mid || nonce high
 *      This:  32-bit counter ||            0 || nonce low || nonce high
 *
 * This allows an implementation of the old construction to be implemented with
 * |CRYPTO_chacha_20|, which implements the new construction, with the
 * limitation that no more than 2^32 blocks may be encrypted. An implementation
 * of a protocol that uses 96-bit counters as nonces cannot use this function,
 * though, since this function shifts the nonce 32 bits. */
static inline void CRYPTO_chacha_96_bit_nonce_from_64_bit_nonce(
                     uint8_t out[12], const uint8_t in[8]) {
  out[0] = 0;
  out[1] = 0;
  out[2] = 0;
  out[3] = 0;
  memcpy(out + 4, in, 8);
}

#if defined(__cplusplus)
}
#endif

#endif /* OPENSSL_HEADER_CHACHA_INTERNAL_H */
