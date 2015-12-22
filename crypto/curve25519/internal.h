/* Copyright (c) 2015, Google Inc.
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

#ifndef OPENSSL_HEADER_CURVE25519_INTERNAL_H
#define OPENSSL_HEADER_CURVE25519_INTERNAL_H

#if defined(__cplusplus)
extern "C" {
#endif


#if defined(OPENSSL_X86_64) && !defined(OPENSSL_SMALL) && \
    !defined(OPENSSL_WINDOWS) && !defined(OPENSSL_NO_ASM)
#define BORINGSSL_X25519_X86_64

void x25519_x86_64(uint8_t out[32], const uint8_t scalar[32],
                   const uint8_t point[32]);
#endif


#if defined(OPENSSL_ARM) && !defined(OPENSSL_NO_ASM)
#define BORINGSSL_X25519_NEON

/* x25519_NEON is defined in asm/x25519-arm.S. */
void x25519_NEON(uint8_t out[32], const uint8_t scalar[32],
                 const uint8_t point[32]);
#endif


#if defined(__cplusplus)
}  /* extern C */
#endif

#endif  /* OPENSSL_HEADER_CURVE25519_INTERNAL_H */
