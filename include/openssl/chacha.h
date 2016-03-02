/* Copyright (c) 2014, Google Inc.
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

#ifndef OPENSSL_HEADER_CHACHA_H
#define OPENSSL_HEADER_CHACHA_H

#include <openssl/base.h>

#ifdef  __cplusplus
extern "C" {
#endif


/* ChaCha20_ctr32 encrypts |in_len| bytes from |in| with the given key and
 * writes the result to |out|, which may/must point at or before |in|.
 * The initial block counter (and nonce) is specified by |counter|. */
void ChaCha20_ctr32(uint8_t *out, const uint8_t *in, size_t in_len,
                    const uint32_t key[8], const uint32_t counter[4]);


#if defined(__cplusplus)
}  /* extern C */
#endif

#endif  /* OPENSSL_HEADER_CHACHA_H */
