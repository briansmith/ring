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

#ifndef OPENSSL_HEADER_NEWHOPE_H
#define OPENSSL_HEADER_NEWHOPE_H

#include <openssl/base.h>
#include <openssl/sha.h>

#if defined(__cplusplus)
extern "C" {
#endif


/* Post-quantum key agreement, based upon the reference
 * implementation. Note: this implementation does not interoperate
 * with the reference implementation!
 *
 * Source: https://github.com/tpoeppelmann/newhope
 *
 * The authors' permission to use their code is gratefully acknowledged. */


/* NEWHOPE_POLY_new returns a new |NEWHOPE_POLY| object, or NULL on error. */
OPENSSL_EXPORT NEWHOPE_POLY *NEWHOPE_POLY_new(void);

/* NEWHOPE_POLY_free frees |p|. */
OPENSSL_EXPORT void NEWHOPE_POLY_free(NEWHOPE_POLY *p);

/* NEWHOPE_SERVERMSG_LENGTH is the length of the server's message to the
 * client. */
#define NEWHOPE_SERVERMSG_LENGTH (((1024 * 14) / 8) + 32)

/* NEWHOPE_CLIENTMSG_LENGTH is the length of the client's message to the
 * server. */
#define NEWHOPE_CLIENTMSG_LENGTH (((1024 * 14) / 8) + 1024 / 4)

/* NEWHOPE_keygen initializes |out_msg| and |out_sk| for a new key
 * exchange. |msg| must have room for |NEWHOPE_SERVERMSG_LENGTH| bytes. Neither
 * output may be cached. */
OPENSSL_EXPORT void NEWHOPE_keygen(uint8_t out_msg[NEWHOPE_SERVERMSG_LENGTH],
                                   NEWHOPE_POLY *out_sk);

/* NEWHOPE_server_compute_key completes a key exchange given a client message
 * |msg| and the previously generated server secret |sk|. The result of the
 * key exchange is written to |out_key|, which must have space for
 * |SHA256_DIGEST_LENGTH| bytes. Returns 1 on success and 0 on error. */
OPENSSL_EXPORT int NEWHOPE_server_compute_key(
    uint8_t out_key[SHA256_DIGEST_LENGTH], const NEWHOPE_POLY *sk,
    const uint8_t msg[NEWHOPE_CLIENTMSG_LENGTH], size_t msg_len);

/* NEWHOPE_client_compute_key completes a key exchange given a server message
 * |msg|. The result of the key exchange is written to |out_key|, which must
 * have space for |SHA256_DIGEST_LENGTH| bytes. The message to be send to the
 * client is written to |out_msg|, which must have room for
 * |NEWHOPE_CLIENTMSG_LENGTH| bytes. Returns 1 on success and 0 on error. */
OPENSSL_EXPORT int NEWHOPE_client_compute_key(
    uint8_t out_key[SHA256_DIGEST_LENGTH],
    uint8_t out_msg[NEWHOPE_CLIENTMSG_LENGTH],
    const uint8_t msg[NEWHOPE_SERVERMSG_LENGTH], size_t msg_len);


#if defined(__cplusplus)
} /* extern "C" */
#endif

#endif /* OPENSSL_HEADER_NEWHOPE_H */
