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

#ifndef OPENSSL_HEADER_RAND_H
#define OPENSSL_HEADER_RAND_H

#include <openssl/base.h>

#if defined(__cplusplus)
extern "C" {
#endif


/* Random number generation. */


/* RAND_bytes writes |len| bytes of random data to |buf| and returns one. */
OPENSSL_EXPORT int RAND_bytes(uint8_t *buf, size_t len);

/* RAND_cleanup frees any resources used by the RNG. This is not safe if other
 * threads might still be calling |RAND_bytes|. */
OPENSSL_EXPORT void RAND_cleanup(void);


/* Obscure functions. */

#if !defined(OPENSSL_WINDOWS)
/* RAND_set_urandom_fd causes the module to use a copy of |fd| for system
 * randomness rather opening /dev/urandom internally. The caller retains
 * ownership of |fd| and is at liberty to close it at any time. This is useful
 * if, due to a sandbox, /dev/urandom isn't available. If used, it must be
 * called before the first call to |RAND_bytes|, and it is mutually exclusive
 * with |RAND_enable_fork_unsafe_buffering|.
 *
 * |RAND_set_urandom_fd| does not buffer any entropy, so it is safe to call
 * |fork| at any time after calling |RAND_set_urandom_fd|. */
OPENSSL_EXPORT void RAND_set_urandom_fd(int fd);

/* RAND_enable_fork_unsafe_buffering enables efficient buffered reading of
 * /dev/urandom. It adds an overhead of a few KB of memory per thread. It must
 * be called before the first call to |RAND_bytes| and it is mutually exclusive
 * with calls to |RAND_set_urandom_fd|.
 *
 * If |fd| is non-negative then a copy of |fd| will be used rather than opening
 * /dev/urandom internally. Like |RAND_set_urandom_fd|, the caller retains
 * ownership of |fd|. If |fd| is negative then /dev/urandom will be opened and
 * any error from open(2) crashes the address space.
 *
 * It has an unusual name because the buffer is unsafe across calls to |fork|.
 * Hence, this function should never be called by libraries. */
OPENSSL_EXPORT void RAND_enable_fork_unsafe_buffering(int fd);
#endif


#if defined(__cplusplus)
}  /* extern C */
#endif

#endif  /* OPENSSL_HEADER_RAND_H */
