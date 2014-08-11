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

#ifndef HEADER_ASYNC_BIO
#define HEADER_ASYNC_BIO

#include <openssl/bio.h>


// async_bio_create creates a filter BIO for testing asynchronous state
// machines which consume a stream socket. Reads and writes will fail
// and return EAGAIN unless explicitly allowed. Each async BIO has a
// read quota and a write quota. Initially both are zero. As each is
// incremented, bytes are allowed to flow through the BIO.
BIO *async_bio_create();

// async_bio_create_datagram creates a filter BIO for testing for
// asynchronous state machines which consume datagram sockets. The read
// and write quota count in packets rather than bytes.
BIO *async_bio_create_datagram();

// async_bio_allow_read increments |bio|'s read quota by |count|.
void async_bio_allow_read(BIO *bio, size_t count);

// async_bio_allow_write increments |bio|'s write quota by |count|.
void async_bio_allow_write(BIO *bio, size_t count);


#endif  // HEADER_ASYNC_BIO
