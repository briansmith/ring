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

#ifndef HEADER_PACKETED_BIO
#define HEADER_PACKETED_BIO

#include <openssl/bio.h>


// packeted_bio_create creates a filter BIO for testing protocols which expect
// datagram BIOs. It implements a reliable datagram socket and reads and writes
// packets by prefixing each packet with a big-endian 32-bit length. It must be
// layered over a reliable blocking stream BIO.
//
// Note: packeted_bio_create exists because a SOCK_DGRAM socketpair on OS X is
// does not block the caller, unlike on Linux. Writes simply fail with
// ENOBUFS. POSIX also does not guarantee that such sockets are reliable.
BIO *packeted_bio_create();


#endif  // HEADER_PACKETED_BIO
