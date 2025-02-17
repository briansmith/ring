/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_HEADER_MEM_H
#define OPENSSL_HEADER_MEM_H

#include <ring-core/base.h>

// CRYPTO_memcmp returns zero iff the |len| bytes at |a| and |b| are equal. It
// takes an amount of time dependent on |len|, but independent of the contents
// of |a| and |b|. Unlike memcmp, it cannot be used to put elements into a
// defined order as the return value when a != b is undefined, other than to be
// non-zero.
OPENSSL_EXPORT int CRYPTO_memcmp(const void *a, const void *b, size_t len);

#endif  // OPENSSL_HEADER_MEM_H
