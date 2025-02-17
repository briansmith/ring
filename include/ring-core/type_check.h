/*
 * Copyright 1999-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_HEADER_TYPE_CHECK_H
#define OPENSSL_HEADER_TYPE_CHECK_H

#include <ring-core/base.h>


#if defined(__cplusplus) || (defined(_MSC_VER) && !defined(__clang__))
// In C++ and non-clang MSVC, |static_assert| is a keyword.
#define OPENSSL_STATIC_ASSERT(cond, msg) static_assert(cond, msg)
#else
// C11 defines the |_Static_assert| keyword and the |static_assert| macro in
// assert.h. While the former is available at all versions in Clang and GCC, the
// later depends on libc and, in glibc, depends on being built in C11 mode. We
// do not require this, for now, so use |_Static_assert| directly.
#define OPENSSL_STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)
#endif

#endif  // OPENSSL_HEADER_TYPE_CHECK_H
