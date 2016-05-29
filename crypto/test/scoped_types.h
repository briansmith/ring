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

#ifndef OPENSSL_HEADER_CRYPTO_TEST_SCOPED_TYPES_H
#define OPENSSL_HEADER_CRYPTO_TEST_SCOPED_TYPES_H

// Avoid "C4548: expression before comma has no effect; expected expression
// with side-effect." in malloc.h in Visual Studio 2015 Update 1 in debug mode.
#if defined(_MSC_VER) && defined(_DEBUG)
#pragma warning(push)
#pragma warning(disable: 4548)
#endif

#include <memory>

#if defined(_MSC_VER) && defined(_DEBUG)
#pragma warning(pop)
#endif

#include <openssl/bn.h>

template<typename T, void (*func)(T*)>
struct OpenSSLDeleter {
  void operator()(T *obj) {
    func(obj);
  }
};

// XXX: GCC 4.6 doesn't support this use of `using` yet:
//     template<typename T, void (*func)(T*)>
//     using ScopedOpenSSLType = std::unique_ptr<T, OpenSSLDeleter<T, func>>;
// TODO: When we drop GCC 4.6 support, revert back to what BoringSSL is doing.
#define SCOPED_OPENSSL_TYPE(Name, T, func) \
        typedef std::unique_ptr<T, OpenSSLDeleter<T, func>> Name

SCOPED_OPENSSL_TYPE(ScopedBIGNUM, BIGNUM, BN_free);
SCOPED_OPENSSL_TYPE(ScopedBN_CTX, BN_CTX, BN_CTX_free);
SCOPED_OPENSSL_TYPE(ScopedBN_MONT_CTX, BN_MONT_CTX, BN_MONT_CTX_free);

#endif  // OPENSSL_HEADER_CRYPTO_TEST_SCOPED_TYPES_H
