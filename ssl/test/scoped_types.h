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

#ifndef HEADER_SCOPED_TYPES
#define HEADER_SCOPED_TYPES

#include <memory>

#include <openssl/bio.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>


template<typename T, void (*func)(T*)>
struct OpenSSLDeleter {
  void operator()(T *obj) {
    func(obj);
  }
};

template<typename T, void (*func)(T*)>
using ScopedOpenSSLType = std::unique_ptr<T, OpenSSLDeleter<T, func>>;

using ScopedBIO = ScopedOpenSSLType<BIO, BIO_vfree>;
using ScopedDH = ScopedOpenSSLType<DH, DH_free>;
using ScopedEVP_PKEY = ScopedOpenSSLType<EVP_PKEY, EVP_PKEY_free>;

using ScopedSSL = ScopedOpenSSLType<SSL, SSL_free>;
using ScopedSSL_CTX = ScopedOpenSSLType<SSL_CTX, SSL_CTX_free>;
using ScopedSSL_SESSION = ScopedOpenSSLType<SSL_SESSION, SSL_SESSION_free>;


#endif  // HEADER_SCOPED_TYPES