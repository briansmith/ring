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

#include <stdint.h>
#include <stdio.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ec_key.h>
#include <openssl/ecdsa.h>
#include <openssl/hmac.h>
#include <openssl/mem.h>
#include <openssl/rsa.h>

#include "stl_compat.h"


template<typename T, void (*func)(T*)>
struct OpenSSLDeleter {
  void operator()(T *obj) {
    func(obj);
  }
};

template<typename StackType, typename T, void (*func)(T*)>
struct OpenSSLStackDeleter {
  void operator()(StackType *obj) {
    sk_pop_free(reinterpret_cast<_STACK*>(obj),
                reinterpret_cast<void (*)(void *)>(func));
  }
};

template<typename T>
struct OpenSSLFree {
  void operator()(T *buf) {
    OPENSSL_free(buf);
  }
};

struct FileCloser {
  void operator()(FILE *file) {
    fclose(file);
  }
};

template<typename T, void (*func)(T*)>
using ScopedOpenSSLType = bssl::unique_ptr<T, OpenSSLDeleter<T, func>>;

template<typename StackType, typename T, void (*func)(T*)>
using ScopedOpenSSLStack =
    bssl::unique_ptr<StackType, OpenSSLStackDeleter<StackType, T, func>>;

template<typename T, typename CleanupRet, void (*init_func)(T*),
         CleanupRet (*cleanup_func)(T*)>
class ScopedOpenSSLContext {
 public:
  ScopedOpenSSLContext() {
    init_func(&ctx_);
  }
  ~ScopedOpenSSLContext() {
    cleanup_func(&ctx_);
  }

  T *get() { return &ctx_; }
  const T *get() const { return &ctx_; }

  void Reset() {
    cleanup_func(&ctx_);
    init_func(&ctx_);
  }

 private:
  T ctx_;
};

using ScopedBIGNUM = ScopedOpenSSLType<BIGNUM, BN_free>;
using ScopedBN_CTX = ScopedOpenSSLType<BN_CTX, BN_CTX_free>;
using ScopedBN_MONT_CTX = ScopedOpenSSLType<BN_MONT_CTX, BN_MONT_CTX_free>;
using ScopedECDSA_SIG = ScopedOpenSSLType<ECDSA_SIG, ECDSA_SIG_free>;
using ScopedEC_GROUP = ScopedOpenSSLType<EC_GROUP, EC_GROUP_free>;
using ScopedEC_KEY = ScopedOpenSSLType<EC_KEY, EC_KEY_free>;
using ScopedEC_POINT = ScopedOpenSSLType<EC_POINT, EC_POINT_free>;
using ScopedRSA = ScopedOpenSSLType<RSA, RSA_free>;
using ScopedEVP_MD_CTX = ScopedOpenSSLContext<EVP_MD_CTX, int, EVP_MD_CTX_init,
                                              EVP_MD_CTX_cleanup>;
using ScopedHMAC_CTX = ScopedOpenSSLContext<HMAC_CTX, void, HMAC_CTX_init,
                                            HMAC_CTX_cleanup>;

using ScopedOpenSSLBytes = bssl::unique_ptr<uint8_t, OpenSSLFree<uint8_t>>;
using ScopedOpenSSLString = bssl::unique_ptr<char, OpenSSLFree<char>>;

using ScopedFILE = bssl::unique_ptr<FILE, FileCloser>;

#endif  // OPENSSL_HEADER_CRYPTO_TEST_SCOPED_TYPES_H
