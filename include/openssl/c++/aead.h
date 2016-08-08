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

#ifndef OPENSSL_HEADER_CXX_AEAD_H
#define OPENSSL_HEADER_CXX_AEAD_H

#include <openssl/aead.h>
#include <openssl/c++/scoped_helpers.h>

namespace bssl {

using ScopedEVP_AEAD_CTX =
    ScopedContext<EVP_AEAD_CTX, void, EVP_AEAD_CTX_zero, EVP_AEAD_CTX_cleanup>;

}  // namespace bssl

#endif /* OPENSSL_HEADER_CXX_AEAD_H */
