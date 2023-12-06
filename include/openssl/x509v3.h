/* Copyright (c) 2023, Google Inc.
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

#ifndef OPENSSL_HEADER_X509V3_H
#define OPENSSL_HEADER_X509V3_H

// This header primarily exists in order to make compiling against code that
// expects OpenSSL easier. We have merged this header into <openssl/x509.h>.
// However, due to conflicts, some deprecated symbols are defined here.
#include <openssl/x509.h>

// Deprecated constants.

// The following constants are legacy aliases for |X509v3_KU_*|. They are
// defined here instead of in <openssl/x509.h> because NSS's public headers use
// the same symbols. Some callers have inadvertently relied on the conflicts
// only being defined in this header.
#define KU_DIGITAL_SIGNATURE X509v3_KU_DIGITAL_SIGNATURE
#define KU_NON_REPUDIATION X509v3_KU_NON_REPUDIATION
#define KU_KEY_ENCIPHERMENT X509v3_KU_KEY_ENCIPHERMENT
#define KU_DATA_ENCIPHERMENT X509v3_KU_DATA_ENCIPHERMENT
#define KU_KEY_AGREEMENT X509v3_KU_KEY_AGREEMENT
#define KU_KEY_CERT_SIGN X509v3_KU_KEY_CERT_SIGN
#define KU_CRL_SIGN X509v3_KU_CRL_SIGN
#define KU_ENCIPHER_ONLY X509v3_KU_ENCIPHER_ONLY
#define KU_DECIPHER_ONLY X509v3_KU_DECIPHER_ONLY

#endif  // OPENSSL_HEADER_X509V3_H
