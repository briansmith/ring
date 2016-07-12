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

#include <openssl/base.h>

#include <stdint.h>
#include <stdio.h>

#include <memory>

#include <openssl/aead.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/bytestring.h>
#include <openssl/cmac.h>
#include <openssl/curve25519.h>
#include <openssl/dh.h>
#include <openssl/ecdsa.h>
#include <openssl/ec.h>
#include <openssl/ec_key.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/mem.h>
#include <openssl/newhope.h>
#include <openssl/pkcs8.h>
#include <openssl/rsa.h>
#include <openssl/stack.h>
#include <openssl/x509.h>

namespace bssl {

struct FileCloser {
  void operator()(FILE *file) {
    fclose(file);
  }
};

using ScopedASN1_TYPE = ScopedType<ASN1_TYPE, ASN1_TYPE_free>;
using ScopedBIO = ScopedType<BIO, BIO_vfree>;
using ScopedBIGNUM = ScopedType<BIGNUM, BN_free>;
using ScopedBN_CTX = ScopedType<BN_CTX, BN_CTX_free>;
using ScopedBN_MONT_CTX = ScopedType<BN_MONT_CTX, BN_MONT_CTX_free>;
using ScopedCMAC_CTX = ScopedType<CMAC_CTX, CMAC_CTX_free>;
using ScopedDH = ScopedType<DH, DH_free>;
using ScopedECDSA_SIG = ScopedType<ECDSA_SIG, ECDSA_SIG_free>;
using ScopedEC_GROUP = ScopedType<EC_GROUP, EC_GROUP_free>;
using ScopedEC_KEY = ScopedType<EC_KEY, EC_KEY_free>;
using ScopedEC_POINT = ScopedType<EC_POINT, EC_POINT_free>;
using ScopedEVP_PKEY = ScopedType<EVP_PKEY, EVP_PKEY_free>;
using ScopedEVP_PKEY_CTX = ScopedType<EVP_PKEY_CTX, EVP_PKEY_CTX_free>;
using ScopedNEWHOPE_POLY = ScopedType<NEWHOPE_POLY, NEWHOPE_POLY_free>;
using ScopedPKCS8_PRIV_KEY_INFO =
    ScopedType<PKCS8_PRIV_KEY_INFO, PKCS8_PRIV_KEY_INFO_free>;
using ScopedPKCS12 = ScopedType<PKCS12, PKCS12_free>;
using ScopedSPAKE2_CTX = ScopedType<SPAKE2_CTX, SPAKE2_CTX_free>;
using ScopedRSA = ScopedType<RSA, RSA_free>;
using ScopedX509 = ScopedType<X509, X509_free>;
using ScopedX509_ALGOR = ScopedType<X509_ALGOR, X509_ALGOR_free>;
using ScopedX509_SIG = ScopedType<X509_SIG, X509_SIG_free>;
using ScopedX509_STORE_CTX = ScopedType<X509_STORE_CTX, X509_STORE_CTX_free>;

using ScopedX509Stack = ScopedStack<STACK_OF(X509), X509, X509_free>;

using ScopedCBB = ScopedContext<CBB, void, CBB_zero, CBB_cleanup>;
using ScopedEVP_AEAD_CTX =
    ScopedContext<EVP_AEAD_CTX, void, EVP_AEAD_CTX_zero, EVP_AEAD_CTX_cleanup>;
using ScopedEVP_CIPHER_CTX =
    ScopedContext<EVP_CIPHER_CTX, int, EVP_CIPHER_CTX_init,
                  EVP_CIPHER_CTX_cleanup>;
using ScopedEVP_MD_CTX =
    ScopedContext<EVP_MD_CTX, int, EVP_MD_CTX_init, EVP_MD_CTX_cleanup>;
using ScopedHMAC_CTX =
    ScopedContext<HMAC_CTX, void, HMAC_CTX_init, HMAC_CTX_cleanup>;

using ScopedBytes = std::unique_ptr<uint8_t, Free<uint8_t>>;
using ScopedString = std::unique_ptr<char, Free<char>>;

using ScopedFILE = std::unique_ptr<FILE, FileCloser>;

}  // namespace bssl

#endif  // OPENSSL_HEADER_CRYPTO_TEST_SCOPED_TYPES_H
