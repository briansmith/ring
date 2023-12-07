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

#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/x509.h>

#include "../crypto/x509/internal.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) {
  bssl::UniquePtr<X509> x509(d2i_X509(nullptr, &buf, len));
  if (x509 != nullptr) {
    // Extract the public key.
    EVP_PKEY_free(X509_get_pubkey(x509.get()));

    // Fuzz some deferred parsing.
    x509v3_cache_extensions(x509.get());

    // Fuzz every supported extension.
    for (int i = 0; i < X509_get_ext_count(x509.get()); i++) {
      const X509_EXTENSION *ext = X509_get_ext(x509.get(), i);
      void *parsed = X509V3_EXT_d2i(ext);
      if (parsed != nullptr) {
        int nid = OBJ_obj2nid(X509_EXTENSION_get_object(ext));
        BSSL_CHECK(nid != NID_undef);

        // Reserialize the extension. This should succeed if we were able to
        // parse it.
        // TODO(crbug.com/boringssl/352): Ideally we would also assert that
        // |new_ext| is identical to |ext|, but our parser is not strict enough.
        bssl::UniquePtr<X509_EXTENSION> new_ext(
            X509V3_EXT_i2d(nid, X509_EXTENSION_get_critical(ext), parsed));
        BSSL_CHECK(new_ext != nullptr);

        // This can only fail if |ext| was not a supported type, but then
        // |X509V3_EXT_d2i| should have failed.
        BSSL_CHECK(X509V3_EXT_free(nid, parsed));
      }
    }

    // Reserialize |x509|. This should succeed if we were able to parse it.
    // TODO(crbug.com/boringssl/352): Ideally we would also assert the output
    // matches the input, but our parser is not strict enough.
    uint8_t *der = nullptr;
    int der_len = i2d_X509(x509.get(), &der);
    BSSL_CHECK(der_len > 0);
    OPENSSL_free(der);

    // Reserialize |x509|'s TBSCertificate without reusing the cached encoding.
    // TODO(crbug.com/boringssl/352): Ideally we would also assert the output
    // matches the input TBSCertificate, but our parser is not strict enough.
    der = nullptr;
    der_len = i2d_re_X509_tbs(x509.get(), &der);
    BSSL_CHECK(der_len > 0);
    OPENSSL_free(der);

    BIO *bio = BIO_new(BIO_s_mem());
    X509_print(bio, x509.get());
    BIO_free(bio);
  }
  ERR_clear_error();
  return 0;
}
