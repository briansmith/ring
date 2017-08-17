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

#include <assert.h>
#include <stdlib.h>

#include <openssl/bio.h>
#include <openssl/bytestring.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "../ssl/test/fuzzer.h"


static const uint8_t kALPNProtocols[] = {
    0x01, 'a', 0x02, 'a', 'a', 0x03, 'a', 'a', 'a',
};

static const uint8_t kP256KeyPKCS8[] = {
    0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x03, 0x01, 0x07, 0x04, 0x6d, 0x30, 0x6b, 0x02, 0x01, 0x01, 0x04, 0x20,
    0x43, 0x09, 0xc0, 0x67, 0x75, 0x21, 0x47, 0x9d, 0xa8, 0xfa, 0x16, 0xdf,
    0x15, 0x73, 0x61, 0x34, 0x68, 0x6f, 0xe3, 0x8e, 0x47, 0x91, 0x95, 0xab,
    0x79, 0x4a, 0x72, 0x14, 0xcb, 0xe2, 0x49, 0x4f, 0xa1, 0x44, 0x03, 0x42,
    0x00, 0x04, 0xde, 0x09, 0x08, 0x07, 0x03, 0x2e, 0x8f, 0x37, 0x9a, 0xd5,
    0xad, 0xe5, 0xc6, 0x9d, 0xd4, 0x63, 0xc7, 0x4a, 0xe7, 0x20, 0xcb, 0x90,
    0xa0, 0x1f, 0x18, 0x18, 0x72, 0xb5, 0x21, 0x88, 0x38, 0xc0, 0xdb, 0xba,
    0xf6, 0x99, 0xd8, 0xa5, 0x3b, 0x83, 0xe9, 0xe3, 0xd5, 0x61, 0x99, 0x73,
    0x42, 0xc6, 0x6c, 0xe8, 0x0a, 0x95, 0x40, 0x41, 0x3b, 0x0d, 0x10, 0xa7,
    0x4a, 0x93, 0xdb, 0x5a, 0xe7, 0xec,
};

static int NPNSelectCallback(SSL *ssl, uint8_t **out, uint8_t *out_len,
                             const uint8_t *in, unsigned in_len, void *arg) {
  static const uint8_t kProtocol[] = {'a', 'a'};
  *out = const_cast<uint8_t*>(kProtocol);
  *out_len = sizeof(kProtocol);
  return SSL_TLSEXT_ERR_OK;
}

struct GlobalState {
  GlobalState() : ctx(SSL_CTX_new(TLS_method())) {
    debug = getenv("BORINGSSL_FUZZER_DEBUG") != nullptr;

    const uint8_t *bufp = kRSAPrivateKeyDER;
    RSA *privkey = d2i_RSAPrivateKey(NULL, &bufp, sizeof(kRSAPrivateKeyDER));
    assert(privkey != nullptr);

    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, privkey);

    SSL_CTX_use_PrivateKey(ctx, pkey);
    EVP_PKEY_free(pkey);

    bufp = kCertificateDER;
    X509 *cert = d2i_X509(NULL, &bufp, sizeof(kCertificateDER));
    assert(cert != nullptr);

    SSL_CTX_use_certificate(ctx, cert);
    X509_free(cert);

    SSL_CTX_set_next_proto_select_cb(ctx, NPNSelectCallback, nullptr);

    SSL_CTX_set_early_data_enabled(ctx, 1);

    CBS cbs;
    CBS_init(&cbs, kP256KeyPKCS8, sizeof(kP256KeyPKCS8));
    pkey = EVP_parse_private_key(&cbs);
    assert(pkey != nullptr);
    SSL_CTX_set1_tls_channel_id(ctx, pkey);
    EVP_PKEY_free(pkey);
  }

  ~GlobalState() {
    SSL_CTX_free(ctx);
  }

  bool debug;
  SSL_CTX *const ctx;
};

static GlobalState g_state;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) {
  RAND_reset_for_fuzzing();

  CBS cbs;
  CBS_init(&cbs, buf, len);
  bssl::UniquePtr<SSL> client = SetupTest(&cbs, g_state.ctx, false);
  if (!client) {
    if (g_state.debug) {
      fprintf(stderr, "Error parsing parameters.\n");
    }
    return 0;
  }

  SSL_set_renegotiate_mode(client.get(), ssl_renegotiate_freely);
  SSL_set_max_proto_version(client.get(), TLS1_3_VERSION);
  SSL_set_min_proto_version(client.get(), SSL3_VERSION);
  SSL_enable_ocsp_stapling(client.get());
  SSL_enable_signed_cert_timestamps(client.get());
  SSL_set_tlsext_host_name(client.get(), "hostname");
  SSL_set_alpn_protos(client.get(), kALPNProtocols, sizeof(kALPNProtocols));

  // Enable ciphers that are off by default.
  SSL_set_strict_cipher_list(client.get(), "ALL:NULL-SHA");

  BIO *in = BIO_new(BIO_s_mem());
  BIO *out = BIO_new(BIO_s_mem());
  SSL_set_bio(client.get(), in, out);  // Takes ownership of |in| and |out|.

  BIO_write(in, CBS_data(&cbs), CBS_len(&cbs));
  if (SSL_do_handshake(client.get()) == 1) {
    // Keep reading application data until error or EOF.
    uint8_t tmp[1024];
    for (;;) {
      if (SSL_read(client.get(), tmp, sizeof(tmp)) <= 0) {
        break;
      }
    }
  } else if (g_state.debug) {
    fprintf(stderr, "Handshake failed.\n");
  }

  if (g_state.debug) {
    ERR_print_errors_fp(stderr);
  }
  ERR_clear_error();
  return 0;
}
