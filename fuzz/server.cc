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


static const uint8_t kOCSPResponse[] = {0x01, 0x02, 0x03, 0x04};
static const uint8_t kSCT[] = {0x00, 0x06, 0x00, 0x04, 0x05, 0x06, 0x07, 0x08};

static int ALPNSelectCallback(SSL *ssl, const uint8_t **out, uint8_t *out_len,
                              const uint8_t *in, unsigned in_len, void *arg) {
  static const uint8_t kProtocol[] = {'a', 'a'};
  *out = kProtocol;
  *out_len = sizeof(kProtocol);
  return SSL_TLSEXT_ERR_OK;
}

static int NPNAdvertiseCallback(SSL *ssl, const uint8_t **out,
                                unsigned *out_len, void *arg) {
  static const uint8_t kProtocols[] = {
      0x01, 'a', 0x02, 'a', 'a', 0x03, 'a', 'a', 'a',
  };
  *out = kProtocols;
  *out_len = sizeof(kProtocols);
  return SSL_TLSEXT_ERR_OK;
}

struct GlobalState {
  GlobalState()
      : ctx(SSL_CTX_new(TLS_method())) {
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

    if (!SSL_CTX_set_ocsp_response(ctx, kOCSPResponse, sizeof(kOCSPResponse)) ||
        !SSL_CTX_set_signed_cert_timestamp_list(ctx, kSCT, sizeof(kSCT))) {
      abort();
    }

    SSL_CTX_set_alpn_select_cb(ctx, ALPNSelectCallback, nullptr);
    SSL_CTX_set_next_protos_advertised_cb(ctx, NPNAdvertiseCallback, nullptr);
    SSL_CTX_set_early_data_enabled(ctx, 1);

    // If accepting client certificates, allow any certificate.
    SSL_CTX_set_cert_verify_callback(
        ctx, [](X509_STORE_CTX *store_ctx, void *arg) -> int { return 1; },
        nullptr);
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
  bssl::UniquePtr<SSL> server = SetupTest(&cbs, g_state.ctx, true);
  if (!server) {
    if (g_state.debug) {
      fprintf(stderr, "Error parsing parameters.\n");
    }
    return 0;
  }

  SSL_set_max_proto_version(server.get(), TLS1_3_VERSION);
  SSL_set_min_proto_version(server.get(), SSL3_VERSION);
  SSL_set_tls_channel_id_enabled(server.get(), 1);

  // Enable ciphers that are off by default.
  SSL_set_strict_cipher_list(server.get(), "ALL:NULL-SHA");

  BIO *in = BIO_new(BIO_s_mem());
  BIO *out = BIO_new(BIO_s_mem());
  SSL_set_bio(server.get(), in, out);  // Takes ownership of |in| and |out|.

  BIO_write(in, CBS_data(&cbs), CBS_len(&cbs));
  if (SSL_do_handshake(server.get()) == 1) {
    // Keep reading application data until error or EOF.
    uint8_t tmp[1024];
    for (;;) {
      if (SSL_read(server.get(), tmp, sizeof(tmp)) <= 0) {
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
