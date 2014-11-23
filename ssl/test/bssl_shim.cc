/* Copyright (c) 2014, Google Inc.
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

#include <openssl/base.h>

#if !defined(OPENSSL_WINDOWS)
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <sys/types.h>

#include <openssl/bio.h>
#include <openssl/buf.h>
#include <openssl/bytestring.h>
#include <openssl/ssl.h>

#include "async_bio.h"
#include "packeted_bio.h"
#include "test_config.h"

static int usage(const char *program) {
  fprintf(stderr, "Usage: %s [flags...]\n",
          program);
  return 1;
}

static int g_ex_data_index = 0;

static bool SetConfigPtr(SSL *ssl, const TestConfig *config) {
  return SSL_set_ex_data(ssl, g_ex_data_index, (void *)config) == 1;
}

static const TestConfig *GetConfigPtr(SSL *ssl) {
  return (const TestConfig *)SSL_get_ex_data(ssl, g_ex_data_index);
}

static EVP_PKEY *LoadPrivateKey(const std::string &file) {
  BIO *bio = BIO_new(BIO_s_file());
  if (bio == NULL) {
    return NULL;
  }
  if (!BIO_read_filename(bio, file.c_str())) {
    BIO_free(bio);
    return NULL;
  }
  EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
  BIO_free(bio);
  return pkey;
}

static int early_callback_called = 0;

static int select_certificate_callback(const struct ssl_early_callback_ctx *ctx) {
  early_callback_called = 1;

  const TestConfig *config = GetConfigPtr(ctx->ssl);

  if (config->expected_server_name.empty()) {
    return 1;
  }

  const uint8_t *extension_data;
  size_t extension_len;
  CBS extension, server_name_list, host_name;
  uint8_t name_type;

  if (!SSL_early_callback_ctx_extension_get(ctx, TLSEXT_TYPE_server_name,
                                            &extension_data,
                                            &extension_len)) {
    fprintf(stderr, "Could not find server_name extension.\n");
    return -1;
  }

  CBS_init(&extension, extension_data, extension_len);
  if (!CBS_get_u16_length_prefixed(&extension, &server_name_list) ||
      CBS_len(&extension) != 0 ||
      !CBS_get_u8(&server_name_list, &name_type) ||
      name_type != TLSEXT_NAMETYPE_host_name ||
      !CBS_get_u16_length_prefixed(&server_name_list, &host_name) ||
      CBS_len(&server_name_list) != 0) {
    fprintf(stderr, "Could not decode server_name extension.\n");
    return -1;
  }

  if (!CBS_mem_equal(&host_name,
                     (const uint8_t*)config->expected_server_name.data(),
                     config->expected_server_name.size())) {
    fprintf(stderr, "Server name mismatch.\n");
  }

  return 1;
}

static int skip_verify(int preverify_ok, X509_STORE_CTX *store_ctx) {
  return 1;
}

static int next_protos_advertised_callback(SSL *ssl,
                                           const uint8_t **out,
                                           unsigned int *out_len,
                                           void *arg) {
  const TestConfig *config = GetConfigPtr(ssl);
  if (config->advertise_npn.empty())
    return SSL_TLSEXT_ERR_NOACK;

  *out = (const uint8_t*)config->advertise_npn.data();
  *out_len = config->advertise_npn.size();
  return SSL_TLSEXT_ERR_OK;
}

static int next_proto_select_callback(SSL* ssl,
                                      uint8_t** out,
                                      uint8_t* outlen,
                                      const uint8_t* in,
                                      unsigned inlen,
                                      void* arg) {
  const TestConfig *config = GetConfigPtr(ssl);
  if (config->select_next_proto.empty())
    return SSL_TLSEXT_ERR_NOACK;

  *out = (uint8_t*)config->select_next_proto.data();
  *outlen = config->select_next_proto.size();
  return SSL_TLSEXT_ERR_OK;
}

static int alpn_select_callback(SSL* ssl,
                                const uint8_t** out,
                                uint8_t* outlen,
                                const uint8_t* in,
                                unsigned inlen,
                                void* arg) {
  const TestConfig *config = GetConfigPtr(ssl);
  if (config->select_alpn.empty())
    return SSL_TLSEXT_ERR_NOACK;

  if (!config->expected_advertised_alpn.empty() &&
      (config->expected_advertised_alpn.size() != inlen ||
       memcmp(config->expected_advertised_alpn.data(),
              in, inlen) != 0)) {
    fprintf(stderr, "bad ALPN select callback inputs\n");
    exit(1);
  }

  *out = (const uint8_t*)config->select_alpn.data();
  *outlen = config->select_alpn.size();
  return SSL_TLSEXT_ERR_OK;
}

static int cookie_generate_callback(SSL *ssl, uint8_t *cookie, size_t *cookie_len) {
  if (*cookie_len < 32) {
    fprintf(stderr, "Insufficient space for cookie\n");
    return 0;
  }
  *cookie_len = 32;
  memset(cookie, 42, *cookie_len);
  return 1;
}

static int cookie_verify_callback(SSL *ssl, const uint8_t *cookie, size_t cookie_len) {
  if (cookie_len != 32) {
    fprintf(stderr, "Cookie length mismatch.\n");
    return 0;
  }
  for (size_t i = 0; i < cookie_len; i++) {
    if (cookie[i] != 42) {
      fprintf(stderr, "Cookie mismatch.\n");
      return 0;
    }
  }
  return 1;
}

static unsigned psk_client_callback(SSL *ssl, const char *hint,
                                    char *out_identity,
                                    unsigned max_identity_len,
                                    uint8_t *out_psk, unsigned max_psk_len) {
  const TestConfig *config = GetConfigPtr(ssl);

  if (strcmp(hint ? hint : "", config->psk_identity.c_str()) != 0) {
    fprintf(stderr, "Server PSK hint did not match.\n");
    return 0;
  }

  // Account for the trailing '\0' for the identity.
  if (config->psk_identity.size() >= max_identity_len ||
      config->psk.size() > max_psk_len) {
    fprintf(stderr, "PSK buffers too small\n");
    return 0;
  }

  BUF_strlcpy(out_identity, config->psk_identity.c_str(),
              max_identity_len);
  memcpy(out_psk, config->psk.data(), config->psk.size());
  return config->psk.size();
}

static unsigned psk_server_callback(SSL *ssl, const char *identity,
                                    uint8_t *out_psk, unsigned max_psk_len) {
  const TestConfig *config = GetConfigPtr(ssl);

  if (strcmp(identity, config->psk_identity.c_str()) != 0) {
    fprintf(stderr, "Client PSK identity did not match.\n");
    return 0;
  }

  if (config->psk.size() > max_psk_len) {
    fprintf(stderr, "PSK buffers too small\n");
    return 0;
  }

  memcpy(out_psk, config->psk.data(), config->psk.size());
  return config->psk.size();
}

static SSL_CTX *setup_ctx(const TestConfig *config) {
  SSL_CTX *ssl_ctx = NULL;
  DH *dh = NULL;

  ssl_ctx = SSL_CTX_new(config->is_dtls ? DTLS_method() : SSLv23_method());
  if (ssl_ctx == NULL) {
    goto err;
  }

  if (config->is_dtls) {
    // DTLS needs read-ahead to function on a datagram BIO.
    //
    // TODO(davidben): this should not be necessary. DTLS code should only
    // expect a datagram BIO.
    SSL_CTX_set_read_ahead(ssl_ctx, 1);
  }

  if (!SSL_CTX_set_ecdh_auto(ssl_ctx, 1)) {
    goto err;
  }

  if (!SSL_CTX_set_cipher_list(ssl_ctx, "ALL")) {
    goto err;
  }

  dh = DH_get_2048_256(NULL);
  if (dh == NULL ||
      !SSL_CTX_set_tmp_dh(ssl_ctx, dh)) {
    goto err;
  }

  SSL_CTX_set_session_cache_mode(ssl_ctx, SSL_SESS_CACHE_BOTH);

  ssl_ctx->select_certificate_cb = select_certificate_callback;

  SSL_CTX_set_next_protos_advertised_cb(
      ssl_ctx, next_protos_advertised_callback, NULL);
  if (!config->select_next_proto.empty()) {
    SSL_CTX_set_next_proto_select_cb(ssl_ctx, next_proto_select_callback, NULL);
  }

  if (!config->select_alpn.empty()) {
    SSL_CTX_set_alpn_select_cb(ssl_ctx, alpn_select_callback, NULL);
  }

  SSL_CTX_set_cookie_generate_cb(ssl_ctx, cookie_generate_callback);
  SSL_CTX_set_cookie_verify_cb(ssl_ctx, cookie_verify_callback);

  ssl_ctx->tlsext_channel_id_enabled_new = 1;

  DH_free(dh);
  return ssl_ctx;

 err:
  if (dh != NULL) {
    DH_free(dh);
  }
  if (ssl_ctx != NULL) {
    SSL_CTX_free(ssl_ctx);
  }
  return NULL;
}

static int retry_async(SSL *ssl, int ret, BIO *bio) {
  // No error; don't retry.
  if (ret >= 0) {
    return 0;
  }
  // See if we needed to read or write more. If so, allow one byte through on
  // the appropriate end to maximally stress the state machine.
  int err = SSL_get_error(ssl, ret);
  if (err == SSL_ERROR_WANT_READ) {
    async_bio_allow_read(bio, 1);
    return 1;
  } else if (err == SSL_ERROR_WANT_WRITE) {
    async_bio_allow_write(bio, 1);
    return 1;
  }
  return 0;
}

static int do_exchange(SSL_SESSION **out_session,
                       SSL_CTX *ssl_ctx,
                       const TestConfig *config,
                       bool is_resume,
                       int fd,
                       SSL_SESSION *session) {
  early_callback_called = 0;

  SSL *ssl = SSL_new(ssl_ctx);
  if (ssl == NULL) {
    BIO_print_errors_fp(stdout);
    return 1;
  }

  if (!SetConfigPtr(ssl, config)) {
    BIO_print_errors_fp(stdout);
    return 1;
  }

  if (config->fallback_scsv) {
    if (!SSL_enable_fallback_scsv(ssl)) {
      BIO_print_errors_fp(stdout);
      return 1;
    }
  }
  if (!config->key_file.empty()) {
    if (!SSL_use_PrivateKey_file(ssl, config->key_file.c_str(),
                                 SSL_FILETYPE_PEM)) {
      BIO_print_errors_fp(stdout);
      return 1;
    }
  }
  if (!config->cert_file.empty()) {
    if (!SSL_use_certificate_file(ssl, config->cert_file.c_str(),
                                  SSL_FILETYPE_PEM)) {
      BIO_print_errors_fp(stdout);
      return 1;
    }
  }
  if (config->require_any_client_certificate) {
    SSL_set_verify(ssl, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                   skip_verify);
  }
  if (config->false_start) {
    SSL_set_mode(ssl, SSL_MODE_HANDSHAKE_CUTTHROUGH);
  }
  if (config->cbc_record_splitting) {
    SSL_set_mode(ssl, SSL_MODE_CBC_RECORD_SPLITTING);
  }
  if (config->partial_write) {
    SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);
  }
  if (config->no_tls12) {
    SSL_set_options(ssl, SSL_OP_NO_TLSv1_2);
  }
  if (config->no_tls11) {
    SSL_set_options(ssl, SSL_OP_NO_TLSv1_1);
  }
  if (config->no_tls1) {
    SSL_set_options(ssl, SSL_OP_NO_TLSv1);
  }
  if (config->no_ssl3) {
    SSL_set_options(ssl, SSL_OP_NO_SSLv3);
  }
  if (config->cookie_exchange) {
    SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);
  }
  if (config->tls_d5_bug) {
    SSL_set_options(ssl, SSL_OP_TLS_D5_BUG);
  }
  if (config->allow_unsafe_legacy_renegotiation) {
    SSL_set_options(ssl, SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
  }
  if (!config->expected_channel_id.empty()) {
    SSL_enable_tls_channel_id(ssl);
  }
  if (!config->send_channel_id.empty()) {
    EVP_PKEY *pkey = LoadPrivateKey(config->send_channel_id);
    if (pkey == NULL) {
      BIO_print_errors_fp(stdout);
      return 1;
    }
    SSL_enable_tls_channel_id(ssl);
    if (!SSL_set1_tls_channel_id(ssl, pkey)) {
      EVP_PKEY_free(pkey);
      BIO_print_errors_fp(stdout);
      return 1;
    }
    EVP_PKEY_free(pkey);
  }
  if (!config->host_name.empty()) {
    SSL_set_tlsext_host_name(ssl, config->host_name.c_str());
  }
  if (!config->advertise_alpn.empty()) {
    SSL_set_alpn_protos(ssl, (const uint8_t *)config->advertise_alpn.data(),
                        config->advertise_alpn.size());
  }
  if (!config->psk.empty()) {
    SSL_set_psk_client_callback(ssl, psk_client_callback);
    SSL_set_psk_server_callback(ssl, psk_server_callback);
  }
  if (!config->psk_identity.empty() &&
      !SSL_use_psk_identity_hint(ssl, config->psk_identity.c_str())) {
    BIO_print_errors_fp(stdout);
    return 1;
  }
  if (!config->srtp_profiles.empty() &&
      !SSL_set_srtp_profiles(ssl, config->srtp_profiles.c_str())) {
    BIO_print_errors_fp(stdout);
    return 1;
  }
  if (config->enable_ocsp_stapling &&
      !SSL_enable_ocsp_stapling(ssl)) {
    BIO_print_errors_fp(stdout);
    return 1;
  }
  if (config->enable_signed_cert_timestamps &&
      !SSL_enable_signed_cert_timestamps(ssl)) {
    BIO_print_errors_fp(stdout);
    return 1;
  }

  BIO *bio = BIO_new_fd(fd, 1 /* take ownership */);
  if (bio == NULL) {
    BIO_print_errors_fp(stdout);
    return 1;
  }
  if (config->is_dtls) {
    BIO *packeted = packeted_bio_create();
    BIO_push(packeted, bio);
    bio = packeted;
  }
  if (config->async) {
    BIO *async =
        config->is_dtls ? async_bio_create_datagram() : async_bio_create();
    BIO_push(async, bio);
    bio = async;
  }
  SSL_set_bio(ssl, bio, bio);

  if (session != NULL) {
    if (SSL_set_session(ssl, session) != 1) {
      fprintf(stderr, "failed to set session\n");
      return 2;
    }
  }

  int ret;
  do {
    if (config->is_server) {
      ret = SSL_accept(ssl);
    } else {
      ret = SSL_connect(ssl);
    }
  } while (config->async && retry_async(ssl, ret, bio));
  if (ret != 1) {
    SSL_free(ssl);
    BIO_print_errors_fp(stdout);
    return 2;
  }

  if (is_resume && (SSL_session_reused(ssl) == config->expect_session_miss)) {
    fprintf(stderr, "session was%s reused\n",
            SSL_session_reused(ssl) ? "" : " not");
    return 2;
  }

  if (!config->expected_server_name.empty()) {
    const char *server_name =
        SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (server_name != config->expected_server_name) {
      fprintf(stderr, "servername mismatch (got %s; want %s)\n",
              server_name, config->expected_server_name.c_str());
      return 2;
    }

    if (!early_callback_called) {
      fprintf(stderr, "early callback not called\n");
      return 2;
    }
  }

  if (!config->expected_certificate_types.empty()) {
    uint8_t *certificate_types;
    int num_certificate_types =
        SSL_get0_certificate_types(ssl, &certificate_types);
    if (num_certificate_types !=
        (int)config->expected_certificate_types.size() ||
        memcmp(certificate_types,
               config->expected_certificate_types.data(),
               num_certificate_types) != 0) {
      fprintf(stderr, "certificate types mismatch\n");
      return 2;
    }
  }

  if (!config->expected_next_proto.empty()) {
    const uint8_t *next_proto;
    unsigned next_proto_len;
    SSL_get0_next_proto_negotiated(ssl, &next_proto, &next_proto_len);
    if (next_proto_len != config->expected_next_proto.size() ||
        memcmp(next_proto, config->expected_next_proto.data(),
               next_proto_len) != 0) {
      fprintf(stderr, "negotiated next proto mismatch\n");
      return 2;
    }
  }

  if (!config->expected_alpn.empty()) {
    const uint8_t *alpn_proto;
    unsigned alpn_proto_len;
    SSL_get0_alpn_selected(ssl, &alpn_proto, &alpn_proto_len);
    if (alpn_proto_len != config->expected_alpn.size() ||
        memcmp(alpn_proto, config->expected_alpn.data(),
               alpn_proto_len) != 0) {
      fprintf(stderr, "negotiated alpn proto mismatch\n");
      return 2;
    }
  }

  if (!config->expected_channel_id.empty()) {
    uint8_t channel_id[64];
    if (!SSL_get_tls_channel_id(ssl, channel_id, sizeof(channel_id))) {
      fprintf(stderr, "no channel id negotiated\n");
      return 2;
    }
    if (config->expected_channel_id.size() != 64 ||
        memcmp(config->expected_channel_id.data(),
               channel_id, 64) != 0) {
      fprintf(stderr, "channel id mismatch\n");
      return 2;
    }
  }

  if (config->expect_extended_master_secret) {
    if (!ssl->session->extended_master_secret) {
      fprintf(stderr, "No EMS for session when expected");
      return 2;
    }
  }

  if (!config->expected_ocsp_response.empty()) {
    const uint8_t *data;
    size_t len;
    SSL_get0_ocsp_response(ssl, &data, &len);
    if (config->expected_ocsp_response.size() != len ||
        memcmp(config->expected_ocsp_response.data(), data, len) != 0) {
      fprintf(stderr, "OCSP response mismatch\n");
      return 2;
    }
  }

  if (!config->expected_signed_cert_timestamps.empty()) {
    const uint8_t *data;
    size_t len;
    SSL_get0_signed_cert_timestamp_list(ssl, &data, &len);
    if (config->expected_signed_cert_timestamps.size() != len ||
        memcmp(config->expected_signed_cert_timestamps.data(),
               data, len) != 0) {
      fprintf(stderr, "SCT list mismatch\n");
      return 2;
    }
  }

  if (config->renegotiate) {
    if (config->async) {
      fprintf(stderr, "--renegotiate is not supported with --async.\n");
      return 2;
    }

    SSL_renegotiate(ssl);

    ret = SSL_do_handshake(ssl);
    if (ret != 1) {
      SSL_free(ssl);
      BIO_print_errors_fp(stdout);
      return 2;
    }

    SSL_set_state(ssl, SSL_ST_ACCEPT);
    ret = SSL_do_handshake(ssl);
    if (ret != 1) {
      SSL_free(ssl);
      BIO_print_errors_fp(stdout);
      return 2;
    }
  }

  if (config->write_different_record_sizes) {
    if (config->is_dtls) {
      fprintf(stderr, "write_different_record_sizes not supported for DTLS\n");
      return 6;
    }
    // This mode writes a number of different record sizes in an attempt to
    // trip up the CBC record splitting code.
    uint8_t buf[32769];
    memset(buf, 0x42, sizeof(buf));
    static const size_t kRecordSizes[] = {
        0, 1, 255, 256, 257, 16383, 16384, 16385, 32767, 32768, 32769};
    for (size_t i = 0; i < sizeof(kRecordSizes) / sizeof(kRecordSizes[0]);
         i++) {
      int w;
      const size_t len = kRecordSizes[i];
      size_t off = 0;

      if (len > sizeof(buf)) {
        fprintf(stderr, "Bad kRecordSizes value.\n");
        return 5;
      }

      do {
        w = SSL_write(ssl, buf + off, len - off);
        if (w > 0) {
          off += (size_t) w;
        }
      } while ((config->async && retry_async(ssl, w, bio)) ||
               (w > 0 && off < len));

      if (w < 0 || off != len) {
        SSL_free(ssl);
        BIO_print_errors_fp(stdout);
        return 4;
      }
    }
  } else {
    if (config->shim_writes_first) {
      int w;
      do {
        w = SSL_write(ssl, "hello", 5);
      } while (config->async && retry_async(ssl, w, bio));
    }
    for (;;) {
      uint8_t buf[512];
      int n;
      do {
        n = SSL_read(ssl, buf, sizeof(buf));
      } while (config->async && retry_async(ssl, n, bio));
      if (n < 0) {
        SSL_free(ssl);
        BIO_print_errors_fp(stdout);
        return 3;
      } else if (n == 0) {
        break;
      } else {
        for (int i = 0; i < n; i++) {
          buf[i] ^= 0xff;
        }
        int w;
        do {
          w = SSL_write(ssl, buf, n);
        } while (config->async && retry_async(ssl, w, bio));
        if (w != n) {
          SSL_free(ssl);
          BIO_print_errors_fp(stdout);
          return 4;
        }
      }
    }
  }

  if (out_session) {
    *out_session = SSL_get1_session(ssl);
  }

  SSL_shutdown(ssl);
  SSL_free(ssl);
  return 0;
}

int main(int argc, char **argv) {
#if !defined(OPENSSL_WINDOWS)
  signal(SIGPIPE, SIG_IGN);
#endif

  if (!SSL_library_init()) {
    return 1;
  }
  g_ex_data_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
  if (g_ex_data_index < 0) {
    return 1;
  }

  TestConfig config;
  if (!ParseConfig(argc - 1, argv + 1, &config)) {
    return usage(argv[0]);
  }

  SSL_CTX *ssl_ctx = setup_ctx(&config);
  if (ssl_ctx == NULL) {
    BIO_print_errors_fp(stdout);
    return 1;
  }

  SSL_SESSION *session = NULL;
  int ret = do_exchange(&session,
                        ssl_ctx, &config,
                        false /* is_resume */,
                        3 /* fd */, NULL /* session */);
  if (ret != 0) {
    goto out;
  }

  if (config.resume) {
    ret = do_exchange(NULL,
                      ssl_ctx, &config,
                      true /* is_resume */,
                      4 /* fd */,
                      config.is_server ? NULL : session);
    if (ret != 0) {
      goto out;
    }
  }

  ret = 0;

out:
  SSL_SESSION_free(session);
  SSL_CTX_free(ssl_ctx);
  return ret;
}
