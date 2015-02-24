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
#include <netinet/tcp.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>
#else
#include <io.h>
#pragma warning(push, 3)
#include <WinSock2.h>
#include <WS2tcpip.h>
#pragma warning(pop)

#pragma comment(lib, "Ws2_32.lib")
#endif

#include <string.h>
#include <sys/types.h>

#include <openssl/bio.h>
#include <openssl/buf.h>
#include <openssl/bytestring.h>
#include <openssl/ssl.h>

#include "async_bio.h"
#include "packeted_bio.h"
#include "scoped_types.h"
#include "test_config.h"


#if !defined(OPENSSL_WINDOWS)
static int closesocket(int sock) {
  return close(sock);
}

static void PrintSocketError(const char *func) {
  perror(func);
}
#else
static void PrintSocketError(const char *func) {
  fprintf(stderr, "%s: %d\n", func, WSAGetLastError());
}
#endif

static int Usage(const char *program) {
  fprintf(stderr, "Usage: %s [flags...]\n", program);
  return 1;
}

struct TestState {
  TestState() : cert_ready(false), early_callback_called(false) {}

  ScopedEVP_PKEY channel_id;
  bool cert_ready;
  ScopedSSL_SESSION session;
  ScopedSSL_SESSION pending_session;
  bool early_callback_called;
};

static void TestStateExFree(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
			    int index, long argl, void *argp) {
  delete ((TestState *)ptr);
}

static int g_config_index = 0;
static int g_clock_index = 0;
static int g_state_index = 0;

static bool SetConfigPtr(SSL *ssl, const TestConfig *config) {
  return SSL_set_ex_data(ssl, g_config_index, (void *)config) == 1;
}

static const TestConfig *GetConfigPtr(SSL *ssl) {
  return (const TestConfig *)SSL_get_ex_data(ssl, g_config_index);
}

static bool SetClockPtr(SSL *ssl, OPENSSL_timeval *clock) {
  return SSL_set_ex_data(ssl, g_clock_index, (void *)clock) == 1;
}

static OPENSSL_timeval *GetClockPtr(SSL *ssl) {
  return (OPENSSL_timeval *)SSL_get_ex_data(ssl, g_clock_index);
}

static bool SetTestState(SSL *ssl, std::unique_ptr<TestState> async) {
  if (SSL_set_ex_data(ssl, g_state_index, (void *)async.get()) == 1) {
    async.release();
    return true;
  }
  return false;
}

static TestState *GetTestState(SSL *ssl) {
  return (TestState *)SSL_get_ex_data(ssl, g_state_index);
}

static ScopedEVP_PKEY LoadPrivateKey(const std::string &file) {
  ScopedBIO bio(BIO_new(BIO_s_file()));
  if (!bio || !BIO_read_filename(bio.get(), file.c_str())) {
    return nullptr;
  }
  ScopedEVP_PKEY pkey(PEM_read_bio_PrivateKey(bio.get(), NULL, NULL, NULL));
  return pkey;
}

static bool InstallCertificate(SSL *ssl) {
  const TestConfig *config = GetConfigPtr(ssl);
  if (!config->key_file.empty() &&
      !SSL_use_PrivateKey_file(ssl, config->key_file.c_str(),
                               SSL_FILETYPE_PEM)) {
    return false;
  }
  if (!config->cert_file.empty() &&
      !SSL_use_certificate_file(ssl, config->cert_file.c_str(),
                                SSL_FILETYPE_PEM)) {
    return false;
  }
  return true;
}

static int SelectCertificateCallback(const struct ssl_early_callback_ctx *ctx) {
  const TestConfig *config = GetConfigPtr(ctx->ssl);
  GetTestState(ctx->ssl)->early_callback_called = true;

  if (!config->expected_server_name.empty()) {
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
  }

  if (config->fail_early_callback) {
    return -1;
  }

  // Install the certificate in the early callback.
  if (config->use_early_callback) {
    if (config->async) {
      // Install the certificate asynchronously.
      return 0;
    }
    if (!InstallCertificate(ctx->ssl)) {
      return -1;
    }
  }
  return 1;
}

static int SkipVerify(int preverify_ok, X509_STORE_CTX *store_ctx) {
  return 1;
}

static int NextProtosAdvertisedCallback(SSL *ssl, const uint8_t **out,
                                        unsigned int *out_len, void *arg) {
  const TestConfig *config = GetConfigPtr(ssl);
  if (config->advertise_npn.empty()) {
    return SSL_TLSEXT_ERR_NOACK;
  }

  *out = (const uint8_t*)config->advertise_npn.data();
  *out_len = config->advertise_npn.size();
  return SSL_TLSEXT_ERR_OK;
}

static int NextProtoSelectCallback(SSL* ssl, uint8_t** out, uint8_t* outlen,
                            const uint8_t* in, unsigned inlen, void* arg) {
  const TestConfig *config = GetConfigPtr(ssl);
  if (config->select_next_proto.empty()) {
    return SSL_TLSEXT_ERR_NOACK;
  }

  *out = (uint8_t*)config->select_next_proto.data();
  *outlen = config->select_next_proto.size();
  return SSL_TLSEXT_ERR_OK;
}

static int AlpnSelectCallback(SSL* ssl, const uint8_t** out, uint8_t* outlen,
                              const uint8_t* in, unsigned inlen, void* arg) {
  const TestConfig *config = GetConfigPtr(ssl);
  if (config->select_alpn.empty()) {
    return SSL_TLSEXT_ERR_NOACK;
  }

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

static unsigned PskClientCallback(SSL *ssl, const char *hint,
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

static unsigned PskServerCallback(SSL *ssl, const char *identity,
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

static void CurrentTimeCallback(SSL *ssl, OPENSSL_timeval *out_clock) {
  *out_clock = *GetClockPtr(ssl);
}

static void ChannelIdCallback(SSL *ssl, EVP_PKEY **out_pkey) {
  *out_pkey = GetTestState(ssl)->channel_id.release();
}

static int CertCallback(SSL *ssl, void *arg) {
  if (!GetTestState(ssl)->cert_ready) {
    return -1;
  }
  if (!InstallCertificate(ssl)) {
    return 0;
  }
  return 1;
}

static SSL_SESSION *GetSessionCallback(SSL *ssl, uint8_t *data, int len,
                                       int *copy) {
  TestState *async_state = GetTestState(ssl);
  if (async_state->session) {
    *copy = 0;
    return async_state->session.release();
  } else if (async_state->pending_session) {
    return SSL_magic_pending_session_ptr();
  } else {
    return NULL;
  }
}

// Connect returns a new socket connected to localhost on |port| or -1 on
// error.
static int Connect(uint16_t port) {
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock == -1) {
    PrintSocketError("socket");
    return -1;
  }
  int nodelay = 1;
  if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY,
          reinterpret_cast<const char*>(&nodelay), sizeof(nodelay)) != 0) {
    PrintSocketError("setsockopt");
    closesocket(sock);
    return -1;
  }
  sockaddr_in sin;
  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_port = htons(port);
  if (!inet_pton(AF_INET, "127.0.0.1", &sin.sin_addr)) {
    PrintSocketError("inet_pton");
    closesocket(sock);
    return -1;
  }
  if (connect(sock, reinterpret_cast<const sockaddr*>(&sin),
              sizeof(sin)) != 0) {
    PrintSocketError("connect");
    closesocket(sock);
    return -1;
  }
  return sock;
}

class SocketCloser {
 public:
  explicit SocketCloser(int sock) : sock_(sock) {}
  ~SocketCloser() {
    // Half-close and drain the socket before releasing it. This seems to be
    // necessary for graceful shutdown on Windows. It will also avoid write
    // failures in the test runner.
#if defined(OPENSSL_WINDOWS)
    shutdown(sock_, SD_SEND);
#else
    shutdown(sock_, SHUT_WR);
#endif
    while (true) {
      char buf[1024];
      if (recv(sock_, buf, sizeof(buf), 0) <= 0) {
        break;
      }
    }
    closesocket(sock_);
  }

 private:
  const int sock_;
};

static ScopedSSL_CTX SetupCtx(const TestConfig *config) {
  ScopedSSL_CTX ssl_ctx(SSL_CTX_new(
      config->is_dtls ? DTLS_method() : TLS_method()));
  if (!ssl_ctx) {
    return nullptr;
  }

  if (config->is_dtls) {
    // DTLS needs read-ahead to function on a datagram BIO.
    //
    // TODO(davidben): this should not be necessary. DTLS code should only
    // expect a datagram BIO.
    SSL_CTX_set_read_ahead(ssl_ctx.get(), 1);
  }

  if (!SSL_CTX_set_ecdh_auto(ssl_ctx.get(), 1)) {
    return nullptr;
  }

  if (!SSL_CTX_set_cipher_list(ssl_ctx.get(), "ALL")) {
    return nullptr;
  }

  ScopedDH dh(DH_get_2048_256(NULL));
  if (!dh || !SSL_CTX_set_tmp_dh(ssl_ctx.get(), dh.get())) {
    return nullptr;
  }

  if (config->async && config->is_server) {
    // Disable the internal session cache. To test asynchronous session lookup,
    // we use an external session cache.
    SSL_CTX_set_session_cache_mode(
        ssl_ctx.get(), SSL_SESS_CACHE_BOTH | SSL_SESS_CACHE_NO_INTERNAL);
    SSL_CTX_sess_set_get_cb(ssl_ctx.get(), GetSessionCallback);
  } else {
    SSL_CTX_set_session_cache_mode(ssl_ctx.get(), SSL_SESS_CACHE_BOTH);
  }

  ssl_ctx->select_certificate_cb = SelectCertificateCallback;

  SSL_CTX_set_next_protos_advertised_cb(
      ssl_ctx.get(), NextProtosAdvertisedCallback, NULL);
  if (!config->select_next_proto.empty()) {
    SSL_CTX_set_next_proto_select_cb(ssl_ctx.get(), NextProtoSelectCallback,
                                     NULL);
  }

  if (!config->select_alpn.empty()) {
    SSL_CTX_set_alpn_select_cb(ssl_ctx.get(), AlpnSelectCallback, NULL);
  }

  ssl_ctx->tlsext_channel_id_enabled_new = 1;
  SSL_CTX_set_channel_id_cb(ssl_ctx.get(), ChannelIdCallback);

  ssl_ctx->current_time_cb = CurrentTimeCallback;

  return ssl_ctx;
}

// RetryAsync is called after a failed operation on |ssl| with return code
// |ret|. If the operation should be retried, it simulates one asynchronous
// event and returns true. Otherwise it returns false. |async| and |clock_delta|
// are the AsyncBio and simulated timeout for |ssl|, respectively.
static bool RetryAsync(SSL *ssl, int ret, BIO *async,
                       OPENSSL_timeval *clock_delta) {
  // No error; don't retry.
  if (ret >= 0) {
    return false;
  }

  if (clock_delta->tv_usec != 0 || clock_delta->tv_sec != 0) {
    // Process the timeout and retry.
    OPENSSL_timeval *clock = GetClockPtr(ssl);
    clock->tv_usec += clock_delta->tv_usec;
    clock->tv_sec += clock->tv_usec / 1000000;
    clock->tv_usec %= 1000000;
    clock->tv_sec += clock_delta->tv_sec;
    memset(clock_delta, 0, sizeof(*clock_delta));

    if (DTLSv1_handle_timeout(ssl) < 0) {
      printf("Error retransmitting.\n");
      return false;
    }
    return true;
  }

  // See if we needed to read or write more. If so, allow one byte through on
  // the appropriate end to maximally stress the state machine.
  switch (SSL_get_error(ssl, ret)) {
    case SSL_ERROR_WANT_READ:
      AsyncBioAllowRead(async, 1);
      return true;
    case SSL_ERROR_WANT_WRITE:
      AsyncBioAllowWrite(async, 1);
      return true;
    case SSL_ERROR_WANT_CHANNEL_ID_LOOKUP: {
      ScopedEVP_PKEY pkey = LoadPrivateKey(GetConfigPtr(ssl)->send_channel_id);
      if (!pkey) {
        return false;
      }
      GetTestState(ssl)->channel_id = std::move(pkey);
      return true;
    }
    case SSL_ERROR_WANT_X509_LOOKUP:
      GetTestState(ssl)->cert_ready = true;
      return true;
    case SSL_ERROR_PENDING_SESSION:
      GetTestState(ssl)->session =
          std::move(GetTestState(ssl)->pending_session);
      return true;
    case SSL_ERROR_PENDING_CERTIFICATE:
      // The handshake will resume without a second call to the early callback.
      return InstallCertificate(ssl);
    default:
      return false;
  }
}

// DoExchange runs a test SSL exchange against the peer. On success, it returns
// true and sets |*out_session| to the negotiated SSL session. If the test is a
// resumption attempt, |is_resume| is true and |session| is the session from the
// previous exchange.
static bool DoExchange(ScopedSSL_SESSION *out_session, SSL_CTX *ssl_ctx,
                       const TestConfig *config, bool is_resume,
                       SSL_SESSION *session) {
  OPENSSL_timeval clock = {0}, clock_delta = {0};
  ScopedSSL ssl(SSL_new(ssl_ctx));
  if (!ssl) {
    return false;
  }

  if (!SetConfigPtr(ssl.get(), config) ||
      !SetClockPtr(ssl.get(), &clock) |
      !SetTestState(ssl.get(), std::unique_ptr<TestState>(new TestState))) {
    return false;
  }

  if (config->fallback_scsv &&
      !SSL_set_mode(ssl.get(), SSL_MODE_SEND_FALLBACK_SCSV)) {
    return false;
  }
  if (!config->use_early_callback) {
    if (config->async) {
      // TODO(davidben): Also test |s->ctx->client_cert_cb| on the client.
      SSL_set_cert_cb(ssl.get(), CertCallback, NULL);
    } else if (!InstallCertificate(ssl.get())) {
      return false;
    }
  }
  if (config->require_any_client_certificate) {
    SSL_set_verify(ssl.get(), SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                   SkipVerify);
  }
  if (config->false_start) {
    SSL_set_mode(ssl.get(), SSL_MODE_ENABLE_FALSE_START);
  }
  if (config->cbc_record_splitting) {
    SSL_set_mode(ssl.get(), SSL_MODE_CBC_RECORD_SPLITTING);
  }
  if (config->partial_write) {
    SSL_set_mode(ssl.get(), SSL_MODE_ENABLE_PARTIAL_WRITE);
  }
  if (config->no_tls12) {
    SSL_set_options(ssl.get(), SSL_OP_NO_TLSv1_2);
  }
  if (config->no_tls11) {
    SSL_set_options(ssl.get(), SSL_OP_NO_TLSv1_1);
  }
  if (config->no_tls1) {
    SSL_set_options(ssl.get(), SSL_OP_NO_TLSv1);
  }
  if (config->no_ssl3) {
    SSL_set_options(ssl.get(), SSL_OP_NO_SSLv3);
  }
  if (config->tls_d5_bug) {
    SSL_set_options(ssl.get(), SSL_OP_TLS_D5_BUG);
  }
  if (config->allow_unsafe_legacy_renegotiation) {
    SSL_set_options(ssl.get(), SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
  }
  if (!config->expected_channel_id.empty()) {
    SSL_enable_tls_channel_id(ssl.get());
  }
  if (!config->send_channel_id.empty()) {
    SSL_enable_tls_channel_id(ssl.get());
    if (!config->async) {
      // The async case will be supplied by |ChannelIdCallback|.
      ScopedEVP_PKEY pkey = LoadPrivateKey(config->send_channel_id);
      if (!pkey || !SSL_set1_tls_channel_id(ssl.get(), pkey.get())) {
        return false;
      }
    }
  }
  if (!config->host_name.empty() &&
      !SSL_set_tlsext_host_name(ssl.get(), config->host_name.c_str())) {
    return false;
  }
  if (!config->advertise_alpn.empty() &&
      SSL_set_alpn_protos(ssl.get(),
                          (const uint8_t *)config->advertise_alpn.data(),
                          config->advertise_alpn.size()) != 0) {
    return false;
  }
  if (!config->psk.empty()) {
    SSL_set_psk_client_callback(ssl.get(), PskClientCallback);
    SSL_set_psk_server_callback(ssl.get(), PskServerCallback);
  }
  if (!config->psk_identity.empty() &&
      !SSL_use_psk_identity_hint(ssl.get(), config->psk_identity.c_str())) {
    return false;
  }
  if (!config->srtp_profiles.empty() &&
      !SSL_set_srtp_profiles(ssl.get(), config->srtp_profiles.c_str())) {
    return false;
  }
  if (config->enable_ocsp_stapling &&
      !SSL_enable_ocsp_stapling(ssl.get())) {
    return false;
  }
  if (config->enable_signed_cert_timestamps &&
      !SSL_enable_signed_cert_timestamps(ssl.get())) {
    return false;
  }
  SSL_enable_fastradio_padding(ssl.get(), config->fastradio_padding);
  if (config->min_version != 0) {
    SSL_set_min_version(ssl.get(), (uint16_t)config->min_version);
  }
  if (config->max_version != 0) {
    SSL_set_max_version(ssl.get(), (uint16_t)config->max_version);
  }
  if (config->mtu != 0) {
    SSL_set_options(ssl.get(), SSL_OP_NO_QUERY_MTU);
    SSL_set_mtu(ssl.get(), config->mtu);
  }

  int sock = Connect(config->port);
  if (sock == -1) {
    return false;
  }
  SocketCloser closer(sock);

  ScopedBIO bio(BIO_new_socket(sock, BIO_NOCLOSE));
  if (!bio) {
    return false;
  }
  if (config->is_dtls) {
    ScopedBIO packeted = PacketedBioCreate(&clock_delta);
    BIO_push(packeted.get(), bio.release());
    bio = std::move(packeted);
  }
  BIO *async = NULL;
  if (config->async) {
    ScopedBIO async_scoped =
        config->is_dtls ? AsyncBioCreateDatagram() : AsyncBioCreate();
    BIO_push(async_scoped.get(), bio.release());
    async = async_scoped.get();
    bio = std::move(async_scoped);
  }
  SSL_set_bio(ssl.get(), bio.get(), bio.get());
  bio.release();  // SSL_set_bio takes ownership.

  if (session != NULL) {
    if (!config->is_server) {
      if (SSL_set_session(ssl.get(), session) != 1) {
        return false;
      }
    } else if (config->async) {
      // The internal session cache is disabled, so install the session
      // manually.
      GetTestState(ssl.get())->pending_session.reset(
          SSL_SESSION_up_ref(session));
    }
  }

  int ret;
  if (config->implicit_handshake) {
    if (config->is_server) {
      SSL_set_accept_state(ssl.get());
    } else {
      SSL_set_connect_state(ssl.get());
    }
  } else {
    do {
      if (config->is_server) {
        ret = SSL_accept(ssl.get());
      } else {
        ret = SSL_connect(ssl.get());
      }
    } while (config->async && RetryAsync(ssl.get(), ret, async, &clock_delta));
    if (ret != 1) {
      return false;
    }

    if (is_resume &&
        (!!SSL_session_reused(ssl.get()) == config->expect_session_miss)) {
      fprintf(stderr, "session was%s reused\n",
              SSL_session_reused(ssl.get()) ? "" : " not");
      return false;
    }

    if (config->is_server && !GetTestState(ssl.get())->early_callback_called) {
      fprintf(stderr, "early callback not called\n");
      return false;
    }

    if (!config->expected_server_name.empty()) {
      const char *server_name =
        SSL_get_servername(ssl.get(), TLSEXT_NAMETYPE_host_name);
      if (server_name != config->expected_server_name) {
        fprintf(stderr, "servername mismatch (got %s; want %s)\n",
                server_name, config->expected_server_name.c_str());
        return false;
      }
    }

    if (!config->expected_certificate_types.empty()) {
      uint8_t *certificate_types;
      int num_certificate_types =
        SSL_get0_certificate_types(ssl.get(), &certificate_types);
      if (num_certificate_types !=
          (int)config->expected_certificate_types.size() ||
          memcmp(certificate_types,
                 config->expected_certificate_types.data(),
                 num_certificate_types) != 0) {
        fprintf(stderr, "certificate types mismatch\n");
        return false;
      }
    }

    if (!config->expected_next_proto.empty()) {
      const uint8_t *next_proto;
      unsigned next_proto_len;
      SSL_get0_next_proto_negotiated(ssl.get(), &next_proto, &next_proto_len);
      if (next_proto_len != config->expected_next_proto.size() ||
          memcmp(next_proto, config->expected_next_proto.data(),
                 next_proto_len) != 0) {
        fprintf(stderr, "negotiated next proto mismatch\n");
        return false;
      }
    }

    if (!config->expected_alpn.empty()) {
      const uint8_t *alpn_proto;
      unsigned alpn_proto_len;
      SSL_get0_alpn_selected(ssl.get(), &alpn_proto, &alpn_proto_len);
      if (alpn_proto_len != config->expected_alpn.size() ||
          memcmp(alpn_proto, config->expected_alpn.data(),
                 alpn_proto_len) != 0) {
        fprintf(stderr, "negotiated alpn proto mismatch\n");
        return false;
      }
    }

    if (!config->expected_channel_id.empty()) {
      uint8_t channel_id[64];
      if (!SSL_get_tls_channel_id(ssl.get(), channel_id, sizeof(channel_id))) {
        fprintf(stderr, "no channel id negotiated\n");
        return false;
      }
      if (config->expected_channel_id.size() != 64 ||
          memcmp(config->expected_channel_id.data(),
                 channel_id, 64) != 0) {
        fprintf(stderr, "channel id mismatch\n");
        return false;
      }
    }

    if (config->expect_extended_master_secret) {
      if (!ssl->session->extended_master_secret) {
        fprintf(stderr, "No EMS for session when expected");
        return false;
      }
    }

    if (!config->expected_ocsp_response.empty()) {
      const uint8_t *data;
      size_t len;
      SSL_get0_ocsp_response(ssl.get(), &data, &len);
      if (config->expected_ocsp_response.size() != len ||
          memcmp(config->expected_ocsp_response.data(), data, len) != 0) {
        fprintf(stderr, "OCSP response mismatch\n");
        return false;
      }
    }

    if (!config->expected_signed_cert_timestamps.empty()) {
      const uint8_t *data;
      size_t len;
      SSL_get0_signed_cert_timestamp_list(ssl.get(), &data, &len);
      if (config->expected_signed_cert_timestamps.size() != len ||
          memcmp(config->expected_signed_cert_timestamps.data(),
                 data, len) != 0) {
        fprintf(stderr, "SCT list mismatch\n");
        return false;
      }
    }
  }

  if (config->renegotiate) {
    if (config->async) {
      fprintf(stderr, "-renegotiate is not supported with -async.\n");
      return false;
    }
    if (config->implicit_handshake) {
      fprintf(stderr, "-renegotiate is not supported with -implicit-handshake.\n");
      return false;
    }

    SSL_renegotiate(ssl.get());

    ret = SSL_do_handshake(ssl.get());
    if (ret != 1) {
      return false;
    }

    SSL_set_state(ssl.get(), SSL_ST_ACCEPT);
    ret = SSL_do_handshake(ssl.get());
    if (ret != 1) {
      return false;
    }
  }

  if (config->write_different_record_sizes) {
    if (config->is_dtls) {
      fprintf(stderr, "write_different_record_sizes not supported for DTLS\n");
      return false;
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
        return false;
      }

      do {
        w = SSL_write(ssl.get(), buf + off, len - off);
        if (w > 0) {
          off += (size_t) w;
        }
      } while ((config->async && RetryAsync(ssl.get(), w, async, &clock_delta)) ||
               (w > 0 && off < len));

      if (w < 0 || off != len) {
        return false;
      }
    }
  } else {
    if (config->shim_writes_first) {
      int w;
      do {
        w = SSL_write(ssl.get(), "hello", 5);
      } while (config->async && RetryAsync(ssl.get(), w, async, &clock_delta));
    }
    for (;;) {
      uint8_t buf[512];
      int n;
      do {
        n = SSL_read(ssl.get(), buf, sizeof(buf));
      } while (config->async && RetryAsync(ssl.get(), n, async, &clock_delta));
      int err = SSL_get_error(ssl.get(), n);
      if (err == SSL_ERROR_ZERO_RETURN ||
          (n == 0 && err == SSL_ERROR_SYSCALL)) {
        if (n != 0) {
          fprintf(stderr, "Invalid SSL_get_error output\n");
          return false;
        }
        // Accept shutdowns with or without close_notify.
        // TODO(davidben): Write tests which distinguish these two cases.
        break;
      } else if (err != SSL_ERROR_NONE) {
        if (n > 0) {
          fprintf(stderr, "Invalid SSL_get_error output\n");
          return false;
        }
        return false;
      }
      // Successfully read data.
      if (n <= 0) {
        fprintf(stderr, "Invalid SSL_get_error output\n");
        return false;
      }
      for (int i = 0; i < n; i++) {
        buf[i] ^= 0xff;
      }
      int w;
      do {
        w = SSL_write(ssl.get(), buf, n);
      } while (config->async && RetryAsync(ssl.get(), w, async, &clock_delta));
      if (w != n) {
        return false;
      }
    }
  }

  if (out_session) {
    out_session->reset(SSL_get1_session(ssl.get()));
  }

  SSL_shutdown(ssl.get());
  return true;
}

int main(int argc, char **argv) {
#if defined(OPENSSL_WINDOWS)
  /* Initialize Winsock. */
  WORD wsa_version = MAKEWORD(2, 2);
  WSADATA wsa_data;
  int wsa_err = WSAStartup(wsa_version, &wsa_data);
  if (wsa_err != 0) {
    fprintf(stderr, "WSAStartup failed: %d\n", wsa_err);
    return 1;
  }
  if (wsa_data.wVersion != wsa_version) {
    fprintf(stderr, "Didn't get expected version: %x\n", wsa_data.wVersion);
    return 1;
  }
#else
  signal(SIGPIPE, SIG_IGN);
#endif

  if (!SSL_library_init()) {
    return 1;
  }
  g_config_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
  g_clock_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
  g_state_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, TestStateExFree);
  if (g_config_index < 0 || g_clock_index < 0 || g_state_index < 0) {
    return 1;
  }

  TestConfig config;
  if (!ParseConfig(argc - 1, argv + 1, &config)) {
    return Usage(argv[0]);
  }

  ScopedSSL_CTX ssl_ctx = SetupCtx(&config);
  if (!ssl_ctx) {
    BIO_print_errors_fp(stdout);
    return 1;
  }

  ScopedSSL_SESSION session;
  if (!DoExchange(&session, ssl_ctx.get(), &config, false /* is_resume */,
                  NULL /* session */)) {
    BIO_print_errors_fp(stdout);
    return 1;
  }

  if (config.resume &&
      !DoExchange(NULL, ssl_ctx.get(), &config, true /* is_resume */,
                  session.get())) {
    BIO_print_errors_fp(stdout);
    return 1;
  }

  return 0;
}
