/* Copyright (c) 2018, Google Inc.
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

#include "handshake_util.h"

#include <assert.h>

#include <functional>

#include "async_bio.h"
#include "packeted_bio.h"
#include "test_config.h"
#include "test_state.h"

#include <openssl/ssl.h>

using namespace bssl;

bool RetryAsync(SSL *ssl, int ret) {
  // No error; don't retry.
  if (ret >= 0) {
    return false;
  }

  TestState *test_state = GetTestState(ssl);
  assert(GetTestConfig(ssl)->async);

  if (test_state->packeted_bio != nullptr &&
      PacketedBioAdvanceClock(test_state->packeted_bio)) {
    // The DTLS retransmit logic silently ignores write failures. So the test
    // may progress, allow writes through synchronously.
    AsyncBioEnforceWriteQuota(test_state->async_bio, false);
    int timeout_ret = DTLSv1_handle_timeout(ssl);
    AsyncBioEnforceWriteQuota(test_state->async_bio, true);

    if (timeout_ret < 0) {
      fprintf(stderr, "Error retransmitting.\n");
      return false;
    }
    return true;
  }

  // See if we needed to read or write more. If so, allow one byte through on
  // the appropriate end to maximally stress the state machine.
  switch (SSL_get_error(ssl, ret)) {
    case SSL_ERROR_WANT_READ:
      AsyncBioAllowRead(test_state->async_bio, 1);
      return true;
    case SSL_ERROR_WANT_WRITE:
      AsyncBioAllowWrite(test_state->async_bio, 1);
      return true;
    case SSL_ERROR_WANT_CHANNEL_ID_LOOKUP: {
      UniquePtr<EVP_PKEY> pkey =
          LoadPrivateKey(GetTestConfig(ssl)->send_channel_id);
      if (!pkey) {
        return false;
      }
      test_state->channel_id = std::move(pkey);
      return true;
    }
    case SSL_ERROR_WANT_X509_LOOKUP:
      test_state->cert_ready = true;
      return true;
    case SSL_ERROR_PENDING_SESSION:
      test_state->session = std::move(test_state->pending_session);
      return true;
    case SSL_ERROR_PENDING_CERTIFICATE:
      test_state->early_callback_ready = true;
      return true;
    case SSL_ERROR_WANT_PRIVATE_KEY_OPERATION:
      test_state->private_key_retries++;
      return true;
    case SSL_ERROR_WANT_CERTIFICATE_VERIFY:
      test_state->custom_verify_ready = true;
      return true;
    default:
      return false;
  }
}

int CheckIdempotentError(const char *name, SSL *ssl,
                         std::function<int()> func) {
  int ret = func();
  int ssl_err = SSL_get_error(ssl, ret);
  uint32_t err = ERR_peek_error();
  if (ssl_err == SSL_ERROR_SSL || ssl_err == SSL_ERROR_ZERO_RETURN) {
    int ret2 = func();
    int ssl_err2 = SSL_get_error(ssl, ret2);
    uint32_t err2 = ERR_peek_error();
    if (ret != ret2 || ssl_err != ssl_err2 || err != err2) {
      fprintf(stderr, "Repeating %s did not replay the error.\n", name);
      char buf[256];
      ERR_error_string_n(err, buf, sizeof(buf));
      fprintf(stderr, "Wanted: %d %d %s\n", ret, ssl_err, buf);
      ERR_error_string_n(err2, buf, sizeof(buf));
      fprintf(stderr, "Got:    %d %d %s\n", ret2, ssl_err2, buf);
      // runner treats exit code 90 as always failing. Otherwise, it may
      // accidentally consider the result an expected protocol failure.
      exit(90);
    }
  }
  return ret;
}

// MoveBIOs moves the |BIO|s of |src| to |dst|.  It is used for handoff.
static void MoveBIOs(SSL *dest, SSL *src) {
  BIO *rbio = SSL_get_rbio(src);
  BIO_up_ref(rbio);
  SSL_set0_rbio(dest, rbio);

  BIO *wbio = SSL_get_wbio(src);
  BIO_up_ref(wbio);
  SSL_set0_wbio(dest, wbio);

  SSL_set0_rbio(src, nullptr);
  SSL_set0_wbio(src, nullptr);
}

static bool HandoffReady(SSL *ssl, int ret) {
  return ret < 0 && SSL_get_error(ssl, ret) == SSL_ERROR_HANDOFF;
}

static bool HandbackReady(SSL *ssl, int ret) {
  return ret < 0 && SSL_get_error(ssl, ret) == SSL_ERROR_HANDBACK;
}

bool DoSplitHandshake(UniquePtr<SSL> *ssl_uniqueptr, SettingsWriter *writer,
                      bool is_resume) {
  SSL *ssl = ssl_uniqueptr->get();
  SSL_set_handoff_mode(ssl, 1);

  const TestConfig *config = GetTestConfig(ssl);
  int ret = -1;
  do {
    ret = CheckIdempotentError("SSL_do_handshake", ssl,
                               [&]() -> int { return SSL_do_handshake(ssl); });
  } while (!HandoffReady(ssl, ret) &&
           config->async &&
           RetryAsync(ssl, ret));

  ScopedCBB cbb;
  Array<uint8_t> handoff;
  if (!HandoffReady(ssl, ret) ||
      !CBB_init(cbb.get(), 512) ||
      !SSL_serialize_handoff(ssl, cbb.get()) ||
      !CBBFinishArray(cbb.get(), &handoff) ||
      !writer->WriteHandoff(handoff)) {
    fprintf(stderr, "Handoff failed.\n");
    return false;
  }

  UniquePtr<SSL_CTX> ctx = config->SetupCtx(ssl->ctx.get());
  if (!ctx) {
    return false;
  }
  UniquePtr<SSL> ssl_handshaker =
      config->NewSSL(ctx.get(), nullptr, false, nullptr);
  if (!ssl_handshaker) {
    return false;
  }
  MoveBIOs(ssl_handshaker.get(), ssl);

  if (!MoveTestState(ssl_handshaker.get(), ssl) ||
      !SSL_apply_handoff(ssl_handshaker.get(), handoff)) {
    fprintf(stderr, "Handoff application failed.\n");
    return false;
  }

  do {
    ret = CheckIdempotentError(
        "SSL_do_handshake", ssl_handshaker.get(),
        [&]() -> int { return SSL_do_handshake(ssl_handshaker.get()); });
  } while (config->async && RetryAsync(ssl_handshaker.get(), ret));

  Array<uint8_t> handback;
  if (!HandbackReady(ssl_handshaker.get(), ret) ||
      !CBB_init(cbb.get(), 512) ||
      !SSL_serialize_handback(ssl_handshaker.get(), cbb.get()) ||
      !CBBFinishArray(cbb.get(), &handback) ||
      !writer->WriteHandback(handback)) {
    fprintf(stderr, "Handback failed.\n");
    return false;
  }

  UniquePtr<SSL> ssl_handback =
      config->NewSSL(ctx.get(), nullptr, false, nullptr);
  if (!ssl_handback) {
    return false;
  }
  MoveBIOs(ssl_handback.get(), ssl_handshaker.get());

  if (!MoveTestState(ssl_handback.get(), ssl_handshaker.get()) ||
      !SSL_apply_handback(ssl_handback.get(), handback)) {
    fprintf(stderr, "Handback application failed.\n");
    return false;
  }

  *ssl_uniqueptr = std::move(ssl_handback);
  return true;
}
