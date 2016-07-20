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

#include <openssl/ssl.h>

#include <assert.h>
#include <string.h>

#include <openssl/bytestring.h>
#include <openssl/digest.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/rand.h>
#include <openssl/stack.h>

#include "internal.h"


enum server_hs_state_t {
  state_process_client_hello = 0,
  state_send_hello_retry_request,
  state_flush_hello_retry_request,
  state_process_second_client_hello,
  state_send_server_hello,
  state_send_encrypted_extensions,
  state_send_certificate_request,
  state_send_server_certificate,
  state_send_server_certificate_verify,
  state_complete_server_certificate_verify,
  state_send_server_finished,
  state_flush,
  state_process_client_certificate,
  state_process_client_certificate_verify,
  state_process_client_finished,
  state_done,
};

static const uint8_t kZeroes[EVP_MAX_MD_SIZE] = {0};

static int resolve_psk_secret(SSL *ssl) {
  SSL_HANDSHAKE *hs = ssl->s3->hs;

  if (ssl->s3->tmp.new_cipher->algorithm_auth != SSL_aPSK) {
    return tls13_advance_key_schedule(ssl, kZeroes, hs->hash_len);
  }

  /* TODO(davidben): Support PSK. */
  OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
  return 0;
}

static int resolve_ecdhe_secret(SSL *ssl, int *out_need_retry,
                                struct ssl_early_callback_ctx *early_ctx) {
  *out_need_retry = 0;
  SSL_HANDSHAKE *hs = ssl->s3->hs;

  if (ssl->s3->tmp.new_cipher->algorithm_mkey != SSL_kECDHE) {
    return tls13_advance_key_schedule(ssl, kZeroes, hs->hash_len);
  }

  const uint8_t *key_share_buf = NULL;
  size_t key_share_len = 0;
  CBS key_share;
  if (!SSL_early_callback_ctx_extension_get(early_ctx, TLSEXT_TYPE_key_share,
                                            &key_share_buf, &key_share_len)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_MISSING_KEY_SHARE);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_MISSING_EXTENSION);
    return ssl_hs_error;
  }

  CBS_init(&key_share, key_share_buf, key_share_len);
  int found_key_share;
  uint8_t *dhe_secret;
  size_t dhe_secret_len;
  uint8_t alert;
  if (!ext_key_share_parse_clienthello(ssl, &found_key_share, &dhe_secret,
                                       &dhe_secret_len, &alert, &key_share)) {
    ssl3_send_alert(ssl, SSL3_AL_FATAL, alert);
    return 0;
  }

  if (!found_key_share) {
    *out_need_retry = 1;
    return 0;
  }

  int ok = tls13_advance_key_schedule(ssl, dhe_secret, dhe_secret_len);
  OPENSSL_free(dhe_secret);
  return ok;
}

static enum ssl_hs_wait_t do_process_client_hello(SSL *ssl, SSL_HANDSHAKE *hs) {
  if (!tls13_check_message_type(ssl, SSL3_MT_CLIENT_HELLO)) {
    return ssl_hs_error;
  }

  struct ssl_early_callback_ctx early_ctx;
  if (!ssl_early_callback_init(ssl, &early_ctx, ssl->init_msg,
                               ssl->init_num)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_CLIENTHELLO_PARSE_FAILED);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
    return ssl_hs_error;
  }

  CBS cbs, client_random, session_id, cipher_suites, compression_methods;
  uint16_t client_wire_version;
  CBS_init(&cbs, ssl->init_msg, ssl->init_num);
  if (!CBS_get_u16(&cbs, &client_wire_version) ||
      !CBS_get_bytes(&cbs, &client_random, SSL3_RANDOM_SIZE) ||
      !CBS_get_u8_length_prefixed(&cbs, &session_id) ||
      CBS_len(&session_id) > SSL_MAX_SSL_SESSION_ID_LENGTH) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
    return ssl_hs_error;
  }

  uint16_t min_version, max_version;
  if (!ssl_get_version_range(ssl, &min_version, &max_version)) {
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
    return ssl_hs_error;
  }

  assert(ssl->s3->have_version);

  /* Load the client random. */
  memcpy(ssl->s3->client_random, CBS_data(&client_random), SSL3_RANDOM_SIZE);

  ssl->hit = 0;
  if (!ssl_get_new_session(ssl, 1 /* server */)) {
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
    return ssl_hs_error;
  }

  if (ssl->ctx->dos_protection_cb != NULL &&
      ssl->ctx->dos_protection_cb(&early_ctx) == 0) {
    /* Connection rejected for DOS reasons. */
    OPENSSL_PUT_ERROR(SSL, SSL_R_CONNECTION_REJECTED);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_ACCESS_DENIED);
    return ssl_hs_error;
  }

  if (!CBS_get_u16_length_prefixed(&cbs, &cipher_suites) ||
      CBS_len(&cipher_suites) == 0 ||
      CBS_len(&cipher_suites) % 2 != 0 ||
      !CBS_get_u8_length_prefixed(&cbs, &compression_methods) ||
      CBS_len(&compression_methods) == 0) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
    return ssl_hs_error;
  }

  /* TLS 1.3 requires the peer only advertise the null compression. */
  if (CBS_len(&compression_methods) != 1 ||
      CBS_data(&compression_methods)[0] != 0) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_INVALID_COMPRESSION_LIST);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_ILLEGAL_PARAMETER);
    return ssl_hs_error;
  }

  /* TLS extensions. */
  if (!ssl_parse_clienthello_tlsext(ssl, &cbs)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_PARSE_TLSEXT);
    return ssl_hs_error;
  }

  /* There should be nothing left over in the message. */
  if (CBS_len(&cbs) != 0) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_BAD_PACKET_LENGTH);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
    return ssl_hs_error;
  }

  /* Let cert callback update server certificates if required.
   *
   * TODO(davidben): Can this get run earlier? */
  if (ssl->cert->cert_cb != NULL) {
    int rv = ssl->cert->cert_cb(ssl, ssl->cert->cert_cb_arg);
    if (rv == 0) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_CERT_CB_ERROR);
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
      return ssl_hs_error;
    }
    if (rv < 0) {
      hs->state = state_process_client_hello;
      return ssl_hs_x509_lookup;
    }
  }

  STACK_OF(SSL_CIPHER) *ciphers =
      ssl_bytes_to_cipher_list(ssl, &cipher_suites, max_version);
  if (ciphers == NULL) {
    return ssl_hs_error;
  }

  const SSL_CIPHER *cipher =
      ssl3_choose_cipher(ssl, ciphers, ssl_get_cipher_preferences(ssl));
  sk_SSL_CIPHER_free(ciphers);
  if (cipher == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_NO_SHARED_CIPHER);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_HANDSHAKE_FAILURE);
    return ssl_hs_error;
  }

  ssl->session->cipher = cipher;
  ssl->s3->tmp.new_cipher = cipher;

  /* The PRF hash is now known. Set up the key schedule and hash the
   * ClientHello. */
  size_t hash_len =
      EVP_MD_size(ssl_get_handshake_digest(ssl_get_algorithm_prf(ssl)));
  if (!tls13_init_key_schedule(ssl, kZeroes, hash_len)) {
    return ssl_hs_error;
  }

  /* Resolve PSK and incorporate it into the secret. */
  if (!resolve_psk_secret(ssl)) {
    return ssl_hs_error;
  }

  /* Resolve ECDHE and incorporate it into the secret. */
  int need_retry;
  if (!resolve_ecdhe_secret(ssl, &need_retry, &early_ctx)) {
    if (need_retry) {
      hs->state = state_send_hello_retry_request;
      return ssl_hs_ok;
    }
    return ssl_hs_error;
  }

  hs->state = state_send_server_hello;
  return ssl_hs_ok;
}

static enum ssl_hs_wait_t do_send_hello_retry_request(SSL *ssl,
                                                      SSL_HANDSHAKE *hs) {
  CBB cbb, body, extensions;
  uint16_t group_id;
  if (!ssl->method->init_message(ssl, &cbb, &body,
                                 SSL3_MT_HELLO_RETRY_REQUEST) ||
      !CBB_add_u16(&body, ssl->version) ||
      !CBB_add_u16(&body, ssl_cipher_get_value(ssl->s3->tmp.new_cipher)) ||
      !tls1_get_shared_group(ssl, &group_id) ||
      !CBB_add_u16(&body, group_id) ||
      !CBB_add_u16_length_prefixed(&body, &extensions) ||
      !ssl->method->finish_message(ssl, &cbb)) {
    CBB_cleanup(&cbb);
    return ssl_hs_error;
  }

  hs->state = state_flush_hello_retry_request;
  return ssl_hs_write_message;
}

static enum ssl_hs_wait_t do_flush_hello_retry_request(SSL *ssl,
                                                       SSL_HANDSHAKE *hs) {
  hs->state = state_process_second_client_hello;
  return ssl_hs_flush_and_read_message;
}

static enum ssl_hs_wait_t do_process_second_client_hello(SSL *ssl,
                                                      SSL_HANDSHAKE *hs) {
  if (!tls13_check_message_type(ssl, SSL3_MT_CLIENT_HELLO)) {
    return ssl_hs_error;
  }

  struct ssl_early_callback_ctx early_ctx;
  if (!ssl_early_callback_init(ssl, &early_ctx, ssl->init_msg,
                               ssl->init_num)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_CLIENTHELLO_PARSE_FAILED);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
    return ssl_hs_error;
  }

  int need_retry;
  if (!resolve_ecdhe_secret(ssl, &need_retry, &early_ctx)) {
    if (need_retry) {
      /* Only send one HelloRetryRequest. */
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_ILLEGAL_PARAMETER);
      OPENSSL_PUT_ERROR(SSL, SSL_R_WRONG_CURVE);
    }
    return ssl_hs_error;
  }

  if (!ssl->method->hash_current_message(ssl)) {
    return ssl_hs_error;
  }

  hs->state = state_send_server_hello;
  return ssl_hs_ok;
}

static enum ssl_hs_wait_t do_send_server_hello(SSL *ssl, SSL_HANDSHAKE *hs) {
  CBB cbb, body, extensions;
  if (!ssl->method->init_message(ssl, &cbb, &body, SSL3_MT_SERVER_HELLO) ||
      !CBB_add_u16(&body, ssl->version) ||
      !RAND_bytes(ssl->s3->server_random, sizeof(ssl->s3->server_random)) ||
      !CBB_add_bytes(&body, ssl->s3->server_random, SSL3_RANDOM_SIZE) ||
      !CBB_add_u16(&body, ssl_cipher_get_value(ssl->s3->tmp.new_cipher)) ||
      !CBB_add_u16_length_prefixed(&body, &extensions) ||
      !ext_key_share_add_serverhello(ssl, &extensions) ||
      !ssl->method->finish_message(ssl, &cbb)) {
    CBB_cleanup(&cbb);
    return ssl_hs_error;
  }

  hs->state = state_send_encrypted_extensions;
  return ssl_hs_write_message;
}

static enum ssl_hs_wait_t do_send_encrypted_extensions(SSL *ssl,
                                                       SSL_HANDSHAKE *hs) {
  if (!tls13_set_handshake_traffic(ssl)) {
    return ssl_hs_error;
  }

  CBB cbb, body;
  if (!ssl->method->init_message(ssl, &cbb, &body,
                                 SSL3_MT_ENCRYPTED_EXTENSIONS) ||
      !ssl_add_serverhello_tlsext(ssl, &body) ||
      !ssl->method->finish_message(ssl, &cbb)) {
    CBB_cleanup(&cbb);
    return ssl_hs_error;
  }

  hs->state = state_send_certificate_request;
  return ssl_hs_write_message;
}

static enum ssl_hs_wait_t do_send_certificate_request(SSL *ssl,
                                                      SSL_HANDSHAKE *hs) {
  /* Determine whether to request a client certificate. */
  ssl->s3->tmp.cert_request = !!(ssl->verify_mode & SSL_VERIFY_PEER);
  /* CertificateRequest may only be sent in certificate-based ciphers. */
  if (!ssl_cipher_uses_certificate_auth(ssl->s3->tmp.new_cipher)) {
    ssl->s3->tmp.cert_request = 0;
  }

  if (!ssl->s3->tmp.cert_request) {
    /* Skip this state. */
    hs->state = state_send_server_certificate;
    return ssl_hs_ok;
  }

  CBB cbb, body, sigalgs_cbb;
  if (!ssl->method->init_message(ssl, &cbb, &body,
                                 SSL3_MT_CERTIFICATE_REQUEST) ||
      !CBB_add_u8(&body, 0 /* no certificate_request_context. */)) {
    goto err;
  }

  const uint16_t *sigalgs;
  size_t sigalgs_len = tls12_get_psigalgs(ssl, &sigalgs);
  if (!CBB_add_u16_length_prefixed(&body, &sigalgs_cbb)) {
    goto err;
  }

  for (size_t i = 0; i < sigalgs_len; i++) {
    if (!CBB_add_u16(&sigalgs_cbb, sigalgs[i])) {
      goto err;
    }
  }

  if (!ssl_add_client_CA_list(ssl, &body) ||
      !CBB_add_u16(&body, 0 /* empty certificate_extensions. */) ||
      !ssl->method->finish_message(ssl, &cbb)) {
    goto err;
  }

  hs->state = state_send_server_certificate;
  return ssl_hs_write_message;

err:
  CBB_cleanup(&cbb);
  return ssl_hs_error;
}

static enum ssl_hs_wait_t do_send_server_certificate(SSL *ssl,
                                                     SSL_HANDSHAKE *hs) {
  if (!ssl_cipher_uses_certificate_auth(ssl->s3->tmp.new_cipher)) {
    hs->state = state_send_server_finished;
    return ssl_hs_ok;
  }

  if (!ssl_has_certificate(ssl)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_NO_CERTIFICATE_SET);
    return ssl_hs_error;
  }

  if (!tls13_prepare_certificate(ssl)) {
    return ssl_hs_error;
  }

  hs->state = state_send_server_certificate_verify;
  return ssl_hs_write_message;
}

static enum ssl_hs_wait_t do_send_server_certificate_verify(SSL *ssl,
                                                            SSL_HANDSHAKE *hs,
                                                            int is_first_run) {
  switch (tls13_prepare_certificate_verify(ssl, is_first_run)) {
    case ssl_private_key_success:
      hs->state = state_send_server_finished;
      return ssl_hs_write_message;

    case ssl_private_key_retry:
      hs->state = state_complete_server_certificate_verify;
      return ssl_hs_private_key_operation;

    case ssl_private_key_failure:
      return ssl_hs_error;
  }

  assert(0);
  return ssl_hs_error;
}

static enum ssl_hs_wait_t do_send_server_finished(SSL *ssl, SSL_HANDSHAKE *hs) {
  if (!tls13_prepare_finished(ssl)) {
    return ssl_hs_error;
  }

  hs->state = state_flush;
  return ssl_hs_write_message;
}

static enum ssl_hs_wait_t do_flush(SSL *ssl, SSL_HANDSHAKE *hs) {
  /* Update the secret to the master secret and derive traffic keys. */
  if (!tls13_advance_key_schedule(ssl, kZeroes, hs->hash_len) ||
      !tls13_derive_traffic_secret_0(ssl) ||
      !tls13_set_traffic_key(ssl, type_data, evp_aead_seal,
                             hs->traffic_secret_0, hs->hash_len)) {
    return ssl_hs_error;
  }

  hs->state = state_process_client_certificate;
  return ssl_hs_flush_and_read_message;
}

static enum ssl_hs_wait_t do_process_client_certificate(SSL *ssl,
                                                        SSL_HANDSHAKE *hs) {
  if (!ssl->s3->tmp.cert_request) {
    /* Skip this state. */
    hs->state = state_process_client_certificate_verify;
    return ssl_hs_ok;
  }

  if (!tls13_check_message_type(ssl, SSL3_MT_CERTIFICATE) ||
      !tls13_process_certificate(ssl) ||
      !ssl->method->hash_current_message(ssl)) {
    return ssl_hs_error;
  }

  hs->state = state_process_client_certificate_verify;
  return ssl_hs_read_message;
}

static enum ssl_hs_wait_t do_process_client_certificate_verify(
    SSL *ssl, SSL_HANDSHAKE *hs) {
  if (ssl->session->peer == NULL) {
    /* Skip this state. */
    hs->state = state_process_client_finished;
    return ssl_hs_ok;
  }

  if (!tls13_check_message_type(ssl, SSL3_MT_CERTIFICATE_VERIFY) ||
      !tls13_process_certificate_verify(ssl) ||
      !ssl->method->hash_current_message(ssl)) {
    return 0;
  }

  hs->state = state_process_client_finished;
  return ssl_hs_read_message;
}

static enum ssl_hs_wait_t do_process_client_finished(SSL *ssl,
                                                     SSL_HANDSHAKE *hs) {
  if (!tls13_check_message_type(ssl, SSL3_MT_FINISHED) ||
      !tls13_process_finished(ssl) ||
      !ssl->method->hash_current_message(ssl) ||
      /* evp_aead_seal keys have already been switched. */
      !tls13_set_traffic_key(ssl, type_data, evp_aead_open,
                             hs->traffic_secret_0, hs->hash_len) ||
      !tls13_finalize_keys(ssl)) {
    return ssl_hs_error;
  }

  hs->state = state_done;
  return ssl_hs_ok;
}

enum ssl_hs_wait_t tls13_server_handshake(SSL *ssl) {
  SSL_HANDSHAKE *hs = ssl->s3->hs;

  while (hs->state != state_done) {
    enum ssl_hs_wait_t ret = ssl_hs_error;
    enum server_hs_state_t state = hs->state;
    switch (state) {
      case state_process_client_hello:
        ret = do_process_client_hello(ssl, hs);
        break;
      case state_send_hello_retry_request:
        ret = do_send_hello_retry_request(ssl, hs);
        break;
      case state_flush_hello_retry_request:
        ret = do_flush_hello_retry_request(ssl, hs);
        break;
      case state_process_second_client_hello:
        ret = do_process_second_client_hello(ssl, hs);
        break;
      case state_send_server_hello:
        ret = do_send_server_hello(ssl, hs);
        break;
      case state_send_encrypted_extensions:
        ret = do_send_encrypted_extensions(ssl, hs);
        break;
      case state_send_certificate_request:
        ret = do_send_certificate_request(ssl, hs);
        break;
      case state_send_server_certificate:
        ret = do_send_server_certificate(ssl, hs);
        break;
      case state_send_server_certificate_verify:
        ret = do_send_server_certificate_verify(ssl, hs, 1 /* first run */);
      break;
      case state_complete_server_certificate_verify:
        ret = do_send_server_certificate_verify(ssl, hs, 0 /* complete */);
      break;
      case state_send_server_finished:
        ret = do_send_server_finished(ssl, hs);
        break;
      case state_flush:
        ret = do_flush(ssl, hs);
        break;
      case state_process_client_certificate:
        ret = do_process_client_certificate(ssl, hs);
        break;
      case state_process_client_certificate_verify:
        ret = do_process_client_certificate_verify(ssl, hs);
        break;
      case state_process_client_finished:
        ret = do_process_client_finished(ssl, hs);
        break;
      case state_done:
        ret = ssl_hs_ok;
        break;
    }

    if (ret != ssl_hs_ok) {
      return ret;
    }
  }

  return ssl_hs_ok;
}
