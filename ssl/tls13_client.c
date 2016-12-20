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
#include <openssl/stack.h>
#include <openssl/x509.h>

#include "../crypto/internal.h"
#include "internal.h"


enum client_hs_state_t {
  state_process_hello_retry_request = 0,
  state_send_second_client_hello,
  state_flush_second_client_hello,
  state_process_server_hello,
  state_process_encrypted_extensions,
  state_process_certificate_request,
  state_process_server_certificate,
  state_process_server_certificate_verify,
  state_process_server_finished,
  state_send_client_certificate,
  state_send_client_certificate_verify,
  state_complete_client_certificate_verify,
  state_send_channel_id,
  state_send_client_finished,
  state_flush,
  state_done,
};

static const uint8_t kZeroes[EVP_MAX_MD_SIZE] = {0};

static enum ssl_hs_wait_t do_process_hello_retry_request(SSL_HANDSHAKE *hs) {
  SSL *const ssl = hs->ssl;
  if (ssl->s3->tmp.message_type != SSL3_MT_HELLO_RETRY_REQUEST) {
    hs->tls13_state = state_process_server_hello;
    return ssl_hs_ok;
  }

  CBS cbs, extensions;
  uint16_t server_wire_version;
  CBS_init(&cbs, ssl->init_msg, ssl->init_num);
  if (!CBS_get_u16(&cbs, &server_wire_version) ||
      !CBS_get_u16_length_prefixed(&cbs, &extensions) ||
      /* HelloRetryRequest may not be empty. */
      CBS_len(&extensions) == 0 ||
      CBS_len(&cbs) != 0) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
    return ssl_hs_error;
  }

  int have_cookie, have_key_share;
  CBS cookie, key_share;
  const SSL_EXTENSION_TYPE ext_types[] = {
      {TLSEXT_TYPE_key_share, &have_key_share, &key_share},
      {TLSEXT_TYPE_cookie, &have_cookie, &cookie},
  };

  uint8_t alert;
  if (!ssl_parse_extensions(&extensions, &alert, ext_types,
                            OPENSSL_ARRAY_SIZE(ext_types))) {
    ssl3_send_alert(ssl, SSL3_AL_FATAL, alert);
    return ssl_hs_error;
  }

  if (have_cookie) {
    CBS cookie_value;
    if (!CBS_get_u16_length_prefixed(&cookie, &cookie_value) ||
        CBS_len(&cookie_value) == 0 ||
        CBS_len(&cookie) != 0) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
      return ssl_hs_error;
    }

    if (!CBS_stow(&cookie_value, &hs->cookie, &hs->cookie_len)) {
      return ssl_hs_error;
    }
  }

  if (have_key_share) {
    uint16_t group_id;
    if (!CBS_get_u16(&key_share, &group_id) || CBS_len(&key_share) != 0) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
      return ssl_hs_error;
    }

    /* The group must be supported. */
    const uint16_t *groups;
    size_t groups_len;
    tls1_get_grouplist(ssl, &groups, &groups_len);
    int found = 0;
    for (size_t i = 0; i < groups_len; i++) {
      if (groups[i] == group_id) {
        found = 1;
        break;
      }
    }

    if (!found) {
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_ILLEGAL_PARAMETER);
      OPENSSL_PUT_ERROR(SSL, SSL_R_WRONG_CURVE);
      return ssl_hs_error;
    }

    /* Check that the HelloRetryRequest does not request the key share that
     * was provided in the initial ClientHello. */
    if (SSL_ECDH_CTX_get_id(&hs->ecdh_ctx) == group_id) {
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_ILLEGAL_PARAMETER);
      OPENSSL_PUT_ERROR(SSL, SSL_R_WRONG_CURVE);
      return ssl_hs_error;
    }

    SSL_ECDH_CTX_cleanup(&hs->ecdh_ctx);
    hs->retry_group = group_id;
  }

  hs->received_hello_retry_request = 1;
  hs->tls13_state = state_send_second_client_hello;
  return ssl_hs_ok;
}

static enum ssl_hs_wait_t do_send_second_client_hello(SSL_HANDSHAKE *hs) {
  if (!ssl_write_client_hello(hs)) {
    return ssl_hs_error;
  }

  hs->tls13_state = state_flush_second_client_hello;
  return ssl_hs_write_message;
}

static enum ssl_hs_wait_t do_flush_second_client_hello(SSL_HANDSHAKE *hs) {
  hs->tls13_state = state_process_server_hello;
  return ssl_hs_flush_and_read_message;
}

static enum ssl_hs_wait_t do_process_server_hello(SSL_HANDSHAKE *hs) {
  SSL *const ssl = hs->ssl;
  if (!tls13_check_message_type(ssl, SSL3_MT_SERVER_HELLO)) {
    return ssl_hs_error;
  }

  CBS cbs, server_random, extensions;
  uint16_t server_wire_version;
  uint16_t cipher_suite;
  CBS_init(&cbs, ssl->init_msg, ssl->init_num);
  if (!CBS_get_u16(&cbs, &server_wire_version) ||
      !CBS_get_bytes(&cbs, &server_random, SSL3_RANDOM_SIZE) ||
      !CBS_get_u16(&cbs, &cipher_suite) ||
      !CBS_get_u16_length_prefixed(&cbs, &extensions) ||
      CBS_len(&cbs) != 0) {
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    return ssl_hs_error;
  }

  if (server_wire_version != ssl->version) {
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
    OPENSSL_PUT_ERROR(SSL, SSL_R_WRONG_VERSION_NUMBER);
    return ssl_hs_error;
  }

  assert(ssl->s3->have_version);
  OPENSSL_memcpy(ssl->s3->server_random, CBS_data(&server_random),
                 SSL3_RANDOM_SIZE);

  const SSL_CIPHER *cipher = SSL_get_cipher_by_value(cipher_suite);
  if (cipher == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_UNKNOWN_CIPHER_RETURNED);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_ILLEGAL_PARAMETER);
    return ssl_hs_error;
  }

  /* Check if the cipher is a TLS 1.3 cipher. */
  if (SSL_CIPHER_get_min_version(cipher) > ssl3_protocol_version(ssl) ||
      SSL_CIPHER_get_max_version(cipher) < ssl3_protocol_version(ssl)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_WRONG_CIPHER_RETURNED);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_ILLEGAL_PARAMETER);
    return ssl_hs_error;
  }

  /* Parse out the extensions. */
  int have_key_share = 0, have_pre_shared_key = 0, have_short_header = 0;
  CBS key_share, pre_shared_key, short_header;
  const SSL_EXTENSION_TYPE ext_types[] = {
      {TLSEXT_TYPE_key_share, &have_key_share, &key_share},
      {TLSEXT_TYPE_pre_shared_key, &have_pre_shared_key, &pre_shared_key},
      {TLSEXT_TYPE_short_header, &have_short_header, &short_header},
  };

  uint8_t alert;
  if (!ssl_parse_extensions(&extensions, &alert, ext_types,
                            OPENSSL_ARRAY_SIZE(ext_types))) {
    ssl3_send_alert(ssl, SSL3_AL_FATAL, alert);
    return ssl_hs_error;
  }

  alert = SSL_AD_DECODE_ERROR;
  if (have_pre_shared_key) {
    if (ssl->session == NULL) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_UNEXPECTED_EXTENSION);
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_UNSUPPORTED_EXTENSION);
      return ssl_hs_error;
    }

    if (!ssl_ext_pre_shared_key_parse_serverhello(hs, &alert,
                                                  &pre_shared_key)) {
      ssl3_send_alert(ssl, SSL3_AL_FATAL, alert);
      return ssl_hs_error;
    }

    if (ssl->session->ssl_version != ssl->version) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_OLD_SESSION_VERSION_NOT_RETURNED);
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_ILLEGAL_PARAMETER);
      return ssl_hs_error;
    }

    if (ssl->session->cipher->algorithm_prf != cipher->algorithm_prf) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_OLD_SESSION_PRF_HASH_MISMATCH);
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_ILLEGAL_PARAMETER);
      return ssl_hs_error;
    }

    if (!ssl_session_is_context_valid(ssl, ssl->session)) {
      /* This is actually a client application bug. */
      OPENSSL_PUT_ERROR(SSL,
                        SSL_R_ATTEMPT_TO_REUSE_SESSION_IN_DIFFERENT_CONTEXT);
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_ILLEGAL_PARAMETER);
      return ssl_hs_error;
    }

    ssl->s3->session_reused = 1;
    /* Only authentication information carries over in TLS 1.3. */
    ssl->s3->new_session =
        SSL_SESSION_dup(ssl->session, SSL_SESSION_DUP_AUTH_ONLY);
    if (ssl->s3->new_session == NULL) {
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
      return ssl_hs_error;
    }
    ssl_set_session(ssl, NULL);
  } else if (!ssl_get_new_session(hs, 0)) {
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
    return ssl_hs_error;
  }

  ssl->s3->new_session->cipher = cipher;
  ssl->s3->tmp.new_cipher = cipher;

  /* The PRF hash is now known. Set up the key schedule. */
  size_t hash_len =
      EVP_MD_size(ssl_get_handshake_digest(ssl_get_algorithm_prf(ssl)));
  if (!tls13_init_key_schedule(hs)) {
    return ssl_hs_error;
  }

  /* Incorporate the PSK into the running secret. */
  if (ssl->s3->session_reused) {
    if (!tls13_advance_key_schedule(hs, ssl->s3->new_session->master_key,
                                    ssl->s3->new_session->master_key_length)) {
      return ssl_hs_error;
    }
  } else if (!tls13_advance_key_schedule(hs, kZeroes, hash_len)) {
    return ssl_hs_error;
  }

  if (!have_key_share) {
    /* We do not support psk_ke and thus always require a key share. */
    OPENSSL_PUT_ERROR(SSL, SSL_R_MISSING_KEY_SHARE);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_MISSING_EXTENSION);
    return ssl_hs_error;
  }

  /* Resolve ECDHE and incorporate it into the secret. */
  uint8_t *dhe_secret;
  size_t dhe_secret_len;
  if (!ssl_ext_key_share_parse_serverhello(hs, &dhe_secret, &dhe_secret_len,
                                           &alert, &key_share)) {
    ssl3_send_alert(ssl, SSL3_AL_FATAL, alert);
    return ssl_hs_error;
  }

  if (!tls13_advance_key_schedule(hs, dhe_secret, dhe_secret_len)) {
    OPENSSL_free(dhe_secret);
    return ssl_hs_error;
  }
  OPENSSL_free(dhe_secret);

  /* Negotiate short record headers. */
  if (have_short_header) {
    if (CBS_len(&short_header) != 0) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
      return ssl_hs_error;
    }

    if (!ssl->ctx->short_header_enabled) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_UNEXPECTED_EXTENSION);
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_UNSUPPORTED_EXTENSION);
      return ssl_hs_error;
    }

    ssl->s3->short_header = 1;
  }

  /* If there was no HelloRetryRequest, the version negotiation logic has
   * already hashed the message. */
  if (hs->received_hello_retry_request &&
      !ssl_hash_current_message(ssl)) {
    return ssl_hs_error;
  }

  if (!tls13_derive_handshake_secrets(hs) ||
      !tls13_set_traffic_key(ssl, evp_aead_open, hs->server_handshake_secret,
                             hs->hash_len) ||
      !tls13_set_traffic_key(ssl, evp_aead_seal, hs->client_handshake_secret,
                             hs->hash_len)) {
    return ssl_hs_error;
  }

  hs->tls13_state = state_process_encrypted_extensions;
  return ssl_hs_read_message;
}

static enum ssl_hs_wait_t do_process_encrypted_extensions(SSL_HANDSHAKE *hs) {
  SSL *const ssl = hs->ssl;
  if (!tls13_check_message_type(ssl, SSL3_MT_ENCRYPTED_EXTENSIONS)) {
    return ssl_hs_error;
  }

  CBS cbs;
  CBS_init(&cbs, ssl->init_msg, ssl->init_num);
  if (!ssl_parse_serverhello_tlsext(hs, &cbs)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_PARSE_TLSEXT);
    return ssl_hs_error;
  }
  if (CBS_len(&cbs) != 0) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
    return ssl_hs_error;
  }

  if (!ssl_hash_current_message(ssl)) {
    return ssl_hs_error;
  }

  hs->tls13_state = state_process_certificate_request;
  return ssl_hs_read_message;
}

static enum ssl_hs_wait_t do_process_certificate_request(SSL_HANDSHAKE *hs) {
  SSL *const ssl = hs->ssl;
  /* CertificateRequest may only be sent in non-resumption handshakes. */
  if (ssl->s3->session_reused) {
    hs->tls13_state = state_process_server_finished;
    return ssl_hs_ok;
  }

  /* CertificateRequest is optional. */
  if (ssl->s3->tmp.message_type != SSL3_MT_CERTIFICATE_REQUEST) {
    hs->tls13_state = state_process_server_certificate;
    return ssl_hs_ok;
  }

  CBS cbs, context, supported_signature_algorithms;
  CBS_init(&cbs, ssl->init_msg, ssl->init_num);
  if (!CBS_get_u8_length_prefixed(&cbs, &context) ||
      /* The request context is always empty during the handshake. */
      CBS_len(&context) != 0 ||
      !CBS_get_u16_length_prefixed(&cbs, &supported_signature_algorithms) ||
      CBS_len(&supported_signature_algorithms) == 0 ||
      !tls1_parse_peer_sigalgs(hs, &supported_signature_algorithms)) {
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    return ssl_hs_error;
  }

  uint8_t alert;
  STACK_OF(X509_NAME) *ca_sk = ssl_parse_client_CA_list(ssl, &alert, &cbs);
  if (ca_sk == NULL) {
    ssl3_send_alert(ssl, SSL3_AL_FATAL, alert);
    return ssl_hs_error;
  }

  /* Ignore extensions. */
  CBS extensions;
  if (!CBS_get_u16_length_prefixed(&cbs, &extensions) ||
      CBS_len(&cbs) != 0) {
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
    sk_X509_NAME_pop_free(ca_sk, X509_NAME_free);
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    return ssl_hs_error;
  }

  hs->cert_request = 1;
  sk_X509_NAME_pop_free(hs->ca_names, X509_NAME_free);
  hs->ca_names = ca_sk;

  if (!ssl_hash_current_message(ssl)) {
    return ssl_hs_error;
  }

  hs->tls13_state = state_process_server_certificate;
  return ssl_hs_read_message;
}

static enum ssl_hs_wait_t do_process_server_certificate(SSL_HANDSHAKE *hs) {
  SSL *const ssl = hs->ssl;
  if (!tls13_check_message_type(ssl, SSL3_MT_CERTIFICATE) ||
      !tls13_process_certificate(hs, 0 /* certificate required */) ||
      !ssl_hash_current_message(ssl)) {
    return ssl_hs_error;
  }

  hs->tls13_state = state_process_server_certificate_verify;
  return ssl_hs_read_message;
}

static enum ssl_hs_wait_t do_process_server_certificate_verify(
    SSL_HANDSHAKE *hs) {
  SSL *const ssl = hs->ssl;
  if (!tls13_check_message_type(ssl, SSL3_MT_CERTIFICATE_VERIFY) ||
      !tls13_process_certificate_verify(hs) ||
      !ssl_hash_current_message(ssl)) {
    return ssl_hs_error;
  }

  hs->tls13_state = state_process_server_finished;
  return ssl_hs_read_message;
}

static enum ssl_hs_wait_t do_process_server_finished(SSL_HANDSHAKE *hs) {
  SSL *const ssl = hs->ssl;
  if (!tls13_check_message_type(ssl, SSL3_MT_FINISHED) ||
      !tls13_process_finished(hs) ||
      !ssl_hash_current_message(ssl) ||
      /* Update the secret to the master secret and derive traffic keys. */
      !tls13_advance_key_schedule(hs, kZeroes, hs->hash_len) ||
      !tls13_derive_application_secrets(hs)) {
    return ssl_hs_error;
  }

  ssl->method->received_flight(ssl);
  hs->tls13_state = state_send_client_certificate;
  return ssl_hs_ok;
}

static enum ssl_hs_wait_t do_send_client_certificate(SSL_HANDSHAKE *hs) {
  SSL *const ssl = hs->ssl;
  /* The peer didn't request a certificate. */
  if (!hs->cert_request) {
    hs->tls13_state = state_send_channel_id;
    return ssl_hs_ok;
  }

  /* Call cert_cb to update the certificate. */
  if (ssl->cert->cert_cb != NULL) {
    int rv = ssl->cert->cert_cb(ssl, ssl->cert->cert_cb_arg);
    if (rv == 0) {
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
      OPENSSL_PUT_ERROR(SSL, SSL_R_CERT_CB_ERROR);
      return ssl_hs_error;
    }
    if (rv < 0) {
      hs->tls13_state = state_send_client_certificate;
      return ssl_hs_x509_lookup;
    }
  }

  if (!ssl_auto_chain_if_needed(ssl) ||
      !tls13_prepare_certificate(hs)) {
    return ssl_hs_error;
  }

  hs->tls13_state = state_send_client_certificate_verify;
  return ssl_hs_write_message;
}

static enum ssl_hs_wait_t do_send_client_certificate_verify(SSL_HANDSHAKE *hs,
                                                            int is_first_run) {
  SSL *const ssl = hs->ssl;
  /* Don't send CertificateVerify if there is no certificate. */
  if (!ssl_has_certificate(ssl)) {
    hs->tls13_state = state_send_channel_id;
    return ssl_hs_ok;
  }

  switch (tls13_prepare_certificate_verify(hs, is_first_run)) {
    case ssl_private_key_success:
      hs->tls13_state = state_send_channel_id;
      return ssl_hs_write_message;

    case ssl_private_key_retry:
      hs->tls13_state = state_complete_client_certificate_verify;
      return ssl_hs_private_key_operation;

    case ssl_private_key_failure:
      return ssl_hs_error;
  }

  assert(0);
  return ssl_hs_error;
}

static enum ssl_hs_wait_t do_send_channel_id(SSL_HANDSHAKE *hs) {
  SSL *const ssl = hs->ssl;
  if (!ssl->s3->tlsext_channel_id_valid) {
    hs->tls13_state = state_send_client_finished;
    return ssl_hs_ok;
  }

  if (!ssl_do_channel_id_callback(ssl)) {
    return ssl_hs_error;
  }

  if (ssl->tlsext_channel_id_private == NULL) {
    return ssl_hs_channel_id_lookup;
  }

  CBB cbb, body;
  if (!ssl->method->init_message(ssl, &cbb, &body, SSL3_MT_CHANNEL_ID) ||
      !tls1_write_channel_id(ssl, &body) ||
      !ssl_complete_message(ssl, &cbb)) {
    CBB_cleanup(&cbb);
    return ssl_hs_error;
  }

  hs->tls13_state = state_send_client_finished;
  return ssl_hs_write_message;
}

static enum ssl_hs_wait_t do_send_client_finished(SSL_HANDSHAKE *hs) {
  if (!tls13_prepare_finished(hs)) {
    return ssl_hs_error;
  }

  hs->tls13_state = state_flush;
  return ssl_hs_write_message;
}

static enum ssl_hs_wait_t do_flush(SSL_HANDSHAKE *hs) {
  SSL *const ssl = hs->ssl;
  if (!tls13_set_traffic_key(ssl, evp_aead_open, hs->server_traffic_secret_0,
                             hs->hash_len) ||
      !tls13_set_traffic_key(ssl, evp_aead_seal, hs->client_traffic_secret_0,
                             hs->hash_len) ||
      !tls13_derive_resumption_secret(hs)) {
    return ssl_hs_error;
  }

  hs->tls13_state = state_done;
  return ssl_hs_flush;
}

enum ssl_hs_wait_t tls13_client_handshake(SSL_HANDSHAKE *hs) {
  while (hs->tls13_state != state_done) {
    enum ssl_hs_wait_t ret = ssl_hs_error;
    enum client_hs_state_t state = hs->tls13_state;
    switch (state) {
      case state_process_hello_retry_request:
        ret = do_process_hello_retry_request(hs);
        break;
      case state_send_second_client_hello:
        ret = do_send_second_client_hello(hs);
        break;
      case state_flush_second_client_hello:
        ret = do_flush_second_client_hello(hs);
        break;
      case state_process_server_hello:
        ret = do_process_server_hello(hs);
        break;
      case state_process_encrypted_extensions:
        ret = do_process_encrypted_extensions(hs);
        break;
      case state_process_certificate_request:
        ret = do_process_certificate_request(hs);
        break;
      case state_process_server_certificate:
        ret = do_process_server_certificate(hs);
        break;
      case state_process_server_certificate_verify:
        ret = do_process_server_certificate_verify(hs);
        break;
      case state_process_server_finished:
        ret = do_process_server_finished(hs);
        break;
      case state_send_client_certificate:
        ret = do_send_client_certificate(hs);
        break;
      case state_send_client_certificate_verify:
        ret = do_send_client_certificate_verify(hs, 1 /* first run */);
        break;
      case state_complete_client_certificate_verify:
        ret = do_send_client_certificate_verify(hs, 0 /* complete */);
        break;
      case state_send_channel_id:
        ret = do_send_channel_id(hs);
        break;
      case state_send_client_finished:
        ret = do_send_client_finished(hs);
        break;
      case state_flush:
        ret = do_flush(hs);
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

int tls13_process_new_session_ticket(SSL *ssl) {
  SSL_SESSION *session =
      SSL_SESSION_dup(ssl->s3->established_session,
                      SSL_SESSION_INCLUDE_NONAUTH);
  if (session == NULL) {
    return 0;
  }

  ssl_session_refresh_time(ssl, session);

  CBS cbs, ticket, extensions;
  CBS_init(&cbs, ssl->init_msg, ssl->init_num);
  if (!CBS_get_u32(&cbs, &session->tlsext_tick_lifetime_hint) ||
      !CBS_get_u32(&cbs, &session->ticket_age_add) ||
      !CBS_get_u16_length_prefixed(&cbs, &ticket) ||
      !CBS_stow(&ticket, &session->tlsext_tick, &session->tlsext_ticklen) ||
      !CBS_get_u16_length_prefixed(&cbs, &extensions) ||
      CBS_len(&cbs) != 0) {
    SSL_SESSION_free(session);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    return 0;
  }

  session->ticket_age_add_valid = 1;
  session->not_resumable = 0;

  if (ssl->ctx->new_session_cb != NULL &&
      ssl->ctx->new_session_cb(ssl, session)) {
    /* |new_session_cb|'s return value signals that it took ownership. */
    return 1;
  }

  SSL_SESSION_free(session);
  return 1;
}

void ssl_clear_tls13_state(SSL_HANDSHAKE *hs) {
  SSL_ECDH_CTX_cleanup(&hs->ecdh_ctx);

  OPENSSL_free(hs->key_share_bytes);
  hs->key_share_bytes = NULL;
  hs->key_share_bytes_len = 0;
}
