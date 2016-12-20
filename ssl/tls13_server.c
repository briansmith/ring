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

#include <openssl/aead.h>
#include <openssl/bytestring.h>
#include <openssl/digest.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/rand.h>
#include <openssl/stack.h>

#include "../crypto/internal.h"
#include "internal.h"


enum server_hs_state_t {
  state_process_client_hello = 0,
  state_select_parameters,
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
  state_process_channel_id,
  state_process_client_finished,
  state_send_new_session_ticket,
  state_flush_new_session_tickets,
  state_done,
};

static const uint8_t kZeroes[EVP_MAX_MD_SIZE] = {0};

static int resolve_ecdhe_secret(SSL_HANDSHAKE *hs, int *out_need_retry,
                                SSL_CLIENT_HELLO *client_hello) {
  SSL *const ssl = hs->ssl;
  *out_need_retry = 0;

  /* We only support connections that include an ECDHE key exchange. */
  CBS key_share;
  if (!ssl_client_hello_get_extension(client_hello, &key_share,
                                      TLSEXT_TYPE_key_share)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_MISSING_KEY_SHARE);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_MISSING_EXTENSION);
    return 0;
  }

  int found_key_share;
  uint8_t *dhe_secret;
  size_t dhe_secret_len;
  uint8_t alert = SSL_AD_DECODE_ERROR;
  if (!ssl_ext_key_share_parse_clienthello(hs, &found_key_share, &dhe_secret,
                                           &dhe_secret_len, &alert,
                                           &key_share)) {
    ssl3_send_alert(ssl, SSL3_AL_FATAL, alert);
    return 0;
  }

  if (!found_key_share) {
    *out_need_retry = 1;
    return 0;
  }

  int ok = tls13_advance_key_schedule(hs, dhe_secret, dhe_secret_len);
  OPENSSL_free(dhe_secret);
  return ok;
}

static enum ssl_hs_wait_t do_process_client_hello(SSL_HANDSHAKE *hs) {
  SSL *const ssl = hs->ssl;
  if (!tls13_check_message_type(ssl, SSL3_MT_CLIENT_HELLO)) {
    return ssl_hs_error;
  }

  SSL_CLIENT_HELLO client_hello;
  if (!ssl_client_hello_init(ssl, &client_hello, ssl->init_msg,
                             ssl->init_num)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_CLIENTHELLO_PARSE_FAILED);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
    return ssl_hs_error;
  }

  assert(ssl->s3->have_version);

  /* Load the client random. */
  if (client_hello.random_len != SSL3_RANDOM_SIZE) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
    return ssl_hs_error;
  }
  OPENSSL_memcpy(ssl->s3->client_random, client_hello.random,
                 client_hello.random_len);

  /* TLS 1.3 requires the peer only advertise the null compression. */
  if (client_hello.compression_methods_len != 1 ||
      client_hello.compression_methods[0] != 0) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_INVALID_COMPRESSION_LIST);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_ILLEGAL_PARAMETER);
    return ssl_hs_error;
  }

  /* TLS extensions. */
  if (!ssl_parse_clienthello_tlsext(hs, &client_hello)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_PARSE_TLSEXT);
    return ssl_hs_error;
  }

  /* The short record header extension is incompatible with early data. */
  if (ssl->s3->skip_early_data && ssl->s3->short_header) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_UNEXPECTED_EXTENSION);
    return ssl_hs_error;
  }

  hs->tls13_state = state_select_parameters;
  return ssl_hs_ok;
}

static const SSL_CIPHER *choose_tls13_cipher(
    const SSL *ssl, const SSL_CLIENT_HELLO *client_hello) {
  if (client_hello->cipher_suites_len % 2 != 0) {
    return NULL;
  }

  CBS cipher_suites;
  CBS_init(&cipher_suites, client_hello->cipher_suites,
           client_hello->cipher_suites_len);

  const int aes_is_fine = EVP_has_aes_hardware();
  const uint16_t version = ssl3_protocol_version(ssl);

  const SSL_CIPHER *best = NULL;
  while (CBS_len(&cipher_suites) > 0) {
    uint16_t cipher_suite;
    if (!CBS_get_u16(&cipher_suites, &cipher_suite)) {
      return NULL;
    }

    /* Limit to TLS 1.3 ciphers we know about. */
    const SSL_CIPHER *candidate = SSL_get_cipher_by_value(cipher_suite);
    if (candidate == NULL ||
        SSL_CIPHER_get_min_version(candidate) > version ||
        SSL_CIPHER_get_max_version(candidate) < version) {
      continue;
    }

    /* TLS 1.3 removes legacy ciphers, so honor the client order, but prefer
     * ChaCha20 if we do not have AES hardware. */
    if (aes_is_fine) {
      return candidate;
    }

    if (candidate->algorithm_enc == SSL_CHACHA20POLY1305) {
      return candidate;
    }

    if (best == NULL) {
      best = candidate;
    }
  }

  return best;
}

static enum ssl_hs_wait_t do_select_parameters(SSL_HANDSHAKE *hs) {
  SSL *const ssl = hs->ssl;
  /* Call |cert_cb| to update server certificates if required. */
  if (ssl->cert->cert_cb != NULL) {
    int rv = ssl->cert->cert_cb(ssl, ssl->cert->cert_cb_arg);
    if (rv == 0) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_CERT_CB_ERROR);
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
      return ssl_hs_error;
    }
    if (rv < 0) {
      hs->tls13_state = state_select_parameters;
      return ssl_hs_x509_lookup;
    }
  }

  if (!ssl_auto_chain_if_needed(ssl)) {
    return ssl_hs_error;
  }

  SSL_CLIENT_HELLO client_hello;
  if (!ssl_client_hello_init(ssl, &client_hello, ssl->init_msg,
                             ssl->init_num)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_CLIENTHELLO_PARSE_FAILED);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
    return ssl_hs_error;
  }

  /* Negotiate the cipher suite. */
  ssl->s3->tmp.new_cipher = choose_tls13_cipher(ssl, &client_hello);
  if (ssl->s3->tmp.new_cipher == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_NO_SHARED_CIPHER);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_HANDSHAKE_FAILURE);
    return ssl_hs_error;
  }

  /* Decode the ticket if we agree on a PSK key exchange mode. */
  uint8_t alert = SSL_AD_DECODE_ERROR;
  SSL_SESSION *session = NULL;
  CBS pre_shared_key, binders;
  if (hs->accept_psk_mode &&
      ssl_client_hello_get_extension(&client_hello, &pre_shared_key,
                                     TLSEXT_TYPE_pre_shared_key)) {
    /* Verify that the pre_shared_key extension is the last extension in
     * ClientHello. */
    if (CBS_data(&pre_shared_key) + CBS_len(&pre_shared_key) !=
        client_hello.extensions + client_hello.extensions_len) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_PRE_SHARED_KEY_MUST_BE_LAST);
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_ILLEGAL_PARAMETER);
      return ssl_hs_error;
    }

    if (!ssl_ext_pre_shared_key_parse_clienthello(hs, &session, &binders,
                                                  &alert, &pre_shared_key)) {
      ssl3_send_alert(ssl, SSL3_AL_FATAL, alert);
      return ssl_hs_error;
    }
  }

  if (session != NULL &&
      !ssl_session_is_resumable(ssl, session)) {
    SSL_SESSION_free(session);
    session = NULL;
  }

  /* Set up the new session, either using the original one as a template or
   * creating a fresh one. */
  if (session == NULL) {
    if (!ssl_get_new_session(hs, 1 /* server */)) {
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
      return ssl_hs_error;
    }

    ssl->s3->new_session->cipher = ssl->s3->tmp.new_cipher;

    /* On new sessions, stash the SNI value in the session. */
    if (hs->hostname != NULL) {
      ssl->s3->new_session->tlsext_hostname = BUF_strdup(hs->hostname);
      if (ssl->s3->new_session->tlsext_hostname == NULL) {
        ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
        return ssl_hs_error;
      }
    }
  } else {
    /* Check the PSK binder. */
    if (!tls13_verify_psk_binder(ssl, session, &binders)) {
      SSL_SESSION_free(session);
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECRYPT_ERROR);
      return ssl_hs_error;
    }

    /* Only authentication information carries over in TLS 1.3. */
    ssl->s3->new_session = SSL_SESSION_dup(session, SSL_SESSION_DUP_AUTH_ONLY);
    if (ssl->s3->new_session == NULL) {
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
      return ssl_hs_error;
    }
    ssl->s3->session_reused = 1;
    SSL_SESSION_free(session);
  }

  if (ssl->ctx->dos_protection_cb != NULL &&
      ssl->ctx->dos_protection_cb(&client_hello) == 0) {
    /* Connection rejected for DOS reasons. */
    OPENSSL_PUT_ERROR(SSL, SSL_R_CONNECTION_REJECTED);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
    return ssl_hs_error;
  }

  /* HTTP/2 negotiation depends on the cipher suite, so ALPN negotiation was
   * deferred. Complete it now. */
  if (!ssl_negotiate_alpn(hs, &alert, &client_hello)) {
    ssl3_send_alert(ssl, SSL3_AL_FATAL, alert);
    return ssl_hs_error;
  }

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

  ssl->method->received_flight(ssl);

  /* Resolve ECDHE and incorporate it into the secret. */
  int need_retry;
  if (!resolve_ecdhe_secret(hs, &need_retry, &client_hello)) {
    if (need_retry) {
      hs->tls13_state = state_send_hello_retry_request;
      return ssl_hs_ok;
    }
    return ssl_hs_error;
  }

  hs->tls13_state = state_send_server_hello;
  return ssl_hs_ok;
}

static enum ssl_hs_wait_t do_send_hello_retry_request(SSL_HANDSHAKE *hs) {
  SSL *const ssl = hs->ssl;
  CBB cbb, body, extensions;
  uint16_t group_id;
  if (!ssl->method->init_message(ssl, &cbb, &body,
                                 SSL3_MT_HELLO_RETRY_REQUEST) ||
      !CBB_add_u16(&body, ssl->version) ||
      !tls1_get_shared_group(hs, &group_id) ||
      !CBB_add_u16_length_prefixed(&body, &extensions) ||
      !CBB_add_u16(&extensions, TLSEXT_TYPE_key_share) ||
      !CBB_add_u16(&extensions, 2 /* length */) ||
      !CBB_add_u16(&extensions, group_id) ||
      !ssl_complete_message(ssl, &cbb)) {
    CBB_cleanup(&cbb);
    return ssl_hs_error;
  }

  hs->tls13_state = state_flush_hello_retry_request;
  return ssl_hs_write_message;
}

static enum ssl_hs_wait_t do_flush_hello_retry_request(SSL_HANDSHAKE *hs) {
  hs->tls13_state = state_process_second_client_hello;
  return ssl_hs_flush_and_read_message;
}

static enum ssl_hs_wait_t do_process_second_client_hello(SSL_HANDSHAKE *hs) {
  SSL *const ssl = hs->ssl;
  if (!tls13_check_message_type(ssl, SSL3_MT_CLIENT_HELLO)) {
    return ssl_hs_error;
  }

  SSL_CLIENT_HELLO client_hello;
  if (!ssl_client_hello_init(ssl, &client_hello, ssl->init_msg,
                             ssl->init_num)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_CLIENTHELLO_PARSE_FAILED);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
    return ssl_hs_error;
  }

  int need_retry;
  if (!resolve_ecdhe_secret(hs, &need_retry, &client_hello)) {
    if (need_retry) {
      /* Only send one HelloRetryRequest. */
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_ILLEGAL_PARAMETER);
      OPENSSL_PUT_ERROR(SSL, SSL_R_WRONG_CURVE);
    }
    return ssl_hs_error;
  }

  if (!ssl_hash_current_message(ssl)) {
    return ssl_hs_error;
  }

  ssl->method->received_flight(ssl);
  hs->tls13_state = state_send_server_hello;
  return ssl_hs_ok;
}

static enum ssl_hs_wait_t do_send_server_hello(SSL_HANDSHAKE *hs) {
  SSL *const ssl = hs->ssl;
  CBB cbb, body, extensions;
  if (!ssl->method->init_message(ssl, &cbb, &body, SSL3_MT_SERVER_HELLO) ||
      !CBB_add_u16(&body, ssl->version) ||
      !RAND_bytes(ssl->s3->server_random, sizeof(ssl->s3->server_random)) ||
      !CBB_add_bytes(&body, ssl->s3->server_random, SSL3_RANDOM_SIZE) ||
      !CBB_add_u16(&body, ssl_cipher_get_value(ssl->s3->tmp.new_cipher)) ||
      !CBB_add_u16_length_prefixed(&body, &extensions) ||
      !ssl_ext_pre_shared_key_add_serverhello(hs, &extensions) ||
      !ssl_ext_key_share_add_serverhello(hs, &extensions)) {
    goto err;
  }

  if (ssl->s3->short_header) {
    if (!CBB_add_u16(&extensions, TLSEXT_TYPE_short_header) ||
        !CBB_add_u16(&extensions, 0 /* empty extension */)) {
      goto err;
    }
  }

  if (!ssl_complete_message(ssl, &cbb)) {
    goto err;
  }

  hs->tls13_state = state_send_encrypted_extensions;
  return ssl_hs_write_message;

err:
  CBB_cleanup(&cbb);
  return ssl_hs_error;
}

static enum ssl_hs_wait_t do_send_encrypted_extensions(SSL_HANDSHAKE *hs) {
  SSL *const ssl = hs->ssl;
  if (!tls13_derive_handshake_secrets(hs) ||
      !tls13_set_traffic_key(ssl, evp_aead_open, hs->client_handshake_secret,
                             hs->hash_len) ||
      !tls13_set_traffic_key(ssl, evp_aead_seal, hs->server_handshake_secret,
                             hs->hash_len)) {
    return ssl_hs_error;
  }

  CBB cbb, body;
  if (!ssl->method->init_message(ssl, &cbb, &body,
                                 SSL3_MT_ENCRYPTED_EXTENSIONS) ||
      !ssl_add_serverhello_tlsext(hs, &body) ||
      !ssl_complete_message(ssl, &cbb)) {
    CBB_cleanup(&cbb);
    return ssl_hs_error;
  }

  hs->tls13_state = state_send_certificate_request;
  return ssl_hs_write_message;
}

static enum ssl_hs_wait_t do_send_certificate_request(SSL_HANDSHAKE *hs) {
  SSL *const ssl = hs->ssl;
  /* Determine whether to request a client certificate. */
  hs->cert_request = !!(ssl->verify_mode & SSL_VERIFY_PEER);
  /* CertificateRequest may only be sent in non-resumption handshakes. */
  if (ssl->s3->session_reused) {
    hs->cert_request = 0;
  }

  if (!hs->cert_request) {
    /* Skip this state. */
    hs->tls13_state = state_send_server_certificate;
    return ssl_hs_ok;
  }

  CBB cbb, body, sigalgs_cbb;
  if (!ssl->method->init_message(ssl, &cbb, &body,
                                 SSL3_MT_CERTIFICATE_REQUEST) ||
      !CBB_add_u8(&body, 0 /* no certificate_request_context. */)) {
    goto err;
  }

  const uint16_t *sigalgs;
  size_t num_sigalgs = tls12_get_verify_sigalgs(ssl, &sigalgs);
  if (!CBB_add_u16_length_prefixed(&body, &sigalgs_cbb)) {
    goto err;
  }

  for (size_t i = 0; i < num_sigalgs; i++) {
    if (!CBB_add_u16(&sigalgs_cbb, sigalgs[i])) {
      goto err;
    }
  }

  if (!ssl_add_client_CA_list(ssl, &body) ||
      !CBB_add_u16(&body, 0 /* empty certificate_extensions. */) ||
      !ssl_complete_message(ssl, &cbb)) {
    goto err;
  }

  hs->tls13_state = state_send_server_certificate;
  return ssl_hs_write_message;

err:
  CBB_cleanup(&cbb);
  return ssl_hs_error;
}

static enum ssl_hs_wait_t do_send_server_certificate(SSL_HANDSHAKE *hs) {
  SSL *const ssl = hs->ssl;
  if (ssl->s3->session_reused) {
    hs->tls13_state = state_send_server_finished;
    return ssl_hs_ok;
  }

  if (!ssl_has_certificate(ssl)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_NO_CERTIFICATE_SET);
    return ssl_hs_error;
  }

  if (!tls13_prepare_certificate(hs)) {
    return ssl_hs_error;
  }

  hs->tls13_state = state_send_server_certificate_verify;
  return ssl_hs_write_message;
}

static enum ssl_hs_wait_t do_send_server_certificate_verify(SSL_HANDSHAKE *hs,
                                                            int is_first_run) {
  switch (tls13_prepare_certificate_verify(hs, is_first_run)) {
    case ssl_private_key_success:
      hs->tls13_state = state_send_server_finished;
      return ssl_hs_write_message;

    case ssl_private_key_retry:
      hs->tls13_state = state_complete_server_certificate_verify;
      return ssl_hs_private_key_operation;

    case ssl_private_key_failure:
      return ssl_hs_error;
  }

  assert(0);
  return ssl_hs_error;
}

static enum ssl_hs_wait_t do_send_server_finished(SSL_HANDSHAKE *hs) {
  if (!tls13_prepare_finished(hs)) {
    return ssl_hs_error;
  }

  hs->tls13_state = state_flush;
  return ssl_hs_write_message;
}

static enum ssl_hs_wait_t do_flush(SSL_HANDSHAKE *hs) {
  SSL *const ssl = hs->ssl;
  /* Update the secret to the master secret and derive traffic keys. */
  if (!tls13_advance_key_schedule(hs, kZeroes, hs->hash_len) ||
      !tls13_derive_application_secrets(hs) ||
      !tls13_set_traffic_key(ssl, evp_aead_seal, hs->server_traffic_secret_0,
                             hs->hash_len)) {
    return ssl_hs_error;
  }

  hs->tls13_state = state_process_client_certificate;
  return ssl_hs_flush_and_read_message;
}

static enum ssl_hs_wait_t do_process_client_certificate(SSL_HANDSHAKE *hs) {
  SSL *const ssl = hs->ssl;
  if (!hs->cert_request) {
    /* OpenSSL returns X509_V_OK when no certificates are requested. This is
     * classed by them as a bug, but it's assumed by at least NGINX. */
    ssl->s3->new_session->verify_result = X509_V_OK;

    /* Skip this state. */
    hs->tls13_state = state_process_channel_id;
    return ssl_hs_ok;
  }

  const int allow_anonymous =
      (ssl->verify_mode & SSL_VERIFY_FAIL_IF_NO_PEER_CERT) == 0;

  if (!tls13_check_message_type(ssl, SSL3_MT_CERTIFICATE) ||
      !tls13_process_certificate(hs, allow_anonymous) ||
      !ssl_hash_current_message(ssl)) {
    return ssl_hs_error;
  }

  hs->tls13_state = state_process_client_certificate_verify;
  return ssl_hs_read_message;
}

static enum ssl_hs_wait_t do_process_client_certificate_verify(
    SSL_HANDSHAKE *hs) {
  SSL *const ssl = hs->ssl;
  if (ssl->s3->new_session->x509_peer == NULL) {
    /* Skip this state. */
    hs->tls13_state = state_process_channel_id;
    return ssl_hs_ok;
  }

  if (!tls13_check_message_type(ssl, SSL3_MT_CERTIFICATE_VERIFY) ||
      !tls13_process_certificate_verify(hs) ||
      !ssl_hash_current_message(ssl)) {
    return ssl_hs_error;
  }

  hs->tls13_state = state_process_channel_id;
  return ssl_hs_read_message;
}

static enum ssl_hs_wait_t do_process_channel_id(SSL_HANDSHAKE *hs) {
  SSL *const ssl = hs->ssl;
  if (!ssl->s3->tlsext_channel_id_valid) {
    hs->tls13_state = state_process_client_finished;
    return ssl_hs_ok;
  }

  if (!tls13_check_message_type(ssl, SSL3_MT_CHANNEL_ID) ||
      !tls1_verify_channel_id(ssl) ||
      !ssl_hash_current_message(ssl)) {
    return ssl_hs_error;
  }

  hs->tls13_state = state_process_client_finished;
  return ssl_hs_read_message;
}

static enum ssl_hs_wait_t do_process_client_finished(SSL_HANDSHAKE *hs) {
  SSL *const ssl = hs->ssl;
  if (!tls13_check_message_type(ssl, SSL3_MT_FINISHED) ||
      !tls13_process_finished(hs) ||
      !ssl_hash_current_message(ssl) ||
      /* evp_aead_seal keys have already been switched. */
      !tls13_set_traffic_key(ssl, evp_aead_open, hs->client_traffic_secret_0,
                             hs->hash_len) ||
      !tls13_derive_resumption_secret(hs)) {
    return ssl_hs_error;
  }

  ssl->method->received_flight(ssl);

  /* Refresh the session timestamp so that it is measured from ticket
   * issuance. */
  ssl_session_refresh_time(ssl, ssl->s3->new_session);
  hs->tls13_state = state_send_new_session_ticket;
  return ssl_hs_ok;
}

/* TLS 1.3 recommends single-use tickets, so issue multiple tickets in case the
 * client makes several connections before getting a renewal. */
static const int kNumTickets = 2;

static enum ssl_hs_wait_t do_send_new_session_ticket(SSL_HANDSHAKE *hs) {
  SSL *const ssl = hs->ssl;
  /* If the client doesn't accept resumption with PSK_DHE_KE, don't send a
   * session ticket. */
  if (!hs->accept_psk_mode) {
    hs->tls13_state = state_done;
    return ssl_hs_ok;
  }

  SSL_SESSION *session = ssl->s3->new_session;
  if (!RAND_bytes((uint8_t *)&session->ticket_age_add, 4)) {
    goto err;
  }

  /* TODO(svaldez): Add support for sending 0RTT through TicketEarlyDataInfo
   * extension. */

  CBB cbb, body, ticket, extensions;
  if (!ssl->method->init_message(ssl, &cbb, &body,
                                 SSL3_MT_NEW_SESSION_TICKET) ||
      !CBB_add_u32(&body, session->timeout) ||
      !CBB_add_u32(&body, session->ticket_age_add) ||
      !CBB_add_u16_length_prefixed(&body, &ticket) ||
      !ssl_encrypt_ticket(ssl, &ticket, session) ||
      !CBB_add_u16_length_prefixed(&body, &extensions)) {
    goto err;
  }

  /* Add a fake extension. See draft-davidben-tls-grease-01. */
  if (!CBB_add_u16(&extensions,
                   ssl_get_grease_value(ssl, ssl_grease_ticket_extension)) ||
      !CBB_add_u16(&extensions, 0 /* empty */)) {
    goto err;
  }

  if (!ssl_complete_message(ssl, &cbb)) {
    goto err;
  }

  hs->session_tickets_sent++;
  if (hs->session_tickets_sent >= kNumTickets) {
    hs->tls13_state = state_flush_new_session_tickets;
  } else {
    hs->tls13_state = state_send_new_session_ticket;
  }

  return ssl_hs_write_message;

err:
  CBB_cleanup(&cbb);
  return ssl_hs_error;
}

static enum ssl_hs_wait_t do_flush_new_session_tickets(SSL_HANDSHAKE *hs) {
  hs->tls13_state = state_done;
  return ssl_hs_flush;
}

enum ssl_hs_wait_t tls13_server_handshake(SSL_HANDSHAKE *hs) {
  while (hs->tls13_state != state_done) {
    enum ssl_hs_wait_t ret = ssl_hs_error;
    enum server_hs_state_t state = hs->tls13_state;
    switch (state) {
      case state_process_client_hello:
        ret = do_process_client_hello(hs);
        break;
      case state_select_parameters:
        ret = do_select_parameters(hs);
        break;
      case state_send_hello_retry_request:
        ret = do_send_hello_retry_request(hs);
        break;
      case state_flush_hello_retry_request:
        ret = do_flush_hello_retry_request(hs);
        break;
      case state_process_second_client_hello:
        ret = do_process_second_client_hello(hs);
        break;
      case state_send_server_hello:
        ret = do_send_server_hello(hs);
        break;
      case state_send_encrypted_extensions:
        ret = do_send_encrypted_extensions(hs);
        break;
      case state_send_certificate_request:
        ret = do_send_certificate_request(hs);
        break;
      case state_send_server_certificate:
        ret = do_send_server_certificate(hs);
        break;
      case state_send_server_certificate_verify:
        ret = do_send_server_certificate_verify(hs, 1 /* first run */);
      break;
      case state_complete_server_certificate_verify:
        ret = do_send_server_certificate_verify(hs, 0 /* complete */);
      break;
      case state_send_server_finished:
        ret = do_send_server_finished(hs);
        break;
      case state_flush:
        ret = do_flush(hs);
        break;
      case state_process_client_certificate:
        ret = do_process_client_certificate(hs);
        break;
      case state_process_client_certificate_verify:
        ret = do_process_client_certificate_verify(hs);
        break;
      case state_process_channel_id:
        ret = do_process_channel_id(hs);
        break;
      case state_process_client_finished:
        ret = do_process_client_finished(hs);
        break;
      case state_send_new_session_ticket:
        ret = do_send_new_session_ticket(hs);
        break;
      case state_flush_new_session_tickets:
        ret = do_flush_new_session_tickets(hs);
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
