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
  state_certificate_callback,
  state_send_client_certificate,
  state_send_client_certificate_verify,
  state_complete_client_certificate_verify,
  state_send_client_finished,
  state_flush,
  state_done,
};

static enum ssl_hs_wait_t do_process_hello_retry_request(SSL *ssl,
                                                         SSL_HANDSHAKE *hs) {
  if (ssl->s3->tmp.message_type != SSL3_MT_HELLO_RETRY_REQUEST) {
    hs->state = state_process_server_hello;
    return ssl_hs_ok;
  }

  CBS cbs, extensions;
  uint16_t server_wire_version, cipher_suite, group_id;
  CBS_init(&cbs, ssl->init_msg, ssl->init_num);
  if (!CBS_get_u16(&cbs, &server_wire_version) ||
      !CBS_get_u16(&cbs, &cipher_suite) ||
      !CBS_get_u16(&cbs, &group_id) ||
      /* We do not currently parse any HelloRetryRequest extensions. */
      !CBS_get_u16_length_prefixed(&cbs, &extensions) ||
      CBS_len(&cbs) != 0) {
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
    return ssl_hs_error;
  }

  /* TODO(svaldez): Don't do early_data on HelloRetryRequest. */

  const uint16_t *groups;
  size_t groups_len;
  tls1_get_grouplist(ssl, 0 /* local groups */, &groups, &groups_len);
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

  for (size_t i = 0; i < ssl->s3->hs->groups_len; i++) {
    /* Check that the HelloRetryRequest does not request a key share that was
     * provided in the initial ClientHello.
     *
     * TODO(svaldez): Don't enforce this check when the HelloRetryRequest is due
     * to a cookie. */
    if (SSL_ECDH_CTX_get_id(&ssl->s3->hs->groups[i]) == group_id) {
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_ILLEGAL_PARAMETER);
      OPENSSL_PUT_ERROR(SSL, SSL_R_WRONG_CURVE);
      return ssl_hs_error;
    }
  }

  ssl_handshake_clear_groups(ssl->s3->hs);
  ssl->s3->hs->retry_group = group_id;

  hs->state = state_send_second_client_hello;
  return ssl_hs_ok;
}

static enum ssl_hs_wait_t do_send_second_client_hello(SSL *ssl,
                                                      SSL_HANDSHAKE *hs) {
  CBB cbb, body;
  if (!ssl->method->init_message(ssl, &cbb, &body, SSL3_MT_CLIENT_HELLO) ||
      !ssl_add_client_hello_body(ssl, &body) ||
      !ssl->method->finish_message(ssl, &cbb)) {
    CBB_cleanup(&cbb);
    return ssl_hs_error;
  }

  hs->state = state_flush_second_client_hello;
  return ssl_hs_write_message;
}

static enum ssl_hs_wait_t do_flush_second_client_hello(SSL *ssl,
                                                       SSL_HANDSHAKE *hs) {
  hs->state = state_process_server_hello;
  return ssl_hs_flush_and_read_message;
}

static enum ssl_hs_wait_t do_process_server_hello(SSL *ssl, SSL_HANDSHAKE *hs) {
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

  /* Parse out the extensions. */
  int have_key_share = 0;
  CBS key_share;
  while (CBS_len(&extensions) != 0) {
    uint16_t type;
    CBS extension;
    if (!CBS_get_u16(&extensions, &type) ||
        !CBS_get_u16_length_prefixed(&extensions, &extension)) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_PARSE_TLSEXT);
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
      return ssl_hs_error;
    }

    switch (type) {
      case TLSEXT_TYPE_key_share:
        if (have_key_share) {
          OPENSSL_PUT_ERROR(SSL, SSL_R_DUPLICATE_EXTENSION);
          ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
          return ssl_hs_error;
        }
        key_share = extension;
        have_key_share = 1;
        break;
      default:
        OPENSSL_PUT_ERROR(SSL, SSL_R_UNEXPECTED_EXTENSION);
        ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_UNSUPPORTED_EXTENSION);
        return ssl_hs_error;
    }
  }

  assert(ssl->s3->have_version);
  memcpy(ssl->s3->server_random, CBS_data(&server_random), SSL3_RANDOM_SIZE);

  ssl->hit = 0;
  if (!ssl_get_new_session(ssl, 0)) {
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
    return ssl_hs_error;
  }

  const SSL_CIPHER *cipher = SSL_get_cipher_by_value(cipher_suite);
  if (cipher == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_UNKNOWN_CIPHER_RETURNED);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_ILLEGAL_PARAMETER);
    return ssl_hs_error;
  }

  /* Check if the cipher is disabled. */
  if ((cipher->algorithm_mkey & ssl->cert->mask_k) ||
      (cipher->algorithm_auth & ssl->cert->mask_a) ||
      SSL_CIPHER_get_min_version(cipher) > ssl3_protocol_version(ssl) ||
      SSL_CIPHER_get_max_version(cipher) < ssl3_protocol_version(ssl) ||
      !sk_SSL_CIPHER_find(ssl_get_ciphers_by_id(ssl), NULL, cipher)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_WRONG_CIPHER_RETURNED);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_ILLEGAL_PARAMETER);
    return ssl_hs_error;
  }

  ssl->session->cipher = cipher;
  ssl->s3->tmp.new_cipher = cipher;

  /* The PRF hash is now known. Set up the key schedule. */
  static const uint8_t kZeroes[EVP_MAX_MD_SIZE] = {0};
  size_t hash_len =
      EVP_MD_size(ssl_get_handshake_digest(ssl_get_algorithm_prf(ssl)));
  if (!tls13_init_key_schedule(ssl, kZeroes, hash_len)) {
    return ssl_hs_error;
  }

  /* Resolve PSK and incorporate it into the secret. */
  if (cipher->algorithm_auth == SSL_aPSK) {
    /* TODO(davidben): Support PSK. */
    OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
    return ssl_hs_error;
  } else if (!tls13_advance_key_schedule(ssl, kZeroes, hash_len)) {
    return ssl_hs_error;
  }

  /* Resolve ECDHE and incorporate it into the secret. */
  if (cipher->algorithm_mkey == SSL_kECDHE) {
    if (!have_key_share) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_MISSING_KEY_SHARE);
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_MISSING_EXTENSION);
      return ssl_hs_error;
    }

    uint8_t *dhe_secret;
    size_t dhe_secret_len;
    uint8_t alert = SSL_AD_DECODE_ERROR;
    if (!ext_key_share_parse_serverhello(ssl, &dhe_secret, &dhe_secret_len,
                                         &alert, &key_share)) {
      ssl3_send_alert(ssl, SSL3_AL_FATAL, alert);
      return ssl_hs_error;
    }

    int ok = tls13_advance_key_schedule(ssl, dhe_secret, dhe_secret_len);
    OPENSSL_free(dhe_secret);
    if (!ok) {
      return ssl_hs_error;
    }
  } else {
    if (have_key_share) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_UNEXPECTED_EXTENSION);
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_UNSUPPORTED_EXTENSION);
      return ssl_hs_error;
    }
    if (!tls13_advance_key_schedule(ssl, kZeroes, hash_len)) {
      return ssl_hs_error;
    }
  }

  /* If there was no HelloRetryRequest, the version negotiation logic has
   * already hashed the message. */
  if (ssl->s3->hs->retry_group != 0 &&
      !ssl->method->hash_current_message(ssl)) {
    return ssl_hs_error;
  }

  if (!tls13_set_handshake_traffic(ssl)) {
    return ssl_hs_error;
  }

  hs->state = state_process_encrypted_extensions;
  return ssl_hs_read_message;
}

static enum ssl_hs_wait_t do_process_encrypted_extensions(SSL *ssl,
                                                          SSL_HANDSHAKE *hs) {
  if (!tls13_check_message_type(ssl, SSL3_MT_ENCRYPTED_EXTENSIONS)) {
    return ssl_hs_error;
  }

  CBS cbs;
  CBS_init(&cbs, ssl->init_msg, ssl->init_num);
  if (!ssl_parse_serverhello_tlsext(ssl, &cbs)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_PARSE_TLSEXT);
    return ssl_hs_error;
  }
  if (CBS_len(&cbs) != 0) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
    return ssl_hs_error;
  }

  if (!ssl->method->hash_current_message(ssl)) {
    return ssl_hs_error;
  }

  hs->state = state_process_certificate_request;
  return ssl_hs_read_message;
}

static enum ssl_hs_wait_t do_process_certificate_request(SSL *ssl,
                                                         SSL_HANDSHAKE *hs) {
  ssl->s3->tmp.cert_request = 0;

  /* CertificateRequest may only be sent in certificate-based ciphers. */
  if (!ssl_cipher_uses_certificate_auth(ssl->s3->tmp.new_cipher)) {
    hs->state = state_process_server_finished;
    return ssl_hs_ok;
  }

  /* CertificateRequest is optional. */
  if (ssl->s3->tmp.message_type != SSL3_MT_CERTIFICATE_REQUEST) {
    hs->state = state_process_server_certificate;
    return ssl_hs_ok;
  }

  CBS cbs, context, supported_signature_algorithms;
  CBS_init(&cbs, ssl->init_msg, ssl->init_num);
  if (!CBS_get_u8_length_prefixed(&cbs, &context) ||
      !CBS_stow(&context, &ssl->s3->hs->cert_context,
                &ssl->s3->hs->cert_context_len) ||
      !CBS_get_u16_length_prefixed(&cbs, &supported_signature_algorithms) ||
      !tls1_parse_peer_sigalgs(ssl, &supported_signature_algorithms)) {
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
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    return ssl_hs_error;
  }

  ssl->s3->tmp.cert_request = 1;
  sk_X509_NAME_pop_free(ssl->s3->tmp.ca_names, X509_NAME_free);
  ssl->s3->tmp.ca_names = ca_sk;

  if (!ssl->method->hash_current_message(ssl)) {
    return ssl_hs_error;
  }

  hs->state = state_process_server_certificate;
  return ssl_hs_read_message;
}

static enum ssl_hs_wait_t do_process_server_certificate(SSL *ssl,
                                                        SSL_HANDSHAKE *hs) {
  if (!tls13_check_message_type(ssl, SSL3_MT_CERTIFICATE) ||
      !tls13_process_certificate(ssl) ||
      !ssl->method->hash_current_message(ssl)) {
    return ssl_hs_error;
  }

  hs->state = state_process_server_certificate_verify;
  return ssl_hs_read_message;
}

static enum ssl_hs_wait_t do_process_server_certificate_verify(
    SSL *ssl, SSL_HANDSHAKE *hs) {
  if (!tls13_check_message_type(ssl, SSL3_MT_CERTIFICATE_VERIFY) ||
      !tls13_process_certificate_verify(ssl) ||
      !ssl->method->hash_current_message(ssl)) {
    return 0;
  }

  hs->state = state_process_server_finished;
  return ssl_hs_read_message;
}

static enum ssl_hs_wait_t do_process_server_finished(SSL *ssl,
                                                     SSL_HANDSHAKE *hs) {
  static const uint8_t kZeroes[EVP_MAX_MD_SIZE] = {0};

  if (!tls13_check_message_type(ssl, SSL3_MT_FINISHED) ||
      !tls13_process_finished(ssl) ||
      !ssl->method->hash_current_message(ssl) ||
      /* Update the secret to the master secret and derive traffic keys. */
      !tls13_advance_key_schedule(ssl, kZeroes, hs->hash_len) ||
      !tls13_derive_traffic_secret_0(ssl)) {
    return ssl_hs_error;
  }

  hs->state = state_certificate_callback;
  return ssl_hs_ok;
}

static enum ssl_hs_wait_t do_certificate_callback(SSL *ssl, SSL_HANDSHAKE *hs) {
  /* The peer didn't request a certificate. */
  if (!ssl->s3->tmp.cert_request) {
    hs->state = state_send_client_finished;
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
      hs->state = state_certificate_callback;
      return ssl_hs_x509_lookup;
    }
  }

  hs->state = state_send_client_certificate;
  return ssl_hs_ok;
}

static enum ssl_hs_wait_t do_send_client_certificate(SSL *ssl,
                                                     SSL_HANDSHAKE *hs) {
  /* Call client_cert_cb to update the certificate. */
  int should_retry;
  if (!ssl_do_client_cert_cb(ssl, &should_retry)) {
    if (should_retry) {
      hs->state = state_send_client_certificate;
      return ssl_hs_x509_lookup;
    }
    return ssl_hs_error;
  }

  if (!tls13_prepare_certificate(ssl)) {
    return ssl_hs_error;
  }

  hs->state = state_send_client_certificate_verify;
  return ssl_hs_write_message;
}

static enum ssl_hs_wait_t do_send_client_certificate_verify(SSL *ssl,
                                                            SSL_HANDSHAKE *hs,
                                                            int is_first_run) {
  /* Don't send CertificateVerify if there is no certificate. */
  if (!ssl_has_certificate(ssl)) {
    hs->state = state_send_client_finished;
    return ssl_hs_ok;
  }

  switch (tls13_prepare_certificate_verify(ssl, is_first_run)) {
    case ssl_private_key_success:
      hs->state = state_send_client_finished;
      return ssl_hs_write_message;

    case ssl_private_key_retry:
      hs->state = state_complete_client_certificate_verify;
      return ssl_hs_private_key_operation;

    case ssl_private_key_failure:
      return ssl_hs_error;
  }

  assert(0);
  return ssl_hs_error;
}

static enum ssl_hs_wait_t do_send_client_finished(SSL *ssl, SSL_HANDSHAKE *hs) {
  if (!tls13_prepare_finished(ssl)) {
    return ssl_hs_error;
  }

  hs->state = state_flush;
  return ssl_hs_write_message;
}

static enum ssl_hs_wait_t do_flush(SSL *ssl, SSL_HANDSHAKE *hs) {
  if (!tls13_set_traffic_key(ssl, type_data, evp_aead_open,
                             hs->traffic_secret_0, hs->hash_len) ||
      !tls13_set_traffic_key(ssl, type_data, evp_aead_seal,
                             hs->traffic_secret_0, hs->hash_len) ||
      !tls13_finalize_keys(ssl)) {
    return ssl_hs_error;
  }

  hs->state = state_done;
  return ssl_hs_flush;
}

enum ssl_hs_wait_t tls13_client_handshake(SSL *ssl) {
  SSL_HANDSHAKE *hs = ssl->s3->hs;

  while (hs->state != state_done) {
    enum ssl_hs_wait_t ret = ssl_hs_error;
    enum client_hs_state_t state = hs->state;
    switch (state) {
      case state_process_hello_retry_request:
        ret = do_process_hello_retry_request(ssl, hs);
        break;
      case state_send_second_client_hello:
        ret = do_send_second_client_hello(ssl, hs);
        break;
      case state_flush_second_client_hello:
        ret = do_flush_second_client_hello(ssl, hs);
        break;
      case state_process_server_hello:
        ret = do_process_server_hello(ssl, hs);
        break;
      case state_process_encrypted_extensions:
        ret = do_process_encrypted_extensions(ssl, hs);
        break;
      case state_process_certificate_request:
        ret = do_process_certificate_request(ssl, hs);
        break;
      case state_process_server_certificate:
        ret = do_process_server_certificate(ssl, hs);
        break;
      case state_process_server_certificate_verify:
        ret = do_process_server_certificate_verify(ssl, hs);
        break;
      case state_process_server_finished:
        ret = do_process_server_finished(ssl, hs);
        break;
      case state_certificate_callback:
        ret = do_certificate_callback(ssl, hs);
        break;
      case state_send_client_certificate:
        ret = do_send_client_certificate(ssl, hs);
        break;
      case state_send_client_certificate_verify:
        ret = do_send_client_certificate_verify(ssl, hs, 1 /* first run */);
      break;
      case state_complete_client_certificate_verify:
        ret = do_send_client_certificate_verify(ssl, hs, 0 /* complete */);
      break;
      case state_send_client_finished:
        ret = do_send_client_finished(ssl, hs);
        break;
      case state_flush:
        ret = do_flush(ssl, hs);
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
