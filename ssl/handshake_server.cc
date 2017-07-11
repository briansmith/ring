/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */
/* ====================================================================
 * Copyright (c) 1998-2007 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 *
 * Portions of the attached software ("Contribution") are developed by 
 * SUN MICROSYSTEMS, INC., and are contributed to the OpenSSL project.
 *
 * The Contribution is licensed pursuant to the OpenSSL open source
 * license provided above.
 *
 * ECC cipher suite support in OpenSSL originally written by
 * Vipul Gupta and Sumit Gupta of Sun Microsystems Laboratories.
 *
 */
/* ====================================================================
 * Copyright 2005 Nokia. All rights reserved.
 *
 * The portions of the attached software ("Contribution") is developed by
 * Nokia Corporation and is licensed pursuant to the OpenSSL open source
 * license.
 *
 * The Contribution, originally written by Mika Kousa and Pasi Eronen of
 * Nokia Corporation, consists of the "PSK" (Pre-Shared Key) ciphersuites
 * support (see RFC 4279) to OpenSSL.
 *
 * No patent licenses or other rights except those expressly stated in
 * the OpenSSL open source license shall be deemed granted or received
 * expressly, by implication, estoppel, or otherwise.
 *
 * No assurances are provided by Nokia that the Contribution does not
 * infringe the patent or other intellectual property rights of any third
 * party or that the license provides you with all the necessary rights
 * to make use of the Contribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND. IN
 * ADDITION TO THE DISCLAIMERS INCLUDED IN THE LICENSE, NOKIA
 * SPECIFICALLY DISCLAIMS ANY LIABILITY FOR CLAIMS BROUGHT BY YOU OR ANY
 * OTHER ENTITY BASED ON INFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS OR
 * OTHERWISE. */

#include <openssl/ssl.h>

#include <assert.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/buf.h>
#include <openssl/bytestring.h>
#include <openssl/cipher.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <openssl/mem.h>
#include <openssl/nid.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include "internal.h"
#include "../crypto/internal.h"


static int ssl3_process_client_hello(SSL_HANDSHAKE *hs);
static int ssl3_select_certificate(SSL_HANDSHAKE *hs);
static int ssl3_select_parameters(SSL_HANDSHAKE *hs);
static int ssl3_send_server_hello(SSL_HANDSHAKE *hs);
static int ssl3_send_server_certificate(SSL_HANDSHAKE *hs);
static int ssl3_send_server_key_exchange(SSL_HANDSHAKE *hs);
static int ssl3_send_server_hello_done(SSL_HANDSHAKE *hs);
static int ssl3_get_client_certificate(SSL_HANDSHAKE *hs);
static int ssl3_get_client_key_exchange(SSL_HANDSHAKE *hs);
static int ssl3_get_cert_verify(SSL_HANDSHAKE *hs);
static int ssl3_get_next_proto(SSL_HANDSHAKE *hs);
static int ssl3_get_channel_id(SSL_HANDSHAKE *hs);
static int ssl3_send_server_finished(SSL_HANDSHAKE *hs);

int ssl3_accept(SSL_HANDSHAKE *hs) {
  SSL *const ssl = hs->ssl;
  int ret = -1;

  assert(ssl->handshake_func == ssl3_accept);
  assert(ssl->server);

  for (;;) {
    int state = hs->state;

    switch (hs->state) {
      case SSL_ST_INIT:
        ssl_do_info_callback(ssl, SSL_CB_HANDSHAKE_START, 1);
        hs->state = SSL3_ST_SR_CLNT_HELLO_A;
        break;

      case SSL3_ST_SR_CLNT_HELLO_A:
        ret = ssl->method->ssl_get_message(ssl);
        if (ret <= 0) {
          goto end;
        }
        hs->state = SSL3_ST_SR_CLNT_HELLO_B;
        break;

      case SSL3_ST_SR_CLNT_HELLO_B:
        ret = ssl3_process_client_hello(hs);
        if (ret <= 0) {
          goto end;
        }
        hs->state = SSL3_ST_SR_CLNT_HELLO_C;
        break;

      case SSL3_ST_SR_CLNT_HELLO_C:
        ret = ssl3_select_certificate(hs);
        if (ret <= 0) {
          goto end;
        }
        if (hs->state != SSL_ST_TLS13) {
          hs->state = SSL3_ST_SR_CLNT_HELLO_D;
        }
        break;

      case SSL3_ST_SR_CLNT_HELLO_D:
        ret = ssl3_select_parameters(hs);
        if (ret <= 0) {
          goto end;
        }
        ssl->method->received_flight(ssl);
        hs->state = SSL3_ST_SW_SRVR_HELLO_A;
        break;

      case SSL3_ST_SW_SRVR_HELLO_A:
        ret = ssl3_send_server_hello(hs);
        if (ret <= 0) {
          goto end;
        }
        if (ssl->session != NULL) {
          hs->state = SSL3_ST_SW_FINISHED_A;
        } else {
          hs->state = SSL3_ST_SW_CERT_A;
        }
        break;

      case SSL3_ST_SW_CERT_A:
        ret = ssl3_send_server_certificate(hs);
        if (ret <= 0) {
          goto end;
        }
        hs->state = SSL3_ST_SW_KEY_EXCH_A;
        break;

      case SSL3_ST_SW_KEY_EXCH_A:
        if (hs->server_params_len > 0) {
          ret = ssl3_send_server_key_exchange(hs);
          if (ret <= 0) {
            goto end;
          }
        }

        hs->state = SSL3_ST_SW_SRVR_DONE_A;
        break;

      case SSL3_ST_SW_SRVR_DONE_A:
        ret = ssl3_send_server_hello_done(hs);
        if (ret <= 0) {
          goto end;
        }
        hs->next_state = SSL3_ST_SR_CERT_A;
        hs->state = SSL3_ST_SW_FLUSH;
        break;

      case SSL3_ST_SR_CERT_A:
        if (hs->cert_request) {
          ret = ssl3_get_client_certificate(hs);
          if (ret <= 0) {
            goto end;
          }
        }
        hs->state = SSL3_ST_VERIFY_CLIENT_CERT;
        break;

      case SSL3_ST_VERIFY_CLIENT_CERT:
        if (sk_CRYPTO_BUFFER_num(hs->new_session->certs) > 0) {
          switch (ssl_verify_peer_cert(hs)) {
            case ssl_verify_ok:
              break;
            case ssl_verify_invalid:
              ret = -1;
              goto end;
            case ssl_verify_retry:
              ssl->rwstate = SSL_CERTIFICATE_VERIFY;
              ret = -1;
              goto end;
          }
        }
        hs->state = SSL3_ST_SR_KEY_EXCH_A;
        break;

      case SSL3_ST_SR_KEY_EXCH_A:
      case SSL3_ST_SR_KEY_EXCH_B:
        ret = ssl3_get_client_key_exchange(hs);
        if (ret <= 0) {
          goto end;
        }
        hs->state = SSL3_ST_SR_CERT_VRFY_A;
        break;

      case SSL3_ST_SR_CERT_VRFY_A:
        ret = ssl3_get_cert_verify(hs);
        if (ret <= 0) {
          goto end;
        }

        hs->state = SSL3_ST_SR_CHANGE;
        break;

      case SSL3_ST_SR_CHANGE:
        ret = ssl->method->read_change_cipher_spec(ssl);
        if (ret <= 0) {
          goto end;
        }

        if (!tls1_change_cipher_state(hs, SSL3_CHANGE_CIPHER_SERVER_READ)) {
          ret = -1;
          goto end;
        }

        hs->state = SSL3_ST_SR_NEXT_PROTO_A;
        break;

      case SSL3_ST_SR_NEXT_PROTO_A:
        if (hs->next_proto_neg_seen) {
          ret = ssl3_get_next_proto(hs);
          if (ret <= 0) {
            goto end;
          }
        }
        hs->state = SSL3_ST_SR_CHANNEL_ID_A;
        break;

      case SSL3_ST_SR_CHANNEL_ID_A:
        if (ssl->s3->tlsext_channel_id_valid) {
          ret = ssl3_get_channel_id(hs);
          if (ret <= 0) {
            goto end;
          }
        }
        hs->state = SSL3_ST_SR_FINISHED_A;
        break;

      case SSL3_ST_SR_FINISHED_A:
        ret = ssl3_get_finished(hs);
        if (ret <= 0) {
          goto end;
        }

        ssl->method->received_flight(ssl);
        if (ssl->session != NULL) {
          hs->state = SSL_ST_OK;
        } else {
          hs->state = SSL3_ST_SW_FINISHED_A;
        }

        /* If this is a full handshake with ChannelID then record the handshake
         * hashes in |hs->new_session| in case we need them to verify a
         * ChannelID signature on a resumption of this session in the future. */
        if (ssl->session == NULL && ssl->s3->tlsext_channel_id_valid) {
          ret = tls1_record_handshake_hashes_for_channel_id(hs);
          if (ret <= 0) {
            goto end;
          }
        }
        break;

      case SSL3_ST_SW_FINISHED_A:
        ret = ssl3_send_server_finished(hs);
        if (ret <= 0) {
          goto end;
        }
        hs->state = SSL3_ST_SW_FLUSH;
        if (ssl->session != NULL) {
          hs->next_state = SSL3_ST_SR_CHANGE;
        } else {
          hs->next_state = SSL_ST_OK;
        }
        break;

      case SSL3_ST_SW_FLUSH:
        ret = ssl->method->flush_flight(ssl);
        if (ret <= 0) {
          goto end;
        }

        hs->state = hs->next_state;
        if (hs->state != SSL_ST_OK) {
          ssl->method->expect_flight(ssl);
        }
        break;

      case SSL_ST_TLS13: {
        int early_return = 0;
        ret = tls13_handshake(hs, &early_return);
        if (ret <= 0) {
          goto end;
        }

        if (early_return) {
          ret = 1;
          goto end;
        }

        hs->state = SSL_ST_OK;
        break;
      }

      case SSL_ST_OK:
        ssl->method->release_current_message(ssl, 1 /* free_buffer */);

        /* If we aren't retaining peer certificates then we can discard it
         * now. */
        if (hs->new_session != NULL &&
            ssl->retain_only_sha256_of_client_certs) {
          sk_CRYPTO_BUFFER_pop_free(hs->new_session->certs, CRYPTO_BUFFER_free);
          hs->new_session->certs = NULL;
          ssl->ctx->x509_method->session_clear(hs->new_session);
        }

        SSL_SESSION_free(ssl->s3->established_session);
        if (ssl->session != NULL) {
          SSL_SESSION_up_ref(ssl->session);
          ssl->s3->established_session = ssl->session;
        } else {
          ssl->s3->established_session = hs->new_session;
          ssl->s3->established_session->not_resumable = 0;
          hs->new_session = NULL;
        }

        ssl->s3->initial_handshake_complete = 1;
        ssl_update_cache(hs, SSL_SESS_CACHE_SERVER);

        ssl_do_info_callback(ssl, SSL_CB_HANDSHAKE_DONE, 1);
        ret = 1;
        goto end;

      default:
        OPENSSL_PUT_ERROR(SSL, SSL_R_UNKNOWN_STATE);
        ret = -1;
        goto end;
    }

    if (hs->state != state) {
      ssl_do_info_callback(ssl, SSL_CB_ACCEPT_LOOP, 1);
    }
  }

end:
  ssl_do_info_callback(ssl, SSL_CB_ACCEPT_EXIT, ret);
  return ret;
}

int ssl_client_cipher_list_contains_cipher(const SSL_CLIENT_HELLO *client_hello,
                                           uint16_t id) {
  CBS cipher_suites;
  CBS_init(&cipher_suites, client_hello->cipher_suites,
           client_hello->cipher_suites_len);

  while (CBS_len(&cipher_suites) > 0) {
    uint16_t got_id;
    if (!CBS_get_u16(&cipher_suites, &got_id)) {
      return 0;
    }

    if (got_id == id) {
      return 1;
    }
  }

  return 0;
}

static int negotiate_version(SSL_HANDSHAKE *hs, uint8_t *out_alert,
                             const SSL_CLIENT_HELLO *client_hello) {
  SSL *const ssl = hs->ssl;
  assert(!ssl->s3->have_version);
  CBS supported_versions, versions;
  if (ssl_client_hello_get_extension(client_hello, &supported_versions,
                                     TLSEXT_TYPE_supported_versions)) {
    if (!CBS_get_u8_length_prefixed(&supported_versions, &versions) ||
        CBS_len(&supported_versions) != 0 ||
        CBS_len(&versions) == 0) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
      *out_alert = SSL_AD_DECODE_ERROR;
      return 0;
    }
  } else {
    /* Convert the ClientHello version to an equivalent supported_versions
     * extension. */
    static const uint8_t kTLSVersions[] = {
        0x03, 0x03, /* TLS 1.2 */
        0x03, 0x02, /* TLS 1.1 */
        0x03, 0x01, /* TLS 1 */
        0x03, 0x00, /* SSL 3 */
    };

    static const uint8_t kDTLSVersions[] = {
        0xfe, 0xfd, /* DTLS 1.2 */
        0xfe, 0xff, /* DTLS 1.0 */
    };

    size_t versions_len = 0;
    if (SSL_is_dtls(ssl)) {
      if (client_hello->version <= DTLS1_2_VERSION) {
        versions_len = 4;
      } else if (client_hello->version <= DTLS1_VERSION) {
        versions_len = 2;
      }
      CBS_init(&versions, kDTLSVersions + sizeof(kDTLSVersions) - versions_len,
               versions_len);
    } else {
      if (client_hello->version >= TLS1_2_VERSION) {
        versions_len = 8;
      } else if (client_hello->version >= TLS1_1_VERSION) {
        versions_len = 6;
      } else if (client_hello->version >= TLS1_VERSION) {
        versions_len = 4;
      } else if (client_hello->version >= SSL3_VERSION) {
        versions_len = 2;
      }
      CBS_init(&versions, kTLSVersions + sizeof(kTLSVersions) - versions_len,
               versions_len);
    }
  }

  if (!ssl_negotiate_version(hs, out_alert, &ssl->version, &versions)) {
    return 0;
  }

  /* At this point, the connection's version is known and |ssl->version| is
   * fixed. Begin enforcing the record-layer version. */
  ssl->s3->have_version = 1;

  /* Handle FALLBACK_SCSV. */
  if (ssl_client_cipher_list_contains_cipher(client_hello,
                                             SSL3_CK_FALLBACK_SCSV & 0xffff) &&
      ssl3_protocol_version(ssl) < hs->max_version) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_INAPPROPRIATE_FALLBACK);
    *out_alert = SSL3_AD_INAPPROPRIATE_FALLBACK;
    return 0;
  }

  return 1;
}

static STACK_OF(SSL_CIPHER) *
    ssl_parse_client_cipher_list(const SSL_CLIENT_HELLO *client_hello) {
  CBS cipher_suites;
  CBS_init(&cipher_suites, client_hello->cipher_suites,
           client_hello->cipher_suites_len);

  STACK_OF(SSL_CIPHER) *sk = sk_SSL_CIPHER_new_null();
  if (sk == NULL) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  while (CBS_len(&cipher_suites) > 0) {
    uint16_t cipher_suite;

    if (!CBS_get_u16(&cipher_suites, &cipher_suite)) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_ERROR_IN_RECEIVED_CIPHER_LIST);
      goto err;
    }

    const SSL_CIPHER *c = SSL_get_cipher_by_value(cipher_suite);
    if (c != NULL && !sk_SSL_CIPHER_push(sk, c)) {
      OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
      goto err;
    }
  }

  return sk;

err:
  sk_SSL_CIPHER_free(sk);
  return NULL;
}

/* ssl_get_compatible_server_ciphers determines the key exchange and
 * authentication cipher suite masks compatible with the server configuration
 * and current ClientHello parameters of |hs|. It sets |*out_mask_k| to the key
 * exchange mask and |*out_mask_a| to the authentication mask. */
static void ssl_get_compatible_server_ciphers(SSL_HANDSHAKE *hs,
                                              uint32_t *out_mask_k,
                                              uint32_t *out_mask_a) {
  SSL *const ssl = hs->ssl;
  uint32_t mask_k = 0;
  uint32_t mask_a = 0;

  if (ssl_has_certificate(ssl)) {
    mask_a |= ssl_cipher_auth_mask_for_key(hs->local_pubkey);
    if (EVP_PKEY_id(hs->local_pubkey) == EVP_PKEY_RSA) {
      mask_k |= SSL_kRSA;
    }
  }

  /* Check for a shared group to consider ECDHE ciphers. */
  uint16_t unused;
  if (tls1_get_shared_group(hs, &unused)) {
    mask_k |= SSL_kECDHE;
  }

  /* PSK requires a server callback. */
  if (ssl->psk_server_callback != NULL) {
    mask_k |= SSL_kPSK;
    mask_a |= SSL_aPSK;
  }

  *out_mask_k = mask_k;
  *out_mask_a = mask_a;
}

static const SSL_CIPHER *ssl3_choose_cipher(
    SSL_HANDSHAKE *hs, const SSL_CLIENT_HELLO *client_hello,
    const struct ssl_cipher_preference_list_st *server_pref) {
  SSL *const ssl = hs->ssl;
  STACK_OF(SSL_CIPHER) *prio, *allow;
  /* in_group_flags will either be NULL, or will point to an array of bytes
   * which indicate equal-preference groups in the |prio| stack. See the
   * comment about |in_group_flags| in the |ssl_cipher_preference_list_st|
   * struct. */
  const uint8_t *in_group_flags;
  /* group_min contains the minimal index so far found in a group, or -1 if no
   * such value exists yet. */
  int group_min = -1;

  STACK_OF(SSL_CIPHER) *client_pref =
      ssl_parse_client_cipher_list(client_hello);
  if (client_pref == NULL) {
    return NULL;
  }

  if (ssl->options & SSL_OP_CIPHER_SERVER_PREFERENCE) {
    prio = server_pref->ciphers;
    in_group_flags = server_pref->in_group_flags;
    allow = client_pref;
  } else {
    prio = client_pref;
    in_group_flags = NULL;
    allow = server_pref->ciphers;
  }

  uint32_t mask_k, mask_a;
  ssl_get_compatible_server_ciphers(hs, &mask_k, &mask_a);

  const SSL_CIPHER *ret = NULL;
  for (size_t i = 0; i < sk_SSL_CIPHER_num(prio); i++) {
    const SSL_CIPHER *c = sk_SSL_CIPHER_value(prio, i);

    size_t cipher_index;
    if (/* Check if the cipher is supported for the current version. */
        SSL_CIPHER_get_min_version(c) <= ssl3_protocol_version(ssl) &&
        ssl3_protocol_version(ssl) <= SSL_CIPHER_get_max_version(c) &&
        /* Check the cipher is supported for the server configuration. */
        (c->algorithm_mkey & mask_k) &&
        (c->algorithm_auth & mask_a) &&
        /* Check the cipher is in the |allow| list. */
        sk_SSL_CIPHER_find(allow, &cipher_index, c)) {
      if (in_group_flags != NULL && in_group_flags[i] == 1) {
        /* This element of |prio| is in a group. Update the minimum index found
         * so far and continue looking. */
        if (group_min == -1 || (size_t)group_min > cipher_index) {
          group_min = cipher_index;
        }
      } else {
        if (group_min != -1 && (size_t)group_min < cipher_index) {
          cipher_index = group_min;
        }
        ret = sk_SSL_CIPHER_value(allow, cipher_index);
        break;
      }
    }

    if (in_group_flags != NULL && in_group_flags[i] == 0 && group_min != -1) {
      /* We are about to leave a group, but we found a match in it, so that's
       * our answer. */
      ret = sk_SSL_CIPHER_value(allow, group_min);
      break;
    }
  }

  sk_SSL_CIPHER_free(client_pref);
  return ret;
}

static int ssl3_process_client_hello(SSL_HANDSHAKE *hs) {
  SSL *const ssl = hs->ssl;
  if (!ssl_check_message_type(ssl, SSL3_MT_CLIENT_HELLO)) {
    return -1;
  }

  SSL_CLIENT_HELLO client_hello;
  if (!ssl_client_hello_init(ssl, &client_hello, ssl->init_msg,
                             ssl->init_num)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
    return -1;
  }

  /* Run the early callback. */
  if (ssl->ctx->select_certificate_cb != NULL) {
    switch (ssl->ctx->select_certificate_cb(&client_hello)) {
      case ssl_select_cert_retry:
        ssl->rwstate = SSL_CERTIFICATE_SELECTION_PENDING;
        return -1;

      case ssl_select_cert_error:
        /* Connection rejected. */
        OPENSSL_PUT_ERROR(SSL, SSL_R_CONNECTION_REJECTED);
        ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_HANDSHAKE_FAILURE);
        return -1;

      default:
        /* fallthrough */;
    }
  }

  /* Freeze the version range after the early callback. */
  if (!ssl_get_version_range(ssl, &hs->min_version, &hs->max_version)) {
    return -1;
  }

  uint8_t alert = SSL_AD_DECODE_ERROR;
  if (!negotiate_version(hs, &alert, &client_hello)) {
    ssl3_send_alert(ssl, SSL3_AL_FATAL, alert);
    return -1;
  }

  hs->client_version = client_hello.version;
  if (client_hello.random_len != SSL3_RANDOM_SIZE) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
    return -1;
  }
  OPENSSL_memcpy(ssl->s3->client_random, client_hello.random,
                 client_hello.random_len);

  /* Only null compression is supported. TLS 1.3 further requires the peer
   * advertise no other compression. */
  if (OPENSSL_memchr(client_hello.compression_methods, 0,
                     client_hello.compression_methods_len) == NULL ||
      (ssl3_protocol_version(ssl) >= TLS1_3_VERSION &&
       client_hello.compression_methods_len != 1)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_INVALID_COMPRESSION_LIST);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_ILLEGAL_PARAMETER);
    return -1;
  }

  /* TLS extensions. */
  if (!ssl_parse_clienthello_tlsext(hs, &client_hello)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_PARSE_TLSEXT);
    return -1;
  }

  return 1;
}

static int ssl3_select_certificate(SSL_HANDSHAKE *hs) {
  SSL *const ssl = hs->ssl;
  /* Call |cert_cb| to update server certificates if required. */
  if (ssl->cert->cert_cb != NULL) {
    int rv = ssl->cert->cert_cb(ssl, ssl->cert->cert_cb_arg);
    if (rv == 0) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_CERT_CB_ERROR);
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
      return -1;
    }
    if (rv < 0) {
      ssl->rwstate = SSL_X509_LOOKUP;
      return -1;
    }
  }

  if (!ssl_on_certificate_selected(hs)) {
    return -1;
  }

  if (ssl3_protocol_version(ssl) >= TLS1_3_VERSION) {
    /* Jump to the TLS 1.3 state machine. */
    hs->state = SSL_ST_TLS13;
    hs->do_tls13_handshake = tls13_server_handshake;
    return 1;
  }

  SSL_CLIENT_HELLO client_hello;
  if (!ssl_client_hello_init(ssl, &client_hello, ssl->init_msg,
                             ssl->init_num)) {
    return -1;
  }

  /* Negotiate the cipher suite. This must be done after |cert_cb| so the
   * certificate is finalized. */
  hs->new_cipher =
      ssl3_choose_cipher(hs, &client_hello, ssl_get_cipher_preferences(ssl));
  if (hs->new_cipher == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_NO_SHARED_CIPHER);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_HANDSHAKE_FAILURE);
    return -1;
  }

  return 1;
}

static int ssl3_select_parameters(SSL_HANDSHAKE *hs) {
  SSL *const ssl = hs->ssl;
  SSL_CLIENT_HELLO client_hello;
  if (!ssl_client_hello_init(ssl, &client_hello, ssl->init_msg,
                             ssl->init_num)) {
    return -1;
  }

  /* Determine whether we are doing session resumption. */
  int tickets_supported = 0, renew_ticket = 0;
  /* TODO(davidben): Switch |ssl_get_prev_session| to take a |bssl::UniquePtr|
   * output and simplify this. */
  SSL_SESSION *session_raw = nullptr;
  auto session_ret = ssl_get_prev_session(ssl, &session_raw, &tickets_supported,
                                          &renew_ticket, &client_hello);
  bssl::UniquePtr<SSL_SESSION> session(session_raw);
  switch (session_ret) {
    case ssl_session_success:
      break;
    case ssl_session_error:
      return -1;
    case ssl_session_retry:
      ssl->rwstate = SSL_PENDING_SESSION;
      return -1;
    case ssl_session_ticket_retry:
      ssl->rwstate = SSL_PENDING_TICKET;
      return -1;
  }

  if (session) {
    if (session->extended_master_secret && !hs->extended_master_secret) {
      /* A ClientHello without EMS that attempts to resume a session with EMS
       * is fatal to the connection. */
      OPENSSL_PUT_ERROR(SSL, SSL_R_RESUMED_EMS_SESSION_WITHOUT_EMS_EXTENSION);
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_HANDSHAKE_FAILURE);
      return -1;
    }

    if (!ssl_session_is_resumable(hs, session.get()) ||
        /* If the client offers the EMS extension, but the previous session
         * didn't use it, then negotiate a new session. */
        hs->extended_master_secret != session->extended_master_secret) {
      session.reset();
    }
  }

  if (session) {
    /* Use the old session. */
    hs->ticket_expected = renew_ticket;
    ssl->session = session.release();
    ssl->s3->session_reused = 1;
  } else {
    hs->ticket_expected = tickets_supported;
    ssl_set_session(ssl, NULL);
    if (!ssl_get_new_session(hs, 1 /* server */)) {
      return -1;
    }

    /* Clear the session ID if we want the session to be single-use. */
    if (!(ssl->ctx->session_cache_mode & SSL_SESS_CACHE_SERVER)) {
      hs->new_session->session_id_length = 0;
    }
  }

  if (ssl->ctx->dos_protection_cb != NULL &&
      ssl->ctx->dos_protection_cb(&client_hello) == 0) {
    /* Connection rejected for DOS reasons. */
    OPENSSL_PUT_ERROR(SSL, SSL_R_CONNECTION_REJECTED);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
    return -1;
  }

  if (ssl->session == NULL) {
    hs->new_session->cipher = hs->new_cipher;

    /* On new sessions, stash the SNI value in the session. */
    if (hs->hostname != NULL) {
      OPENSSL_free(hs->new_session->tlsext_hostname);
      hs->new_session->tlsext_hostname = BUF_strdup(hs->hostname);
      if (hs->new_session->tlsext_hostname == NULL) {
        ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
        return -1;
      }
    }

    /* Determine whether to request a client certificate. */
    hs->cert_request = !!(ssl->verify_mode & SSL_VERIFY_PEER);
    /* Only request a certificate if Channel ID isn't negotiated. */
    if ((ssl->verify_mode & SSL_VERIFY_PEER_IF_NO_OBC) &&
        ssl->s3->tlsext_channel_id_valid) {
      hs->cert_request = 0;
    }
    /* CertificateRequest may only be sent in certificate-based ciphers. */
    if (!ssl_cipher_uses_certificate_auth(hs->new_cipher)) {
      hs->cert_request = 0;
    }

    if (!hs->cert_request) {
      /* OpenSSL returns X509_V_OK when no certificates are requested. This is
       * classed by them as a bug, but it's assumed by at least NGINX. */
      hs->new_session->verify_result = X509_V_OK;
    }
  }

  /* HTTP/2 negotiation depends on the cipher suite, so ALPN negotiation was
   * deferred. Complete it now. */
  uint8_t alert = SSL_AD_DECODE_ERROR;
  if (!ssl_negotiate_alpn(hs, &alert, &client_hello)) {
    ssl3_send_alert(ssl, SSL3_AL_FATAL, alert);
    return -1;
  }

  /* Now that all parameters are known, initialize the handshake hash and hash
   * the ClientHello. */
  if (!SSL_TRANSCRIPT_init_hash(&hs->transcript, ssl3_protocol_version(ssl),
                                hs->new_cipher->algorithm_prf) ||
      !ssl_hash_current_message(hs)) {
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
    return -1;
  }

  /* Release the handshake buffer if client authentication isn't required. */
  if (!hs->cert_request) {
    SSL_TRANSCRIPT_free_buffer(&hs->transcript);
  }

  return 1;
}

static int ssl3_send_server_hello(SSL_HANDSHAKE *hs) {
  SSL *const ssl = hs->ssl;

  /* We only accept ChannelIDs on connections with ECDHE in order to avoid a
   * known attack while we fix ChannelID itself. */
  if (ssl->s3->tlsext_channel_id_valid &&
      (hs->new_cipher->algorithm_mkey & SSL_kECDHE) == 0) {
    ssl->s3->tlsext_channel_id_valid = 0;
  }

  /* If this is a resumption and the original handshake didn't support
   * ChannelID then we didn't record the original handshake hashes in the
   * session and so cannot resume with ChannelIDs. */
  if (ssl->session != NULL &&
      ssl->session->original_handshake_hash_len == 0) {
    ssl->s3->tlsext_channel_id_valid = 0;
  }

  struct OPENSSL_timeval now;
  ssl_get_current_time(ssl, &now);
  ssl->s3->server_random[0] = now.tv_sec >> 24;
  ssl->s3->server_random[1] = now.tv_sec >> 16;
  ssl->s3->server_random[2] = now.tv_sec >> 8;
  ssl->s3->server_random[3] = now.tv_sec;
  if (!RAND_bytes(ssl->s3->server_random + 4, SSL3_RANDOM_SIZE - 4)) {
    return -1;
  }

  /* TODO(davidben): Implement the TLS 1.1 and 1.2 downgrade sentinels once TLS
   * 1.3 is finalized and we are not implementing a draft version. */

  const SSL_SESSION *session = hs->new_session;
  if (ssl->session != NULL) {
    session = ssl->session;
  }

  CBB cbb, body, session_id;
  if (!ssl->method->init_message(ssl, &cbb, &body, SSL3_MT_SERVER_HELLO) ||
      !CBB_add_u16(&body, ssl->version) ||
      !CBB_add_bytes(&body, ssl->s3->server_random, SSL3_RANDOM_SIZE) ||
      !CBB_add_u8_length_prefixed(&body, &session_id) ||
      !CBB_add_bytes(&session_id, session->session_id,
                     session->session_id_length) ||
      !CBB_add_u16(&body, ssl_cipher_get_value(hs->new_cipher)) ||
      !CBB_add_u8(&body, 0 /* no compression */) ||
      !ssl_add_serverhello_tlsext(hs, &body) ||
      !ssl_add_message_cbb(ssl, &cbb)) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
    CBB_cleanup(&cbb);
    return -1;
  }

  return 1;
}

static int ssl3_send_server_certificate(SSL_HANDSHAKE *hs) {
  SSL *const ssl = hs->ssl;
  bssl::ScopedCBB cbb;

  if (ssl_cipher_uses_certificate_auth(hs->new_cipher)) {
    if (!ssl_has_certificate(ssl)) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_NO_CERTIFICATE_SET);
      return -1;
    }

    if (!ssl3_output_cert_chain(ssl)) {
      return -1;
    }

    if (hs->certificate_status_expected) {
      CBB body, ocsp_response;
      if (!ssl->method->init_message(ssl, cbb.get(), &body,
                                     SSL3_MT_CERTIFICATE_STATUS) ||
          !CBB_add_u8(&body, TLSEXT_STATUSTYPE_ocsp) ||
          !CBB_add_u24_length_prefixed(&body, &ocsp_response) ||
          !CBB_add_bytes(&ocsp_response,
                         CRYPTO_BUFFER_data(ssl->cert->ocsp_response),
                         CRYPTO_BUFFER_len(ssl->cert->ocsp_response)) ||
          !ssl_add_message_cbb(ssl, cbb.get())) {
        OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
        return -1;
      }
    }
  }

  /* Assemble ServerKeyExchange parameters if needed. */
  uint32_t alg_k = hs->new_cipher->algorithm_mkey;
  uint32_t alg_a = hs->new_cipher->algorithm_auth;
  if (ssl_cipher_requires_server_key_exchange(hs->new_cipher) ||
      ((alg_a & SSL_aPSK) && ssl->psk_identity_hint)) {

    /* Pre-allocate enough room to comfortably fit an ECDHE public key. Prepend
     * the client and server randoms for the signing transcript. */
    CBB child;
    if (!CBB_init(cbb.get(), SSL3_RANDOM_SIZE * 2 + 128) ||
        !CBB_add_bytes(cbb.get(), ssl->s3->client_random, SSL3_RANDOM_SIZE) ||
        !CBB_add_bytes(cbb.get(), ssl->s3->server_random, SSL3_RANDOM_SIZE)) {
      return -1;
    }

    /* PSK ciphers begin with an identity hint. */
    if (alg_a & SSL_aPSK) {
      size_t len =
          (ssl->psk_identity_hint == NULL) ? 0 : strlen(ssl->psk_identity_hint);
      if (!CBB_add_u16_length_prefixed(cbb.get(), &child) ||
          !CBB_add_bytes(&child, (const uint8_t *)ssl->psk_identity_hint,
                         len)) {
        return -1;
      }
    }

    if (alg_k & SSL_kECDHE) {
      /* Determine the group to use. */
      uint16_t group_id;
      if (!tls1_get_shared_group(hs, &group_id)) {
        OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
        ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_HANDSHAKE_FAILURE);
        return -1;
       }
      hs->new_session->group_id = group_id;

      /* Set up ECDH, generate a key, and emit the public half. */
      if (!SSL_ECDH_CTX_init(&hs->ecdh_ctx, group_id) ||
          !CBB_add_u8(cbb.get(), NAMED_CURVE_TYPE) ||
          !CBB_add_u16(cbb.get(), group_id) ||
          !CBB_add_u8_length_prefixed(cbb.get(), &child) ||
          !SSL_ECDH_CTX_offer(&hs->ecdh_ctx, &child)) {
        return -1;
      }
    } else {
      assert(alg_k & SSL_kPSK);
    }

    if (!CBB_finish(cbb.get(), &hs->server_params, &hs->server_params_len)) {
      return -1;
    }
  }

  return 1;
}

static int ssl3_send_server_key_exchange(SSL_HANDSHAKE *hs) {
  SSL *const ssl = hs->ssl;
  CBB cbb, body, child;
  if (!ssl->method->init_message(ssl, &cbb, &body,
                                 SSL3_MT_SERVER_KEY_EXCHANGE) ||
      /* |hs->server_params| contains a prefix for signing. */
      hs->server_params_len < 2 * SSL3_RANDOM_SIZE ||
      !CBB_add_bytes(&body, hs->server_params + 2 * SSL3_RANDOM_SIZE,
                     hs->server_params_len - 2 * SSL3_RANDOM_SIZE)) {
    goto err;
  }

  /* Add a signature. */
  if (ssl_cipher_uses_certificate_auth(hs->new_cipher)) {
    if (!ssl_has_private_key(ssl)) {
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
      goto err;
    }

    /* Determine the signature algorithm. */
    uint16_t signature_algorithm;
    if (!tls1_choose_signature_algorithm(hs, &signature_algorithm)) {
      goto err;
    }
    if (ssl3_protocol_version(ssl) >= TLS1_2_VERSION) {
      if (!CBB_add_u16(&body, signature_algorithm)) {
        OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
        ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
        goto err;
      }
    }

    /* Add space for the signature. */
    const size_t max_sig_len = EVP_PKEY_size(hs->local_pubkey);
    uint8_t *ptr;
    if (!CBB_add_u16_length_prefixed(&body, &child) ||
        !CBB_reserve(&child, &ptr, max_sig_len)) {
      goto err;
    }

    size_t sig_len;
    switch (ssl_private_key_sign(hs, ptr, &sig_len, max_sig_len,
                                 signature_algorithm, hs->server_params,
                                 hs->server_params_len)) {
      case ssl_private_key_success:
        if (!CBB_did_write(&child, sig_len)) {
          goto err;
        }
        break;
      case ssl_private_key_failure:
        goto err;
      case ssl_private_key_retry:
        ssl->rwstate = SSL_PRIVATE_KEY_OPERATION;
        goto err;
    }
  }

  if (!ssl_add_message_cbb(ssl, &cbb)) {
    goto err;
  }

  OPENSSL_free(hs->server_params);
  hs->server_params = NULL;
  hs->server_params_len = 0;

  return 1;

err:
  CBB_cleanup(&cbb);
  return -1;
}

static int ssl3_send_server_hello_done(SSL_HANDSHAKE *hs) {
  SSL *const ssl = hs->ssl;
  CBB cbb, body;

  if (hs->cert_request) {
    CBB cert_types, sigalgs_cbb;
    if (!ssl->method->init_message(ssl, &cbb, &body,
                                   SSL3_MT_CERTIFICATE_REQUEST) ||
        !CBB_add_u8_length_prefixed(&body, &cert_types) ||
        !CBB_add_u8(&cert_types, SSL3_CT_RSA_SIGN) ||
        (ssl3_protocol_version(ssl) >= TLS1_VERSION &&
         !CBB_add_u8(&cert_types, TLS_CT_ECDSA_SIGN)) ||
        (ssl3_protocol_version(ssl) >= TLS1_2_VERSION &&
         (!CBB_add_u16_length_prefixed(&body, &sigalgs_cbb) ||
          !tls12_add_verify_sigalgs(ssl, &sigalgs_cbb))) ||
        !ssl_add_client_CA_list(ssl, &body) ||
        !ssl_add_message_cbb(ssl, &cbb)) {
      goto err;
    }
  }

  if (!ssl->method->init_message(ssl, &cbb, &body, SSL3_MT_SERVER_HELLO_DONE) ||
      !ssl_add_message_cbb(ssl, &cbb)) {
    goto err;
  }

  return 1;

err:
  OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
  CBB_cleanup(&cbb);
  return -1;
}

static int ssl3_get_client_certificate(SSL_HANDSHAKE *hs) {
  SSL *const ssl = hs->ssl;
  assert(hs->cert_request);

  int msg_ret = ssl->method->ssl_get_message(ssl);
  if (msg_ret <= 0) {
    return msg_ret;
  }

  if (ssl->s3->tmp.message_type != SSL3_MT_CERTIFICATE) {
    if (ssl->version == SSL3_VERSION &&
        ssl->s3->tmp.message_type == SSL3_MT_CLIENT_KEY_EXCHANGE) {
      /* In SSL 3.0, the Certificate message is omitted to signal no
       * certificate. */
      if (ssl->verify_mode & SSL_VERIFY_FAIL_IF_NO_PEER_CERT) {
        OPENSSL_PUT_ERROR(SSL, SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE);
        ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_HANDSHAKE_FAILURE);
        return -1;
      }

      /* OpenSSL returns X509_V_OK when no certificates are received. This is
       * classed by them as a bug, but it's assumed by at least NGINX. */
      hs->new_session->verify_result = X509_V_OK;
      ssl->s3->tmp.reuse_message = 1;
      return 1;
    }

    OPENSSL_PUT_ERROR(SSL, SSL_R_UNEXPECTED_MESSAGE);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_UNEXPECTED_MESSAGE);
    return -1;
  }

  if (!ssl_hash_current_message(hs)) {
    return -1;
  }

  CBS certificate_msg;
  CBS_init(&certificate_msg, ssl->init_msg, ssl->init_num);

  sk_CRYPTO_BUFFER_pop_free(hs->new_session->certs, CRYPTO_BUFFER_free);
  EVP_PKEY_free(hs->peer_pubkey);
  hs->peer_pubkey = NULL;
  uint8_t alert = SSL_AD_DECODE_ERROR;
  hs->new_session->certs = ssl_parse_cert_chain(
      &alert, &hs->peer_pubkey,
      ssl->retain_only_sha256_of_client_certs ? hs->new_session->peer_sha256
                                              : NULL,
      &certificate_msg, ssl->ctx->pool);
  if (hs->new_session->certs == NULL) {
    ssl3_send_alert(ssl, SSL3_AL_FATAL, alert);
    return -1;
  }

  if (CBS_len(&certificate_msg) != 0 ||
      !ssl->ctx->x509_method->session_cache_objects(hs->new_session)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
    return -1;
  }

  if (sk_CRYPTO_BUFFER_num(hs->new_session->certs) == 0) {
    /* No client certificate so the handshake buffer may be discarded. */
    SSL_TRANSCRIPT_free_buffer(&hs->transcript);

    /* In SSL 3.0, sending no certificate is signaled by omitting the
     * Certificate message. */
    if (ssl->version == SSL3_VERSION) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_NO_CERTIFICATES_RETURNED);
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_HANDSHAKE_FAILURE);
      return -1;
    }

    if (ssl->verify_mode & SSL_VERIFY_FAIL_IF_NO_PEER_CERT) {
      /* Fail for TLS only if we required a certificate */
      OPENSSL_PUT_ERROR(SSL, SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE);
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_HANDSHAKE_FAILURE);
      return -1;
    }

    /* OpenSSL returns X509_V_OK when no certificates are received. This is
     * classed by them as a bug, but it's assumed by at least NGINX. */
    hs->new_session->verify_result = X509_V_OK;
    return 1;
  }

  /* The hash will have been filled in. */
  if (ssl->retain_only_sha256_of_client_certs) {
    hs->new_session->peer_sha256_valid = 1;
  }

  return 1;
}

static int ssl3_get_client_key_exchange(SSL_HANDSHAKE *hs) {
  SSL *const ssl = hs->ssl;
  CBS client_key_exchange;
  uint8_t *premaster_secret = NULL;
  size_t premaster_secret_len = 0;
  uint8_t *decrypt_buf = NULL;

  if (hs->state == SSL3_ST_SR_KEY_EXCH_A) {
    int ret = ssl->method->ssl_get_message(ssl);
    if (ret <= 0) {
      return ret;
    }
  }

  if (!ssl_check_message_type(ssl, SSL3_MT_CLIENT_KEY_EXCHANGE)) {
    return -1;
  }

  CBS_init(&client_key_exchange, ssl->init_msg, ssl->init_num);
  uint32_t alg_k = hs->new_cipher->algorithm_mkey;
  uint32_t alg_a = hs->new_cipher->algorithm_auth;

  /* If using a PSK key exchange, parse the PSK identity. */
  if (alg_a & SSL_aPSK) {
    CBS psk_identity;

    /* If using PSK, the ClientKeyExchange contains a psk_identity. If PSK,
     * then this is the only field in the message. */
    if (!CBS_get_u16_length_prefixed(&client_key_exchange, &psk_identity) ||
        ((alg_k & SSL_kPSK) && CBS_len(&client_key_exchange) != 0)) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
      goto err;
    }

    if (CBS_len(&psk_identity) > PSK_MAX_IDENTITY_LEN ||
        CBS_contains_zero_byte(&psk_identity)) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_DATA_LENGTH_TOO_LONG);
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_ILLEGAL_PARAMETER);
      goto err;
    }

    if (!CBS_strdup(&psk_identity, &hs->new_session->psk_identity)) {
      OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
      goto err;
    }
  }

  /* Depending on the key exchange method, compute |premaster_secret| and
   * |premaster_secret_len|. */
  if (alg_k & SSL_kRSA) {
    CBS encrypted_premaster_secret;
    if (ssl->version > SSL3_VERSION) {
      if (!CBS_get_u16_length_prefixed(&client_key_exchange,
                                       &encrypted_premaster_secret) ||
          CBS_len(&client_key_exchange) != 0) {
        OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
        ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
        goto err;
      }
    } else {
      encrypted_premaster_secret = client_key_exchange;
    }

    /* Allocate a buffer large enough for an RSA decryption. */
    const size_t rsa_size = EVP_PKEY_size(hs->local_pubkey);
    decrypt_buf = (uint8_t *)OPENSSL_malloc(rsa_size);
    if (decrypt_buf == NULL) {
      OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
      goto err;
    }

    /* Decrypt with no padding. PKCS#1 padding will be removed as part of the
     * timing-sensitive code below. */
    size_t decrypt_len;
    switch (ssl_private_key_decrypt(hs, decrypt_buf, &decrypt_len, rsa_size,
                                    CBS_data(&encrypted_premaster_secret),
                                    CBS_len(&encrypted_premaster_secret))) {
      case ssl_private_key_success:
        break;
      case ssl_private_key_failure:
        goto err;
      case ssl_private_key_retry:
        ssl->rwstate = SSL_PRIVATE_KEY_OPERATION;
        hs->state = SSL3_ST_SR_KEY_EXCH_B;
        goto err;
    }

    if (decrypt_len != rsa_size) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_DECRYPTION_FAILED);
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECRYPT_ERROR);
      goto err;
    }

    /* Prepare a random premaster, to be used on invalid padding. See RFC 5246,
     * section 7.4.7.1. */
    premaster_secret_len = SSL_MAX_MASTER_KEY_LENGTH;
    premaster_secret = (uint8_t *)OPENSSL_malloc(premaster_secret_len);
    if (premaster_secret == NULL) {
      OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
      goto err;
    }
    if (!RAND_bytes(premaster_secret, premaster_secret_len)) {
      goto err;
    }

    /* The smallest padded premaster is 11 bytes of overhead. Small keys are
     * publicly invalid. */
    if (decrypt_len < 11 + premaster_secret_len) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_DECRYPTION_FAILED);
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECRYPT_ERROR);
      goto err;
    }

    /* Check the padding. See RFC 3447, section 7.2.2. */
    size_t padding_len = decrypt_len - premaster_secret_len;
    uint8_t good = constant_time_eq_int_8(decrypt_buf[0], 0) &
                   constant_time_eq_int_8(decrypt_buf[1], 2);
    for (size_t i = 2; i < padding_len - 1; i++) {
      good &= ~constant_time_is_zero_8(decrypt_buf[i]);
    }
    good &= constant_time_is_zero_8(decrypt_buf[padding_len - 1]);

    /* The premaster secret must begin with |client_version|. This too must be
     * checked in constant time (http://eprint.iacr.org/2003/052/). */
    good &= constant_time_eq_8(decrypt_buf[padding_len],
                               (unsigned)(hs->client_version >> 8));
    good &= constant_time_eq_8(decrypt_buf[padding_len + 1],
                               (unsigned)(hs->client_version & 0xff));

    /* Select, in constant time, either the decrypted premaster or the random
     * premaster based on |good|. */
    for (size_t i = 0; i < premaster_secret_len; i++) {
      premaster_secret[i] = constant_time_select_8(
          good, decrypt_buf[padding_len + i], premaster_secret[i]);
    }

    OPENSSL_free(decrypt_buf);
    decrypt_buf = NULL;
  } else if (alg_k & SSL_kECDHE) {
    /* Parse the ClientKeyExchange. */
    CBS peer_key;
    if (!CBS_get_u8_length_prefixed(&client_key_exchange, &peer_key) ||
        CBS_len(&client_key_exchange) != 0) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
      goto err;
    }

    /* Compute the premaster. */
    uint8_t alert = SSL_AD_DECODE_ERROR;
    if (!SSL_ECDH_CTX_finish(&hs->ecdh_ctx, &premaster_secret,
                             &premaster_secret_len, &alert, CBS_data(&peer_key),
                             CBS_len(&peer_key))) {
      ssl3_send_alert(ssl, SSL3_AL_FATAL, alert);
      goto err;
    }

    /* The key exchange state may now be discarded. */
    SSL_ECDH_CTX_cleanup(&hs->ecdh_ctx);
  } else if (!(alg_k & SSL_kPSK)) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_HANDSHAKE_FAILURE);
    goto err;
  }

  /* For a PSK cipher suite, the actual pre-master secret is combined with the
   * pre-shared key. */
  if (alg_a & SSL_aPSK) {
    if (ssl->psk_server_callback == NULL) {
      OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
      goto err;
    }

    /* Look up the key for the identity. */
    uint8_t psk[PSK_MAX_PSK_LEN];
    unsigned psk_len = ssl->psk_server_callback(
        ssl, hs->new_session->psk_identity, psk, sizeof(psk));
    if (psk_len > PSK_MAX_PSK_LEN) {
      OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_INTERNAL_ERROR);
      goto err;
    } else if (psk_len == 0) {
      /* PSK related to the given identity not found */
      OPENSSL_PUT_ERROR(SSL, SSL_R_PSK_IDENTITY_NOT_FOUND);
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_UNKNOWN_PSK_IDENTITY);
      goto err;
    }

    if (alg_k & SSL_kPSK) {
      /* In plain PSK, other_secret is a block of 0s with the same length as the
       * pre-shared key. */
      premaster_secret_len = psk_len;
      premaster_secret = (uint8_t *)OPENSSL_malloc(premaster_secret_len);
      if (premaster_secret == NULL) {
        OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
        goto err;
      }
      OPENSSL_memset(premaster_secret, 0, premaster_secret_len);
    }

    CBB new_premaster, child;
    uint8_t *new_data;
    size_t new_len;
    CBB_zero(&new_premaster);
    if (!CBB_init(&new_premaster, 2 + psk_len + 2 + premaster_secret_len) ||
        !CBB_add_u16_length_prefixed(&new_premaster, &child) ||
        !CBB_add_bytes(&child, premaster_secret, premaster_secret_len) ||
        !CBB_add_u16_length_prefixed(&new_premaster, &child) ||
        !CBB_add_bytes(&child, psk, psk_len) ||
        !CBB_finish(&new_premaster, &new_data, &new_len)) {
      OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
      CBB_cleanup(&new_premaster);
      goto err;
    }

    OPENSSL_cleanse(premaster_secret, premaster_secret_len);
    OPENSSL_free(premaster_secret);
    premaster_secret = new_data;
    premaster_secret_len = new_len;
  }

  if (!ssl_hash_current_message(hs)) {
    goto err;
  }

  /* Compute the master secret */
  hs->new_session->master_key_length = tls1_generate_master_secret(
      hs, hs->new_session->master_key, premaster_secret, premaster_secret_len);
  if (hs->new_session->master_key_length == 0) {
    goto err;
  }
  hs->new_session->extended_master_secret = hs->extended_master_secret;

  OPENSSL_cleanse(premaster_secret, premaster_secret_len);
  OPENSSL_free(premaster_secret);
  return 1;

err:
  if (premaster_secret != NULL) {
    OPENSSL_cleanse(premaster_secret, premaster_secret_len);
    OPENSSL_free(premaster_secret);
  }
  OPENSSL_free(decrypt_buf);

  return -1;
}

static int ssl3_get_cert_verify(SSL_HANDSHAKE *hs) {
  SSL *const ssl = hs->ssl;
  CBS certificate_verify, signature;

  /* Only RSA and ECDSA client certificates are supported, so a
   * CertificateVerify is required if and only if there's a client certificate.
   * */
  if (hs->peer_pubkey == NULL) {
    SSL_TRANSCRIPT_free_buffer(&hs->transcript);
    return 1;
  }

  int msg_ret = ssl->method->ssl_get_message(ssl);
  if (msg_ret <= 0) {
    return msg_ret;
  }

  if (!ssl_check_message_type(ssl, SSL3_MT_CERTIFICATE_VERIFY)) {
    return -1;
  }

  CBS_init(&certificate_verify, ssl->init_msg, ssl->init_num);

  /* Determine the digest type if needbe. */
  uint16_t signature_algorithm = 0;
  if (ssl3_protocol_version(ssl) >= TLS1_2_VERSION) {
    if (!CBS_get_u16(&certificate_verify, &signature_algorithm)) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
      return -1;
    }
    uint8_t alert = SSL_AD_DECODE_ERROR;
    if (!tls12_check_peer_sigalg(ssl, &alert, signature_algorithm)) {
      ssl3_send_alert(ssl, SSL3_AL_FATAL, alert);
      return -1;
    }
    hs->new_session->peer_signature_algorithm = signature_algorithm;
  } else if (!tls1_get_legacy_signature_algorithm(&signature_algorithm,
                                                  hs->peer_pubkey)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_PEER_ERROR_UNSUPPORTED_CERTIFICATE_TYPE);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_UNSUPPORTED_CERTIFICATE);
    return -1;
  }

  /* Parse and verify the signature. */
  if (!CBS_get_u16_length_prefixed(&certificate_verify, &signature) ||
      CBS_len(&certificate_verify) != 0) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
    return -1;
  }

  int sig_ok;
  /* The SSL3 construction for CertificateVerify does not decompose into a
   * single final digest and signature, and must be special-cased. */
  if (ssl3_protocol_version(ssl) == SSL3_VERSION) {
    uint8_t digest[EVP_MAX_MD_SIZE];
    size_t digest_len;
    if (!SSL_TRANSCRIPT_ssl3_cert_verify_hash(&hs->transcript, digest,
                                              &digest_len, hs->new_session,
                                              signature_algorithm)) {
      return -1;
    }

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(hs->peer_pubkey, NULL);
    sig_ok = pctx != NULL &&
             EVP_PKEY_verify_init(pctx) &&
             EVP_PKEY_verify(pctx, CBS_data(&signature), CBS_len(&signature),
                             digest, digest_len);
    EVP_PKEY_CTX_free(pctx);
  } else {
    sig_ok = ssl_public_key_verify(
        ssl, CBS_data(&signature), CBS_len(&signature), signature_algorithm,
        hs->peer_pubkey, (const uint8_t *)hs->transcript.buffer->data,
        hs->transcript.buffer->length);
  }

#if defined(BORINGSSL_UNSAFE_FUZZER_MODE)
  sig_ok = 1;
  ERR_clear_error();
#endif
  if (!sig_ok) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_BAD_SIGNATURE);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECRYPT_ERROR);
    return -1;
  }

  /* The handshake buffer is no longer necessary, and we may hash the current
   * message.*/
  SSL_TRANSCRIPT_free_buffer(&hs->transcript);
  if (!ssl_hash_current_message(hs)) {
    return -1;
  }

  return 1;
}

/* ssl3_get_next_proto reads a Next Protocol Negotiation handshake message. It
 * sets the next_proto member in s if found */
static int ssl3_get_next_proto(SSL_HANDSHAKE *hs) {
  SSL *const ssl = hs->ssl;
  int ret = ssl->method->ssl_get_message(ssl);
  if (ret <= 0) {
    return ret;
  }

  if (!ssl_check_message_type(ssl, SSL3_MT_NEXT_PROTO) ||
      !ssl_hash_current_message(hs)) {
    return -1;
  }

  CBS next_protocol, selected_protocol, padding;
  CBS_init(&next_protocol, ssl->init_msg, ssl->init_num);
  if (!CBS_get_u8_length_prefixed(&next_protocol, &selected_protocol) ||
      !CBS_get_u8_length_prefixed(&next_protocol, &padding) ||
      CBS_len(&next_protocol) != 0) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
    return 0;
  }

  if (!CBS_stow(&selected_protocol, &ssl->s3->next_proto_negotiated,
                &ssl->s3->next_proto_negotiated_len)) {
    return 0;
  }

  return 1;
}

/* ssl3_get_channel_id reads and verifies a ClientID handshake message. */
static int ssl3_get_channel_id(SSL_HANDSHAKE *hs) {
  SSL *const ssl = hs->ssl;
  int msg_ret = ssl->method->ssl_get_message(ssl);
  if (msg_ret <= 0) {
    return msg_ret;
  }

  if (!ssl_check_message_type(ssl, SSL3_MT_CHANNEL_ID) ||
      !tls1_verify_channel_id(hs) ||
      !ssl_hash_current_message(hs)) {
    return -1;
  }
  return 1;
}

static int ssl3_send_server_finished(SSL_HANDSHAKE *hs) {
  SSL *const ssl = hs->ssl;

  if (hs->ticket_expected) {
    const SSL_SESSION *session;
    SSL_SESSION *session_copy = NULL;
    if (ssl->session == NULL) {
      /* Fix the timeout to measure from the ticket issuance time. */
      ssl_session_rebase_time(ssl, hs->new_session);
      session = hs->new_session;
    } else {
      /* We are renewing an existing session. Duplicate the session to adjust
       * the timeout. */
      session_copy = SSL_SESSION_dup(ssl->session, SSL_SESSION_INCLUDE_NONAUTH);
      if (session_copy == NULL) {
        return -1;
      }

      ssl_session_rebase_time(ssl, session_copy);
      session = session_copy;
    }

    CBB cbb, body, ticket;
    int ok = ssl->method->init_message(ssl, &cbb, &body,
                                       SSL3_MT_NEW_SESSION_TICKET) &&
             CBB_add_u32(&body, session->timeout) &&
             CBB_add_u16_length_prefixed(&body, &ticket) &&
             ssl_encrypt_ticket(ssl, &ticket, session) &&
             ssl_add_message_cbb(ssl, &cbb);
    SSL_SESSION_free(session_copy);
    CBB_cleanup(&cbb);
    if (!ok) {
      return -1;
    }
  }

  if (!ssl->method->add_change_cipher_spec(ssl) ||
      !tls1_change_cipher_state(hs, SSL3_CHANGE_CIPHER_SERVER_WRITE)) {
    return -1;
  }

  return ssl3_send_finished(hs);
}
