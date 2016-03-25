/*
 * DTLS implementation written by Nagendra Modadugu
 * (nagendra@cs.stanford.edu) for the OpenSSL project 2005. 
 */
/* ====================================================================
 * Copyright (c) 1999-2007 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
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

#include <openssl/ssl.h>

#include <assert.h>

#include <openssl/bn.h>
#include <openssl/buf.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include "internal.h"


int dtls1_accept(SSL *ssl) {
  BUF_MEM *buf = NULL;
  void (*cb)(const SSL *ssl, int type, int value) = NULL;
  uint32_t alg_a;
  int ret = -1;
  int new_state, state, skip = 0;

  assert(ssl->handshake_func == dtls1_accept);
  assert(ssl->server);
  assert(SSL_IS_DTLS(ssl));

  ERR_clear_system_error();

  if (ssl->info_callback != NULL) {
    cb = ssl->info_callback;
  } else if (ssl->ctx->info_callback != NULL) {
    cb = ssl->ctx->info_callback;
  }

  for (;;) {
    state = ssl->state;

    switch (ssl->state) {
      case SSL_ST_ACCEPT:
        if (cb != NULL) {
          cb(ssl, SSL_CB_HANDSHAKE_START, 1);
        }

        if (ssl->init_buf == NULL) {
          buf = BUF_MEM_new();
          if (buf == NULL || !BUF_MEM_grow(buf, SSL3_RT_MAX_PLAIN_LENGTH)) {
            ret = -1;
            goto end;
          }
          ssl->init_buf = buf;
          buf = NULL;
        }

        ssl->init_num = 0;

        if (!ssl_init_wbio_buffer(ssl, 1)) {
          ret = -1;
          goto end;
        }

        if (!ssl3_init_handshake_buffer(ssl)) {
          OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
          ret = -1;
          goto end;
        }

        ssl->state = SSL3_ST_SR_CLNT_HELLO_A;
        break;

      case SSL3_ST_SR_CLNT_HELLO_A:
      case SSL3_ST_SR_CLNT_HELLO_B:
      case SSL3_ST_SR_CLNT_HELLO_C:
      case SSL3_ST_SR_CLNT_HELLO_D:
        ssl->shutdown = 0;
        ret = ssl3_get_client_hello(ssl);
        if (ret <= 0) {
          goto end;
        }
        dtls1_stop_timer(ssl);
        ssl->state = SSL3_ST_SW_SRVR_HELLO_A;
        ssl->init_num = 0;
        break;

      case SSL3_ST_SW_SRVR_HELLO_A:
      case SSL3_ST_SW_SRVR_HELLO_B:
        dtls1_start_timer(ssl);
        ret = ssl3_send_server_hello(ssl);
        if (ret <= 0) {
          goto end;
        }

        if (ssl->hit) {
          if (ssl->tlsext_ticket_expected) {
            ssl->state = SSL3_ST_SW_SESSION_TICKET_A;
          } else {
            ssl->state = SSL3_ST_SW_CHANGE_A;
          }
        } else {
          ssl->state = SSL3_ST_SW_CERT_A;
        }
        ssl->init_num = 0;
        break;

      case SSL3_ST_SW_CERT_A:
      case SSL3_ST_SW_CERT_B:
        if (ssl_cipher_has_server_public_key(ssl->s3->tmp.new_cipher)) {
          dtls1_start_timer(ssl);
          ret = ssl3_send_server_certificate(ssl);
          if (ret <= 0) {
            goto end;
          }
          if (ssl->s3->tmp.certificate_status_expected) {
            ssl->state = SSL3_ST_SW_CERT_STATUS_A;
          } else {
            ssl->state = SSL3_ST_SW_KEY_EXCH_A;
          }
        } else {
          skip = 1;
          ssl->state = SSL3_ST_SW_KEY_EXCH_A;
        }
        ssl->init_num = 0;
        break;

      case SSL3_ST_SW_CERT_STATUS_A:
      case SSL3_ST_SW_CERT_STATUS_B:
        ret = ssl3_send_certificate_status(ssl);
        if (ret <= 0) {
          goto end;
        }
        ssl->state = SSL3_ST_SW_KEY_EXCH_A;
        ssl->init_num = 0;
        break;

      case SSL3_ST_SW_KEY_EXCH_A:
      case SSL3_ST_SW_KEY_EXCH_B:
      case SSL3_ST_SW_KEY_EXCH_C:
        alg_a = ssl->s3->tmp.new_cipher->algorithm_auth;

        /* Send a ServerKeyExchange message if:
         * - The key exchange is ephemeral or anonymous
         *   Diffie-Hellman.
         * - There is a PSK identity hint.
         *
         * TODO(davidben): This logic is currently duplicated
         * in s3_srvr.c. Fix this. In the meantime, keep them
         * in sync. */
        if (ssl_cipher_requires_server_key_exchange(ssl->s3->tmp.new_cipher) ||
            ((alg_a & SSL_aPSK) && ssl->psk_identity_hint)) {
          dtls1_start_timer(ssl);
          ret = ssl3_send_server_key_exchange(ssl);
          if (ret <= 0) {
            goto end;
          }
        } else {
          skip = 1;
        }

        ssl->state = SSL3_ST_SW_CERT_REQ_A;
        ssl->init_num = 0;
        break;

      case SSL3_ST_SW_CERT_REQ_A:
      case SSL3_ST_SW_CERT_REQ_B:
        if (ssl->s3->tmp.cert_request) {
          dtls1_start_timer(ssl);
          ret = ssl3_send_certificate_request(ssl);
          if (ret <= 0) {
            goto end;
          }
        } else {
          skip = 1;
        }
        ssl->state = SSL3_ST_SW_SRVR_DONE_A;
        ssl->init_num = 0;
        break;

      case SSL3_ST_SW_SRVR_DONE_A:
      case SSL3_ST_SW_SRVR_DONE_B:
        dtls1_start_timer(ssl);
        ret = ssl3_send_server_done(ssl);
        if (ret <= 0) {
          goto end;
        }
        ssl->s3->tmp.next_state = SSL3_ST_SR_CERT_A;
        ssl->state = SSL3_ST_SW_FLUSH;
        ssl->init_num = 0;
        break;

      case SSL3_ST_SW_FLUSH:
        ssl->rwstate = SSL_WRITING;
        if (BIO_flush(ssl->wbio) <= 0) {
          ret = -1;
          goto end;
        }
        ssl->rwstate = SSL_NOTHING;
        ssl->state = ssl->s3->tmp.next_state;
        break;

      case SSL3_ST_SR_CERT_A:
      case SSL3_ST_SR_CERT_B:
        if (ssl->s3->tmp.cert_request) {
          ret = ssl3_get_client_certificate(ssl);
          if (ret <= 0) {
            goto end;
          }
        }
        ssl->init_num = 0;
        ssl->state = SSL3_ST_SR_KEY_EXCH_A;
        break;

      case SSL3_ST_SR_KEY_EXCH_A:
      case SSL3_ST_SR_KEY_EXCH_B:
      case SSL3_ST_SR_KEY_EXCH_C:
        ret = ssl3_get_client_key_exchange(ssl);
        if (ret <= 0) {
          goto end;
        }
        ssl->state = SSL3_ST_SR_CERT_VRFY_A;
        ssl->init_num = 0;
        break;

      case SSL3_ST_SR_CERT_VRFY_A:
      case SSL3_ST_SR_CERT_VRFY_B:
        ret = ssl3_get_cert_verify(ssl);
        if (ret <= 0) {
          goto end;
        }
        ssl->state = SSL3_ST_SR_CHANGE;
        ssl->init_num = 0;
        break;

      case SSL3_ST_SR_CHANGE:
        ret = ssl->method->ssl_read_change_cipher_spec(ssl);
        if (ret <= 0) {
          goto end;
        }

        if (!tls1_change_cipher_state(ssl, SSL3_CHANGE_CIPHER_SERVER_READ)) {
          ret = -1;
          goto end;
        }

        ssl->state = SSL3_ST_SR_FINISHED_A;
        break;

      case SSL3_ST_SR_FINISHED_A:
      case SSL3_ST_SR_FINISHED_B:
        ret = ssl3_get_finished(ssl, SSL3_ST_SR_FINISHED_A,
                                SSL3_ST_SR_FINISHED_B);
        if (ret <= 0) {
          goto end;
        }
        dtls1_stop_timer(ssl);
        if (ssl->hit) {
          ssl->state = SSL_ST_OK;
        } else if (ssl->tlsext_ticket_expected) {
          ssl->state = SSL3_ST_SW_SESSION_TICKET_A;
        } else {
          ssl->state = SSL3_ST_SW_CHANGE_A;
        }
        ssl->init_num = 0;
        break;

      case SSL3_ST_SW_SESSION_TICKET_A:
      case SSL3_ST_SW_SESSION_TICKET_B:
        ret = ssl3_send_new_session_ticket(ssl);
        if (ret <= 0) {
          goto end;
        }
        ssl->state = SSL3_ST_SW_CHANGE_A;
        ssl->init_num = 0;
        break;

      case SSL3_ST_SW_CHANGE_A:
      case SSL3_ST_SW_CHANGE_B:
        ret = dtls1_send_change_cipher_spec(ssl, SSL3_ST_SW_CHANGE_A,
                                            SSL3_ST_SW_CHANGE_B);

        if (ret <= 0) {
          goto end;
        }

        ssl->state = SSL3_ST_SW_FINISHED_A;
        ssl->init_num = 0;

        if (!tls1_change_cipher_state(ssl, SSL3_CHANGE_CIPHER_SERVER_WRITE)) {
          ret = -1;
          goto end;
        }
        break;

      case SSL3_ST_SW_FINISHED_A:
      case SSL3_ST_SW_FINISHED_B:
        ret = ssl3_send_finished(ssl, SSL3_ST_SW_FINISHED_A,
                                 SSL3_ST_SW_FINISHED_B);
        if (ret <= 0) {
          goto end;
        }
        ssl->state = SSL3_ST_SW_FLUSH;
        if (ssl->hit) {
          ssl->s3->tmp.next_state = SSL3_ST_SR_CHANGE;
        } else {
          ssl->s3->tmp.next_state = SSL_ST_OK;
        }
        ssl->init_num = 0;
        break;

      case SSL_ST_OK:
        ssl3_cleanup_key_block(ssl);

        /* remove buffering on output */
        ssl_free_wbio_buffer(ssl);

        ssl->init_num = 0;
        ssl->s3->initial_handshake_complete = 1;

        ssl_update_cache(ssl, SSL_SESS_CACHE_SERVER);

        if (cb != NULL) {
          cb(ssl, SSL_CB_HANDSHAKE_DONE, 1);
        }

        ret = 1;

        /* done handshaking, next message is client hello */
        ssl->d1->handshake_read_seq = 0;
        /* next message is server hello */
        ssl->d1->handshake_write_seq = 0;
        ssl->d1->next_handshake_write_seq = 0;
        goto end;

      default:
        OPENSSL_PUT_ERROR(SSL, SSL_R_UNKNOWN_STATE);
        ret = -1;
        goto end;
    }

    if (!ssl->s3->tmp.reuse_message && !skip) {
      if (cb != NULL && ssl->state != state) {
        new_state = ssl->state;
        ssl->state = state;
        cb(ssl, SSL_CB_ACCEPT_LOOP, 1);
        ssl->state = new_state;
      }
    }
    skip = 0;
  }

end:
  BUF_MEM_free(buf);
  if (cb != NULL) {
    cb(ssl, SSL_CB_ACCEPT_EXIT, ret);
  }
  return ret;
}
