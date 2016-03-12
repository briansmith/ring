/* DTLS implementation written by Nagendra Modadugu
 * (nagendra@cs.stanford.edu) for the OpenSSL project 2005. */
/* ====================================================================
 * Copyright (c) 1998-2005 The OpenSSL Project.  All rights reserved.
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
 * [including the GNU Public Licence.] */

#include <openssl/ssl.h>

#include <assert.h>
#include <string.h>

#include <openssl/buf.h>
#include <openssl/mem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "internal.h"


static int do_dtls1_write(SSL *ssl, int type, const uint8_t *buf,
                          unsigned int len, enum dtls1_use_epoch_t use_epoch);

/* dtls1_get_record reads a new input record. On success, it places it in
 * |ssl->s3->rrec| and returns one. Otherwise it returns <= 0 on error or if
 * more data is needed. */
static int dtls1_get_record(SSL *ssl) {
again:
  /* Read a new packet if there is no unconsumed one. */
  if (ssl_read_buffer_len(ssl) == 0) {
    int ret = ssl_read_buffer_extend_to(ssl, 0 /* unused */);
    if (ret <= 0) {
      return ret;
    }
  }
  assert(ssl_read_buffer_len(ssl) > 0);

  /* Ensure the packet is large enough to decrypt in-place. */
  if (ssl_read_buffer_len(ssl) < ssl_record_prefix_len(ssl)) {
    ssl_read_buffer_clear(ssl);
    goto again;
  }

  uint8_t *out = ssl_read_buffer(ssl) + ssl_record_prefix_len(ssl);
  size_t max_out = ssl_read_buffer_len(ssl) - ssl_record_prefix_len(ssl);
  uint8_t type, alert;
  size_t len, consumed;
  switch (dtls_open_record(ssl, &type, out, &len, &consumed, &alert, max_out,
                           ssl_read_buffer(ssl), ssl_read_buffer_len(ssl))) {
    case ssl_open_record_success:
      ssl_read_buffer_consume(ssl, consumed);

      if (len > 0xffff) {
        OPENSSL_PUT_ERROR(SSL, ERR_R_OVERFLOW);
        return -1;
      }

      SSL3_RECORD *rr = &ssl->s3->rrec;
      rr->type = type;
      rr->length = (uint16_t)len;
      rr->data = out;
      return 1;

    case ssl_open_record_discard:
      ssl_read_buffer_consume(ssl, consumed);
      goto again;

    case ssl_open_record_error:
      ssl3_send_alert(ssl, SSL3_AL_FATAL, alert);
      return -1;

    case ssl_open_record_partial:
      /* Impossible in DTLS. */
      break;
  }

  assert(0);
  OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
  return -1;
}

int dtls1_read_app_data(SSL *ssl, uint8_t *buf, int len, int peek) {
  assert(!SSL_in_init(ssl));
  return dtls1_read_bytes(ssl, SSL3_RT_APPLICATION_DATA, buf, len, peek);
}

int dtls1_read_change_cipher_spec(SSL *ssl) {
  uint8_t byte;
  int ret = dtls1_read_bytes(ssl, SSL3_RT_CHANGE_CIPHER_SPEC, &byte,
                             1 /* len */, 0 /* no peek */);
  if (ret <= 0) {
    return ret;
  }
  assert(ret == 1);

  if (ssl->s3->rrec.length != 0 || byte != SSL3_MT_CCS) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_BAD_CHANGE_CIPHER_SPEC);
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_ILLEGAL_PARAMETER);
    return -1;
  }

  if (ssl->msg_callback != NULL) {
    ssl->msg_callback(0, ssl->version, SSL3_RT_CHANGE_CIPHER_SPEC, &byte, 1,
                      ssl, ssl->msg_callback_arg);
  }

  return 1;
}

void dtls1_read_close_notify(SSL *ssl) {
  /* Bidirectional shutdown doesn't make sense for an unordered transport. DTLS
   * alerts also aren't delivered reliably, so we may even time out because the
   * peer never received our close_notify. Report to the caller that the channel
   * has fully shut down. */
  ssl->shutdown |= SSL_RECEIVED_SHUTDOWN;
}

/* Return up to 'len' payload bytes received in 'type' records.
 * 'type' is one of the following:
 *
 *   -  SSL3_RT_HANDSHAKE (when dtls1_get_message calls us)
 *   -  SSL3_RT_CHANGE_CIPHER_SPEC (when dtls1_read_change_cipher_spec calls us)
 *   -  SSL3_RT_APPLICATION_DATA (when dtls1_read_app_data calls us)
 *
 * If we don't have stored data to work from, read a DTLS record first (possibly
 * multiple records if we still don't have anything to return).
 *
 * This function must handle any surprises the peer may have for us, such as
 * Alert records (e.g. close_notify) and out of records. */
int dtls1_read_bytes(SSL *ssl, int type, unsigned char *buf, int len, int peek) {
  int al, ret;
  unsigned int n;
  SSL3_RECORD *rr;
  void (*cb)(const SSL *ssl, int type, int value) = NULL;

  if ((type != SSL3_RT_APPLICATION_DATA && type != SSL3_RT_HANDSHAKE &&
       type != SSL3_RT_CHANGE_CIPHER_SPEC) ||
      (peek && type != SSL3_RT_APPLICATION_DATA)) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
    return -1;
  }

start:
  /* ssl->s3->rrec.type     - is the type of record
   * ssl->s3->rrec.data     - data
   * ssl->s3->rrec.off      - offset into 'data' for next read
   * ssl->s3->rrec.length   - number of bytes. */
  rr = &ssl->s3->rrec;

  /* Check for timeout */
  if (DTLSv1_handle_timeout(ssl) > 0) {
    goto start;
  }

  /* get new packet if necessary */
  if (rr->length == 0) {
    ret = dtls1_get_record(ssl);
    if (ret <= 0) {
      ret = dtls1_read_failed(ssl, ret);
      /* anything other than a timeout is an error */
      if (ret <= 0) {
        return ret;
      } else {
        goto start;
      }
    }
  }

  /* we now have a packet which can be read and processed */

  /* If the other end has shut down, throw anything we read away (even in
   * 'peek' mode) */
  if (ssl->shutdown & SSL_RECEIVED_SHUTDOWN) {
    rr->length = 0;
    return 0;
  }


  if (type == rr->type) {
    /* Make sure that we are not getting application data when we
     * are doing a handshake for the first time. */
    if (SSL_in_init(ssl) && (type == SSL3_RT_APPLICATION_DATA) &&
        (ssl->s3->aead_read_ctx == NULL)) {
      /* TODO(davidben): Is this check redundant with the handshake_func
       * check? */
      al = SSL_AD_UNEXPECTED_MESSAGE;
      OPENSSL_PUT_ERROR(SSL, SSL_R_APP_DATA_IN_HANDSHAKE);
      goto f_err;
    }

    /* Discard empty records. */
    if (rr->length == 0) {
      goto start;
    }

    if (len <= 0) {
      return len;
    }

    if ((unsigned int)len > rr->length) {
      n = rr->length;
    } else {
      n = (unsigned int)len;
    }

    memcpy(buf, rr->data, n);
    if (!peek) {
      rr->length -= n;
      rr->data += n;
      if (rr->length == 0) {
        /* The record has been consumed, so we may now clear the buffer. */
        ssl_read_buffer_discard(ssl);
      }
    }

    return n;
  }

  /* If we get here, then type != rr->type. */

  /* If an alert record, process the alert. */
  if (rr->type == SSL3_RT_ALERT) {
    /* Alerts records may not contain fragmented or multiple alerts. */
    if (rr->length != 2) {
      al = SSL_AD_DECODE_ERROR;
      OPENSSL_PUT_ERROR(SSL, SSL_R_BAD_ALERT);
      goto f_err;
    }

    if (ssl->msg_callback) {
      ssl->msg_callback(0, ssl->version, SSL3_RT_ALERT, rr->data, 2, ssl,
                      ssl->msg_callback_arg);
    }
    const uint8_t alert_level = rr->data[0];
    const uint8_t alert_descr = rr->data[1];
    rr->length -= 2;
    rr->data += 2;

    if (ssl->info_callback != NULL) {
      cb = ssl->info_callback;
    } else if (ssl->ctx->info_callback != NULL) {
      cb = ssl->ctx->info_callback;
    }

    if (cb != NULL) {
      uint16_t alert = (alert_level << 8) | alert_descr;
      cb(ssl, SSL_CB_READ_ALERT, alert);
    }

    if (alert_level == SSL3_AL_WARNING) {
      if (alert_descr == SSL_AD_CLOSE_NOTIFY) {
        ssl->s3->clean_shutdown = 1;
        ssl->shutdown |= SSL_RECEIVED_SHUTDOWN;
        return 0;
      }
    } else if (alert_level == SSL3_AL_FATAL) {
      char tmp[16];

      OPENSSL_PUT_ERROR(SSL, SSL_AD_REASON_OFFSET + alert_descr);
      BIO_snprintf(tmp, sizeof tmp, "%d", alert_descr);
      ERR_add_error_data(2, "SSL alert number ", tmp);
      ssl->shutdown |= SSL_RECEIVED_SHUTDOWN;
      SSL_CTX_remove_session(ssl->ctx, ssl->session);
      return 0;
    } else {
      al = SSL_AD_ILLEGAL_PARAMETER;
      OPENSSL_PUT_ERROR(SSL, SSL_R_UNKNOWN_ALERT_TYPE);
      goto f_err;
    }

    goto start;
  }

  /* Cross-epoch records are discarded, but we may receive out-of-order
   * application data between ChangeCipherSpec and Finished or a ChangeCipherSpec
   * before the appropriate point in the handshake. Those must be silently
   * discarded.
   *
   * However, only allow the out-of-order records in the correct epoch.
   * Application data must come in the encrypted epoch, and ChangeCipherSpec in
   * the unencrypted epoch (we never renegotiate). Other cases fall through and
   * fail with a fatal error. */
  if ((rr->type == SSL3_RT_APPLICATION_DATA &&
       ssl->s3->aead_read_ctx != NULL) ||
      (rr->type == SSL3_RT_CHANGE_CIPHER_SPEC &&
       ssl->s3->aead_read_ctx == NULL)) {
    rr->length = 0;
    goto start;
  }

  if (rr->type == SSL3_RT_HANDSHAKE) {
    if (type != SSL3_RT_APPLICATION_DATA) {
      /* Out-of-order handshake record while looking for ChangeCipherSpec. Drop
       * it silently. */
      assert(type == SSL3_RT_CHANGE_CIPHER_SPEC);
      rr->length = 0;
      goto start;
    }

    /* Parse the first fragment header to determine if this is a pre-CCS or
     * post-CCS handshake record. DTLS resets handshake message numbers on each
     * handshake, so renegotiations and retransmissions are ambiguous. */
    if (rr->length < DTLS1_HM_HEADER_LENGTH) {
      al = SSL_AD_DECODE_ERROR;
      OPENSSL_PUT_ERROR(SSL, SSL_R_BAD_HANDSHAKE_RECORD);
      goto f_err;
    }
    struct hm_header_st msg_hdr;
    dtls1_get_message_header(rr->data, &msg_hdr);

    if (msg_hdr.type == SSL3_MT_FINISHED) {
      if (msg_hdr.frag_off == 0) {
        /* Retransmit our last flight of messages. If the peer sends the second
         * Finished, they may not have received ours. Only do this for the
         * first fragment, in case the Finished was fragmented. */
        if (dtls1_check_timeout_num(ssl) < 0) {
          return -1;
        }

        dtls1_retransmit_buffered_messages(ssl);
      }

      rr->length = 0;
      goto start;
    }

    /* Otherwise, this is a pre-CCS handshake message from an unsupported
     * renegotiation attempt. Fall through to the error path. */
  }

  al = SSL_AD_UNEXPECTED_MESSAGE;
  OPENSSL_PUT_ERROR(SSL, SSL_R_UNEXPECTED_RECORD);

f_err:
  ssl3_send_alert(ssl, SSL3_AL_FATAL, al);
  return -1;
}

int dtls1_write_app_data(SSL *ssl, const void *buf_, int len) {
  assert(!SSL_in_init(ssl));

  if (len > SSL3_RT_MAX_PLAIN_LENGTH) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_DTLS_MESSAGE_TOO_BIG);
    return -1;
  }

  return dtls1_write_bytes(ssl, SSL3_RT_APPLICATION_DATA, buf_, len,
                           dtls1_use_current_epoch);
}

/* Call this to write data in records of type 'type' It will return <= 0 if not
 * all data has been sent or non-blocking IO. */
int dtls1_write_bytes(SSL *ssl, int type, const void *buf, int len,
                      enum dtls1_use_epoch_t use_epoch) {
  assert(len <= SSL3_RT_MAX_PLAIN_LENGTH);
  return do_dtls1_write(ssl, type, buf, len, use_epoch);
}

static int do_dtls1_write(SSL *ssl, int type, const uint8_t *buf,
                          unsigned int len, enum dtls1_use_epoch_t use_epoch) {
  /* There should never be a pending write buffer in DTLS. One can't write half
   * a datagram, so the write buffer is always dropped in
   * |ssl_write_buffer_flush|. */
  assert(!ssl_write_buffer_is_pending(ssl));

  /* If we have an alert to send, lets send it */
  if (ssl->s3->alert_dispatch) {
    int ret = ssl->method->ssl_dispatch_alert(ssl);
    if (ret <= 0) {
      return ret;
    }
    /* if it went, fall through and send more stuff */
  }

  if (len > SSL3_RT_MAX_PLAIN_LENGTH) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
    return -1;
  }

  if (len == 0) {
    return 0;
  }

  size_t max_out = len + ssl_max_seal_overhead(ssl);
  uint8_t *out;
  size_t ciphertext_len;
  if (!ssl_write_buffer_init(ssl, &out, max_out) ||
      !dtls_seal_record(ssl, out, &ciphertext_len, max_out, type, buf, len,
                        use_epoch)) {
    ssl_write_buffer_clear(ssl);
    return -1;
  }
  ssl_write_buffer_set_len(ssl, ciphertext_len);

  int ret = ssl_write_buffer_flush(ssl);
  if (ret <= 0) {
    return ret;
  }
  return (int)len;
}

int dtls1_dispatch_alert(SSL *ssl) {
  ssl->s3->alert_dispatch = 0;
  int ret = do_dtls1_write(ssl, SSL3_RT_ALERT, &ssl->s3->send_alert[0], 2,
                           dtls1_use_current_epoch);
  if (ret <= 0) {
    ssl->s3->alert_dispatch = 1;
    return ret;
  }

  /* If the alert is fatal, flush the BIO now. */
  if (ssl->s3->send_alert[0] == SSL3_AL_FATAL) {
    BIO_flush(ssl->wbio);
  }

  if (ssl->msg_callback != NULL) {
    ssl->msg_callback(1 /* write */, ssl->version, SSL3_RT_ALERT,
                      ssl->s3->send_alert, 2, ssl, ssl->msg_callback_arg);
  }

  void (*cb)(const SSL *ssl, int type, int value) = NULL;
  if (ssl->info_callback != NULL) {
    cb = ssl->info_callback;
  } else if (ssl->ctx->info_callback != NULL) {
    cb = ssl->ctx->info_callback;
  }

  if (cb != NULL) {
    int alert = (ssl->s3->send_alert[0] << 8) | ssl->s3->send_alert[1];
    cb(ssl, SSL_CB_WRITE_ALERT, alert);
  }

  return 1;
}
