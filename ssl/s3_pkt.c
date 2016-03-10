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
 * Copyright (c) 1998-2002 The OpenSSL Project.  All rights reserved.
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
 * Hudson (tjh@cryptsoft.com). */

#include <openssl/ssl.h>

#include <assert.h>
#include <limits.h>
#include <string.h>

#include <openssl/buf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/rand.h>

#include "internal.h"


static int do_ssl3_write(SSL *ssl, int type, const uint8_t *buf, unsigned len);

/* kMaxWarningAlerts is the number of consecutive warning alerts that will be
 * processed. */
static const uint8_t kMaxWarningAlerts = 4;

/* ssl3_get_record reads a new input record. On success, it places it in
 * |ssl->s3->rrec| and returns one. Otherwise it returns <= 0 on error or if
 * more data is needed. */
static int ssl3_get_record(SSL *ssl) {
  int ret;
again:
  /* Ensure the buffer is large enough to decrypt in-place. */
  ret = ssl_read_buffer_extend_to(ssl, ssl_record_prefix_len(ssl));
  if (ret <= 0) {
    return ret;
  }
  assert(ssl_read_buffer_len(ssl) >= ssl_record_prefix_len(ssl));

  uint8_t *out = ssl_read_buffer(ssl) + ssl_record_prefix_len(ssl);
  size_t max_out = ssl_read_buffer_len(ssl) - ssl_record_prefix_len(ssl);
  uint8_t type, alert;
  size_t len, consumed;
  switch (tls_open_record(ssl, &type, out, &len, &consumed, &alert, max_out,
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

    case ssl_open_record_partial:
      ret = ssl_read_buffer_extend_to(ssl, consumed);
      if (ret <= 0) {
        return ret;
      }
      goto again;

    case ssl_open_record_discard:
      ssl_read_buffer_consume(ssl, consumed);
      goto again;

    case ssl_open_record_error:
      ssl3_send_alert(ssl, SSL3_AL_FATAL, alert);
      return -1;
  }

  assert(0);
  OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
  return -1;
}

int ssl3_write_app_data(SSL *ssl, const void *buf, int len) {
  assert(!SSL_in_init(ssl) || SSL_in_false_start(ssl));

  return ssl3_write_bytes(ssl, SSL3_RT_APPLICATION_DATA, buf, len);
}

/* Call this to write data in records of type |type|. It will return <= 0 if
 * not all data has been sent or non-blocking IO. */
int ssl3_write_bytes(SSL *ssl, int type, const void *buf_, int len) {
  const uint8_t *buf = buf_;
  unsigned tot, n, nw;

  ssl->rwstate = SSL_NOTHING;
  assert(ssl->s3->wnum <= INT_MAX);
  tot = ssl->s3->wnum;
  ssl->s3->wnum = 0;

  /* Ensure that if we end up with a smaller value of data to write out than
   * the the original len from a write which didn't complete for non-blocking
   * I/O and also somehow ended up avoiding the check for this in
   * ssl3_write_pending/SSL_R_BAD_WRITE_RETRY as it must never be possible to
   * end up with (len-tot) as a large number that will then promptly send
   * beyond the end of the users buffer ... so we trap and report the error in
   * a way the user will notice. */
  if (len < 0 || (size_t)len < tot) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_BAD_LENGTH);
    return -1;
  }

  n = (len - tot);
  for (;;) {
    /* max contains the maximum number of bytes that we can put into a
     * record. */
    unsigned max = ssl->max_send_fragment;
    if (n > max) {
      nw = max;
    } else {
      nw = n;
    }

    int ret = do_ssl3_write(ssl, type, &buf[tot], nw);
    if (ret <= 0) {
      ssl->s3->wnum = tot;
      return ret;
    }

    if (ret == (int)n || (type == SSL3_RT_APPLICATION_DATA &&
                          (ssl->mode & SSL_MODE_ENABLE_PARTIAL_WRITE))) {
      return tot + ret;
    }

    n -= ret;
    tot += ret;
  }
}

static int ssl3_write_pending(SSL *ssl, int type, const uint8_t *buf,
                              unsigned int len) {
  if (ssl->s3->wpend_tot > (int)len ||
      (ssl->s3->wpend_buf != buf &&
       !(ssl->mode & SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER)) ||
      ssl->s3->wpend_type != type) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_BAD_WRITE_RETRY);
    return -1;
  }

  int ret = ssl_write_buffer_flush(ssl);
  if (ret <= 0) {
    return ret;
  }
  return ssl->s3->wpend_ret;
}

/* do_ssl3_write writes an SSL record of the given type. */
static int do_ssl3_write(SSL *ssl, int type, const uint8_t *buf, unsigned len) {
  /* If there is still data from the previous record, flush it. */
  if (ssl_write_buffer_is_pending(ssl)) {
    return ssl3_write_pending(ssl, type, buf, len);
  }

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
  if (max_out < len) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_OVERFLOW);
    return -1;
  }
  uint8_t *out;
  size_t ciphertext_len;
  if (!ssl_write_buffer_init(ssl, &out, max_out) ||
      !tls_seal_record(ssl, out, &ciphertext_len, max_out, type, buf, len)) {
    return -1;
  }
  ssl_write_buffer_set_len(ssl, ciphertext_len);

  /* memorize arguments so that ssl3_write_pending can detect bad write retries
   * later */
  ssl->s3->wpend_tot = len;
  ssl->s3->wpend_buf = buf;
  ssl->s3->wpend_type = type;
  ssl->s3->wpend_ret = len;

  /* we now just need to write the buffer */
  return ssl3_write_pending(ssl, type, buf, len);
}

int ssl3_read_app_data(SSL *ssl, uint8_t *buf, int len, int peek) {
  assert(!SSL_in_init(ssl));
  return ssl3_read_bytes(ssl, SSL3_RT_APPLICATION_DATA, buf, len, peek);
}

int ssl3_read_change_cipher_spec(SSL *ssl) {
  uint8_t byte;
  int ret = ssl3_read_bytes(ssl, SSL3_RT_CHANGE_CIPHER_SPEC, &byte, 1 /* len */,
                            0 /* no peek */);
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

void ssl3_read_close_notify(SSL *ssl) {
  ssl3_read_bytes(ssl, 0, NULL, 0, 0);
}

static int ssl3_can_renegotiate(SSL *ssl) {
  switch (ssl->renegotiate_mode) {
    case ssl_renegotiate_never:
      return 0;
    case ssl_renegotiate_once:
      return ssl->s3->total_renegotiations == 0;
    case ssl_renegotiate_freely:
      return 1;
    case ssl_renegotiate_ignore:
      return 1;
  }

  assert(0);
  return 0;
}

/* Return up to 'len' payload bytes received in 'type' records.
 * 'type' is one of the following:
 *
 *   -  SSL3_RT_HANDSHAKE (when ssl3_get_message calls us)
 *   -  SSL3_RT_CHANGE_CIPHER_SPEC (when ssl3_read_change_cipher_spec calls us)
 *   -  SSL3_RT_APPLICATION_DATA (when ssl3_read_app_data calls us)
 *   -  0 (during a shutdown, no data has to be returned)
 *
 * If we don't have stored data to work from, read a SSL/TLS record first
 * (possibly multiple records if we still don't have anything to return).
 *
 * This function must handle any surprises the peer may have for us, such as
 * Alert records (e.g. close_notify) or renegotiation requests. */
int ssl3_read_bytes(SSL *ssl, int type, uint8_t *buf, int len, int peek) {
  int al, i, ret;
  unsigned int n;
  SSL3_RECORD *rr;
  void (*cb)(const SSL *ssl, int type, int value) = NULL;

  if ((type && type != SSL3_RT_APPLICATION_DATA && type != SSL3_RT_HANDSHAKE &&
       type != SSL3_RT_CHANGE_CIPHER_SPEC) ||
      (peek && type != SSL3_RT_APPLICATION_DATA)) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
    return -1;
  }

start:
  ssl->rwstate = SSL_NOTHING;

  /* ssl->s3->rrec.type    - is the type of record
   * ssl->s3->rrec.data    - data
   * ssl->s3->rrec.off     - offset into 'data' for next read
   * ssl->s3->rrec.length  - number of bytes. */
  rr = &ssl->s3->rrec;

  /* get new packet if necessary */
  if (rr->length == 0) {
    ret = ssl3_get_record(ssl);
    if (ret <= 0) {
      return ret;
    }
  }

  /* we now have a packet which can be read and processed */

  /* If the other end has shut down, throw anything we read away (even in
   * 'peek' mode) */
  if (ssl->shutdown & SSL_RECEIVED_SHUTDOWN) {
    rr->length = 0;
    ssl->rwstate = SSL_NOTHING;
    return 0;
  }

  if (type != 0 && type == rr->type) {
    ssl->s3->warning_alert_count = 0;

    /* Make sure that we are not getting application data when we are doing a
     * handshake for the first time. */
    if (SSL_in_init(ssl) && type == SSL3_RT_APPLICATION_DATA &&
        ssl->s3->aead_read_ctx == NULL) {
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

  /* Process unexpected records. */

  if (type == SSL3_RT_APPLICATION_DATA && rr->type == SSL3_RT_HANDSHAKE) {
    /* If peer renegotiations are disabled, all out-of-order handshake records
     * are fatal. Renegotiations as a server are never supported. */
    if (ssl->server || !ssl3_can_renegotiate(ssl)) {
      al = SSL_AD_NO_RENEGOTIATION;
      OPENSSL_PUT_ERROR(SSL, SSL_R_NO_RENEGOTIATION);
      goto f_err;
    }

    /* This must be a HelloRequest, possibly fragmented over multiple records.
     * Consume data from the handshake protocol until it is complete. */
    static const uint8_t kHelloRequest[] = {SSL3_MT_HELLO_REQUEST, 0, 0, 0};
    while (ssl->s3->hello_request_len < sizeof(kHelloRequest)) {
      if (rr->length == 0) {
        /* Get a new record. */
        goto start;
      }
      if (rr->data[0] != kHelloRequest[ssl->s3->hello_request_len]) {
        al = SSL_AD_DECODE_ERROR;
        OPENSSL_PUT_ERROR(SSL, SSL_R_BAD_HELLO_REQUEST);
        goto f_err;
      }
      rr->data++;
      rr->length--;
      ssl->s3->hello_request_len++;
    }
    ssl->s3->hello_request_len = 0;

    if (ssl->msg_callback) {
      ssl->msg_callback(0, ssl->version, SSL3_RT_HANDSHAKE, kHelloRequest,
                      sizeof(kHelloRequest), ssl, ssl->msg_callback_arg);
    }

    if (!SSL_is_init_finished(ssl) || !ssl->s3->initial_handshake_complete) {
      /* This cannot happen. If a handshake is in progress, |type| must be
       * |SSL3_RT_HANDSHAKE|. */
      assert(0);
      OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
      goto err;
    }

    if (ssl->renegotiate_mode == ssl_renegotiate_ignore) {
      goto start;
    }

    /* Renegotiation is only supported at quiescent points in the application
     * protocol, namely in HTTPS, just before reading the HTTP response. Require
     * the record-layer be idle and avoid complexities of sending a handshake
     * record while an application_data record is being written. */
    if (ssl_write_buffer_is_pending(ssl)) {
      al = SSL_AD_NO_RENEGOTIATION;
      OPENSSL_PUT_ERROR(SSL, SSL_R_NO_RENEGOTIATION);
      goto f_err;
    }

    /* Begin a new handshake. */
    ssl->s3->total_renegotiations++;
    ssl->state = SSL_ST_CONNECT;
    i = ssl->handshake_func(ssl);
    if (i < 0) {
      return i;
    }
    if (i == 0) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_SSL_HANDSHAKE_FAILURE);
      return -1;
    }

    /* The handshake completed synchronously. Continue reading records. */
    goto start;
  }

  /* If an alert record, process one alert out of the record. Note that we allow
   * a single record to contain multiple alerts. */
  if (rr->type == SSL3_RT_ALERT) {
    /* Alerts may not be fragmented. */
    if (rr->length < 2) {
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

      /* This is a warning but we receive it if we requested renegotiation and
       * the peer denied it. Terminate with a fatal alert because if
       * application tried to renegotiatie it presumably had a good reason and
       * expects it to succeed.
       *
       * In future we might have a renegotiation where we don't care if the
       * peer refused it where we carry on. */
      else if (alert_descr == SSL_AD_NO_RENEGOTIATION) {
        al = SSL_AD_HANDSHAKE_FAILURE;
        OPENSSL_PUT_ERROR(SSL, SSL_R_NO_RENEGOTIATION);
        goto f_err;
      }

      ssl->s3->warning_alert_count++;
      if (ssl->s3->warning_alert_count > kMaxWarningAlerts) {
        al = SSL_AD_UNEXPECTED_MESSAGE;
        OPENSSL_PUT_ERROR(SSL, SSL_R_TOO_MANY_WARNING_ALERTS);
        goto f_err;
      }
    } else if (alert_level == SSL3_AL_FATAL) {
      char tmp[16];

      ssl->rwstate = SSL_NOTHING;
      OPENSSL_PUT_ERROR(SSL, SSL_AD_REASON_OFFSET + alert_descr);
      BIO_snprintf(tmp, sizeof(tmp), "%d", alert_descr);
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

  if (ssl->shutdown & SSL_SENT_SHUTDOWN) {
    /* close_notify has been sent, so discard all records other than alerts. */
    rr->length = 0;
    goto start;
  }

  al = SSL_AD_UNEXPECTED_MESSAGE;
  OPENSSL_PUT_ERROR(SSL, SSL_R_UNEXPECTED_RECORD);

f_err:
  ssl3_send_alert(ssl, SSL3_AL_FATAL, al);
err:
  return -1;
}

int ssl3_send_alert(SSL *ssl, int level, int desc) {
  /* If a fatal one, remove from cache */
  if (level == 2 && ssl->session != NULL) {
    SSL_CTX_remove_session(ssl->ctx, ssl->session);
  }

  ssl->s3->alert_dispatch = 1;
  ssl->s3->send_alert[0] = level;
  ssl->s3->send_alert[1] = desc;
  if (!ssl_write_buffer_is_pending(ssl)) {
    /* Nothing is being written out, so the alert may be dispatched
     * immediately. */
    return ssl->method->ssl_dispatch_alert(ssl);
  }

  /* else data is still being written out, we will get written some time in the
   * future */
  return -1;
}

int ssl3_dispatch_alert(SSL *ssl) {
  ssl->s3->alert_dispatch = 0;
  int ret = do_ssl3_write(ssl, SSL3_RT_ALERT, &ssl->s3->send_alert[0], 2);
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
