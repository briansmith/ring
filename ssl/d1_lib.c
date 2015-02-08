/*
 * DTLS implementation written by Nagendra Modadugu
 * (nagendra@cs.stanford.edu) for the OpenSSL project 2005.
 */
/* ====================================================================
 * Copyright (c) 1999-2005 The OpenSSL Project.  All rights reserved.
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
 * Hudson (tjh@cryptsoft.com). */

#include <openssl/base.h>

#include <limits.h>
#include <stdio.h>

#if defined(OPENSSL_WINDOWS)
#include <sys/timeb.h>
#else
#include <sys/socket.h>
#include <sys/time.h>
#endif

#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/obj.h>

#include "ssl_locl.h"

/* DTLS1_MTU_TIMEOUTS is the maximum number of timeouts to expire
 * before starting to decrease the MTU. */
#define DTLS1_MTU_TIMEOUTS                     2

/* DTLS1_MAX_TIMEOUTS is the maximum number of timeouts to expire
 * before failing the DTLS handshake. */
#define DTLS1_MAX_TIMEOUTS                     12

static void get_current_time(SSL *ssl, OPENSSL_timeval *out_clock);
static OPENSSL_timeval *dtls1_get_timeout(SSL *s, OPENSSL_timeval *timeleft);

const SSL3_ENC_METHOD DTLSv1_enc_data = {
  tls1_enc,
  tls1_prf,
  tls1_setup_key_block,
  tls1_generate_master_secret,
  tls1_change_cipher_state,
  tls1_final_finish_mac,
  tls1_cert_verify_mac,
  TLS_MD_CLIENT_FINISH_CONST,TLS_MD_CLIENT_FINISH_CONST_SIZE,
  TLS_MD_SERVER_FINISH_CONST,TLS_MD_SERVER_FINISH_CONST_SIZE,
  tls1_alert_code,
  tls1_export_keying_material,
  SSL_ENC_FLAG_DTLS|SSL_ENC_FLAG_EXPLICIT_IV,
};

const SSL3_ENC_METHOD DTLSv1_2_enc_data = {
  tls1_enc,
  tls1_prf,
  tls1_setup_key_block,
  tls1_generate_master_secret,
  tls1_change_cipher_state,
  tls1_final_finish_mac,
  tls1_cert_verify_mac,
  TLS_MD_CLIENT_FINISH_CONST,TLS_MD_CLIENT_FINISH_CONST_SIZE,
  TLS_MD_SERVER_FINISH_CONST,TLS_MD_SERVER_FINISH_CONST_SIZE,
  tls1_alert_code,
  tls1_export_keying_material,
  SSL_ENC_FLAG_DTLS | SSL_ENC_FLAG_EXPLICIT_IV | SSL_ENC_FLAG_SIGALGS |
      SSL_ENC_FLAG_SHA256_PRF | SSL_ENC_FLAG_TLS1_2_CIPHERS,
};

int dtls1_new(SSL *s) {
  DTLS1_STATE *d1;

  if (!ssl3_new(s)) {
    return 0;
  }
  d1 = OPENSSL_malloc(sizeof *d1);
  if (d1 == NULL) {
    ssl3_free(s);
    return 0;
  }
  memset(d1, 0, sizeof *d1);

  d1->unprocessed_rcds.q = pqueue_new();
  d1->processed_rcds.q = pqueue_new();
  d1->buffered_messages = pqueue_new();
  d1->sent_messages = pqueue_new();
  d1->buffered_app_data.q = pqueue_new();

  if (!d1->unprocessed_rcds.q || !d1->processed_rcds.q ||
      !d1->buffered_messages || !d1->sent_messages ||
      !d1->buffered_app_data.q) {
    if (d1->unprocessed_rcds.q) {
      pqueue_free(d1->unprocessed_rcds.q);
    }
    if (d1->processed_rcds.q) {
      pqueue_free(d1->processed_rcds.q);
    }
    if (d1->buffered_messages) {
      pqueue_free(d1->buffered_messages);
    }
    if (d1->sent_messages) {
      pqueue_free(d1->sent_messages);
    }
    if (d1->buffered_app_data.q) {
      pqueue_free(d1->buffered_app_data.q);
    }
    OPENSSL_free(d1);
    ssl3_free(s);
    return 0;
  }

  s->d1 = d1;

  /* Set the version to the highest version for DTLS. This controls the initial
   * state of |s->enc_method| and what the API reports as the version prior to
   * negotiation.
   *
   * TODO(davidben): This is fragile and confusing. */
  s->version = DTLS1_2_VERSION;
  return 1;
}

static void dtls1_clear_queues(SSL *s) {
  pitem *item = NULL;
  hm_fragment *frag = NULL;
  DTLS1_RECORD_DATA *rdata;

  while ((item = pqueue_pop(s->d1->unprocessed_rcds.q)) != NULL) {
    rdata = (DTLS1_RECORD_DATA *)item->data;
    if (rdata->rbuf.buf) {
      OPENSSL_free(rdata->rbuf.buf);
    }
    OPENSSL_free(item->data);
    pitem_free(item);
  }

  while ((item = pqueue_pop(s->d1->processed_rcds.q)) != NULL) {
    rdata = (DTLS1_RECORD_DATA *)item->data;
    if (rdata->rbuf.buf) {
      OPENSSL_free(rdata->rbuf.buf);
    }
    OPENSSL_free(item->data);
    pitem_free(item);
  }

  while ((item = pqueue_pop(s->d1->buffered_messages)) != NULL) {
    frag = (hm_fragment *)item->data;
    dtls1_hm_fragment_free(frag);
    pitem_free(item);
  }

  while ((item = pqueue_pop(s->d1->sent_messages)) != NULL) {
    frag = (hm_fragment *)item->data;
    dtls1_hm_fragment_free(frag);
    pitem_free(item);
  }

  while ((item = pqueue_pop(s->d1->buffered_app_data.q)) != NULL) {
    rdata = (DTLS1_RECORD_DATA *)item->data;
    if (rdata->rbuf.buf) {
      OPENSSL_free(rdata->rbuf.buf);
    }
    OPENSSL_free(item->data);
    pitem_free(item);
  }
}

void dtls1_free(SSL *s) {
  ssl3_free(s);

  if (s == NULL || s->d1 == NULL) {
    return;
  }

  dtls1_clear_queues(s);

  pqueue_free(s->d1->unprocessed_rcds.q);
  pqueue_free(s->d1->processed_rcds.q);
  pqueue_free(s->d1->buffered_messages);
  pqueue_free(s->d1->sent_messages);
  pqueue_free(s->d1->buffered_app_data.q);

  OPENSSL_free(s->d1);
  s->d1 = NULL;
}

long dtls1_ctrl(SSL *s, int cmd, long larg, void *parg) {
  int ret = 0;

  switch (cmd) {
    case DTLS_CTRL_GET_TIMEOUT:
      if (dtls1_get_timeout(s, (OPENSSL_timeval *)parg) != NULL) {
        ret = 1;
      }
      break;

    case DTLS_CTRL_HANDLE_TIMEOUT:
      ret = dtls1_handle_timeout(s);
      break;

    default:
      ret = ssl3_ctrl(s, cmd, larg, parg);
      break;
  }

  return ret;
}

const SSL_CIPHER *dtls1_get_cipher(unsigned int u) {
  const SSL_CIPHER *ciph = ssl3_get_cipher(u);
  /* DTLS does not support stream ciphers. */
  if (ciph == NULL || ciph->algorithm_enc == SSL_RC4) {
    return NULL;
  }

  return ciph;
}

void dtls1_start_timer(SSL *s) {
  /* If timer is not set, initialize duration with 1 second */
  if (s->d1->next_timeout.tv_sec == 0 && s->d1->next_timeout.tv_usec == 0) {
    s->d1->timeout_duration = 1;
  }

  /* Set timeout to current time */
  get_current_time(s, &s->d1->next_timeout);

  /* Add duration to current time */
  s->d1->next_timeout.tv_sec += s->d1->timeout_duration;
  BIO_ctrl(SSL_get_rbio(s), BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT, 0,
           &s->d1->next_timeout);
}

static OPENSSL_timeval *dtls1_get_timeout(SSL *s, OPENSSL_timeval *timeleft) {
  OPENSSL_timeval timenow;

  /* If no timeout is set, just return NULL */
  if (s->d1->next_timeout.tv_sec == 0 && s->d1->next_timeout.tv_usec == 0) {
    return NULL;
  }

  /* Get current time */
  get_current_time(s, &timenow);

  /* If timer already expired, set remaining time to 0 */
  if (s->d1->next_timeout.tv_sec < timenow.tv_sec ||
      (s->d1->next_timeout.tv_sec == timenow.tv_sec &&
       s->d1->next_timeout.tv_usec <= timenow.tv_usec)) {
    memset(timeleft, 0, sizeof(OPENSSL_timeval));
    return timeleft;
  }

  /* Calculate time left until timer expires */
  memcpy(timeleft, &s->d1->next_timeout, sizeof(OPENSSL_timeval));
  timeleft->tv_sec -= timenow.tv_sec;
  timeleft->tv_usec -= timenow.tv_usec;
  if (timeleft->tv_usec < 0) {
    timeleft->tv_sec--;
    timeleft->tv_usec += 1000000;
  }

  /* If remaining time is less than 15 ms, set it to 0 to prevent issues
   * because of small devergences with socket timeouts. */
  if (timeleft->tv_sec == 0 && timeleft->tv_usec < 15000) {
    memset(timeleft, 0, sizeof(OPENSSL_timeval));
  }

  return timeleft;
}

int dtls1_is_timer_expired(SSL *s) {
  OPENSSL_timeval timeleft;

  /* Get time left until timeout, return false if no timer running */
  if (dtls1_get_timeout(s, &timeleft) == NULL) {
    return 0;
  }

  /* Return false if timer is not expired yet */
  if (timeleft.tv_sec > 0 || timeleft.tv_usec > 0) {
    return 0;
  }

  /* Timer expired, so return true */
  return 1;
}

void dtls1_double_timeout(SSL *s) {
  s->d1->timeout_duration *= 2;
  if (s->d1->timeout_duration > 60) {
    s->d1->timeout_duration = 60;
  }
  dtls1_start_timer(s);
}

void dtls1_stop_timer(SSL *s) {
  /* Reset everything */
  s->d1->num_timeouts = 0;
  memset(&s->d1->next_timeout, 0, sizeof(OPENSSL_timeval));
  s->d1->timeout_duration = 1;
  BIO_ctrl(SSL_get_rbio(s), BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT, 0,
           &s->d1->next_timeout);
  /* Clear retransmission buffer */
  dtls1_clear_record_buffer(s);
}

int dtls1_check_timeout_num(SSL *s) {
  s->d1->num_timeouts++;

  /* Reduce MTU after 2 unsuccessful retransmissions */
  if (s->d1->num_timeouts > DTLS1_MTU_TIMEOUTS &&
      !(SSL_get_options(s) & SSL_OP_NO_QUERY_MTU)) {
    long mtu = BIO_ctrl(SSL_get_wbio(s), BIO_CTRL_DGRAM_GET_FALLBACK_MTU, 0,
                        NULL);
    if (mtu >= 0 && mtu <= (1 << 30) && (unsigned)mtu >= dtls1_min_mtu()) {
      s->d1->mtu = (unsigned)mtu;
    }
  }

  if (s->d1->num_timeouts > DTLS1_MAX_TIMEOUTS) {
    /* fail the connection, enough alerts have been sent */
    OPENSSL_PUT_ERROR(SSL, dtls1_check_timeout_num, SSL_R_READ_TIMEOUT_EXPIRED);
    return -1;
  }

  return 0;
}

int dtls1_handle_timeout(SSL *s) {
  /* if no timer is expired, don't do anything */
  if (!dtls1_is_timer_expired(s)) {
    return 0;
  }

  dtls1_double_timeout(s);

  if (dtls1_check_timeout_num(s) < 0) {
    return -1;
  }

  dtls1_start_timer(s);
  return dtls1_retransmit_buffered_messages(s);
}

static void get_current_time(SSL *ssl, OPENSSL_timeval *out_clock) {
  if (ssl->ctx->current_time_cb != NULL) {
    ssl->ctx->current_time_cb(ssl, out_clock);
    return;
  }

#if defined(OPENSSL_WINDOWS)
  struct _timeb time;
  _ftime(&time);
  out_clock->tv_sec = time.time;
  out_clock->tv_usec = time.millitm * 1000;
#else
  gettimeofday(out_clock, NULL);
#endif
}

int dtls1_set_handshake_header(SSL *s, int htype, unsigned long len) {
  uint8_t *message = (uint8_t *)s->init_buf->data;
  const struct hm_header_st *msg_hdr = &s->d1->w_msg_hdr;
  uint8_t serialised_header[DTLS1_HM_HEADER_LENGTH];
  uint8_t *p = serialised_header;

  s->d1->handshake_write_seq = s->d1->next_handshake_write_seq;
  s->d1->next_handshake_write_seq++;

  dtls1_set_message_header(s, htype, len, s->d1->handshake_write_seq, 0, len);
  s->init_num = (int)len + DTLS1_HM_HEADER_LENGTH;
  s->init_off = 0;

  /* Buffer the message to handle re-xmits */
  dtls1_buffer_message(s, 0);

  /* Add the new message to the handshake hash. Serialize the message
   * header as if it were a single fragment. */
  *p++ = msg_hdr->type;
  l2n3(msg_hdr->msg_len, p);
  s2n(msg_hdr->seq, p);
  l2n3(0, p);
  l2n3(msg_hdr->msg_len, p);
  return ssl3_finish_mac(s, serialised_header, sizeof(serialised_header)) &&
         ssl3_finish_mac(s, message + DTLS1_HM_HEADER_LENGTH, len);
}

int dtls1_handshake_write(SSL *s) {
  return dtls1_do_write(s, SSL3_RT_HANDSHAKE);
}
