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

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <openssl/buf.h>
#include <openssl/mem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "internal.h"


/* mod 128 saturating subtract of two 64-bit values in big-endian order */
static int satsub64be(const uint8_t *v1, const uint8_t *v2) {
  int ret, sat, brw, i;

  if (sizeof(long) == 8) {
    do {
      const union {
        long one;
        char little;
      } is_endian = {1};
      long l;

      if (is_endian.little) {
        break;
      }
      /* not reached on little-endians */
      /* following test is redundant, because input is
       * always aligned, but I take no chances... */
      if (((size_t)v1 | (size_t)v2) & 0x7) {
        break;
      }

      l = *((long *)v1);
      l -= *((long *)v2);
      if (l > 128) {
        return 128;
      } else if (l < -128) {
        return -128;
      } else {
        return (int)l;
      }
    } while (0);
  }

  ret = (int)v1[7] - (int)v2[7];
  sat = 0;
  brw = ret >> 8; /* brw is either 0 or -1 */
  if (ret & 0x80) {
    for (i = 6; i >= 0; i--) {
      brw += (int)v1[i] - (int)v2[i];
      sat |= ~brw;
      brw >>= 8;
    }
  } else {
    for (i = 6; i >= 0; i--) {
      brw += (int)v1[i] - (int)v2[i];
      sat |= brw;
      brw >>= 8;
    }
  }
  brw <<= 8; /* brw is either 0 or -256 */

  if (sat & 0xff) {
    return brw | 0x80;
  } else {
    return brw + (ret & 0xFF);
  }
}

static int dtls1_record_replay_check(SSL *s, DTLS1_BITMAP *bitmap);
static void dtls1_record_bitmap_update(SSL *s, DTLS1_BITMAP *bitmap);
static int dtls1_process_record(SSL *s);
static int do_dtls1_write(SSL *s, int type, const uint8_t *buf,
                          unsigned int len, enum dtls1_use_epoch_t use_epoch);

static int dtls1_process_record(SSL *s) {
  int al;
  SSL3_RECORD *rr = &s->s3->rrec;

  /* check is not needed I believe */
  if (rr->length > SSL3_RT_MAX_ENCRYPTED_LENGTH) {
    al = SSL_AD_RECORD_OVERFLOW;
    OPENSSL_PUT_ERROR(SSL, dtls1_process_record,
                      SSL_R_ENCRYPTED_LENGTH_TOO_LONG);
    goto f_err;
  }

  /* |rr->data| points to |rr->length| bytes of ciphertext in |s->packet|. */
  rr->data = &s->packet[DTLS1_RT_HEADER_LENGTH];

  uint8_t seq[8];
  seq[0] = rr->epoch >> 8;
  seq[1] = rr->epoch & 0xff;
  memcpy(&seq[2], &rr->seq_num[2], 6);

  /* Decrypt the packet in-place. Note it is important that |SSL_AEAD_CTX_open|
   * not write beyond |rr->length|. There may be another record in the packet.
   *
   * TODO(davidben): This assumes |s->version| is the same as the record-layer
   * version which isn't always true, but it only differs with the NULL cipher
   * which ignores the parameter. */
  size_t plaintext_len;
  if (!SSL_AEAD_CTX_open(s->aead_read_ctx, rr->data, &plaintext_len, rr->length,
                         rr->type, s->version, seq, rr->data, rr->length)) {
    /* Bad packets are silently dropped in DTLS. Clear the error queue of any
     * errors decryption may have added. */
    ERR_clear_error();
    rr->length = 0;
    s->packet_length = 0;
    goto err;
  }

  if (plaintext_len > SSL3_RT_MAX_PLAIN_LENGTH) {
    al = SSL_AD_RECORD_OVERFLOW;
    OPENSSL_PUT_ERROR(SSL, dtls1_process_record, SSL_R_DATA_LENGTH_TOO_LONG);
    goto f_err;
  }
  assert(plaintext_len < (1u << 16));
  rr->length = plaintext_len;

  rr->off = 0;
  /* So at this point the following is true
   * ssl->s3->rrec.type 	is the type of record
   * ssl->s3->rrec.length	== number of bytes in record
   * ssl->s3->rrec.off	== offset to first valid byte
   * ssl->s3->rrec.data	== the first byte of the record body. */

  /* we have pulled in a full packet so zero things */
  s->packet_length = 0;
  return 1;

f_err:
  ssl3_send_alert(s, SSL3_AL_FATAL, al);

err:
  return 0;
}

/* Call this to get a new input record.
 * It will return <= 0 if more data is needed, normally due to an error
 * or non-blocking IO.
 * When it finishes, one packet has been decoded and can be found in
 * ssl->s3->rrec.type    - is the type of record
 * ssl->s3->rrec.data,   - data
 * ssl->s3->rrec.length, - number of bytes
 *
 * used only by dtls1_read_bytes */
int dtls1_get_record(SSL *s) {
  uint8_t ssl_major, ssl_minor;
  int n;
  SSL3_RECORD *rr;
  uint8_t *p = NULL;
  uint16_t version;

  rr = &(s->s3->rrec);

  /* get something from the wire */
again:
  /* check if we have the header */
  if ((s->rstate != SSL_ST_READ_BODY) ||
      (s->packet_length < DTLS1_RT_HEADER_LENGTH)) {
    n = ssl3_read_n(s, DTLS1_RT_HEADER_LENGTH, 0);
    /* read timeout is handled by dtls1_read_bytes */
    if (n <= 0) {
      return n; /* error or non-blocking */
    }

    /* this packet contained a partial record, dump it */
    if (s->packet_length != DTLS1_RT_HEADER_LENGTH) {
      s->packet_length = 0;
      goto again;
    }

    s->rstate = SSL_ST_READ_BODY;

    p = s->packet;

    if (s->msg_callback) {
      s->msg_callback(0, 0, SSL3_RT_HEADER, p, DTLS1_RT_HEADER_LENGTH, s,
                      s->msg_callback_arg);
    }

    /* Pull apart the header into the DTLS1_RECORD */
    rr->type = *(p++);
    ssl_major = *(p++);
    ssl_minor = *(p++);
    version = (((uint16_t)ssl_major) << 8) | ssl_minor;

    /* sequence number is 64 bits, with top 2 bytes = epoch */
    n2s(p, rr->epoch);

    memcpy(&(s->s3->read_sequence[2]), p, 6);
    p += 6;

    n2s(p, rr->length);

    /* Lets check version */
    if (s->s3->have_version) {
      if (version != s->version) {
        /* The record's version doesn't match, so silently drop it.
         *
         * TODO(davidben): This doesn't work. The DTLS record layer is not
         * packet-based, so the remainder of the packet isn't dropped and we
         * get a framing error. It's also unclear what it means to silently
         * drop a record in a packet containing two records. */
        rr->length = 0;
        s->packet_length = 0;
        goto again;
      }
    }

    if ((version & 0xff00) != (s->version & 0xff00)) {
      /* wrong version, silently discard record */
      rr->length = 0;
      s->packet_length = 0;
      goto again;
    }

    if (rr->length > SSL3_RT_MAX_ENCRYPTED_LENGTH) {
      /* record too long, silently discard it */
      rr->length = 0;
      s->packet_length = 0;
      goto again;
    }

    /* now s->rstate == SSL_ST_READ_BODY */
  }

  /* s->rstate == SSL_ST_READ_BODY, get and decode the data */

  if (rr->length > s->packet_length - DTLS1_RT_HEADER_LENGTH) {
    /* now s->packet_length == DTLS1_RT_HEADER_LENGTH */
    n = ssl3_read_n(s, rr->length, 1);
    /* This packet contained a partial record, dump it. */
    if (n != rr->length) {
      rr->length = 0;
      s->packet_length = 0;
      goto again;
    }

    /* now n == rr->length,
     * and s->packet_length == DTLS1_RT_HEADER_LENGTH + rr->length */
  }
  s->rstate = SSL_ST_READ_HEADER; /* set state for later operations */

  if (rr->epoch != s->d1->r_epoch) {
    /* This record is from the wrong epoch. If it is the next epoch, it could be
     * buffered. For simplicity, drop it and expect retransmit to handle it
     * later; DTLS is supposed to handle packet loss. */
    rr->length = 0;
    s->packet_length = 0;
    goto again;
  }

  /* Check whether this is a repeat, or aged record. */
  if (!dtls1_record_replay_check(s, &s->d1->bitmap)) {
    rr->length = 0;
    s->packet_length = 0; /* dump this record */
    goto again;           /* get another record */
  }

  /* just read a 0 length packet */
  if (rr->length == 0) {
    goto again;
  }

  if (!dtls1_process_record(s)) {
    rr->length = 0;
    s->packet_length = 0; /* dump this record */
    goto again;           /* get another record */
  }
  dtls1_record_bitmap_update(s, &s->d1->bitmap); /* Mark receipt of record. */

  return 1;
}

int dtls1_read_app_data(SSL *ssl, uint8_t *buf, int len, int peek) {
  return dtls1_read_bytes(ssl, SSL3_RT_APPLICATION_DATA, buf, len, peek);
}

void dtls1_read_close_notify(SSL *ssl) {
  dtls1_read_bytes(ssl, 0, NULL, 0, 0);
}

/* Return up to 'len' payload bytes received in 'type' records.
 * 'type' is one of the following:
 *
 *   -  SSL3_RT_HANDSHAKE (when ssl3_get_message calls us)
 *   -  SSL3_RT_APPLICATION_DATA (when ssl3_read calls us)
 *   -  0 (during a shutdown, no data has to be returned)
 *
 * If we don't have stored data to work from, read a SSL/TLS record first
 * (possibly multiple records if we still don't have anything to return).
 *
 * This function must handle any surprises the peer may have for us, such as
 * Alert records (e.g. close_notify), ChangeCipherSpec records (not really
 * a surprise, but handled as if it were), or renegotiation requests.
 * Also if record payloads contain fragments too small to process, we store
 * them until there is enough for the respective protocol (the record protocol
 * may use arbitrary fragmentation and even interleaving):
 *     Change cipher spec protocol
 *             just 1 byte needed, no need for keeping anything stored
 *     Alert protocol
 *             2 bytes needed (AlertLevel, AlertDescription)
 *     Handshake protocol
 *             4 bytes needed (HandshakeType, uint24 length) -- we just have
 *             to detect unexpected Client Hello and Hello Request messages
 *             here, anything else is handled by higher layers
 *     Application data protocol
 *             none of our business
 */
int dtls1_read_bytes(SSL *s, int type, unsigned char *buf, int len, int peek) {
  int al, i, ret;
  unsigned int n;
  SSL3_RECORD *rr;
  void (*cb)(const SSL *ssl, int type2, int val) = NULL;

  /* XXX: check what the second '&& type' is about */
  if ((type && (type != SSL3_RT_APPLICATION_DATA) &&
       (type != SSL3_RT_HANDSHAKE) && type) ||
      (peek && (type != SSL3_RT_APPLICATION_DATA))) {
    OPENSSL_PUT_ERROR(SSL, dtls1_read_bytes, ERR_R_INTERNAL_ERROR);
    return -1;
  }

  if (!s->in_handshake && SSL_in_init(s)) {
    /* type == SSL3_RT_APPLICATION_DATA */
    i = s->handshake_func(s);
    if (i < 0) {
      return i;
    }
    if (i == 0) {
      OPENSSL_PUT_ERROR(SSL, dtls1_read_bytes, SSL_R_SSL_HANDSHAKE_FAILURE);
      return -1;
    }
  }

start:
  s->rwstate = SSL_NOTHING;

  /* s->s3->rrec.type     - is the type of record
   * s->s3->rrec.data     - data
   * s->s3->rrec.off      - offset into 'data' for next read
   * s->s3->rrec.length   - number of bytes. */
  rr = &s->s3->rrec;

  /* Check for timeout */
  if (DTLSv1_handle_timeout(s) > 0) {
    goto start;
  }

  /* get new packet if necessary */
  if (rr->length == 0 || s->rstate == SSL_ST_READ_BODY) {
    ret = dtls1_get_record(s);
    if (ret <= 0) {
      ret = dtls1_read_failed(s, ret);
      /* anything other than a timeout is an error */
      if (ret <= 0) {
        return ret;
      } else {
        goto start;
      }
    }
  }

  /* we now have a packet which can be read and processed */

  /* |change_cipher_spec is set when we receive a ChangeCipherSpec and reset by
   * ssl3_get_finished. */
  if (s->s3->change_cipher_spec && rr->type != SSL3_RT_HANDSHAKE &&
      rr->type != SSL3_RT_ALERT) {
    /* We now have an unexpected record between CCS and Finished. Most likely
     * the packets were reordered on their way. DTLS is unreliable, so drop the
     * packet and expect the peer to retransmit. */
    rr->length = 0;
    goto start;
  }

  /* If the other end has shut down, throw anything we read away (even in
   * 'peek' mode) */
  if (s->shutdown & SSL_RECEIVED_SHUTDOWN) {
    rr->length = 0;
    s->rwstate = SSL_NOTHING;
    return 0;
  }


  if (type == rr->type) { /* SSL3_RT_APPLICATION_DATA or SSL3_RT_HANDSHAKE */
    /* make sure that we are not getting application data when we
     * are doing a handshake for the first time */
    if (SSL_in_init(s) && (type == SSL3_RT_APPLICATION_DATA) &&
        (s->aead_read_ctx == NULL)) {
      /* TODO(davidben): Is this check redundant with the handshake_func
       * check? */
      al = SSL_AD_UNEXPECTED_MESSAGE;
      OPENSSL_PUT_ERROR(SSL, dtls1_read_bytes, SSL_R_APP_DATA_IN_HANDSHAKE);
      goto f_err;
    }

    if (len <= 0) {
      return len;
    }

    if ((unsigned int)len > rr->length) {
      n = rr->length;
    } else {
      n = (unsigned int)len;
    }

    memcpy(buf, &(rr->data[rr->off]), n);
    if (!peek) {
      rr->length -= n;
      rr->off += n;
      if (rr->length == 0) {
        s->rstate = SSL_ST_READ_HEADER;
        rr->off = 0;
      }
    }

    return n;
  }

  /* If we get here, then type != rr->type. */

  /* If an alert record, process one alert out of the record. Note that we allow
   * a single record to contain multiple alerts. */
  if (rr->type == SSL3_RT_ALERT) {
    /* Alerts may not be fragmented. */
    if (rr->length < 2) {
      al = SSL_AD_DECODE_ERROR;
      OPENSSL_PUT_ERROR(SSL, dtls1_read_bytes, SSL_R_BAD_ALERT);
      goto f_err;
    }

    if (s->msg_callback) {
      s->msg_callback(0, s->version, SSL3_RT_ALERT, &rr->data[rr->off], 2, s,
                      s->msg_callback_arg);
    }
    const uint8_t alert_level = rr->data[rr->off++];
    const uint8_t alert_descr = rr->data[rr->off++];
    rr->length -= 2;

    if (s->info_callback != NULL) {
      cb = s->info_callback;
    } else if (s->ctx->info_callback != NULL) {
      cb = s->ctx->info_callback;
    }

    if (cb != NULL) {
      uint16_t alert = (alert_level << 8) | alert_descr;
      cb(s, SSL_CB_READ_ALERT, alert);
    }

    if (alert_level == SSL3_AL_WARNING) {
      s->s3->warn_alert = alert_descr;
      if (alert_descr == SSL_AD_CLOSE_NOTIFY) {
        s->shutdown |= SSL_RECEIVED_SHUTDOWN;
        return 0;
      }
    } else if (alert_level == SSL3_AL_FATAL) {
      char tmp[16];

      s->rwstate = SSL_NOTHING;
      s->s3->fatal_alert = alert_descr;
      OPENSSL_PUT_ERROR(SSL, dtls1_read_bytes,
                        SSL_AD_REASON_OFFSET + alert_descr);
      BIO_snprintf(tmp, sizeof tmp, "%d", alert_descr);
      ERR_add_error_data(2, "SSL alert number ", tmp);
      s->shutdown |= SSL_RECEIVED_SHUTDOWN;
      SSL_CTX_remove_session(s->ctx, s->session);
      return 0;
    } else {
      al = SSL_AD_ILLEGAL_PARAMETER;
      OPENSSL_PUT_ERROR(SSL, dtls1_read_bytes, SSL_R_UNKNOWN_ALERT_TYPE);
      goto f_err;
    }

    goto start;
  }

  if (s->shutdown & SSL_SENT_SHUTDOWN) {
    /* but we have not received a shutdown */
    s->rwstate = SSL_NOTHING;
    rr->length = 0;
    return 0;
  }

  if (rr->type == SSL3_RT_CHANGE_CIPHER_SPEC) {
    /* 'Change Cipher Spec' is just a single byte, so we know exactly what the
     * record payload has to look like */
    if (rr->length != 1 || rr->off != 0 || rr->data[0] != SSL3_MT_CCS) {
      al = SSL_AD_ILLEGAL_PARAMETER;
      OPENSSL_PUT_ERROR(SSL, dtls1_read_bytes, SSL_R_BAD_CHANGE_CIPHER_SPEC);
      goto f_err;
    }

    rr->length = 0;

    if (s->msg_callback) {
      s->msg_callback(0, s->version, SSL3_RT_CHANGE_CIPHER_SPEC, rr->data, 1, s,
                      s->msg_callback_arg);
    }

    /* We can't process a CCS now, because previous handshake
     * messages are still missing, so just drop it.
     */
    if (!s->d1->change_cipher_spec_ok) {
      goto start;
    }

    s->d1->change_cipher_spec_ok = 0;

    s->s3->change_cipher_spec = 1;
    if (!ssl3_do_change_cipher_spec(s)) {
      goto err;
    }

    /* do this whenever CCS is processed */
    dtls1_reset_seq_numbers(s, SSL3_CC_READ);

    goto start;
  }

  /* Unexpected handshake message. It may be a retransmitted Finished (the only
   * post-CCS message). Otherwise, it's a pre-CCS handshake message from an
   * unsupported renegotiation attempt. */
  if (rr->type == SSL3_RT_HANDSHAKE && !s->in_handshake) {
    if (rr->length < DTLS1_HM_HEADER_LENGTH) {
      al = SSL_AD_DECODE_ERROR;
      OPENSSL_PUT_ERROR(SSL, dtls1_read_bytes, SSL_R_BAD_HANDSHAKE_RECORD);
      goto f_err;
    }
    struct hm_header_st msg_hdr;
    dtls1_get_message_header(&rr->data[rr->off], &msg_hdr);

    /* Ignore a stray Finished from the previous handshake. */
    if (msg_hdr.type == SSL3_MT_FINISHED) {
      if (msg_hdr.frag_off == 0) {
        /* Retransmit our last flight of messages. If the peer sends the second
         * Finished, they may not have received ours. Only do this for the
         * first fragment, in case the Finished was fragmented. */
        if (dtls1_check_timeout_num(s) < 0) {
          return -1;
        }

        dtls1_retransmit_buffered_messages(s);
      }

      rr->length = 0;
      goto start;
    }
  }

  /* We already handled these. */
  assert(rr->type != SSL3_RT_CHANGE_CIPHER_SPEC && rr->type != SSL3_RT_ALERT);

  al = SSL_AD_UNEXPECTED_MESSAGE;
  OPENSSL_PUT_ERROR(SSL, dtls1_read_bytes, SSL_R_UNEXPECTED_RECORD);

f_err:
  ssl3_send_alert(s, SSL3_AL_FATAL, al);
err:
  return -1;
}

int dtls1_write_app_data(SSL *s, const void *buf_, int len) {
  int i;

  if (SSL_in_init(s) && !s->in_handshake) {
    i = s->handshake_func(s);
    if (i < 0) {
      return i;
    }
    if (i == 0) {
      OPENSSL_PUT_ERROR(SSL, dtls1_write_app_data, SSL_R_SSL_HANDSHAKE_FAILURE);
      return -1;
    }
  }

  if (len > SSL3_RT_MAX_PLAIN_LENGTH) {
    OPENSSL_PUT_ERROR(SSL, dtls1_write_app_data, SSL_R_DTLS_MESSAGE_TOO_BIG);
    return -1;
  }

  i = dtls1_write_bytes(s, SSL3_RT_APPLICATION_DATA, buf_, len,
                        dtls1_use_current_epoch);
  return i;
}

/* Call this to write data in records of type 'type' It will return <= 0 if not
 * all data has been sent or non-blocking IO. */
int dtls1_write_bytes(SSL *s, int type, const void *buf, int len,
                      enum dtls1_use_epoch_t use_epoch) {
  int i;

  assert(len <= SSL3_RT_MAX_PLAIN_LENGTH);
  s->rwstate = SSL_NOTHING;
  i = do_dtls1_write(s, type, buf, len, use_epoch);
  return i;
}

/* dtls1_seal_record seals a new record of type |type| and plaintext |in| and
 * writes it to |out|. At most |max_out| bytes will be written. It returns one
 * on success and zero on error. On success, it updates the write sequence
 * number. */
static int dtls1_seal_record(SSL *s, uint8_t *out, size_t *out_len,
                             size_t max_out, uint8_t type, const uint8_t *in,
                             size_t in_len, enum dtls1_use_epoch_t use_epoch) {
  if (max_out < DTLS1_RT_HEADER_LENGTH) {
    OPENSSL_PUT_ERROR(SSL, dtls1_seal_record, SSL_R_BUFFER_TOO_SMALL);
    return 0;
  }

  /* Determine the parameters for the current epoch. */
  uint16_t epoch = s->d1->w_epoch;
  SSL_AEAD_CTX *aead = s->aead_write_ctx;
  uint8_t *seq = s->s3->write_sequence;
  if (use_epoch == dtls1_use_previous_epoch) {
    /* DTLS renegotiation is unsupported, so only epochs 0 (NULL cipher) and 1
     * (negotiated cipher) exist. */
    assert(s->d1->w_epoch == 1);
    epoch = s->d1->w_epoch - 1;
    aead = NULL;
    seq = s->d1->last_write_sequence;
  }

  out[0] = type;

  uint16_t wire_version = s->s3->have_version ? s->version : DTLS1_VERSION;
  out[1] = wire_version >> 8;
  out[2] = wire_version & 0xff;

  out[3] = epoch >> 8;
  out[4] = epoch & 0xff;
  memcpy(&out[5], &seq[2], 6);

  size_t ciphertext_len;
  if (!SSL_AEAD_CTX_seal(aead, out + DTLS1_RT_HEADER_LENGTH, &ciphertext_len,
                         max_out - DTLS1_RT_HEADER_LENGTH, type, wire_version,
                         &out[3] /* seq */, in, in_len) ||
      !ssl3_record_sequence_update(&seq[2], 6)) {
    return 0;
  }

  if (ciphertext_len >= 1 << 16) {
    OPENSSL_PUT_ERROR(SSL, dtls1_seal_record, ERR_R_OVERFLOW);
    return 0;
  }
  out[11] = ciphertext_len >> 8;
  out[12] = ciphertext_len & 0xff;

  *out_len = DTLS1_RT_HEADER_LENGTH + ciphertext_len;

  if (s->msg_callback) {
    s->msg_callback(1 /* write */, 0, SSL3_RT_HEADER, out,
                    DTLS1_RT_HEADER_LENGTH, s, s->msg_callback_arg);
  }

  return 1;
}

static int do_dtls1_write(SSL *s, int type, const uint8_t *buf,
                          unsigned int len, enum dtls1_use_epoch_t use_epoch) {
  SSL3_BUFFER *wb = &s->s3->wbuf;

  /* ssl3_write_pending drops the write if |BIO_write| fails in DTLS, so there
   * is never pending data. */
  assert(s->s3->wbuf.left == 0);

  /* If we have an alert to send, lets send it */
  if (s->s3->alert_dispatch) {
    int ret = s->method->ssl_dispatch_alert(s);
    if (ret <= 0) {
      return ret;
    }
    /* if it went, fall through and send more stuff */
  }

  if (wb->buf == NULL && !ssl3_setup_write_buffer(s)) {
    return -1;
  }

  if (len == 0) {
    return 0;
  }

  /* Align the output so the ciphertext is aligned to |SSL3_ALIGN_PAYLOAD|. */
  uintptr_t align = (uintptr_t)wb->buf + DTLS1_RT_HEADER_LENGTH;
  align = (0 - align) & (SSL3_ALIGN_PAYLOAD - 1);
  uint8_t *out = wb->buf + align;
  wb->offset = align;
  size_t max_out = wb->len - wb->offset;

  size_t ciphertext_len;
  if (!dtls1_seal_record(s, out, &ciphertext_len, max_out, type, buf, len,
                         use_epoch)) {
    return -1;
  }

  /* now let's set up wb */
  wb->left = ciphertext_len;

  /* memorize arguments so that ssl3_write_pending can detect bad write retries
   * later */
  s->s3->wpend_tot = len;
  s->s3->wpend_buf = buf;
  s->s3->wpend_type = type;
  s->s3->wpend_ret = len;

  /* we now just need to write the buffer */
  return ssl3_write_pending(s, type, buf, len);
}

static int dtls1_record_replay_check(SSL *s, DTLS1_BITMAP *bitmap) {
  int cmp;
  unsigned int shift;
  const uint8_t *seq = s->s3->read_sequence;

  cmp = satsub64be(seq, bitmap->max_seq_num);
  if (cmp > 0) {
    memcpy(s->s3->rrec.seq_num, seq, 8);
    return 1; /* this record in new */
  }
  shift = -cmp;
  if (shift >= sizeof(bitmap->map) * 8) {
    return 0; /* stale, outside the window */
  } else if (bitmap->map & (((uint64_t)1) << shift)) {
    return 0; /* record previously received */
  }

  memcpy(s->s3->rrec.seq_num, seq, 8);
  return 1;
}

static void dtls1_record_bitmap_update(SSL *s, DTLS1_BITMAP *bitmap) {
  int cmp;
  unsigned int shift;
  const uint8_t *seq = s->s3->read_sequence;

  cmp = satsub64be(seq, bitmap->max_seq_num);
  if (cmp > 0) {
    shift = cmp;
    if (shift < sizeof(bitmap->map) * 8) {
      bitmap->map <<= shift, bitmap->map |= 1UL;
    } else {
      bitmap->map = 1UL;
    }
    memcpy(bitmap->max_seq_num, seq, 8);
  } else {
    shift = -cmp;
    if (shift < sizeof(bitmap->map) * 8) {
      bitmap->map |= ((uint64_t)1) << shift;
    }
  }
}

int dtls1_dispatch_alert(SSL *s) {
  int i, j;
  void (*cb)(const SSL *ssl, int type, int val) = NULL;
  uint8_t buf[DTLS1_AL_HEADER_LENGTH];
  uint8_t *ptr = &buf[0];

  s->s3->alert_dispatch = 0;

  memset(buf, 0x00, sizeof(buf));
  *ptr++ = s->s3->send_alert[0];
  *ptr++ = s->s3->send_alert[1];

  i = do_dtls1_write(s, SSL3_RT_ALERT, &buf[0], sizeof(buf),
                     dtls1_use_current_epoch);
  if (i <= 0) {
    s->s3->alert_dispatch = 1;
  } else {
    if (s->s3->send_alert[0] == SSL3_AL_FATAL) {
      (void)BIO_flush(s->wbio);
    }

    if (s->msg_callback) {
      s->msg_callback(1, s->version, SSL3_RT_ALERT, s->s3->send_alert, 2, s,
                      s->msg_callback_arg);
    }

    if (s->info_callback != NULL) {
      cb = s->info_callback;
    } else if (s->ctx->info_callback != NULL) {
      cb = s->ctx->info_callback;
    }

    if (cb != NULL) {
      j = (s->s3->send_alert[0] << 8) | s->s3->send_alert[1];
      cb(s, SSL_CB_WRITE_ALERT, j);
    }
  }

  return i;
}

void dtls1_reset_seq_numbers(SSL *s, int rw) {
  uint8_t *seq;
  unsigned int seq_bytes = sizeof(s->s3->read_sequence);

  if (rw & SSL3_CC_READ) {
    seq = s->s3->read_sequence;
    s->d1->r_epoch++;
    memset(&s->d1->bitmap, 0, sizeof(DTLS1_BITMAP));
  } else {
    seq = s->s3->write_sequence;
    memcpy(s->d1->last_write_sequence, seq, sizeof(s->s3->write_sequence));
    s->d1->w_epoch++;
  }

  memset(seq, 0x00, seq_bytes);
}
