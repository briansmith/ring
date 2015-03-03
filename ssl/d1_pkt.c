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

#include <stdio.h>
#include <errno.h>
#include <assert.h>

#include <openssl/buf.h>
#include <openssl/mem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "ssl_locl.h"


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
static DTLS1_BITMAP *dtls1_get_bitmap(SSL *s, SSL3_RECORD *rr,
                                      unsigned int *is_next_epoch);
static int dtls1_buffer_record(SSL *s, record_pqueue *q,
                               uint8_t *priority);
static int dtls1_process_record(SSL *s);
static int do_dtls1_write(SSL *s, int type, const uint8_t *buf,
                          unsigned int len);

/* copy buffered record into SSL structure */
static int dtls1_copy_record(SSL *s, pitem *item) {
  DTLS1_RECORD_DATA *rdata;

  rdata = (DTLS1_RECORD_DATA *)item->data;

  if (s->s3->rbuf.buf != NULL) {
    OPENSSL_free(s->s3->rbuf.buf);
  }

  s->packet = rdata->packet;
  s->packet_length = rdata->packet_length;
  memcpy(&(s->s3->rbuf), &(rdata->rbuf), sizeof(SSL3_BUFFER));
  memcpy(&(s->s3->rrec), &(rdata->rrec), sizeof(SSL3_RECORD));

  /* Set proper sequence number for mac calculation */
  memcpy(&(s->s3->read_sequence[2]), &(rdata->packet[5]), 6);

  return 1;
}

static int dtls1_buffer_record(SSL *s, record_pqueue *queue,
                               uint8_t *priority) {
  DTLS1_RECORD_DATA *rdata;
  pitem *item;

  /* Limit the size of the queue to prevent DOS attacks */
  if (pqueue_size(queue->q) >= 100) {
    return 0;
  }

  rdata = OPENSSL_malloc(sizeof(DTLS1_RECORD_DATA));
  item = pitem_new(priority, rdata);
  if (rdata == NULL || item == NULL) {
    if (rdata != NULL) {
      OPENSSL_free(rdata);
    }
    if (item != NULL) {
      pitem_free(item);
    }

    OPENSSL_PUT_ERROR(SSL, dtls1_buffer_record, ERR_R_INTERNAL_ERROR);
    return -1;
  }

  rdata->packet = s->packet;
  rdata->packet_length = s->packet_length;
  memcpy(&(rdata->rbuf), &(s->s3->rbuf), sizeof(SSL3_BUFFER));
  memcpy(&(rdata->rrec), &(s->s3->rrec), sizeof(SSL3_RECORD));

  item->data = rdata;

  s->packet = NULL;
  s->packet_length = 0;
  memset(&(s->s3->rbuf), 0, sizeof(SSL3_BUFFER));
  memset(&(s->s3->rrec), 0, sizeof(SSL3_RECORD));

  if (!ssl3_setup_buffers(s)) {
    goto internal_error;
  }

  /* insert should not fail, since duplicates are dropped */
  if (pqueue_insert(queue->q, item) == NULL) {
    goto internal_error;
  }

  return 1;

internal_error:
  OPENSSL_PUT_ERROR(SSL, dtls1_buffer_record, ERR_R_INTERNAL_ERROR);
  if (rdata->rbuf.buf != NULL) {
    OPENSSL_free(rdata->rbuf.buf);
  }
  OPENSSL_free(rdata);
  pitem_free(item);
  return -1;
}

static int dtls1_retrieve_buffered_record(SSL *s, record_pqueue *queue) {
  pitem *item;

  item = pqueue_pop(queue->q);
  if (item) {
    dtls1_copy_record(s, item);

    OPENSSL_free(item->data);
    pitem_free(item);

    return 1;
  }

  return 0;
}

/* retrieve a buffered record that belongs to the new epoch, i.e., not
 * processed yet */
#define dtls1_get_unprocessed_record(s) \
  dtls1_retrieve_buffered_record((s), &((s)->d1->unprocessed_rcds))

/* retrieve a buffered record that belongs to the current epoch, i.e.,
 * processed */
#define dtls1_get_processed_record(s) \
  dtls1_retrieve_buffered_record((s), &((s)->d1->processed_rcds))

static int dtls1_process_buffered_records(SSL *s) {
  pitem *item;

  item = pqueue_peek(s->d1->unprocessed_rcds.q);
  if (item) {
    /* Check if epoch is current. */
    if (s->d1->unprocessed_rcds.epoch != s->d1->r_epoch) {
      return 1; /* Nothing to do. */
    }

    /* Process all the records. */
    while (pqueue_peek(s->d1->unprocessed_rcds.q)) {
      dtls1_get_unprocessed_record(s);
      if (!dtls1_process_record(s)) {
        return 0;
      }
      if (dtls1_buffer_record(s, &(s->d1->processed_rcds),
                              s->s3->rrec.seq_num) < 0) {
        return -1;
      }
    }
  }

  /* sync epoch numbers once all the unprocessed records have been processed */
  s->d1->processed_rcds.epoch = s->d1->r_epoch;
  s->d1->unprocessed_rcds.epoch = s->d1->r_epoch + 1;

  return 1;
}

static int dtls1_process_record(SSL *s) {
  int al;
  SSL3_RECORD *rr;

  rr = &(s->s3->rrec);

  /* At this point, s->packet_length == SSL3_RT_HEADER_LNGTH + rr->length, and
   * we have that many bytes in s->packet. */
  rr->input = &(s->packet[DTLS1_RT_HEADER_LENGTH]);

  /* ok, we can now read from 's->packet' data into 'rr' rr->input points at
   * rr->length bytes, which need to be copied into rr->data by either the
   * decryption or by the decompression When the data is 'copied' into the
   * rr->data buffer, rr->input will be pointed at the new buffer */

  /* We now have - encrypted [ MAC [ compressed [ plain ] ] ] rr->length bytes
   * of encrypted compressed stuff. */

  /* check is not needed I believe */
  if (rr->length > SSL3_RT_MAX_ENCRYPTED_LENGTH) {
    al = SSL_AD_RECORD_OVERFLOW;
    OPENSSL_PUT_ERROR(SSL, dtls1_process_record,
                      SSL_R_ENCRYPTED_LENGTH_TOO_LONG);
    goto f_err;
  }

  /* decrypt in place in 'rr->input' */
  rr->data = rr->input;

  if (!s->enc_method->enc(s, 0)) {
    /* Bad packets are silently dropped in DTLS. Clear the error queue of any
     * errors decryption may have added. */
    ERR_clear_error();
    rr->length = 0;
    s->packet_length = 0;
    goto err;
  }

  if (rr->length > SSL3_RT_MAX_PLAIN_LENGTH) {
    al = SSL_AD_RECORD_OVERFLOW;
    OPENSSL_PUT_ERROR(SSL, dtls1_process_record, SSL_R_DATA_LENGTH_TOO_LONG);
    goto f_err;
  }

  rr->off = 0;
  /* So at this point the following is true
   * ssl->s3->rrec.type 	is the type of record
   * ssl->s3->rrec.length	== number of bytes in record
   * ssl->s3->rrec.off	== offset to first valid byte
   * ssl->s3->rrec.data	== where to take bytes from, increment
   *			   after use :-). */

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
  int ssl_major, ssl_minor;
  int i, n;
  SSL3_RECORD *rr;
  unsigned char *p = NULL;
  unsigned short version;
  DTLS1_BITMAP *bitmap;
  unsigned int is_next_epoch;

  rr = &(s->s3->rrec);

  /* The epoch may have changed. If so, process all the pending records. This
   * is a non-blocking operation. */
  if (dtls1_process_buffered_records(s) < 0) {
    return -1;
  }

  /* If we're renegotiating, then there may be buffered records. */
  if (dtls1_get_processed_record(s)) {
    return 1;
  }

  /* get something from the wire */
again:
  /* check if we have the header */
  if ((s->rstate != SSL_ST_READ_BODY) ||
      (s->packet_length < DTLS1_RT_HEADER_LENGTH)) {
    n = ssl3_read_n(s, DTLS1_RT_HEADER_LENGTH, s->s3->rbuf.len, 0);
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
    version = (ssl_major << 8) | ssl_minor;

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
    i = rr->length;
    n = ssl3_read_n(s, i, i, 1);
    if (n <= 0) {
      return n; /* error or non-blocking io */
    }

    /* this packet contained a partial record, dump it */
    if (n != i) {
      rr->length = 0;
      s->packet_length = 0;
      goto again;
    }

    /* now n == rr->length,
     * and s->packet_length == DTLS1_RT_HEADER_LENGTH + rr->length */
  }
  s->rstate = SSL_ST_READ_HEADER; /* set state for later operations */

  /* match epochs.  NULL means the packet is dropped on the floor */
  bitmap = dtls1_get_bitmap(s, rr, &is_next_epoch);
  if (bitmap == NULL) {
    rr->length = 0;
    s->packet_length = 0; /* dump this record */
    goto again;           /* get another record */
  }

  /* Check whether this is a repeat, or aged record. */
  if (!dtls1_record_replay_check(s, bitmap)) {
    rr->length = 0;
    s->packet_length = 0; /* dump this record */
    goto again;           /* get another record */
  }

  /* just read a 0 length packet */
  if (rr->length == 0) {
    goto again;
  }

  /* If this record is from the next epoch (either HM or ALERT),
   * and a handshake is currently in progress, buffer it since it
   * cannot be processed at this time.
   */
  if (is_next_epoch) {
    if (SSL_in_init(s) || s->in_handshake) {
      if (dtls1_buffer_record(s, &(s->d1->unprocessed_rcds), rr->seq_num) < 0) {
        return -1;
      }
      dtls1_record_bitmap_update(s, bitmap); /* Mark receipt of record. */
    }
    rr->length = 0;
    s->packet_length = 0;
    goto again;
  }

  if (!dtls1_process_record(s)) {
    rr->length = 0;
    s->packet_length = 0; /* dump this record */
    goto again;           /* get another record */
  }
  dtls1_record_bitmap_update(s, bitmap); /* Mark receipt of record. */

  return 1;
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

  if (s->s3->rbuf.buf == NULL && !ssl3_setup_buffers(s)) {
    /* TODO(davidben): Is this redundant with the calls in the handshake? */
    return -1;
  }

start:
  s->rwstate = SSL_NOTHING;

  /* s->s3->rrec.type     - is the type of record
   * s->s3->rrec.data     - data
   * s->s3->rrec.off      - offset into 'data' for next read
   * s->s3->rrec.length   - number of bytes. */
  rr = &s->s3->rrec;

  /* We are not handshaking and have no data yet,
   * so process data buffered during the last handshake
   * in advance, if any.
   */
  if (s->state == SSL_ST_OK && rr->length == 0) {
    pitem *item;
    item = pqueue_pop(s->d1->buffered_app_data.q);
    if (item) {
      dtls1_copy_record(s, item);

      OPENSSL_free(item->data);
      pitem_free(item);
    }
  }

  /* Check for timeout */
  if (dtls1_handle_timeout(s) > 0) {
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
  if (s->s3->change_cipher_spec && rr->type != SSL3_RT_HANDSHAKE) {
    /* We now have application data between CCS and Finished. Most likely the
     * packets were reordered on their way, so buffer the application data for
     * later processing rather than dropping the connection. */
    if (dtls1_buffer_record(s, &(s->d1->buffered_app_data), rr->seq_num) < 0) {
      OPENSSL_PUT_ERROR(SSL, dtls1_read_bytes, ERR_R_INTERNAL_ERROR);
      return -1;
    }
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
      OPENSSL_PUT_ERROR(SSL, ssl3_read_bytes, SSL_R_BAD_ALERT);
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
      OPENSSL_PUT_ERROR(SSL, ssl3_read_bytes, SSL_R_BAD_HANDSHAKE_RECORD);
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

int dtls1_write_app_data_bytes(SSL *s, int type, const void *buf_, int len) {
  int i;

  if (SSL_in_init(s) && !s->in_handshake) {
    i = s->handshake_func(s);
    if (i < 0) {
      return i;
    }
    if (i == 0) {
      OPENSSL_PUT_ERROR(SSL, dtls1_write_app_data_bytes,
                        SSL_R_SSL_HANDSHAKE_FAILURE);
      return -1;
    }
  }

  if (len > SSL3_RT_MAX_PLAIN_LENGTH) {
    OPENSSL_PUT_ERROR(SSL, dtls1_write_app_data_bytes,
                      SSL_R_DTLS_MESSAGE_TOO_BIG);
    return -1;
  }

  i = dtls1_write_bytes(s, type, buf_, len);
  return i;
}

/* Call this to write data in records of type 'type' It will return <= 0 if not
 * all data has been sent or non-blocking IO. */
int dtls1_write_bytes(SSL *s, int type, const void *buf, int len) {
  int i;

  assert(len <= SSL3_RT_MAX_PLAIN_LENGTH);
  s->rwstate = SSL_NOTHING;
  i = do_dtls1_write(s, type, buf, len);
  return i;
}

static int do_dtls1_write(SSL *s, int type, const uint8_t *buf,
                          unsigned int len) {
  uint8_t *p, *pseq;
  int i;
  int prefix_len = 0;
  int eivlen = 0;
  SSL3_RECORD *wr;
  SSL3_BUFFER *wb;

  /* first check if there is a SSL3_BUFFER still being written
   * out.  This will happen with non blocking IO */
  if (s->s3->wbuf.left != 0) {
    assert(0); /* XDTLS:  want to see if we ever get here */
    return ssl3_write_pending(s, type, buf, len);
  }

  /* If we have an alert to send, lets send it */
  if (s->s3->alert_dispatch) {
    i = s->method->ssl_dispatch_alert(s);
    if (i <= 0) {
      return i;
    }
    /* if it went, fall through and send more stuff */
  }

  if (len == 0) {
    return 0;
  }

  wr = &(s->s3->wrec);
  wb = &(s->s3->wbuf);

  p = wb->buf + prefix_len;

  /* write the header */

  *(p++) = type & 0xff;
  wr->type = type;
  /* Special case: for hello verify request, client version 1.0 and
   * we haven't decided which version to use yet send back using
   * version 1.0 header: otherwise some clients will ignore it.
   */
  if (!s->s3->have_version) {
    *(p++) = DTLS1_VERSION >> 8;
    *(p++) = DTLS1_VERSION & 0xff;
  } else {
    *(p++) = s->version >> 8;
    *(p++) = s->version & 0xff;
  }

  /* field where we are to write out packet epoch, seq num and len */
  pseq = p;
  p += 10;

  /* Leave room for the variable nonce for AEADs which specify it explicitly. */
  if (s->aead_write_ctx != NULL &&
      s->aead_write_ctx->variable_nonce_included_in_record) {
    eivlen = s->aead_write_ctx->variable_nonce_len;
  }

  /* lets setup the record stuff. */
  wr->data = p + eivlen; /* make room for IV in case of CBC */
  wr->length = (int)len;
  wr->input = (unsigned char *)buf;

  /* we now 'read' from wr->input, wr->length bytes into wr->data */
  memcpy(wr->data, wr->input, wr->length);
  wr->input = wr->data;

  /* this is true regardless of mac size */
  wr->input = p;
  wr->data = p;
  wr->length += eivlen;

  if (!s->enc_method->enc(s, 1)) {
    goto err;
  }

  /* there's only one epoch between handshake and app data */
  s2n(s->d1->w_epoch, pseq);

  memcpy(pseq, &(s->s3->write_sequence[2]), 6);
  pseq += 6;
  s2n(wr->length, pseq);

  if (s->msg_callback) {
    s->msg_callback(1, 0, SSL3_RT_HEADER, pseq - DTLS1_RT_HEADER_LENGTH,
                    DTLS1_RT_HEADER_LENGTH, s, s->msg_callback_arg);
  }

  /* we should now have wr->data pointing to the encrypted data, which is
   * wr->length long */
  wr->type = type; /* not needed but helps for debugging */
  wr->length += DTLS1_RT_HEADER_LENGTH;

  ssl3_record_sequence_update(&(s->s3->write_sequence[0]));

  /* now let's set up wb */
  wb->left = prefix_len + wr->length;
  wb->offset = 0;

  /* memorize arguments so that ssl3_write_pending can detect bad write retries
   * later */
  s->s3->wpend_tot = len;
  s->s3->wpend_buf = buf;
  s->s3->wpend_type = type;
  s->s3->wpend_ret = len;

  /* we now just need to write the buffer */
  return ssl3_write_pending(s, type, buf, len);

err:
  return -1;
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

  i = do_dtls1_write(s, SSL3_RT_ALERT, &buf[0], sizeof(buf));
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

static DTLS1_BITMAP *dtls1_get_bitmap(SSL *s, SSL3_RECORD *rr,
                                      unsigned int *is_next_epoch) {
  *is_next_epoch = 0;

  /* In current epoch, accept HM, CCS, DATA, & ALERT */
  if (rr->epoch == s->d1->r_epoch) {
    return &s->d1->bitmap;
  } else if (rr->epoch == (unsigned long)(s->d1->r_epoch + 1) &&
             (rr->type == SSL3_RT_HANDSHAKE || rr->type == SSL3_RT_ALERT)) {
    /* Only HM and ALERT messages can be from the next epoch */
    *is_next_epoch = 1;
    return &s->d1->next_bitmap;
  }

  return NULL;
}

void dtls1_reset_seq_numbers(SSL *s, int rw) {
  uint8_t *seq;
  unsigned int seq_bytes = sizeof(s->s3->read_sequence);

  if (rw & SSL3_CC_READ) {
    seq = s->s3->read_sequence;
    s->d1->r_epoch++;
    memcpy(&(s->d1->bitmap), &(s->d1->next_bitmap), sizeof(DTLS1_BITMAP));
    memset(&(s->d1->next_bitmap), 0x00, sizeof(DTLS1_BITMAP));
  } else {
    seq = s->s3->write_sequence;
    memcpy(s->d1->last_write_sequence, seq, sizeof(s->s3->write_sequence));
    s->d1->w_epoch++;
  }

  memset(seq, 0x00, seq_bytes);
}
