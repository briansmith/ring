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

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#include <openssl/buf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/rand.h>

#include "internal.h"


static int do_ssl3_write(SSL *s, int type, const uint8_t *buf, unsigned int len,
                         char fragment);
static int ssl3_get_record(SSL *s);

int ssl3_read_n(SSL *s, int n, int extend) {
  /* If |extend| is 0, obtain new n-byte packet;
   * if |extend| is 1, increase packet by another n bytes.
   *
   * The packet will be in the sub-array of |s->s3->rbuf.buf| specified by
   * |s->packet| and |s->packet_length|. (If DTLS and |extend| is 0, additional
   * bytes will be read into |rbuf|, up to the size of the buffer.)
   *
   * TODO(davidben): |dtls1_get_record| and |ssl3_get_record| have very
   * different needs. Separate the two record layers. In DTLS, |BIO_read| is
   * called at most once, and only when |extend| is 0. In TLS, the buffer never
   * contains more than one record. */
  int i, len, left;
  uintptr_t align = 0;
  uint8_t *pkt;
  SSL3_BUFFER *rb;

  if (n <= 0) {
    return n;
  }

  rb = &s->s3->rbuf;
  if (rb->buf == NULL && !ssl3_setup_read_buffer(s)) {
    return -1;
  }

  left = rb->left;

  align = (uintptr_t)rb->buf + SSL3_RT_HEADER_LENGTH;
  align = (0 - align) & (SSL3_ALIGN_PAYLOAD - 1);

  if (!extend) {
    /* start with empty packet ... */
    if (left == 0) {
      rb->offset = align;
    } else if (align != 0 && left >= SSL3_RT_HEADER_LENGTH) {
      /* check if next packet length is large enough to justify payload
       * alignment... */
      pkt = rb->buf + rb->offset;
      if (pkt[0] == SSL3_RT_APPLICATION_DATA && (pkt[3] << 8 | pkt[4]) >= 128) {
        /* Note that even if packet is corrupted and its length field is
         * insane, we can only be led to wrong decision about whether memmove
         * will occur or not. Header values has no effect on memmove arguments
         * and therefore no buffer overrun can be triggered. */
        memmove(rb->buf + align, pkt, left);
        rb->offset = align;
      }
    }
    s->packet = rb->buf + rb->offset;
    s->packet_length = 0;
    /* ... now we can act as if 'extend' was set */
  }

  /* In DTLS, if there is leftover data from the previous packet or |extend| is
   * true, clamp to the previous read. DTLS records may not span packet
   * boundaries. */
  if (SSL_IS_DTLS(s) && n > left && (left > 0 || extend)) {
    n = left;
  }

  /* if there is enough in the buffer from a previous read, take some */
  if (left >= n) {
    s->packet_length += n;
    rb->left = left - n;
    rb->offset += n;
    return n;
  }

  /* else we need to read more data */

  len = s->packet_length;
  pkt = rb->buf + align;
  /* Move any available bytes to front of buffer: |len| bytes already pointed
   * to by |packet|, |left| extra ones at the end. */
  if (s->packet != pkt) {
    /* len > 0 */
    memmove(pkt, s->packet, len + left);
    s->packet = pkt;
    rb->offset = len + align;
  }

  if (n > (int)(rb->len - rb->offset)) {
    OPENSSL_PUT_ERROR(SSL, ssl3_read_n, ERR_R_INTERNAL_ERROR);
    return -1;
  }

  int max = n;
  if (SSL_IS_DTLS(s) && !extend) {
    max = rb->len - rb->offset;
  }

  while (left < n) {
    /* Now we have len+left bytes at the front of s->s3->rbuf.buf and need to
     * read in more until we have len+n (up to len+max if possible). */
    ERR_clear_system_error();
    if (s->rbio != NULL) {
      s->rwstate = SSL_READING;
      i = BIO_read(s->rbio, pkt + len + left, max - left);
    } else {
      OPENSSL_PUT_ERROR(SSL, ssl3_read_n, SSL_R_READ_BIO_NOT_SET);
      i = -1;
    }

    if (i <= 0) {
      rb->left = left;
      if (len + left == 0) {
        ssl3_release_read_buffer(s);
      }
      return i;
    }
    left += i;
    /* reads should *never* span multiple packets for DTLS because the
     * underlying transport protocol is message oriented as opposed to byte
     * oriented as in the TLS case. */
    if (SSL_IS_DTLS(s) && n > left) {
      n = left; /* makes the while condition false */
    }
  }

  /* done reading, now the book-keeping */
  rb->offset += n;
  rb->left = left - n;
  s->packet_length += n;
  s->rwstate = SSL_NOTHING;

  return n;
}

/* kMaxEmptyRecords is the number of consecutive, empty records that will be
 * processed. Without this limit an attacker could send empty records at a
 * faster rate than we can process and cause |ssl3_get_record| to loop
 * forever. */
static const uint8_t kMaxEmptyRecords = 32;

/* kMaxWarningAlerts is the number of consecutive warning alerts that will be
 * processed. */
static const uint8_t kMaxWarningAlerts = 4;

/* Call this to get a new input record. It will return <= 0 if more data is
 * needed, normally due to an error or non-blocking IO. When it finishes, one
 * packet has been decoded and can be found in
 * ssl->s3->rrec.type    - is the type of record
 * ssl->s3->rrec.data    - data
 * ssl->s3->rrec.length  - number of bytes */
/* used only by ssl3_read_bytes */
static int ssl3_get_record(SSL *s) {
  uint8_t ssl_major, ssl_minor;
  int al, n, i, ret = -1;
  SSL3_RECORD *rr = &s->s3->rrec;
  uint8_t *p;
  uint16_t version;
  size_t extra;

again:
  /* check if we have the header */
  if (s->rstate != SSL_ST_READ_BODY ||
      s->packet_length < SSL3_RT_HEADER_LENGTH) {
    n = ssl3_read_n(s, SSL3_RT_HEADER_LENGTH, 0);
    if (n <= 0) {
      return n; /* error or non-blocking */
    }
    s->rstate = SSL_ST_READ_BODY;

    /* Some bytes were read, so the read buffer must be existant and
     * |s->s3->init_extra| is defined. */
    assert(s->s3->rbuf.buf != NULL);
    extra = s->s3->init_extra ? SSL3_RT_MAX_EXTRA : 0;

    p = s->packet;
    if (s->msg_callback) {
      s->msg_callback(0, 0, SSL3_RT_HEADER, p, 5, s, s->msg_callback_arg);
    }

    /* Pull apart the header into the SSL3_RECORD */
    rr->type = *(p++);
    ssl_major = *(p++);
    ssl_minor = *(p++);
    version = (((uint16_t)ssl_major) << 8) | ssl_minor;
    n2s(p, rr->length);

    if (s->s3->have_version && version != s->version) {
      OPENSSL_PUT_ERROR(SSL, ssl3_get_record, SSL_R_WRONG_VERSION_NUMBER);
      al = SSL_AD_PROTOCOL_VERSION;
      goto f_err;
    }

    if ((version >> 8) != SSL3_VERSION_MAJOR) {
      OPENSSL_PUT_ERROR(SSL, ssl3_get_record, SSL_R_WRONG_VERSION_NUMBER);
      goto err;
    }

    if (rr->length > SSL3_RT_MAX_ENCRYPTED_LENGTH + extra) {
      al = SSL_AD_RECORD_OVERFLOW;
      OPENSSL_PUT_ERROR(SSL, ssl3_get_record, SSL_R_ENCRYPTED_LENGTH_TOO_LONG);
      goto f_err;
    }

    /* now s->rstate == SSL_ST_READ_BODY */
  } else {
    /* |packet_length| is non-zero and |s->rstate| is |SSL_ST_READ_BODY|. The
     * read buffer must be existant and |s->s3->init_extra| is defined. */
    assert(s->s3->rbuf.buf != NULL);
    extra = s->s3->init_extra ? SSL3_RT_MAX_EXTRA : 0;
  }

  /* s->rstate == SSL_ST_READ_BODY, get and decode the data */

  if (rr->length > s->packet_length - SSL3_RT_HEADER_LENGTH) {
    /* now s->packet_length == SSL3_RT_HEADER_LENGTH */
    i = rr->length;
    n = ssl3_read_n(s, i, 1);
    if (n <= 0) {
      /* Error or non-blocking IO. Now |n| == |rr->length|, and
       * |s->packet_length| == |SSL3_RT_HEADER_LENGTH| + |rr->length|. */
      return n;
    }
  }

  s->rstate = SSL_ST_READ_HEADER; /* set state for later operations */

  /* |rr->data| points to |rr->length| bytes of ciphertext in |s->packet|. */
  rr->data = &s->packet[SSL3_RT_HEADER_LENGTH];

  /* Decrypt the packet in-place.
   *
   * TODO(davidben): This assumes |s->version| is the same as the record-layer
   * version which isn't always true, but it only differs with the NULL cipher
   * which ignores the parameter. */
  size_t plaintext_len;
  if (!SSL_AEAD_CTX_open(s->aead_read_ctx, rr->data, &plaintext_len, rr->length,
                         rr->type, s->version, s->s3->read_sequence, rr->data,
                         rr->length)) {
    al = SSL_AD_BAD_RECORD_MAC;
    OPENSSL_PUT_ERROR(SSL, ssl3_get_record,
                      SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC);
    goto f_err;
  }
  if (!ssl3_record_sequence_update(s->s3->read_sequence, 8)) {
    goto err;
  }
  if (plaintext_len > SSL3_RT_MAX_PLAIN_LENGTH + extra) {
    al = SSL_AD_RECORD_OVERFLOW;
    OPENSSL_PUT_ERROR(SSL, ssl3_get_record, SSL_R_DATA_LENGTH_TOO_LONG);
    goto f_err;
  }
  assert(plaintext_len <= (1u << 16));
  rr->length = plaintext_len;

  rr->off = 0;
  /* So at this point the following is true:
   * ssl->s3->rrec.type is the type of record;
   * ssl->s3->rrec.length is the number of bytes in the record;
   * ssl->s3->rrec.off is the offset to first valid byte;
   * ssl->s3->rrec.data the first byte of the record body. */

  /* we have pulled in a full packet so zero things */
  s->packet_length = 0;

  /* just read a 0 length packet */
  if (rr->length == 0) {
    s->s3->empty_record_count++;
    if (s->s3->empty_record_count > kMaxEmptyRecords) {
      al = SSL_AD_UNEXPECTED_MESSAGE;
      OPENSSL_PUT_ERROR(SSL, ssl3_get_record, SSL_R_TOO_MANY_EMPTY_FRAGMENTS);
      goto f_err;
    }
    goto again;
  }
  s->s3->empty_record_count = 0;

  return 1;

f_err:
  ssl3_send_alert(s, SSL3_AL_FATAL, al);
err:
  return ret;
}

int ssl3_write_app_data(SSL *ssl, const void *buf, int len) {
  return ssl3_write_bytes(ssl, SSL3_RT_APPLICATION_DATA, buf, len);
}

/* Call this to write data in records of type |type|. It will return <= 0 if
 * not all data has been sent or non-blocking IO. */
int ssl3_write_bytes(SSL *s, int type, const void *buf_, int len) {
  const uint8_t *buf = buf_;
  unsigned int tot, n, nw;
  int i;

  s->rwstate = SSL_NOTHING;
  assert(s->s3->wnum <= INT_MAX);
  tot = s->s3->wnum;
  s->s3->wnum = 0;

  if (!s->in_handshake && SSL_in_init(s) && !SSL_in_false_start(s)) {
    i = s->handshake_func(s);
    if (i < 0) {
      return i;
    }
    if (i == 0) {
      OPENSSL_PUT_ERROR(SSL, ssl3_write_bytes, SSL_R_SSL_HANDSHAKE_FAILURE);
      return -1;
    }
  }

  /* Ensure that if we end up with a smaller value of data to write out than
   * the the original len from a write which didn't complete for non-blocking
   * I/O and also somehow ended up avoiding the check for this in
   * ssl3_write_pending/SSL_R_BAD_WRITE_RETRY as it must never be possible to
   * end up with (len-tot) as a large number that will then promptly send
   * beyond the end of the users buffer ... so we trap and report the error in
   * a way the user will notice. */
  if (len < 0 || (size_t)len < tot) {
    OPENSSL_PUT_ERROR(SSL, ssl3_write_bytes, SSL_R_BAD_LENGTH);
    return -1;
  }

  int record_split_done = 0;
  n = (len - tot);
  for (;;) {
    /* max contains the maximum number of bytes that we can put into a
     * record. */
    unsigned max = s->max_send_fragment;
    /* fragment is true if do_ssl3_write should send the first byte in its own
     * record in order to randomise a CBC IV. */
    int fragment = 0;
    if (!record_split_done && s->s3->need_record_splitting &&
        type == SSL3_RT_APPLICATION_DATA) {
      /* Only the the first record per write call needs to be split. The
       * remaining plaintext was determined before the IV was randomized. */
      fragment = 1;
      record_split_done = 1;
    }
    if (n > max) {
      nw = max;
    } else {
      nw = n;
    }

    i = do_ssl3_write(s, type, &buf[tot], nw, fragment);
    if (i <= 0) {
      s->s3->wnum = tot;
      return i;
    }

    if (i == (int)n || (type == SSL3_RT_APPLICATION_DATA &&
                        (s->mode & SSL_MODE_ENABLE_PARTIAL_WRITE))) {
      return tot + i;
    }

    n -= i;
    tot += i;
  }
}

/* ssl3_seal_record seals a new record of type |type| and plaintext |in| and
 * writes it to |out|. At most |max_out| bytes will be written. It returns one
 * on success and zero on error. On success, it updates the write sequence
 * number. */
static int ssl3_seal_record(SSL *s, uint8_t *out, size_t *out_len,
                            size_t max_out, uint8_t type, const uint8_t *in,
                            size_t in_len) {
  if (max_out < SSL3_RT_HEADER_LENGTH) {
    OPENSSL_PUT_ERROR(SSL, ssl3_seal_record, SSL_R_BUFFER_TOO_SMALL);
    return 0;
  }

  out[0] = type;

  /* Some servers hang if initial ClientHello is larger than 256 bytes and
   * record version number > TLS 1.0. */
  uint16_t wire_version = s->version;
  if (!s->s3->have_version && s->version > SSL3_VERSION) {
    wire_version = TLS1_VERSION;
  }
  out[1] = wire_version >> 8;
  out[2] = wire_version & 0xff;

  size_t ciphertext_len;
  if (!SSL_AEAD_CTX_seal(s->aead_write_ctx, out + SSL3_RT_HEADER_LENGTH,
                         &ciphertext_len, max_out - SSL3_RT_HEADER_LENGTH,
                         type, wire_version, s->s3->write_sequence, in,
                         in_len) ||
      !ssl3_record_sequence_update(s->s3->write_sequence, 8)) {
    return 0;
  }

  if (ciphertext_len >= 1 << 16) {
    OPENSSL_PUT_ERROR(SSL, ssl3_seal_record, ERR_R_OVERFLOW);
    return 0;
  }
  out[3] = ciphertext_len >> 8;
  out[4] = ciphertext_len & 0xff;

  *out_len = SSL3_RT_HEADER_LENGTH + ciphertext_len;

 if (s->msg_callback) {
   s->msg_callback(1 /* write */, 0, SSL3_RT_HEADER, out, SSL3_RT_HEADER_LENGTH,
                   s, s->msg_callback_arg);
 }

  return 1;
}

/* do_ssl3_write writes an SSL record of the given type. If |fragment| is 1
 * then it splits the record into a one byte record and a record with the rest
 * of the data in order to randomise a CBC IV. */
static int do_ssl3_write(SSL *s, int type, const uint8_t *buf, unsigned int len,
                         char fragment) {
  SSL3_BUFFER *wb = &s->s3->wbuf;

  /* first check if there is a SSL3_BUFFER still being written out. This will
   * happen with non blocking IO */
  if (wb->left != 0) {
    return ssl3_write_pending(s, type, buf, len);
  }

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
  if (len == 1) {
    /* No sense in fragmenting a one-byte record. */
    fragment = 0;
  }

  /* Align the output so the ciphertext is aligned to |SSL3_ALIGN_PAYLOAD|. */
  uintptr_t align;
  if (fragment) {
    /* Only CBC-mode ciphers require fragmenting. CBC-mode ciphertext is a
     * multiple of the block size which we may assume is aligned. Thus we only
     * need to account for a second copy of the record header. */
    align = (uintptr_t)wb->buf + 2 * SSL3_RT_HEADER_LENGTH;
  } else {
    align = (uintptr_t)wb->buf + SSL3_RT_HEADER_LENGTH;
  }
  align = (0 - align) & (SSL3_ALIGN_PAYLOAD - 1);
  uint8_t *out = wb->buf + align;
  wb->offset = align;
  size_t max_out = wb->len - wb->offset;

  const uint8_t *orig_buf = buf;
  unsigned int orig_len = len;
  size_t fragment_len = 0;
  if (fragment) {
    /* Write the first byte in its own record as a countermeasure against
     * known-IV weaknesses in CBC ciphersuites. (See
     * http://www.openssl.org/~bodo/tls-cbc.txt.) */
    if (!ssl3_seal_record(s, out, &fragment_len, max_out, type, buf, 1)) {
      return -1;
    }
    out += fragment_len;
    max_out -= fragment_len;
    buf++;
    len--;
  }

  assert((((uintptr_t)out + SSL3_RT_HEADER_LENGTH) & (SSL3_ALIGN_PAYLOAD - 1))
         == 0);
  size_t ciphertext_len;
  if (!ssl3_seal_record(s, out, &ciphertext_len, max_out, type, buf, len)) {
    return -1;
  }
  ciphertext_len += fragment_len;

  /* now let's set up wb */
  wb->left = ciphertext_len;

  /* memorize arguments so that ssl3_write_pending can detect bad write retries
   * later */
  s->s3->wpend_tot = orig_len;
  s->s3->wpend_buf = orig_buf;
  s->s3->wpend_type = type;
  s->s3->wpend_ret = orig_len;

  /* we now just need to write the buffer */
  return ssl3_write_pending(s, type, orig_buf, orig_len);
}

/* if s->s3->wbuf.left != 0, we need to call this */
int ssl3_write_pending(SSL *s, int type, const uint8_t *buf, unsigned int len) {
  int i;
  SSL3_BUFFER *wb = &(s->s3->wbuf);

  if (s->s3->wpend_tot > (int)len ||
      (s->s3->wpend_buf != buf &&
       !(s->mode & SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER)) ||
      s->s3->wpend_type != type) {
    OPENSSL_PUT_ERROR(SSL, ssl3_write_pending, SSL_R_BAD_WRITE_RETRY);
    return -1;
  }

  for (;;) {
    ERR_clear_system_error();
    if (s->wbio != NULL) {
      s->rwstate = SSL_WRITING;
      i = BIO_write(s->wbio, (char *)&(wb->buf[wb->offset]),
                    (unsigned int)wb->left);
    } else {
      OPENSSL_PUT_ERROR(SSL, ssl3_write_pending, SSL_R_BIO_NOT_SET);
      i = -1;
    }
    if (i == wb->left) {
      wb->left = 0;
      wb->offset += i;
      ssl3_release_write_buffer(s);
      s->rwstate = SSL_NOTHING;
      return s->s3->wpend_ret;
    } else if (i <= 0) {
      if (SSL_IS_DTLS(s)) {
        /* For DTLS, just drop it. That's kind of the whole point in
         * using a datagram service */
        wb->left = 0;
      }
      return i;
    }
    /* TODO(davidben): This codepath is used in DTLS, but the write
     * payload may not split across packets. */
    wb->offset += i;
    wb->left -= i;
  }
}

/* ssl3_expect_change_cipher_spec informs the record layer that a
 * ChangeCipherSpec record is required at this point. If a Handshake record is
 * received before ChangeCipherSpec, the connection will fail. Moreover, if
 * there are unprocessed handshake bytes, the handshake will also fail and the
 * function returns zero. Otherwise, the function returns one. */
int ssl3_expect_change_cipher_spec(SSL *s) {
  if (s->s3->handshake_fragment_len > 0 || s->s3->tmp.reuse_message) {
    OPENSSL_PUT_ERROR(SSL, ssl3_expect_change_cipher_spec,
                      SSL_R_UNPROCESSED_HANDSHAKE_DATA);
    return 0;
  }

  s->s3->flags |= SSL3_FLAGS_EXPECT_CCS;
  return 1;
}

int ssl3_read_app_data(SSL *ssl, uint8_t *buf, int len, int peek) {
  return ssl3_read_bytes(ssl, SSL3_RT_APPLICATION_DATA, buf, len, peek);
}

void ssl3_read_close_notify(SSL *ssl) {
  ssl3_read_bytes(ssl, 0, NULL, 0, 0);
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
int ssl3_read_bytes(SSL *s, int type, uint8_t *buf, int len, int peek) {
  int al, i, ret;
  unsigned int n;
  SSL3_RECORD *rr;
  void (*cb)(const SSL *ssl, int type2, int val) = NULL;

  if ((type && type != SSL3_RT_APPLICATION_DATA && type != SSL3_RT_HANDSHAKE) ||
      (peek && type != SSL3_RT_APPLICATION_DATA)) {
    OPENSSL_PUT_ERROR(SSL, ssl3_read_bytes, ERR_R_INTERNAL_ERROR);
    return -1;
  }

  if (type == SSL3_RT_HANDSHAKE && s->s3->handshake_fragment_len > 0) {
    /* (partially) satisfy request from storage */
    uint8_t *src = s->s3->handshake_fragment;
    uint8_t *dst = buf;
    unsigned int k;

    /* peek == 0 */
    n = 0;
    while (len > 0 && s->s3->handshake_fragment_len > 0) {
      *dst++ = *src++;
      len--;
      s->s3->handshake_fragment_len--;
      n++;
    }
    /* move any remaining fragment bytes: */
    for (k = 0; k < s->s3->handshake_fragment_len; k++) {
      s->s3->handshake_fragment[k] = *src++;
    }
    return n;
  }

  /* Now s->s3->handshake_fragment_len == 0 if type == SSL3_RT_HANDSHAKE. */

  /* This may require multiple iterations. False Start will cause
   * |s->handshake_func| to signal success one step early, but the handshake
   * must be completely finished before other modes are accepted.
   *
   * TODO(davidben): Move this check up to a higher level. */
  while (!s->in_handshake && SSL_in_init(s)) {
    assert(type == SSL3_RT_APPLICATION_DATA);
    i = s->handshake_func(s);
    if (i < 0) {
      return i;
    }
    if (i == 0) {
      OPENSSL_PUT_ERROR(SSL, ssl3_read_bytes, SSL_R_SSL_HANDSHAKE_FAILURE);
      return -1;
    }
  }

start:
  s->rwstate = SSL_NOTHING;

  /* s->s3->rrec.type    - is the type of record
   * s->s3->rrec.data    - data
   * s->s3->rrec.off     - offset into 'data' for next read
   * s->s3->rrec.length  - number of bytes. */
  rr = &s->s3->rrec;

  /* get new packet if necessary */
  if (rr->length == 0 || s->rstate == SSL_ST_READ_BODY) {
    ret = ssl3_get_record(s);
    if (ret <= 0) {
      return ret;
    }
  }

  /* we now have a packet which can be read and processed */

  /* |change_cipher_spec is set when we receive a ChangeCipherSpec and reset by
   * ssl3_get_finished. */
  if (s->s3->change_cipher_spec && rr->type != SSL3_RT_HANDSHAKE &&
      rr->type != SSL3_RT_ALERT) {
    al = SSL_AD_UNEXPECTED_MESSAGE;
    OPENSSL_PUT_ERROR(SSL, ssl3_read_bytes,
                      SSL_R_DATA_BETWEEN_CCS_AND_FINISHED);
    goto f_err;
  }

  /* If we are expecting a ChangeCipherSpec, it is illegal to receive a
   * Handshake record. */
  if (rr->type == SSL3_RT_HANDSHAKE && (s->s3->flags & SSL3_FLAGS_EXPECT_CCS)) {
    al = SSL_AD_UNEXPECTED_MESSAGE;
    OPENSSL_PUT_ERROR(SSL, ssl3_read_bytes, SSL_R_HANDSHAKE_RECORD_BEFORE_CCS);
    goto f_err;
  }

  /* If the other end has shut down, throw anything we read away (even in
   * 'peek' mode) */
  if (s->shutdown & SSL_RECEIVED_SHUTDOWN) {
    rr->length = 0;
    s->rwstate = SSL_NOTHING;
    return 0;
  }

  if (type == rr->type) {
    s->s3->warning_alert_count = 0;

    /* SSL3_RT_APPLICATION_DATA or SSL3_RT_HANDSHAKE */
    /* make sure that we are not getting application data when we are doing a
     * handshake for the first time */
    if (SSL_in_init(s) && type == SSL3_RT_APPLICATION_DATA &&
        s->aead_read_ctx == NULL) {
      /* TODO(davidben): Is this check redundant with the handshake_func
       * check? */
      al = SSL_AD_UNEXPECTED_MESSAGE;
      OPENSSL_PUT_ERROR(SSL, ssl3_read_bytes, SSL_R_APP_DATA_IN_HANDSHAKE);
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
        if (s->s3->rbuf.left == 0) {
          ssl3_release_read_buffer(s);
        }
      }
    }

    return n;
  }

  /* Process unexpected records. */

  if (rr->type == SSL3_RT_HANDSHAKE) {
    /* If peer renegotiations are disabled, all out-of-order handshake records
     * are fatal. Renegotiations as a server are never supported. */
    if (!s->accept_peer_renegotiations || s->server) {
      al = SSL_AD_NO_RENEGOTIATION;
      OPENSSL_PUT_ERROR(SSL, ssl3_read_bytes, SSL_R_NO_RENEGOTIATION);
      goto f_err;
    }

    /* HelloRequests may be fragmented across multiple records. */
    const size_t size = sizeof(s->s3->handshake_fragment);
    const size_t avail = size - s->s3->handshake_fragment_len;
    const size_t todo = (rr->length < avail) ? rr->length : avail;
    memcpy(s->s3->handshake_fragment + s->s3->handshake_fragment_len,
           &rr->data[rr->off], todo);
    rr->off += todo;
    rr->length -= todo;
    s->s3->handshake_fragment_len += todo;
    if (s->s3->handshake_fragment_len < size) {
      goto start; /* fragment was too small */
    }

    /* Parse out and consume a HelloRequest. */
    if (s->s3->handshake_fragment[0] != SSL3_MT_HELLO_REQUEST ||
        s->s3->handshake_fragment[1] != 0 ||
        s->s3->handshake_fragment[2] != 0 ||
        s->s3->handshake_fragment[3] != 0) {
      al = SSL_AD_DECODE_ERROR;
      OPENSSL_PUT_ERROR(SSL, ssl3_read_bytes, SSL_R_BAD_HELLO_REQUEST);
      goto f_err;
    }
    s->s3->handshake_fragment_len = 0;

    if (s->msg_callback) {
      s->msg_callback(0, s->version, SSL3_RT_HANDSHAKE,
                      s->s3->handshake_fragment, 4, s, s->msg_callback_arg);
    }

    if (!SSL_is_init_finished(s) || !s->s3->initial_handshake_complete) {
      /* This cannot happen. If a handshake is in progress, |type| must be
       * |SSL3_RT_HANDSHAKE|. */
      assert(0);
      OPENSSL_PUT_ERROR(SSL, ssl3_read_bytes, ERR_R_INTERNAL_ERROR);
      goto err;
    }

    /* Renegotiation is only supported at quiescent points in the application
     * protocol, namely in HTTPS, just before reading the HTTP response. Require
     * the record-layer be idle and avoid complexities of sending a handshake
     * record while an application_data record is being written. */
    if (s->s3->wbuf.left != 0 || s->s3->rbuf.left != 0) {
      al = SSL_AD_NO_RENEGOTIATION;
      OPENSSL_PUT_ERROR(SSL, ssl3_read_bytes, SSL_R_NO_RENEGOTIATION);
      goto f_err;
    }

    /* Begin a new handshake. */
    s->state = SSL_ST_CONNECT;
    i = s->handshake_func(s);
    if (i < 0) {
      return i;
    }
    if (i == 0) {
      OPENSSL_PUT_ERROR(SSL, ssl3_read_bytes, SSL_R_SSL_HANDSHAKE_FAILURE);
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

      /* This is a warning but we receive it if we requested renegotiation and
       * the peer denied it. Terminate with a fatal alert because if
       * application tried to renegotiatie it presumably had a good reason and
       * expects it to succeed.
       *
       * In future we might have a renegotiation where we don't care if the
       * peer refused it where we carry on. */
      else if (alert_descr == SSL_AD_NO_RENEGOTIATION) {
        al = SSL_AD_HANDSHAKE_FAILURE;
        OPENSSL_PUT_ERROR(SSL, ssl3_read_bytes, SSL_R_NO_RENEGOTIATION);
        goto f_err;
      }

      s->s3->warning_alert_count++;
      if (s->s3->warning_alert_count > kMaxWarningAlerts) {
        al = SSL_AD_UNEXPECTED_MESSAGE;
        OPENSSL_PUT_ERROR(SSL, ssl3_read_bytes, SSL_R_TOO_MANY_WARNING_ALERTS);
        goto f_err;
      }
    } else if (alert_level == SSL3_AL_FATAL) {
      char tmp[16];

      s->rwstate = SSL_NOTHING;
      s->s3->fatal_alert = alert_descr;
      OPENSSL_PUT_ERROR(SSL, ssl3_read_bytes,
                        SSL_AD_REASON_OFFSET + alert_descr);
      BIO_snprintf(tmp, sizeof(tmp), "%d", alert_descr);
      ERR_add_error_data(2, "SSL alert number ", tmp);
      s->shutdown |= SSL_RECEIVED_SHUTDOWN;
      SSL_CTX_remove_session(s->ctx, s->session);
      return 0;
    } else {
      al = SSL_AD_ILLEGAL_PARAMETER;
      OPENSSL_PUT_ERROR(SSL, ssl3_read_bytes, SSL_R_UNKNOWN_ALERT_TYPE);
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
      OPENSSL_PUT_ERROR(SSL, ssl3_read_bytes, SSL_R_BAD_CHANGE_CIPHER_SPEC);
      goto f_err;
    }

    /* Check we have a cipher to change to */
    if (s->s3->tmp.new_cipher == NULL) {
      al = SSL_AD_UNEXPECTED_MESSAGE;
      OPENSSL_PUT_ERROR(SSL, ssl3_read_bytes, SSL_R_CCS_RECEIVED_EARLY);
      goto f_err;
    }

    if (!(s->s3->flags & SSL3_FLAGS_EXPECT_CCS)) {
      al = SSL_AD_UNEXPECTED_MESSAGE;
      OPENSSL_PUT_ERROR(SSL, ssl3_read_bytes, SSL_R_CCS_RECEIVED_EARLY);
      goto f_err;
    }

    s->s3->flags &= ~SSL3_FLAGS_EXPECT_CCS;

    rr->length = 0;

    if (s->msg_callback) {
      s->msg_callback(0, s->version, SSL3_RT_CHANGE_CIPHER_SPEC, rr->data, 1, s,
                      s->msg_callback_arg);
    }

    s->s3->change_cipher_spec = 1;
    if (!ssl3_do_change_cipher_spec(s)) {
      goto err;
    } else {
      goto start;
    }
  }

  /* We already handled these. */
  assert(rr->type != SSL3_RT_CHANGE_CIPHER_SPEC && rr->type != SSL3_RT_ALERT &&
         rr->type != SSL3_RT_HANDSHAKE);

  al = SSL_AD_UNEXPECTED_MESSAGE;
  OPENSSL_PUT_ERROR(SSL, ssl3_read_bytes, SSL_R_UNEXPECTED_RECORD);

f_err:
  ssl3_send_alert(s, SSL3_AL_FATAL, al);
err:
  return -1;
}

int ssl3_do_change_cipher_spec(SSL *s) {
  int i;

  if (s->state & SSL_ST_ACCEPT) {
    i = SSL3_CHANGE_CIPHER_SERVER_READ;
  } else {
    i = SSL3_CHANGE_CIPHER_CLIENT_READ;
  }

  if (s->s3->tmp.key_block == NULL) {
    if (s->session == NULL || s->session->master_key_length == 0) {
      /* might happen if dtls1_read_bytes() calls this */
      OPENSSL_PUT_ERROR(SSL, ssl3_do_change_cipher_spec,
                        SSL_R_CCS_RECEIVED_EARLY);
      return 0;
    }

    s->session->cipher = s->s3->tmp.new_cipher;
    if (!s->enc_method->setup_key_block(s)) {
      return 0;
    }
  }

  if (!s->enc_method->change_cipher_state(s, i)) {
    return 0;
  }

  return 1;
}

int ssl3_send_alert(SSL *s, int level, int desc) {
  /* Map tls/ssl alert value to correct one */
  desc = s->enc_method->alert_value(desc);
  if (s->version == SSL3_VERSION && desc == SSL_AD_PROTOCOL_VERSION) {
    /* SSL 3.0 does not have protocol_version alerts */
    desc = SSL_AD_HANDSHAKE_FAILURE;
  }
  if (desc < 0) {
    return -1;
  }

  /* If a fatal one, remove from cache */
  if (level == 2 && s->session != NULL) {
    SSL_CTX_remove_session(s->ctx, s->session);
  }

  s->s3->alert_dispatch = 1;
  s->s3->send_alert[0] = level;
  s->s3->send_alert[1] = desc;
  if (s->s3->wbuf.left == 0) {
    /* data is still being written out. */
    return s->method->ssl_dispatch_alert(s);
  }

  /* else data is still being written out, we will get written some time in the
   * future */
  return -1;
}

int ssl3_dispatch_alert(SSL *s) {
  int i, j;
  void (*cb)(const SSL *ssl, int type, int val) = NULL;

  s->s3->alert_dispatch = 0;
  i = do_ssl3_write(s, SSL3_RT_ALERT, &s->s3->send_alert[0], 2, 0);
  if (i <= 0) {
    s->s3->alert_dispatch = 1;
  } else {
    /* Alert sent to BIO.  If it is important, flush it now. If the message
     * does not get sent due to non-blocking IO, we will not worry too much. */
    if (s->s3->send_alert[0] == SSL3_AL_FATAL) {
      BIO_flush(s->wbio);
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
