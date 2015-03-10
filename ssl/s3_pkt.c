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
#include <errno.h>
#include <limits.h>
#include <stdio.h>

#include <openssl/buf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/rand.h>

#include "ssl_locl.h"


static int do_ssl3_write(SSL *s, int type, const uint8_t *buf, unsigned int len,
                         char fragment, char is_fragment);
static int ssl3_get_record(SSL *s);

int ssl3_read_n(SSL *s, int n, int max, int extend) {
  /* If |extend| is 0, obtain new n-byte packet;
   * if |extend| is 1, increase packet by another n bytes.
   *
   * The packet will be in the sub-array of |s->s3->rbuf.buf| specified by
   * |s->packet| and |s->packet_length|. (If |s->read_ahead| is set, |max|
   * bytes may be stored in |rbuf| (plus |s->packet_length| bytes if |extend|
   * is one.) */
  int i, len, left;
  long align = 0;
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

  align = (long)rb->buf + SSL3_RT_HEADER_LENGTH;
  align = (-align) & (SSL3_ALIGN_PAYLOAD - 1);

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

  /* For DTLS/UDP reads should not span multiple packets because the read
   * operation returns the whole packet at once (as long as it fits into the
   * buffer). */
  if (SSL_IS_DTLS(s) && left > 0 && n > left) {
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

  if (!s->read_ahead) {
    /* ignore max parameter */
    max = n;
  } else {
    if (max < n) {
      max = n;
    }
    if (max > (int)(rb->len - rb->offset)) {
      max = rb->len - rb->offset;
    }
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
      if (s->mode & SSL_MODE_RELEASE_BUFFERS && !SSL_IS_DTLS(s) &&
          len + left == 0) {
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

/* MAX_EMPTY_RECORDS defines the number of consecutive, empty records that will
 * be processed per call to ssl3_get_record. Without this limit an attacker
 * could send empty records at a faster rate than we can process and cause
 * ssl3_get_record to loop forever. */
#define MAX_EMPTY_RECORDS 32

/* Call this to get a new input record. It will return <= 0 if more data is
 * needed, normally due to an error or non-blocking IO. When it finishes, one
 * packet has been decoded and can be found in
 * ssl->s3->rrec.type    - is the type of record
 * ssl->s3->rrec.data    - data
 * ssl->s3->rrec.length  - number of bytes */
/* used only by ssl3_read_bytes */
static int ssl3_get_record(SSL *s) {
  int ssl_major, ssl_minor, al;
  int n, i, ret = -1;
  SSL3_RECORD *rr;
  uint8_t *p;
  short version;
  size_t extra;
  unsigned empty_record_count = 0;

  rr = &s->s3->rrec;

  if (s->options & SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER) {
    extra = SSL3_RT_MAX_EXTRA;
  } else {
    extra = 0;
  }

  if (extra && !s->s3->init_extra) {
    /* An application error: SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER set after
     * ssl3_setup_buffers() was done */
    OPENSSL_PUT_ERROR(SSL, ssl3_get_record, ERR_R_INTERNAL_ERROR);
    return -1;
  }

again:
  /* check if we have the header */
  if (s->rstate != SSL_ST_READ_BODY ||
      s->packet_length < SSL3_RT_HEADER_LENGTH) {
    n = ssl3_read_n(s, SSL3_RT_HEADER_LENGTH, s->s3->rbuf.len, 0);
    if (n <= 0) {
      return n; /* error or non-blocking */
    }
    s->rstate = SSL_ST_READ_BODY;

    p = s->packet;
    if (s->msg_callback) {
      s->msg_callback(0, 0, SSL3_RT_HEADER, p, 5, s, s->msg_callback_arg);
    }

    /* Pull apart the header into the SSL3_RECORD */
    rr->type = *(p++);
    ssl_major = *(p++);
    ssl_minor = *(p++);
    version = (ssl_major << 8) | ssl_minor;
    n2s(p, rr->length);

    if (s->s3->have_version && version != s->version) {
      OPENSSL_PUT_ERROR(SSL, ssl3_get_record, SSL_R_WRONG_VERSION_NUMBER);
      if ((s->version & 0xFF00) == (version & 0xFF00)) {
        /* Send back error using their minor version number. */
        s->version = (unsigned short)version;
      }
      al = SSL_AD_PROTOCOL_VERSION;
      goto f_err;
    }

    if ((version >> 8) != SSL3_VERSION_MAJOR) {
      OPENSSL_PUT_ERROR(SSL, ssl3_get_record, SSL_R_WRONG_VERSION_NUMBER);
      goto err;
    }

    if (rr->length > s->s3->rbuf.len - SSL3_RT_HEADER_LENGTH) {
      al = SSL_AD_RECORD_OVERFLOW;
      OPENSSL_PUT_ERROR(SSL, ssl3_get_record, SSL_R_PACKET_LENGTH_TOO_LONG);
      goto f_err;
    }

    /* now s->rstate == SSL_ST_READ_BODY */
  }

  /* s->rstate == SSL_ST_READ_BODY, get and decode the data */

  if (rr->length > s->packet_length - SSL3_RT_HEADER_LENGTH) {
    /* now s->packet_length == SSL3_RT_HEADER_LENGTH */
    i = rr->length;
    n = ssl3_read_n(s, i, i, 1);
    if (n <= 0) {
      /* Error or non-blocking IO. Now |n| == |rr->length|, and
       * |s->packet_length| == |SSL3_RT_HEADER_LENGTH| + |rr->length|. */
      return n;
    }
  }

  s->rstate = SSL_ST_READ_HEADER; /* set state for later operations */

  /* At this point, s->packet_length == SSL3_RT_HEADER_LNGTH + rr->length, and
   * we have that many bytes in s->packet. */
  rr->input = &s->packet[SSL3_RT_HEADER_LENGTH];

  /* ok, we can now read from |s->packet| data into |rr|. |rr->input| points at
   * |rr->length| bytes, which need to be copied into |rr->data| by decryption.
   * When the data is 'copied' into the |rr->data| buffer, |rr->input| will be
   * pointed at the new buffer. */

  /* We now have - encrypted [ MAC [ compressed [ plain ] ] ]
   * rr->length bytes of encrypted compressed stuff. */

  /* check is not needed I believe */
  if (rr->length > SSL3_RT_MAX_ENCRYPTED_LENGTH + extra) {
    al = SSL_AD_RECORD_OVERFLOW;
    OPENSSL_PUT_ERROR(SSL, ssl3_get_record, SSL_R_ENCRYPTED_LENGTH_TOO_LONG);
    goto f_err;
  }

  /* decrypt in place in 'rr->input' */
  rr->data = rr->input;

  if (!s->enc_method->enc(s, 0)) {
    al = SSL_AD_BAD_RECORD_MAC;
    OPENSSL_PUT_ERROR(SSL, ssl3_get_record,
                      SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC);
    goto f_err;
  }

  if (rr->length > SSL3_RT_MAX_PLAIN_LENGTH + extra) {
    al = SSL_AD_RECORD_OVERFLOW;
    OPENSSL_PUT_ERROR(SSL, ssl3_get_record, SSL_R_DATA_LENGTH_TOO_LONG);
    goto f_err;
  }

  rr->off = 0;
  /* So at this point the following is true:
   * ssl->s3->rrec.type is the type of record;
   * ssl->s3->rrec.length is the number of bytes in the record;
   * ssl->s3->rrec.off is the offset to first valid byte;
   * ssl->s3->rrec.data is where to take bytes from (increment after use). */

  /* we have pulled in a full packet so zero things */
  s->packet_length = 0;

  /* just read a 0 length packet */
  if (rr->length == 0) {
    empty_record_count++;
    if (empty_record_count > MAX_EMPTY_RECORDS) {
      al = SSL_AD_UNEXPECTED_MESSAGE;
      OPENSSL_PUT_ERROR(SSL, ssl3_get_record, SSL_R_TOO_MANY_EMPTY_FRAGMENTS);
      goto f_err;
    }
    goto again;
  }

  return 1;

f_err:
  ssl3_send_alert(s, SSL3_AL_FATAL, al);
err:
  return ret;
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

  n = (len - tot);
  for (;;) {
    /* max contains the maximum number of bytes that we can put into a
     * record. */
    unsigned max = s->max_send_fragment;
    /* fragment is true if do_ssl3_write should send the first byte in its own
     * record in order to randomise a CBC IV. */
    int fragment = 0;

    if (n > 1 && s->s3->need_record_splitting &&
        type == SSL3_RT_APPLICATION_DATA && !s->s3->record_split_done) {
      fragment = 1;
      /* record_split_done records that the splitting has been done in case we
       * hit an SSL_WANT_WRITE condition. In that case, we don't need to do the
       * split again. */
      s->s3->record_split_done = 1;
    }

    if (n > max) {
      nw = max;
    } else {
      nw = n;
    }

    i = do_ssl3_write(s, type, &(buf[tot]), nw, fragment, 0);
    if (i <= 0) {
      s->s3->wnum = tot;
      s->s3->record_split_done = 0;
      return i;
    }

    if (i == (int)n || (type == SSL3_RT_APPLICATION_DATA &&
                        (s->mode & SSL_MODE_ENABLE_PARTIAL_WRITE))) {
      /* next chunk of data should get another prepended, one-byte fragment in
       * ciphersuites with known-IV weakness. */
      s->s3->record_split_done = 0;
      return tot + i;
    }

    n -= i;
    tot += i;
  }
}

/* do_ssl3_write writes an SSL record of the given type. If |fragment| is 1
 * then it splits the record into a one byte record and a record with the rest
 * of the data in order to randomise a CBC IV. If |is_fragment| is true then
 * this call resulted from do_ssl3_write calling itself in order to create that
 * one byte fragment. */
static int do_ssl3_write(SSL *s, int type, const uint8_t *buf, unsigned int len,
                         char fragment, char is_fragment) {
  uint8_t *p, *plen;
  int i;
  int prefix_len = 0;
  int eivlen = 0;
  long align = 0;
  SSL3_RECORD *wr;
  SSL3_BUFFER *wb = &(s->s3->wbuf);

  /* first check if there is a SSL3_BUFFER still being written out. This will
   * happen with non blocking IO */
  if (wb->left != 0) {
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

  if (wb->buf == NULL && !ssl3_setup_write_buffer(s)) {
    return -1;
  }

  if (len == 0) {
    return 0;
  }

  wr = &s->s3->wrec;

  if (fragment) {
    /* countermeasure against known-IV weakness in CBC ciphersuites (see
     * http://www.openssl.org/~bodo/tls-cbc.txt) */
    prefix_len = do_ssl3_write(s, type, buf, 1 /* length */, 0 /* fragment */,
                               1 /* is_fragment */);
    if (prefix_len <= 0) {
      goto err;
    }

    if (prefix_len >
        (SSL3_RT_HEADER_LENGTH + SSL3_RT_SEND_MAX_ENCRYPTED_OVERHEAD)) {
      /* insufficient space */
      OPENSSL_PUT_ERROR(SSL, do_ssl3_write, ERR_R_INTERNAL_ERROR);
      goto err;
    }
  }

  if (is_fragment) {
    /* The extra fragment would be couple of cipher blocks, and that will be a
     * multiple of SSL3_ALIGN_PAYLOAD. So, if we want to align the real
     * payload, we can just pretend that we have two headers and a byte. */
    align = (long)wb->buf + 2 * SSL3_RT_HEADER_LENGTH + 1;
    align = (-align) & (SSL3_ALIGN_PAYLOAD - 1);
    p = wb->buf + align;
    wb->offset = align;
  } else if (prefix_len) {
    p = wb->buf + wb->offset + prefix_len;
  } else {
    align = (long)wb->buf + SSL3_RT_HEADER_LENGTH;
    align = (-align) & (SSL3_ALIGN_PAYLOAD - 1);
    p = wb->buf + align;
    wb->offset = align;
  }

  /* write the header */

  *(p++) = type & 0xff;
  wr->type = type;

  /* Some servers hang if initial ClientHello is larger than 256 bytes and
   * record version number > TLS 1.0. */
  if (!s->s3->have_version && s->version > SSL3_VERSION) {
    *(p++) = TLS1_VERSION >> 8;
    *(p++) = TLS1_VERSION & 0xff;
  } else {
    *(p++) = s->version >> 8;
    *(p++) = s->version & 0xff;
  }

  /* field where we are to write out packet length */
  plen = p;
  p += 2;

  /* Leave room for the variable nonce for AEADs which specify it explicitly. */
  if (s->aead_write_ctx != NULL &&
      s->aead_write_ctx->variable_nonce_included_in_record) {
    eivlen = s->aead_write_ctx->variable_nonce_len;
  }

  /* lets setup the record stuff. */
  wr->data = p + eivlen;
  wr->length = (int)(len - (fragment != 0));
  wr->input = (uint8_t *)buf + (fragment != 0);

  /* we now 'read' from wr->input, wr->length bytes into wr->data */

  memcpy(wr->data, wr->input, wr->length);
  wr->input = wr->data;

  /* we should still have the output to wr->data and the input from wr->input.
   * Length should be wr->length. wr->data still points in the wb->buf */

  wr->input = p;
  wr->data = p;
  wr->length += eivlen;

  if (!s->enc_method->enc(s, 1)) {
    goto err;
  }

  /* record length after mac and block padding */
  s2n(wr->length, plen);

  if (s->msg_callback) {
    s->msg_callback(1, 0, SSL3_RT_HEADER, plen - 5, 5, s, s->msg_callback_arg);
  }

  /* we should now have wr->data pointing to the encrypted data, which is
   * wr->length long. */
  wr->type = type; /* not needed but helps for debugging */
  wr->length += SSL3_RT_HEADER_LENGTH;

  if (is_fragment) {
    /* we are in a recursive call; just return the length, don't write out
     * anything. */
    return wr->length;
  }

  /* now let's set up wb */
  wb->left = prefix_len + wr->length;

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
      if (s->mode & SSL_MODE_RELEASE_BUFFERS && !SSL_IS_DTLS(s)) {
        ssl3_release_write_buffer(s);
      }
      s->rwstate = SSL_NOTHING;
      return s->s3->wpend_ret;
    } else if (i <= 0) {
      if (SSL_IS_DTLS(s)) {
        /* For DTLS, just drop it. That's kind of the whole
           point in using a datagram service */
        wb->left = 0;
      }
      return i;
    }
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

  if (s->s3->rbuf.buf == NULL && !ssl3_setup_read_buffer(s)) {
    /* TODO(davidben): Is this redundant with the calls in the handshake? */
    return -1;
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

  if (s->s3->change_cipher_spec /* set when we receive ChangeCipherSpec,
                                 * reset by ssl3_get_finished */
      && rr->type != SSL3_RT_HANDSHAKE) {
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
        if (s->mode & SSL_MODE_RELEASE_BUFFERS && s->s3->rbuf.left == 0) {
          ssl3_release_read_buffer(s);
        }
      }
    }

    return n;
  }


  /* If we get here, then type != rr->type; if we have a handshake message,
   * then it was unexpected (Hello Request or Client Hello). */

  /* In case of record types for which we have 'fragment' storage, fill that so
   * that we can process the data at a fixed place. */

  if (rr->type == SSL3_RT_HANDSHAKE) {
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
  }

  /* s->s3->handshake_fragment_len == 4  iff  rr->type == SSL3_RT_HANDSHAKE;
   * (Possibly rr is 'empty' now, i.e. rr->length may be 0.) */

  /* If we are a client, check for an incoming 'Hello Request': */
  if (!s->server && s->s3->handshake_fragment_len >= 4 &&
      s->s3->handshake_fragment[0] == SSL3_MT_HELLO_REQUEST &&
      s->session != NULL && s->session->cipher != NULL) {
    s->s3->handshake_fragment_len = 0;

    if (s->s3->handshake_fragment[1] != 0 ||
        s->s3->handshake_fragment[2] != 0 ||
        s->s3->handshake_fragment[3] != 0) {
      al = SSL_AD_DECODE_ERROR;
      OPENSSL_PUT_ERROR(SSL, ssl3_read_bytes, SSL_R_BAD_HELLO_REQUEST);
      goto f_err;
    }

    if (s->msg_callback) {
      s->msg_callback(0, s->version, SSL3_RT_HANDSHAKE,
                      s->s3->handshake_fragment, 4, s, s->msg_callback_arg);
    }

    if (SSL_is_init_finished(s) && !s->s3->renegotiate) {
      ssl3_renegotiate(s);
      if (ssl3_renegotiate_check(s)) {
        i = s->handshake_func(s);
        if (i < 0) {
          return i;
        }
        if (i == 0) {
          OPENSSL_PUT_ERROR(SSL, ssl3_read_bytes, SSL_R_SSL_HANDSHAKE_FAILURE);
          return -1;
        }
      }
    }
    /* we either finished a handshake or ignored the request, now try again to
     * obtain the (application) data we were asked for */
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

  /* Unexpected handshake message (Client Hello, or protocol violation) */
  if (s->s3->handshake_fragment_len >= 4 && !s->in_handshake) {
    if ((s->state & SSL_ST_MASK) == SSL_ST_OK) {
      s->state = s->server ? SSL_ST_ACCEPT : SSL_ST_CONNECT;
      s->renegotiate = 1;
      s->new_session = 1;
    }
    i = s->handshake_func(s);
    if (i < 0) {
      return i;
    }
    if (i == 0) {
      OPENSSL_PUT_ERROR(SSL, ssl3_read_bytes, SSL_R_SSL_HANDSHAKE_FAILURE);
      return -1;
    }

    goto start;
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
  i = do_ssl3_write(s, SSL3_RT_ALERT, &s->s3->send_alert[0], 2, 0, 0);
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
