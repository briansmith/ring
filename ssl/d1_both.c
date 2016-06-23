/*
 * DTLS implementation written by Nagendra Modadugu
 * (nagendra@cs.stanford.edu) for the OpenSSL project 2005. 
 */
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
#include <limits.h>
#include <string.h>

#include <openssl/buf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include "internal.h"


/* TODO(davidben): 28 comes from the size of IP + UDP header. Is this reasonable
 * for these values? Notably, why is kMinMTU a function of the transport
 * protocol's overhead rather than, say, what's needed to hold a minimally-sized
 * handshake fragment plus protocol overhead. */

/* kMinMTU is the minimum acceptable MTU value. */
static const unsigned int kMinMTU = 256 - 28;

/* kDefaultMTU is the default MTU value to use if neither the user nor
 * the underlying BIO supplies one. */
static const unsigned int kDefaultMTU = 1500 - 28;


/* Receiving handshake messages. */

static void dtls1_hm_fragment_free(hm_fragment *frag) {
  if (frag == NULL) {
    return;
  }
  OPENSSL_free(frag->fragment);
  OPENSSL_free(frag->reassembly);
  OPENSSL_free(frag);
}

static hm_fragment *dtls1_hm_fragment_new(size_t frag_len) {
  hm_fragment *frag = OPENSSL_malloc(sizeof(hm_fragment));
  if (frag == NULL) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
    return NULL;
  }
  memset(frag, 0, sizeof(hm_fragment));

  /* If the handshake message is empty, |frag->fragment| and |frag->reassembly|
   * are NULL. */
  if (frag_len > 0) {
    frag->fragment = OPENSSL_malloc(frag_len);
    if (frag->fragment == NULL) {
      OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
      goto err;
    }

    /* Initialize reassembly bitmask. */
    if (frag_len + 7 < frag_len) {
      OPENSSL_PUT_ERROR(SSL, ERR_R_OVERFLOW);
      goto err;
    }
    size_t bitmask_len = (frag_len + 7) / 8;
    frag->reassembly = OPENSSL_malloc(bitmask_len);
    if (frag->reassembly == NULL) {
      OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
      goto err;
    }
    memset(frag->reassembly, 0, bitmask_len);
  }

  return frag;

err:
  dtls1_hm_fragment_free(frag);
  return NULL;
}

/* bit_range returns a |uint8_t| with bits |start|, inclusive, to |end|,
 * exclusive, set. */
static uint8_t bit_range(size_t start, size_t end) {
  return (uint8_t)(~((1u << start) - 1) & ((1u << end) - 1));
}

/* dtls1_hm_fragment_mark marks bytes |start|, inclusive, to |end|, exclusive,
 * as received in |frag|. If |frag| becomes complete, it clears
 * |frag->reassembly|. The range must be within the bounds of |frag|'s message
 * and |frag->reassembly| must not be NULL. */
static void dtls1_hm_fragment_mark(hm_fragment *frag, size_t start,
                                   size_t end) {
  size_t i;
  size_t msg_len = frag->msg_header.msg_len;

  if (frag->reassembly == NULL || start > end || end > msg_len) {
    assert(0);
    return;
  }
  /* A zero-length message will never have a pending reassembly. */
  assert(msg_len > 0);

  if ((start >> 3) == (end >> 3)) {
    frag->reassembly[start >> 3] |= bit_range(start & 7, end & 7);
  } else {
    frag->reassembly[start >> 3] |= bit_range(start & 7, 8);
    for (i = (start >> 3) + 1; i < (end >> 3); i++) {
      frag->reassembly[i] = 0xff;
    }
    if ((end & 7) != 0) {
      frag->reassembly[end >> 3] |= bit_range(0, end & 7);
    }
  }

  /* Check if the fragment is complete. */
  for (i = 0; i < (msg_len >> 3); i++) {
    if (frag->reassembly[i] != 0xff) {
      return;
    }
  }
  if ((msg_len & 7) != 0 &&
      frag->reassembly[msg_len >> 3] != bit_range(0, msg_len & 7)) {
    return;
  }

  OPENSSL_free(frag->reassembly);
  frag->reassembly = NULL;
}

/* dtls1_is_next_message_complete returns one if the next handshake message is
 * complete and zero otherwise. */
static int dtls1_is_next_message_complete(SSL *ssl) {
  hm_fragment *frag = ssl->d1->incoming_messages[ssl->d1->handshake_read_seq %
                                                 SSL_MAX_HANDSHAKE_FLIGHT];
  return frag != NULL && frag->reassembly == NULL;
}

/* dtls1_get_incoming_message returns the incoming message corresponding to
 * |msg_hdr|. If none exists, it creates a new one and inserts it in the
 * queue. Otherwise, it checks |msg_hdr| is consistent with the existing one. It
 * returns NULL on failure. The caller does not take ownership of the result. */
static hm_fragment *dtls1_get_incoming_message(
    SSL *ssl, const struct hm_header_st *msg_hdr) {
  if (msg_hdr->seq < ssl->d1->handshake_read_seq ||
      msg_hdr->seq - ssl->d1->handshake_read_seq >= SSL_MAX_HANDSHAKE_FLIGHT) {
    return NULL;
  }

  size_t idx = msg_hdr->seq % SSL_MAX_HANDSHAKE_FLIGHT;
  hm_fragment *frag = ssl->d1->incoming_messages[idx];
  if (frag != NULL) {
    assert(frag->msg_header.seq == msg_hdr->seq);
    /* The new fragment must be compatible with the previous fragments from this
     * message. */
    if (frag->msg_header.type != msg_hdr->type ||
        frag->msg_header.msg_len != msg_hdr->msg_len) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_FRAGMENT_MISMATCH);
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_ILLEGAL_PARAMETER);
      return NULL;
    }
    return frag;
  }

  /* This is the first fragment from this message. */
  frag = dtls1_hm_fragment_new(msg_hdr->msg_len);
  if (frag == NULL) {
    return NULL;
  }
  memcpy(&frag->msg_header, msg_hdr, sizeof(*msg_hdr));
  ssl->d1->incoming_messages[idx] = frag;
  return frag;
}

/* dtls1_process_handshake_record reads a handshake record and processes it. It
 * returns one if the record was successfully processed and 0 or -1 on error. */
static int dtls1_process_handshake_record(SSL *ssl) {
  SSL3_RECORD *rr = &ssl->s3->rrec;

start:
  if (rr->length == 0) {
    int ret = dtls1_get_record(ssl);
    if (ret <= 0) {
      return ret;
    }
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

  if (rr->type != SSL3_RT_HANDSHAKE) {
    ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_UNEXPECTED_MESSAGE);
    OPENSSL_PUT_ERROR(SSL, SSL_R_UNEXPECTED_RECORD);
    return -1;
  }

  CBS cbs;
  CBS_init(&cbs, rr->data, rr->length);

  while (CBS_len(&cbs) > 0) {
    /* Read a handshake fragment. */
    struct hm_header_st msg_hdr;
    CBS body;
    if (!dtls1_parse_fragment(&cbs, &msg_hdr, &body)) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_BAD_HANDSHAKE_RECORD);
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
      return -1;
    }

    const size_t frag_off = msg_hdr.frag_off;
    const size_t frag_len = msg_hdr.frag_len;
    const size_t msg_len = msg_hdr.msg_len;
    if (frag_off > msg_len || frag_off + frag_len < frag_off ||
        frag_off + frag_len > msg_len ||
        msg_len > ssl_max_handshake_message_len(ssl)) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_EXCESSIVE_MESSAGE_SIZE);
      ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_ILLEGAL_PARAMETER);
      return -1;
    }

    if (msg_hdr.seq < ssl->d1->handshake_read_seq ||
        msg_hdr.seq >
            (unsigned)ssl->d1->handshake_read_seq + SSL_MAX_HANDSHAKE_FLIGHT) {
      /* Ignore fragments from the past, or ones too far in the future. */
      continue;
    }

    hm_fragment *frag = dtls1_get_incoming_message(ssl, &msg_hdr);
    if (frag == NULL) {
      return -1;
    }
    assert(frag->msg_header.msg_len == msg_len);

    if (frag->reassembly == NULL) {
      /* The message is already assembled. */
      continue;
    }
    assert(msg_len > 0);

    /* Copy the body into the fragment. */
    memcpy(frag->fragment + frag_off, CBS_data(&body), CBS_len(&body));
    dtls1_hm_fragment_mark(frag, frag_off, frag_off + frag_len);
  }

  rr->length = 0;
  ssl_read_buffer_discard(ssl);
  return 1;
}

/* dtls1_get_message reads a handshake message of message type |msg_type| (any
 * if |msg_type| == -1). Read an entire handshake message. Handshake messages
 * arrive in fragments. */
long dtls1_get_message(SSL *ssl, int msg_type,
                       enum ssl_hash_message_t hash_message, int *ok) {
  hm_fragment *frag = NULL;
  int al;

  /* s3->tmp is used to store messages that are unexpected, caused
   * by the absence of an optional handshake message */
  if (ssl->s3->tmp.reuse_message) {
    /* A ssl_dont_hash_message call cannot be combined with reuse_message; the
     * ssl_dont_hash_message would have to have been applied to the previous
     * call. */
    assert(hash_message == ssl_hash_message);
    ssl->s3->tmp.reuse_message = 0;
    if (msg_type >= 0 && ssl->s3->tmp.message_type != msg_type) {
      al = SSL_AD_UNEXPECTED_MESSAGE;
      OPENSSL_PUT_ERROR(SSL, SSL_R_UNEXPECTED_MESSAGE);
      goto f_err;
    }
    *ok = 1;
    assert(ssl->init_buf->length >= DTLS1_HM_HEADER_LENGTH);
    ssl->init_msg = (uint8_t *)ssl->init_buf->data + DTLS1_HM_HEADER_LENGTH;
    ssl->init_num = (int)ssl->init_buf->length - DTLS1_HM_HEADER_LENGTH;
    return ssl->init_num;
  }

  /* Process handshake records until the next message is ready. */
  while (!dtls1_is_next_message_complete(ssl)) {
    int ret = dtls1_process_handshake_record(ssl);
    if (ret <= 0) {
      *ok = 0;
      return ret;
    }
  }

  /* Pop an entry from the ring buffer. */
  frag = ssl->d1->incoming_messages[ssl->d1->handshake_read_seq %
                                    SSL_MAX_HANDSHAKE_FLIGHT];
  ssl->d1->incoming_messages[ssl->d1->handshake_read_seq %
                             SSL_MAX_HANDSHAKE_FLIGHT] = NULL;

  assert(frag != NULL);
  assert(frag->reassembly == NULL);
  assert(ssl->d1->handshake_read_seq == frag->msg_header.seq);

  ssl->d1->handshake_read_seq++;

  /* Reconstruct the assembled message. */
  CBB cbb;
  CBB_zero(&cbb);
  if (!BUF_MEM_reserve(ssl->init_buf, (size_t)frag->msg_header.msg_len +
                                          DTLS1_HM_HEADER_LENGTH) ||
      !CBB_init_fixed(&cbb, (uint8_t *)ssl->init_buf->data,
                      ssl->init_buf->max) ||
      !CBB_add_u8(&cbb, frag->msg_header.type) ||
      !CBB_add_u24(&cbb, frag->msg_header.msg_len) ||
      !CBB_add_u16(&cbb, frag->msg_header.seq) ||
      !CBB_add_u24(&cbb, 0 /* frag_off */) ||
      !CBB_add_u24(&cbb, frag->msg_header.msg_len) ||
      !CBB_add_bytes(&cbb, frag->fragment, frag->msg_header.msg_len) ||
      !CBB_finish(&cbb, NULL, &ssl->init_buf->length)) {
    CBB_cleanup(&cbb);
    OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
    goto err;
  }
  assert(ssl->init_buf->length ==
         (size_t)frag->msg_header.msg_len + DTLS1_HM_HEADER_LENGTH);

  /* TODO(davidben): This function has a lot of implicit outputs. Simplify the
   * |ssl_get_message| API. */
  ssl->s3->tmp.message_type = frag->msg_header.type;
  ssl->init_msg = (uint8_t *)ssl->init_buf->data + DTLS1_HM_HEADER_LENGTH;
  ssl->init_num = frag->msg_header.msg_len;

  if (msg_type >= 0 && ssl->s3->tmp.message_type != msg_type) {
    al = SSL_AD_UNEXPECTED_MESSAGE;
    OPENSSL_PUT_ERROR(SSL, SSL_R_UNEXPECTED_MESSAGE);
    goto f_err;
  }
  if (hash_message == ssl_hash_message && !ssl3_hash_current_message(ssl)) {
    goto err;
  }

  ssl_do_msg_callback(ssl, 0 /* read */, ssl->version, SSL3_RT_HANDSHAKE,
                      ssl->init_buf->data,
                      ssl->init_num + DTLS1_HM_HEADER_LENGTH);

  dtls1_hm_fragment_free(frag);

  *ok = 1;
  return ssl->init_num;

f_err:
  ssl3_send_alert(ssl, SSL3_AL_FATAL, al);
err:
  dtls1_hm_fragment_free(frag);
  *ok = 0;
  return -1;
}

void dtls_clear_incoming_messages(SSL *ssl) {
  size_t i;
  for (i = 0; i < SSL_MAX_HANDSHAKE_FLIGHT; i++) {
    dtls1_hm_fragment_free(ssl->d1->incoming_messages[i]);
    ssl->d1->incoming_messages[i] = NULL;
  }
}

int dtls1_parse_fragment(CBS *cbs, struct hm_header_st *out_hdr,
                         CBS *out_body) {
  memset(out_hdr, 0x00, sizeof(struct hm_header_st));

  if (!CBS_get_u8(cbs, &out_hdr->type) ||
      !CBS_get_u24(cbs, &out_hdr->msg_len) ||
      !CBS_get_u16(cbs, &out_hdr->seq) ||
      !CBS_get_u24(cbs, &out_hdr->frag_off) ||
      !CBS_get_u24(cbs, &out_hdr->frag_len) ||
      !CBS_get_bytes(cbs, out_body, out_hdr->frag_len)) {
    return 0;
  }

  return 1;
}


/* Sending handshake messages. */

static void dtls1_update_mtu(SSL *ssl) {
  /* TODO(davidben): What is this code doing and do we need it? */
  if (ssl->d1->mtu < dtls1_min_mtu() &&
      !(SSL_get_options(ssl) & SSL_OP_NO_QUERY_MTU)) {
    long mtu = BIO_ctrl(ssl->wbio, BIO_CTRL_DGRAM_QUERY_MTU, 0, NULL);
    if (mtu >= 0 && mtu <= (1 << 30) && (unsigned)mtu >= dtls1_min_mtu()) {
      ssl->d1->mtu = (unsigned)mtu;
    } else {
      ssl->d1->mtu = kDefaultMTU;
      BIO_ctrl(ssl->wbio, BIO_CTRL_DGRAM_SET_MTU, ssl->d1->mtu, NULL);
    }
  }

  /* The MTU should be above the minimum now. */
  assert(ssl->d1->mtu >= dtls1_min_mtu());
}

/* dtls1_max_record_size returns the maximum record body length that may be
 * written without exceeding the MTU. It accounts for any buffering installed on
 * the write BIO. If no record may be written, it returns zero. */
static size_t dtls1_max_record_size(SSL *ssl) {
  size_t ret = ssl->d1->mtu;

  size_t overhead = ssl_max_seal_overhead(ssl);
  if (ret <= overhead) {
    return 0;
  }
  ret -= overhead;

  size_t pending = BIO_wpending(ssl->wbio);
  if (ret <= pending) {
    return 0;
  }
  ret -= pending;

  return ret;
}

static int dtls1_write_change_cipher_spec(SSL *ssl,
                                          enum dtls1_use_epoch_t use_epoch) {
  dtls1_update_mtu(ssl);

  /* During the handshake, wbio is buffered to pack messages together. Flush the
   * buffer if the ChangeCipherSpec would not fit in a packet. */
  if (dtls1_max_record_size(ssl) == 0) {
    int ret = BIO_flush(ssl->wbio);
    if (ret <= 0) {
      ssl->rwstate = SSL_WRITING;
      return ret;
    }
  }

  static const uint8_t kChangeCipherSpec[1] = {SSL3_MT_CCS};
  int ret =
      dtls1_write_record(ssl, SSL3_RT_CHANGE_CIPHER_SPEC, kChangeCipherSpec,
                         sizeof(kChangeCipherSpec), use_epoch);
  if (ret <= 0) {
    return ret;
  }

  ssl_do_msg_callback(ssl, 1 /* write */, ssl->version,
                      SSL3_RT_CHANGE_CIPHER_SPEC, kChangeCipherSpec,
                      sizeof(kChangeCipherSpec));
  return 1;
}

/* dtls1_do_handshake_write writes handshake message |in| using the given epoch,
 * starting |offset| bytes into the message body. It returns one on success. On
 * error, it returns <= 0 and sets |*out_offset| to the number of bytes of body
 * that were successfully written. This may be used to retry the write
 * later. |in| must be a reassembled handshake message with the full DTLS
 * handshake header. */
static int dtls1_do_handshake_write(SSL *ssl, size_t *out_offset,
                                    const uint8_t *in, size_t offset,
                                    size_t len,
                                    enum dtls1_use_epoch_t use_epoch) {
  dtls1_update_mtu(ssl);

  int ret = -1;
  CBB cbb;
  CBB_zero(&cbb);
  /* Allocate a temporary buffer to hold the message fragments to avoid
   * clobbering the message. */
  uint8_t *buf = OPENSSL_malloc(ssl->d1->mtu);
  if (buf == NULL) {
    goto err;
  }

  /* Although it may be sent as multiple fragments, a DTLS message must be sent
   * serialized as a single fragment for purposes of |ssl_do_msg_callback| and
   * the handshake hash. */
  CBS cbs, body;
  struct hm_header_st hdr;
  CBS_init(&cbs, in, len);
  if (!dtls1_parse_fragment(&cbs, &hdr, &body) ||
      hdr.frag_off != 0 ||
      hdr.frag_len != CBS_len(&body) ||
      hdr.msg_len != CBS_len(&body) ||
      !CBS_skip(&body, offset) ||
      CBS_len(&cbs) != 0) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
    goto err;
  }

  do {
    /* During the handshake, wbio is buffered to pack messages together. Flush
     * the buffer if there isn't enough room to make progress. */
    if (dtls1_max_record_size(ssl) < DTLS1_HM_HEADER_LENGTH + 1) {
      int flush_ret = BIO_flush(ssl->wbio);
      if (flush_ret <= 0) {
        ssl->rwstate = SSL_WRITING;
        ret = flush_ret;
        goto err;
      }
      assert(BIO_wpending(ssl->wbio) == 0);
    }

    size_t todo = dtls1_max_record_size(ssl);
    if (todo < DTLS1_HM_HEADER_LENGTH + 1) {
      /* To make forward progress, the MTU must, at minimum, fit the handshake
       * header and one byte of handshake body. */
      OPENSSL_PUT_ERROR(SSL, SSL_R_MTU_TOO_SMALL);
      goto err;
    }
    todo -= DTLS1_HM_HEADER_LENGTH;

    if (todo > CBS_len(&body)) {
      todo = CBS_len(&body);
    }
    if (todo >= (1u << 24)) {
      todo = (1u << 24) - 1;
    }

    size_t buf_len;
    if (!CBB_init_fixed(&cbb, buf, ssl->d1->mtu) ||
        !CBB_add_u8(&cbb, hdr.type) ||
        !CBB_add_u24(&cbb, hdr.msg_len) ||
        !CBB_add_u16(&cbb, hdr.seq) ||
        !CBB_add_u24(&cbb, offset) ||
        !CBB_add_u24(&cbb, todo) ||
        !CBB_add_bytes(&cbb, CBS_data(&body), todo) ||
        !CBB_finish(&cbb, NULL, &buf_len)) {
      OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
      goto err;
    }

    int write_ret =
        dtls1_write_record(ssl, SSL3_RT_HANDSHAKE, buf, buf_len, use_epoch);
    if (write_ret <= 0) {
      ret = write_ret;
      goto err;
    }

    if (!CBS_skip(&body, todo)) {
      OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
      goto err;
    }
    offset += todo;
  } while (CBS_len(&body) != 0);

  ssl_do_msg_callback(ssl, 1 /* write */, ssl->version, SSL3_RT_HANDSHAKE, in,
                      len);

  ret = 1;

err:
  *out_offset = offset;
  CBB_cleanup(&cbb);
  OPENSSL_free(buf);
  return ret;
}

void dtls_clear_outgoing_messages(SSL *ssl) {
  size_t i;
  for (i = 0; i < ssl->d1->outgoing_messages_len; i++) {
    OPENSSL_free(ssl->d1->outgoing_messages[i].data);
    ssl->d1->outgoing_messages[i].data = NULL;
  }
  ssl->d1->outgoing_messages_len = 0;
}

/* dtls1_add_change_cipher_spec adds a ChangeCipherSpec to the current
 * handshake flight. */
static int dtls1_add_change_cipher_spec(SSL *ssl) {
  if (ssl->d1->outgoing_messages_len >= SSL_MAX_HANDSHAKE_FLIGHT) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
    return 0;
  }

  DTLS_OUTGOING_MESSAGE *msg =
      &ssl->d1->outgoing_messages[ssl->d1->outgoing_messages_len];
  msg->data = NULL;
  msg->len = 0;
  msg->epoch = ssl->d1->w_epoch;
  msg->is_ccs = 1;

  ssl->d1->outgoing_messages_len++;
  return 1;
}

static int dtls1_add_message(SSL *ssl, uint8_t *data, size_t len) {
  if (ssl->d1->outgoing_messages_len >= SSL_MAX_HANDSHAKE_FLIGHT) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
    OPENSSL_free(data);
    return 0;
  }

  DTLS_OUTGOING_MESSAGE *msg =
      &ssl->d1->outgoing_messages[ssl->d1->outgoing_messages_len];
  msg->data = data;
  msg->len = len;
  msg->epoch = ssl->d1->w_epoch;
  msg->is_ccs = 0;

  ssl->d1->outgoing_messages_len++;
  return 1;
}

int dtls1_init_message(SSL *ssl, CBB *cbb, CBB *body, uint8_t type) {
  /* Pick a modest size hint to save most of the |realloc| calls. */
  if (!CBB_init(cbb, 64) ||
      !CBB_add_u8(cbb, type) ||
      !CBB_add_u24(cbb, 0 /* length (filled in later) */) ||
      !CBB_add_u16(cbb, ssl->d1->handshake_write_seq) ||
      !CBB_add_u24(cbb, 0 /* offset */) ||
      !CBB_add_u24_length_prefixed(cbb, body)) {
    return 0;
  }

  return 1;
}

int dtls1_finish_message(SSL *ssl, CBB *cbb) {
  uint8_t *msg = NULL;
  size_t len;
  if (!CBB_finish(cbb, &msg, &len) ||
      len > 0xffffffffu ||
      len < DTLS1_HM_HEADER_LENGTH) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
    OPENSSL_free(msg);
    return 0;
  }

  /* Fix up the header. Copy the fragment length into the total message
   * length. */
  memcpy(msg + 1, msg + DTLS1_HM_HEADER_LENGTH - 3, 3);

  ssl3_update_handshake_hash(ssl, msg, len);

  ssl->d1->handshake_write_seq++;
  ssl->init_off = 0;
  return dtls1_add_message(ssl, msg, len);
}

int dtls1_write_message(SSL *ssl) {
  if (ssl->d1->outgoing_messages_len == 0) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
    return -1;
  }

  const DTLS_OUTGOING_MESSAGE *msg =
      &ssl->d1->outgoing_messages[ssl->d1->outgoing_messages_len - 1];
  if (msg->is_ccs) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
    return -1;
  }

  size_t offset = ssl->init_off;
  int ret = dtls1_do_handshake_write(ssl, &offset, msg->data, offset, msg->len,
                                     dtls1_use_current_epoch);
  ssl->init_off = offset;
  return ret;
}

static int dtls1_retransmit_message(SSL *ssl,
                                    const DTLS_OUTGOING_MESSAGE *msg) {
  /* DTLS renegotiation is unsupported, so only epochs 0 (NULL cipher) and 1
   * (negotiated cipher) exist. */
  assert(ssl->d1->w_epoch == 0 || ssl->d1->w_epoch == 1);
  assert(msg->epoch <= ssl->d1->w_epoch);
  enum dtls1_use_epoch_t use_epoch = dtls1_use_current_epoch;
  if (ssl->d1->w_epoch == 1 && msg->epoch == 0) {
    use_epoch = dtls1_use_previous_epoch;
  }

  /* TODO(davidben): This cannot handle non-blocking writes. */
  int ret;
  if (msg->is_ccs) {
    ret = dtls1_write_change_cipher_spec(ssl, use_epoch);
  } else {
    size_t offset = 0;
    ret = dtls1_do_handshake_write(ssl, &offset, msg->data, offset, msg->len,
                                   use_epoch);
  }

  return ret;
}

int dtls1_retransmit_outgoing_messages(SSL *ssl) {
  /* Ensure we are packing handshake messages. */
  const int was_buffered = ssl_is_wbio_buffered(ssl);
  assert(was_buffered == SSL_in_init(ssl));
  if (!was_buffered && !ssl_init_wbio_buffer(ssl)) {
    return -1;
  }
  assert(ssl_is_wbio_buffered(ssl));

  int ret = -1;
  size_t i;
  for (i = 0; i < ssl->d1->outgoing_messages_len; i++) {
    if (dtls1_retransmit_message(ssl, &ssl->d1->outgoing_messages[i]) <= 0) {
      goto err;
    }
  }

  ret = BIO_flush(ssl->wbio);
  if (ret <= 0) {
    ssl->rwstate = SSL_WRITING;
    goto err;
  }

err:
  if (!was_buffered) {
    ssl_free_wbio_buffer(ssl);
  }
  return ret;
}

int dtls1_send_change_cipher_spec(SSL *ssl, int a, int b) {
  if (ssl->state == a) {
    dtls1_add_change_cipher_spec(ssl);
    ssl->state = b;
  }

  return dtls1_write_change_cipher_spec(ssl, dtls1_use_current_epoch);
}

unsigned int dtls1_min_mtu(void) {
  return kMinMTU;
}
