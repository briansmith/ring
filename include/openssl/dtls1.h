/* ssl/dtls1.h */
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

#ifndef OPENSSL_HEADER_DTLS1_H
#define OPENSSL_HEADER_DTLS1_H

#include <openssl/base.h>
#include <openssl/buf.h>
#include <openssl/pqueue.h>

#ifdef __cplusplus
extern "C" {
#endif


#define DTLS1_VERSION 0xFEFF
#define DTLS1_2_VERSION 0xFEFD

/* lengths of messages */
#define DTLS1_COOKIE_LENGTH 256

#define DTLS1_RT_HEADER_LENGTH 13

#define DTLS1_HM_HEADER_LENGTH 12

#define DTLS1_CCS_HEADER_LENGTH 1

#define DTLS1_AL_HEADER_LENGTH 2

typedef struct dtls1_bitmap_st {
  /* map is a bit mask of the last 64 sequence numbers. Bit
   * |1<<i| corresponds to |max_seq_num - i|. */
  uint64_t map;
  /* max_seq_num is the largest sequence number seen so far. It
   * is a 64-bit value in big-endian encoding. */
  uint8_t max_seq_num[8];
} DTLS1_BITMAP;

/* TODO(davidben): This structure is used for both incoming messages and
 * outgoing messages. |is_ccs| and |epoch| are only used in the latter and
 * should be moved elsewhere. */
struct hm_header_st {
  uint8_t type;
  uint32_t msg_len;
  uint16_t seq;
  uint32_t frag_off;
  uint32_t frag_len;
  int is_ccs;
  /* epoch, for buffered outgoing messages, is the epoch the message was
   * originally sent in. */
  uint16_t epoch;
};

typedef struct record_pqueue_st {
  uint16_t epoch;
  pqueue q;
} record_pqueue;

/* TODO(davidben): This structure is used for both incoming messages and
 * outgoing messages. |fragment| and |reassembly| are only used in the former
 * and should be moved elsewhere. */
typedef struct hm_fragment_st {
  struct hm_header_st msg_header;
  uint8_t *fragment;
  uint8_t *reassembly;
} hm_fragment;

typedef struct dtls1_state_st {
  /* send_cookie is true if we are resending the ClientHello
   * with a cookie from a HelloVerifyRequest. */
  unsigned int send_cookie;

  uint8_t cookie[DTLS1_COOKIE_LENGTH];
  size_t cookie_len;

  /* The current data and handshake epoch.  This is initially undefined, and
   * starts at zero once the initial handshake is completed. */
  uint16_t r_epoch;
  uint16_t w_epoch;

  /* records being received in the current epoch */
  DTLS1_BITMAP bitmap;

  /* renegotiation starts a new set of sequence numbers */
  DTLS1_BITMAP next_bitmap;

  /* handshake message numbers */
  uint16_t handshake_write_seq;
  uint16_t next_handshake_write_seq;

  uint16_t handshake_read_seq;

  /* save last sequence number for retransmissions */
  uint8_t last_write_sequence[8];

  /* Received handshake records (processed and unprocessed) */
  record_pqueue unprocessed_rcds;
  record_pqueue processed_rcds;

  /* buffered_messages is a priority queue of incoming handshake messages that
   * have yet to be processed.
   *
   * TODO(davidben): This data structure may as well be a ring buffer of fixed
   * size. */
  pqueue buffered_messages;

  /* send_messages is a priority queue of outgoing handshake messages sent in
   * the most recent handshake flight.
   *
   * TODO(davidben): This data structure may as well be a STACK_OF(T). */
  pqueue sent_messages;

  /* Buffered application records.  Only for records between CCS and Finished to
   * prevent either protocol violation or unnecessary message loss. */
  record_pqueue buffered_app_data;

  unsigned int mtu; /* max DTLS packet size */

  struct hm_header_st w_msg_hdr;

  /* num_timeouts is the number of times the retransmit timer has fired since
   * the last time it was reset. */
  unsigned int num_timeouts;

  /* Indicates when the last handshake msg or heartbeat sent will
   * timeout. Because of header issues on Windows, this cannot actually be a
   * struct timeval. */
  OPENSSL_timeval next_timeout;

  /* Timeout duration */
  unsigned short timeout_duration;

  unsigned int change_cipher_spec_ok;
} DTLS1_STATE;

typedef struct dtls1_record_data_st {
  uint8_t *packet;
  unsigned int packet_length;
  SSL3_BUFFER rbuf;
  SSL3_RECORD rrec;
} DTLS1_RECORD_DATA;


#ifdef __cplusplus
}  /* extern C */
#endif

#endif  /* OPENSSL_HEADER_DTLS1_H */
