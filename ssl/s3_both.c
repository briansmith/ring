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
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 * ECC cipher suite support in OpenSSL originally developed by
 * SUN MICROSYSTEMS, INC., and contributed to the OpenSSL project. */

#include <openssl/ssl.h>

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#include <openssl/buf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/md5.h>
#include <openssl/obj.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include "internal.h"


/* ssl3_do_write sends |ssl->init_buf| in records of type 'type'
 * (SSL3_RT_HANDSHAKE or SSL3_RT_CHANGE_CIPHER_SPEC). It returns -1 on error, 1
 * on success or zero if the transmission is still incomplete. */
int ssl3_do_write(SSL *ssl, int type) {
  int n;

  n = ssl3_write_bytes(ssl, type, &ssl->init_buf->data[ssl->init_off],
                       ssl->init_num);
  if (n < 0) {
    return -1;
  }

  if (n == ssl->init_num) {
    if (ssl->msg_callback) {
      ssl->msg_callback(1, ssl->version, type, ssl->init_buf->data,
                      (size_t)(ssl->init_off + ssl->init_num), ssl,
                      ssl->msg_callback_arg);
    }
    return 1;
  }

  ssl->init_off += n;
  ssl->init_num -= n;
  return 0;
}

int ssl3_send_finished(SSL *ssl, int a, int b) {
  uint8_t *p;
  int n;

  if (ssl->state == a) {
    p = ssl_handshake_start(ssl);

    n = ssl->s3->enc_method->final_finish_mac(ssl, ssl->server,
                                              ssl->s3->tmp.finish_md);
    if (n == 0) {
      return 0;
    }
    ssl->s3->tmp.finish_md_len = n;
    memcpy(p, ssl->s3->tmp.finish_md, n);

    /* Log the master secret, if logging is enabled. */
    if (!ssl_log_master_secret(ssl, ssl->s3->client_random, SSL3_RANDOM_SIZE,
                               ssl->session->master_key,
                               ssl->session->master_key_length)) {
      return 0;
    }

    /* Copy the finished so we can use it for renegotiation checks */
    if (ssl->server) {
      assert(n <= EVP_MAX_MD_SIZE);
      memcpy(ssl->s3->previous_server_finished, ssl->s3->tmp.finish_md, n);
      ssl->s3->previous_server_finished_len = n;
    } else {
      assert(n <= EVP_MAX_MD_SIZE);
      memcpy(ssl->s3->previous_client_finished, ssl->s3->tmp.finish_md, n);
      ssl->s3->previous_client_finished_len = n;
    }

    if (!ssl_set_handshake_header(ssl, SSL3_MT_FINISHED, n)) {
      return 0;
    }
    ssl->state = b;
  }

  /* SSL3_ST_SEND_xxxxxx_HELLO_B */
  return ssl_do_write(ssl);
}

/* ssl3_take_mac calculates the Finished MAC for the handshakes messages seen
 * so far. */
static void ssl3_take_mac(SSL *ssl) {
  /* If no new cipher setup then return immediately: other functions will set
   * the appropriate error. */
  if (ssl->s3->tmp.new_cipher == NULL) {
    return;
  }

  ssl->s3->tmp.peer_finish_md_len = ssl->s3->enc_method->final_finish_mac(
      ssl, !ssl->server, ssl->s3->tmp.peer_finish_md);
}

int ssl3_get_finished(SSL *ssl, int a, int b) {
  int al, finished_len, ok;
  long message_len;
  uint8_t *p;

  message_len = ssl->method->ssl_get_message(
      ssl, a, b, SSL3_MT_FINISHED, EVP_MAX_MD_SIZE, ssl_dont_hash_message, &ok);

  if (!ok) {
    return message_len;
  }

  /* Snapshot the finished hash before incorporating the new message. */
  ssl3_take_mac(ssl);
  if (!ssl3_hash_current_message(ssl)) {
    goto err;
  }

  p = ssl->init_msg;
  finished_len = ssl->s3->tmp.peer_finish_md_len;

  if (finished_len != message_len) {
    al = SSL_AD_DECODE_ERROR;
    OPENSSL_PUT_ERROR(SSL, SSL_R_BAD_DIGEST_LENGTH);
    goto f_err;
  }

  if (CRYPTO_memcmp(p, ssl->s3->tmp.peer_finish_md, finished_len) != 0) {
    al = SSL_AD_DECRYPT_ERROR;
    OPENSSL_PUT_ERROR(SSL, SSL_R_DIGEST_CHECK_FAILED);
    goto f_err;
  }

  /* Copy the finished so we can use it for renegotiation checks */
  if (ssl->server) {
    assert(finished_len <= EVP_MAX_MD_SIZE);
    memcpy(ssl->s3->previous_client_finished, ssl->s3->tmp.peer_finish_md,
           finished_len);
    ssl->s3->previous_client_finished_len = finished_len;
  } else {
    assert(finished_len <= EVP_MAX_MD_SIZE);
    memcpy(ssl->s3->previous_server_finished, ssl->s3->tmp.peer_finish_md,
           finished_len);
    ssl->s3->previous_server_finished_len = finished_len;
  }

  return 1;

f_err:
  ssl3_send_alert(ssl, SSL3_AL_FATAL, al);
err:
  return 0;
}

int ssl3_send_change_cipher_spec(SSL *ssl, int a, int b) {
  if (ssl->state == a) {
    *((uint8_t *)ssl->init_buf->data) = SSL3_MT_CCS;
    ssl->init_num = 1;
    ssl->init_off = 0;

    ssl->state = b;
  }

  /* SSL3_ST_CW_CHANGE_B */
  return ssl3_do_write(ssl, SSL3_RT_CHANGE_CIPHER_SPEC);
}

int ssl3_output_cert_chain(SSL *ssl) {
  uint8_t *p;
  unsigned long l = 3 + SSL_HM_HEADER_LENGTH(ssl);

  if (!ssl_add_cert_chain(ssl, &l)) {
    return 0;
  }

  l -= 3 + SSL_HM_HEADER_LENGTH(ssl);
  p = ssl_handshake_start(ssl);
  l2n3(l, p);
  l += 3;
  return ssl_set_handshake_header(ssl, SSL3_MT_CERTIFICATE, l);
}

/* Obtain handshake message of message type |msg_type| (any if |msg_type| == -1),
 * maximum acceptable body length |max|. The first four bytes (msg_type and
 * length) are read in state |header_state|, the body is read in state
 * |body_state|. */
long ssl3_get_message(SSL *ssl, int header_state, int body_state, int msg_type,
                      long max, enum ssl_hash_message_t hash_message, int *ok) {
  uint8_t *p;
  unsigned long l;
  long n;
  int al;

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
    ssl->state = body_state;
    ssl->init_msg = (uint8_t *)ssl->init_buf->data + 4;
    ssl->init_num = (int)ssl->s3->tmp.message_size;
    return ssl->init_num;
  }

  p = (uint8_t *)ssl->init_buf->data;

  if (ssl->state == header_state) {
    assert(ssl->init_num < 4);

    for (;;) {
      while (ssl->init_num < 4) {
        int bytes_read = ssl3_read_bytes(
            ssl, SSL3_RT_HANDSHAKE, &p[ssl->init_num], 4 - ssl->init_num, 0);
        if (bytes_read <= 0) {
          *ok = 0;
          return bytes_read;
        }
        ssl->init_num += bytes_read;
      }

      static const uint8_t kHelloRequest[4] = {SSL3_MT_HELLO_REQUEST, 0, 0, 0};
      if (ssl->server || memcmp(p, kHelloRequest, sizeof(kHelloRequest)) != 0) {
        break;
      }

      /* The server may always send 'Hello Request' messages -- we are doing
       * a handshake anyway now, so ignore them if their format is correct.
       * Does not count for 'Finished' MAC. */
      ssl->init_num = 0;

      if (ssl->msg_callback) {
        ssl->msg_callback(0, ssl->version, SSL3_RT_HANDSHAKE, p, 4, ssl,
                        ssl->msg_callback_arg);
      }
    }

    /* ssl->init_num == 4 */

    if (msg_type >= 0 && *p != msg_type) {
      al = SSL_AD_UNEXPECTED_MESSAGE;
      OPENSSL_PUT_ERROR(SSL, SSL_R_UNEXPECTED_MESSAGE);
      goto f_err;
    }
    ssl->s3->tmp.message_type = *(p++);

    n2l3(p, l);
    if (l > (unsigned long)max) {
      al = SSL_AD_ILLEGAL_PARAMETER;
      OPENSSL_PUT_ERROR(SSL, SSL_R_EXCESSIVE_MESSAGE_SIZE);
      goto f_err;
    }

    if (l && !BUF_MEM_grow_clean(ssl->init_buf, l + 4)) {
      OPENSSL_PUT_ERROR(SSL, ERR_R_BUF_LIB);
      goto err;
    }
    ssl->s3->tmp.message_size = l;
    ssl->state = body_state;

    ssl->init_msg = (uint8_t *)ssl->init_buf->data + 4;
    ssl->init_num = 0;
  }

  /* next state (body_state) */
  p = ssl->init_msg;
  n = ssl->s3->tmp.message_size - ssl->init_num;
  while (n > 0) {
    int bytes_read =
        ssl3_read_bytes(ssl, SSL3_RT_HANDSHAKE, &p[ssl->init_num], n, 0);
    if (bytes_read <= 0) {
      ssl->rwstate = SSL_READING;
      *ok = 0;
      return bytes_read;
    }
    ssl->init_num += bytes_read;
    n -= bytes_read;
  }

  /* Feed this message into MAC computation. */
  if (hash_message == ssl_hash_message && !ssl3_hash_current_message(ssl)) {
    goto err;
  }
  if (ssl->msg_callback) {
    ssl->msg_callback(0, ssl->version, SSL3_RT_HANDSHAKE, ssl->init_buf->data,
                    (size_t)ssl->init_num + 4, ssl, ssl->msg_callback_arg);
  }
  *ok = 1;
  return ssl->init_num;

f_err:
  ssl3_send_alert(ssl, SSL3_AL_FATAL, al);

err:
  *ok = 0;
  return -1;
}

int ssl3_hash_current_message(SSL *ssl) {
  /* The handshake header (different size between DTLS and TLS) is included in
   * the hash. */
  size_t header_len = ssl->init_msg - (uint8_t *)ssl->init_buf->data;
  return ssl3_update_handshake_hash(ssl, (uint8_t *)ssl->init_buf->data,
                                    ssl->init_num + header_len);
}

/* ssl3_cert_verify_hash is documented as needing EVP_MAX_MD_SIZE because that
 * is sufficient pre-TLS1.2 as well. */
OPENSSL_COMPILE_ASSERT(EVP_MAX_MD_SIZE > MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH,
                       combined_tls_hash_fits_in_max);

int ssl3_cert_verify_hash(SSL *ssl, uint8_t *out, size_t *out_len,
                          const EVP_MD **out_md, int pkey_type) {
  /* For TLS v1.2 send signature algorithm and signature using
   * agreed digest and cached handshake records. Otherwise, use
   * SHA1 or MD5 + SHA1 depending on key type.  */
  if (ssl3_protocol_version(ssl) >= TLS1_2_VERSION) {
    EVP_MD_CTX mctx;
    unsigned len;

    EVP_MD_CTX_init(&mctx);
    if (!EVP_DigestInit_ex(&mctx, *out_md, NULL) ||
        !EVP_DigestUpdate(&mctx, ssl->s3->handshake_buffer->data,
                          ssl->s3->handshake_buffer->length) ||
        !EVP_DigestFinal(&mctx, out, &len)) {
      OPENSSL_PUT_ERROR(SSL, ERR_R_EVP_LIB);
      EVP_MD_CTX_cleanup(&mctx);
      return 0;
    }
    *out_len = len;
  } else if (pkey_type == EVP_PKEY_RSA) {
    if (ssl->s3->enc_method->cert_verify_mac(ssl, NID_md5, out) == 0 ||
        ssl->s3->enc_method->cert_verify_mac(ssl, NID_sha1,
                                             out + MD5_DIGEST_LENGTH) == 0) {
      return 0;
    }
    *out_len = MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH;
    *out_md = EVP_md5_sha1();
  } else if (pkey_type == EVP_PKEY_EC) {
    if (ssl->s3->enc_method->cert_verify_mac(ssl, NID_sha1, out) == 0) {
      return 0;
    }
    *out_len = SHA_DIGEST_LENGTH;
    *out_md = EVP_sha1();
  } else {
    OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
    return 0;
  }

  return 1;
}

int ssl_verify_alarm_type(long type) {
  int al;

  switch (type) {
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
    case X509_V_ERR_UNABLE_TO_GET_CRL:
    case X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER:
      al = SSL_AD_UNKNOWN_CA;
      break;

    case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
    case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
    case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
    case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
    case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
    case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
    case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
    case X509_V_ERR_CERT_NOT_YET_VALID:
    case X509_V_ERR_CRL_NOT_YET_VALID:
    case X509_V_ERR_CERT_UNTRUSTED:
    case X509_V_ERR_CERT_REJECTED:
      al = SSL_AD_BAD_CERTIFICATE;
      break;

    case X509_V_ERR_CERT_SIGNATURE_FAILURE:
    case X509_V_ERR_CRL_SIGNATURE_FAILURE:
      al = SSL_AD_DECRYPT_ERROR;
      break;

    case X509_V_ERR_CERT_HAS_EXPIRED:
    case X509_V_ERR_CRL_HAS_EXPIRED:
      al = SSL_AD_CERTIFICATE_EXPIRED;
      break;

    case X509_V_ERR_CERT_REVOKED:
      al = SSL_AD_CERTIFICATE_REVOKED;
      break;

    case X509_V_ERR_OUT_OF_MEM:
      al = SSL_AD_INTERNAL_ERROR;
      break;

    case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
    case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
    case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
    case X509_V_ERR_CERT_CHAIN_TOO_LONG:
    case X509_V_ERR_PATH_LENGTH_EXCEEDED:
    case X509_V_ERR_INVALID_CA:
      al = SSL_AD_UNKNOWN_CA;
      break;

    case X509_V_ERR_APPLICATION_VERIFICATION:
      al = SSL_AD_HANDSHAKE_FAILURE;
      break;

    case X509_V_ERR_INVALID_PURPOSE:
      al = SSL_AD_UNSUPPORTED_CERTIFICATE;
      break;

    default:
      al = SSL_AD_CERTIFICATE_UNKNOWN;
      break;
  }

  return al;
}

int ssl_fill_hello_random(uint8_t *out, size_t len, int is_server) {
  if (is_server) {
    const uint32_t current_time = time(NULL);
    uint8_t *p = out;

    if (len < 4) {
      return 0;
    }
    p[0] = current_time >> 24;
    p[1] = current_time >> 16;
    p[2] = current_time >> 8;
    p[3] = current_time;
    return RAND_bytes(p + 4, len - 4);
  } else {
    return RAND_bytes(out, len);
  }
}
