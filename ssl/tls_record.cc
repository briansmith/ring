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
#include <string.h>

#include <openssl/bytestring.h>
#include <openssl/err.h>
#include <openssl/mem.h>

#include "internal.h"
#include "../crypto/internal.h"


/* kMaxEmptyRecords is the number of consecutive, empty records that will be
 * processed. Without this limit an attacker could send empty records at a
 * faster rate than we can process and cause record processing to loop
 * forever. */
static const uint8_t kMaxEmptyRecords = 32;

/* kMaxEarlyDataSkipped is the maximum number of rejected early data bytes that
 * will be skipped. Without this limit an attacker could send records at a
 * faster rate than we can process and cause trial decryption to loop forever.
 * This value should be slightly above kMaxEarlyDataAccepted, which is measured
 * in plaintext. */
static const size_t kMaxEarlyDataSkipped = 16384;

/* kMaxWarningAlerts is the number of consecutive warning alerts that will be
 * processed. */
static const uint8_t kMaxWarningAlerts = 4;

/* ssl_needs_record_splitting returns one if |ssl|'s current outgoing cipher
 * state needs record-splitting and zero otherwise. */
static int ssl_needs_record_splitting(const SSL *ssl) {
#if !defined(BORINGSSL_UNSAFE_FUZZER_MODE)
  return ssl->s3->aead_write_ctx != NULL &&
         ssl->s3->aead_write_ctx->version < TLS1_1_VERSION &&
         (ssl->mode & SSL_MODE_CBC_RECORD_SPLITTING) != 0 &&
         SSL_CIPHER_is_block_cipher(ssl->s3->aead_write_ctx->cipher);
#else
  return 0;
#endif
}

int ssl_record_sequence_update(uint8_t *seq, size_t seq_len) {
  for (size_t i = seq_len - 1; i < seq_len; i--) {
    ++seq[i];
    if (seq[i] != 0) {
      return 1;
    }
  }
  OPENSSL_PUT_ERROR(SSL, ERR_R_OVERFLOW);
  return 0;
}

size_t ssl_record_prefix_len(const SSL *ssl) {
  size_t header_len;
  if (SSL_is_dtls(ssl)) {
    header_len = DTLS1_RT_HEADER_LENGTH;
  } else {
    header_len = SSL3_RT_HEADER_LENGTH;
  }

  return header_len + SSL_AEAD_CTX_explicit_nonce_len(ssl->s3->aead_read_ctx);
}

size_t ssl_seal_align_prefix_len(const SSL *ssl) {
  if (SSL_is_dtls(ssl)) {
    return DTLS1_RT_HEADER_LENGTH +
           SSL_AEAD_CTX_explicit_nonce_len(ssl->s3->aead_write_ctx);
  }

  size_t ret = SSL3_RT_HEADER_LENGTH +
               SSL_AEAD_CTX_explicit_nonce_len(ssl->s3->aead_write_ctx);
  if (ssl_needs_record_splitting(ssl)) {
    ret += SSL3_RT_HEADER_LENGTH;
    ret += ssl_cipher_get_record_split_len(ssl->s3->aead_write_ctx->cipher);
  }
  return ret;
}

size_t SSL_max_seal_overhead(const SSL *ssl) {
  if (SSL_is_dtls(ssl)) {
    return dtls_max_seal_overhead(ssl, dtls1_use_current_epoch);
  }

  size_t ret = SSL3_RT_HEADER_LENGTH;
  ret += SSL_AEAD_CTX_max_overhead(ssl->s3->aead_write_ctx);
  /* TLS 1.3 needs an extra byte for the encrypted record type. */
  if (ssl->s3->aead_write_ctx != NULL &&
      ssl->s3->aead_write_ctx->version >= TLS1_3_VERSION) {
    ret += 1;
  }
  if (ssl_needs_record_splitting(ssl)) {
    ret *= 2;
  }
  return ret;
}

enum ssl_open_record_t tls_open_record(SSL *ssl, uint8_t *out_type, CBS *out,
                                       size_t *out_consumed, uint8_t *out_alert,
                                       uint8_t *in, size_t in_len) {
  *out_consumed = 0;

  CBS cbs;
  CBS_init(&cbs, in, in_len);

  /* Decode the record header. */
  uint8_t type;
  uint16_t version, ciphertext_len;
  if (!CBS_get_u8(&cbs, &type) ||
      !CBS_get_u16(&cbs, &version) ||
      !CBS_get_u16(&cbs, &ciphertext_len)) {
    *out_consumed = SSL3_RT_HEADER_LENGTH;
    return ssl_open_record_partial;
  }

  int version_ok;
  if (ssl->s3->aead_read_ctx == NULL) {
    /* Only check the first byte. Enforcing beyond that can prevent decoding
     * version negotiation failure alerts. */
    version_ok = (version >> 8) == SSL3_VERSION_MAJOR;
  } else if (ssl3_protocol_version(ssl) < TLS1_3_VERSION) {
    /* Earlier versions of TLS switch the record version. */
    version_ok = version == ssl->version;
  } else {
    /* Starting TLS 1.3, the version field is frozen at {3, 1}. */
    version_ok = version == TLS1_VERSION;
  }

  if (!version_ok) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_WRONG_VERSION_NUMBER);
    *out_alert = SSL_AD_PROTOCOL_VERSION;
    return ssl_open_record_error;
  }

  /* Check the ciphertext length. */
  if (ciphertext_len > SSL3_RT_MAX_ENCRYPTED_LENGTH) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_ENCRYPTED_LENGTH_TOO_LONG);
    *out_alert = SSL_AD_RECORD_OVERFLOW;
    return ssl_open_record_error;
  }

  /* Extract the body. */
  CBS body;
  if (!CBS_get_bytes(&cbs, &body, ciphertext_len)) {
    *out_consumed = SSL3_RT_HEADER_LENGTH + (size_t)ciphertext_len;
    return ssl_open_record_partial;
  }

  ssl_do_msg_callback(ssl, 0 /* read */, SSL3_RT_HEADER, in,
                      SSL3_RT_HEADER_LENGTH);

  *out_consumed = in_len - CBS_len(&cbs);

  /* Skip early data received when expecting a second ClientHello if we rejected
   * 0RTT. */
  if (ssl->s3->skip_early_data &&
      ssl->s3->aead_read_ctx == NULL &&
      type == SSL3_RT_APPLICATION_DATA) {
    goto skipped_data;
  }

  /* Decrypt the body in-place. */
  if (!SSL_AEAD_CTX_open(ssl->s3->aead_read_ctx, out, type, version,
                         ssl->s3->read_sequence, (uint8_t *)CBS_data(&body),
                         CBS_len(&body))) {
    if (ssl->s3->skip_early_data &&
        ssl->s3->aead_read_ctx != NULL) {
      ERR_clear_error();
      goto skipped_data;
    }

    OPENSSL_PUT_ERROR(SSL, SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC);
    *out_alert = SSL_AD_BAD_RECORD_MAC;
    return ssl_open_record_error;
  }

  ssl->s3->skip_early_data = 0;

  if (!ssl_record_sequence_update(ssl->s3->read_sequence, 8)) {
    *out_alert = SSL_AD_INTERNAL_ERROR;
    return ssl_open_record_error;
  }

  /* TLS 1.3 hides the record type inside the encrypted data. */
  if (ssl->s3->aead_read_ctx != NULL &&
      ssl->s3->aead_read_ctx->version >= TLS1_3_VERSION) {
    /* The outer record type is always application_data. */
    if (type != SSL3_RT_APPLICATION_DATA) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_INVALID_OUTER_RECORD_TYPE);
      *out_alert = SSL_AD_DECODE_ERROR;
      return ssl_open_record_error;
    }

    do {
      if (!CBS_get_last_u8(out, &type)) {
        OPENSSL_PUT_ERROR(SSL, SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC);
        *out_alert = SSL_AD_DECRYPT_ERROR;
        return ssl_open_record_error;
      }
    } while (type == 0);
  }

  /* Check the plaintext length. */
  if (CBS_len(out) > SSL3_RT_MAX_PLAIN_LENGTH) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_DATA_LENGTH_TOO_LONG);
    *out_alert = SSL_AD_RECORD_OVERFLOW;
    return ssl_open_record_error;
  }

  /* Limit the number of consecutive empty records. */
  if (CBS_len(out) == 0) {
    ssl->s3->empty_record_count++;
    if (ssl->s3->empty_record_count > kMaxEmptyRecords) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_TOO_MANY_EMPTY_FRAGMENTS);
      *out_alert = SSL_AD_UNEXPECTED_MESSAGE;
      return ssl_open_record_error;
    }
    /* Apart from the limit, empty records are returned up to the caller. This
     * allows the caller to reject records of the wrong type. */
  } else {
    ssl->s3->empty_record_count = 0;
  }

  if (type == SSL3_RT_ALERT) {
    /* Return end_of_early_data alerts as-is for the caller to process. */
    if (CBS_len(out) == 2 &&
        CBS_data(out)[0] == SSL3_AL_WARNING &&
        CBS_data(out)[1] == TLS1_AD_END_OF_EARLY_DATA) {
      *out_type = type;
      return ssl_open_record_success;
    }

    return ssl_process_alert(ssl, out_alert, CBS_data(out), CBS_len(out));
  }

  ssl->s3->warning_alert_count = 0;

  *out_type = type;
  return ssl_open_record_success;

skipped_data:
  ssl->s3->early_data_skipped += *out_consumed;
  if (ssl->s3->early_data_skipped < *out_consumed) {
    ssl->s3->early_data_skipped = kMaxEarlyDataSkipped + 1;
  }

  if (ssl->s3->early_data_skipped > kMaxEarlyDataSkipped) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_TOO_MUCH_SKIPPED_EARLY_DATA);
    *out_alert = SSL_AD_UNEXPECTED_MESSAGE;
    return ssl_open_record_error;
  }

  return ssl_open_record_discard;
}

static int do_seal_record(SSL *ssl, uint8_t *out_prefix, uint8_t *out,
                          uint8_t *out_suffix, size_t *out_suffix_len,
                          const size_t max_out_suffix_len, uint8_t type,
                          const uint8_t *in, const size_t in_len) {
  assert(in == out || !buffers_alias(in, in_len, out, in_len));
  assert(!buffers_alias(in, in_len, out_prefix, ssl_record_prefix_len(ssl)));
  assert(!buffers_alias(in, in_len, out_suffix, max_out_suffix_len));

  /* TLS 1.3 hides the actual record type inside the encrypted data. */
  uint8_t *extra_in = NULL;
  size_t extra_in_len = 0;
  if (ssl->s3->aead_write_ctx != NULL &&
      ssl->s3->aead_write_ctx->version >= TLS1_3_VERSION) {
    extra_in = &type;
    extra_in_len = 1;
    out_prefix[0] = SSL3_RT_APPLICATION_DATA;
  } else {
    out_prefix[0] = type;
  }

  /* The TLS record-layer version number is meaningless and, starting in
   * TLS 1.3, is frozen at TLS 1.0. But for historical reasons, SSL 3.0
   * ClientHellos should use SSL 3.0 and pre-TLS-1.3 expects the version
   * to change after version negotiation. */
  uint16_t wire_version = TLS1_VERSION;
  if (ssl->s3->hs != NULL && ssl->s3->hs->max_version == SSL3_VERSION) {
    wire_version = SSL3_VERSION;
  }
  if (ssl->s3->have_version && ssl3_protocol_version(ssl) < TLS1_3_VERSION) {
    wire_version = ssl->version;
  }
  out_prefix[1] = wire_version >> 8;
  out_prefix[2] = wire_version & 0xff;

  /* Write the ciphertext, leaving two bytes for the length. */
  if (!SSL_AEAD_CTX_seal_scatter(
          ssl->s3->aead_write_ctx, out_prefix + SSL3_RT_HEADER_LENGTH, out,
          out_suffix, out_suffix_len, max_out_suffix_len, type, wire_version,
          ssl->s3->write_sequence, in, in_len, extra_in, extra_in_len) ||
      !ssl_record_sequence_update(ssl->s3->write_sequence, 8)) {
    return 0;
  }

  /* Fill in the length. */
  const size_t ciphertext_len =
      SSL_AEAD_CTX_explicit_nonce_len(ssl->s3->aead_write_ctx) + in_len +
      *out_suffix_len;
  if (ciphertext_len >= 1 << 15) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_OVERFLOW);
    return 0;
  }
  out_prefix[3] = ciphertext_len >> 8;
  out_prefix[4] = ciphertext_len & 0xff;

  ssl_do_msg_callback(ssl, 1 /* write */, SSL3_RT_HEADER, out_prefix,
                      SSL3_RT_HEADER_LENGTH);
  return 1;
}

static size_t tls_seal_scatter_prefix_len(const SSL *ssl, uint8_t type,
                                          size_t in_len) {
  size_t ret = SSL3_RT_HEADER_LENGTH;
  if (type == SSL3_RT_APPLICATION_DATA && in_len > 1 &&
      ssl_needs_record_splitting(ssl)) {
    /* In the case of record splitting, the 1-byte record (of the 1/n-1 split)
     * will be placed in the prefix, as will four of the five bytes of the
     * record header for the main record. The final byte will replace the first
     * byte of the plaintext that was used in the small record. */
    ret += ssl_cipher_get_record_split_len(ssl->s3->aead_write_ctx->cipher);
    ret += SSL3_RT_HEADER_LENGTH - 1;
  } else {
    ret += SSL_AEAD_CTX_explicit_nonce_len(ssl->s3->aead_write_ctx);
  }
  return ret;
}

/* tls_seal_scatter_record seals a new record of type |type| and body |in| and
 * splits it between |out_prefix|, |out|, and |out_suffix|. Exactly
 * |tls_seal_scatter_prefix_len| bytes are written to |out_prefix|, |in_len|
 * bytes to |out|, and up to 1 + |SSL_AEAD_CTX_max_overhead| bytes to
 * |out_suffix|. |*out_suffix_len| is set to the actual number of bytes written
 * to |out_suffix|. It returns one on success and zero on error. If enabled,
 * |tls_seal_scatter_record| implements TLS 1.0 CBC 1/n-1 record splitting and
 * may write two records concatenated. */
static int tls_seal_scatter_record(SSL *ssl, uint8_t *out_prefix, uint8_t *out,
                                   uint8_t *out_suffix, size_t *out_suffix_len,
                                   size_t max_out_suffix_len, uint8_t type,
                                   const uint8_t *in, size_t in_len) {
  if (type == SSL3_RT_APPLICATION_DATA && in_len > 1 &&
      ssl_needs_record_splitting(ssl)) {
    assert(SSL_AEAD_CTX_explicit_nonce_len(ssl->s3->aead_write_ctx) == 0);
    const size_t prefix_len = SSL3_RT_HEADER_LENGTH;

    /* Write the 1-byte fragment into |out_prefix|. */
    uint8_t *split_body = out_prefix + prefix_len;
    uint8_t *split_suffix = split_body + 1;

    /* TODO(martinkr): Make AEAD code not complain if max_suffix_len is lower
     * than |EVP_AEAD_max_overhead| but still sufficiently large. */
    size_t split_max_suffix_len =
        SSL_AEAD_CTX_max_suffix_len(ssl->s3->aead_write_ctx, 0);
    size_t split_suffix_len = 0;
    if (!do_seal_record(ssl, out_prefix, split_body, split_suffix,
                        &split_suffix_len, split_max_suffix_len, type, in, 1)) {
      return 0;
    }

    size_t split_record_len = prefix_len + 1 + split_suffix_len;

    assert(SSL3_RT_HEADER_LENGTH + ssl_cipher_get_record_split_len(
                                       ssl->s3->aead_write_ctx->cipher) ==
           split_record_len);

    /* Write the n-1-byte fragment. The header gets split between |out_prefix|
     * (header[:-1]) and |out| (header[-1:]). */
    uint8_t tmp_prefix[SSL3_RT_HEADER_LENGTH];
    if (!do_seal_record(ssl, tmp_prefix, out + 1, out_suffix, out_suffix_len,
                        max_out_suffix_len, type, in + 1, in_len - 1)) {
      return 0;
    }
    assert(tls_seal_scatter_prefix_len(ssl, type, in_len) ==
           split_record_len + SSL3_RT_HEADER_LENGTH - 1);
    OPENSSL_memcpy(out_prefix + split_record_len, tmp_prefix,
                   SSL3_RT_HEADER_LENGTH - 1);
    OPENSSL_memcpy(out, tmp_prefix + SSL3_RT_HEADER_LENGTH - 1, 1);
    return 1;
  }

  return do_seal_record(ssl, out_prefix, out, out_suffix, out_suffix_len,
                        max_out_suffix_len, type, in, in_len);
}

int tls_seal_record(SSL *ssl, uint8_t *out, size_t *out_len, size_t max_out_len,
                    uint8_t type, const uint8_t *in, size_t in_len) {
  if (buffers_alias(in, in_len, out, max_out_len)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_OUTPUT_ALIASES_INPUT);
    return 0;
  }

  const size_t prefix_len = tls_seal_scatter_prefix_len(ssl, type, in_len);

  if (in_len + prefix_len < in_len) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_RECORD_TOO_LARGE);
    return 0;
  }
  if (max_out_len < in_len + prefix_len) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_BUFFER_TOO_SMALL);
    return 0;
  }

  uint8_t *prefix = out;
  uint8_t *body = out + prefix_len;
  uint8_t *suffix = body + in_len;
  size_t max_suffix_len = max_out_len - prefix_len - in_len;
  size_t suffix_len = 0;

  if (!tls_seal_scatter_record(ssl, prefix, body, suffix, &suffix_len,
                               max_suffix_len, type, in, in_len)) {
    return 0;
  }

  if (prefix_len + in_len + suffix_len < prefix_len + in_len) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_RECORD_TOO_LARGE);
    return 0;
  }

  *out_len = prefix_len + in_len + suffix_len;
  return 1;
}

enum ssl_open_record_t ssl_process_alert(SSL *ssl, uint8_t *out_alert,
                                         const uint8_t *in, size_t in_len) {
  /* Alerts records may not contain fragmented or multiple alerts. */
  if (in_len != 2) {
    *out_alert = SSL_AD_DECODE_ERROR;
    OPENSSL_PUT_ERROR(SSL, SSL_R_BAD_ALERT);
    return ssl_open_record_error;
  }

  ssl_do_msg_callback(ssl, 0 /* read */, SSL3_RT_ALERT, in, in_len);

  const uint8_t alert_level = in[0];
  const uint8_t alert_descr = in[1];

  uint16_t alert = (alert_level << 8) | alert_descr;
  ssl_do_info_callback(ssl, SSL_CB_READ_ALERT, alert);

  if (alert_level == SSL3_AL_WARNING) {
    if (alert_descr == SSL_AD_CLOSE_NOTIFY) {
      ssl->s3->recv_shutdown = ssl_shutdown_close_notify;
      return ssl_open_record_close_notify;
    }

    /* Warning alerts do not exist in TLS 1.3. */
    if (ssl->s3->have_version &&
        ssl3_protocol_version(ssl) >= TLS1_3_VERSION) {
      *out_alert = SSL_AD_DECODE_ERROR;
      OPENSSL_PUT_ERROR(SSL, SSL_R_BAD_ALERT);
      return ssl_open_record_error;
    }

    ssl->s3->warning_alert_count++;
    if (ssl->s3->warning_alert_count > kMaxWarningAlerts) {
      *out_alert = SSL_AD_UNEXPECTED_MESSAGE;
      OPENSSL_PUT_ERROR(SSL, SSL_R_TOO_MANY_WARNING_ALERTS);
      return ssl_open_record_error;
    }
    return ssl_open_record_discard;
  }

  if (alert_level == SSL3_AL_FATAL) {
    ssl->s3->recv_shutdown = ssl_shutdown_fatal_alert;

    char tmp[16];
    OPENSSL_PUT_ERROR(SSL, SSL_AD_REASON_OFFSET + alert_descr);
    BIO_snprintf(tmp, sizeof(tmp), "%d", alert_descr);
    ERR_add_error_data(2, "SSL alert number ", tmp);
    return ssl_open_record_fatal_alert;
  }

  *out_alert = SSL_AD_ILLEGAL_PARAMETER;
  OPENSSL_PUT_ERROR(SSL, SSL_R_UNKNOWN_ALERT_TYPE);
  return ssl_open_record_error;
}
