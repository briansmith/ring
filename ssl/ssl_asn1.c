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
 * Copyright 2005 Nokia. All rights reserved.
 *
 * The portions of the attached software ("Contribution") is developed by
 * Nokia Corporation and is licensed pursuant to the OpenSSL open source
 * license.
 *
 * The Contribution, originally written by Mika Kousa and Pasi Eronen of
 * Nokia Corporation, consists of the "PSK" (Pre-Shared Key) ciphersuites
 * support (see RFC 4279) to OpenSSL.
 *
 * No patent licenses or other rights except those expressly stated in
 * the OpenSSL open source license shall be deemed granted or received
 * expressly, by implication, estoppel, or otherwise.
 *
 * No assurances are provided by Nokia that the Contribution does not
 * infringe the patent or other intellectual property rights of any third
 * party or that the license provides you with all the necessary rights
 * to make use of the Contribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND. IN
 * ADDITION TO THE DISCLAIMERS INCLUDED IN THE LICENSE, NOKIA
 * SPECIFICALLY DISCLAIMS ANY LIABILITY FOR CLAIMS BROUGHT BY YOU OR ANY
 * OTHER ENTITY BASED ON INFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS OR
 * OTHERWISE. */

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

#include <openssl/asn1.h>
#include <openssl/asn1_mac.h>
#include <openssl/bytestring.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#include "ssl_locl.h"


/* An SSL_SESSION is serialized as the following ASN.1 structure:
 *
 * SSLSession ::= SEQUENCE {
 *     version                     INTEGER (1),  -- ignored
 *     sslVersion                  INTEGER,      -- protocol version number
 *     cipher                      OCTET STRING, -- two bytes long
 *     sessionID                   OCTET STRING,
 *     masterKey                   OCTET STRING,
 *     keyArg                  [0] IMPLICIT OCTET STRING OPTIONAL,
 *                                 -- ignored: legacy SSLv2-only field.
 *     time                    [1] INTEGER OPTIONAL, -- seconds since UNIX epoch
 *     timeout                 [2] INTEGER OPTIONAL, -- in seconds
 *     peer                    [3] Certificate OPTIONAL,
 *     sessionIDContext        [4] OCTET STRING OPTIONAL,
 *     verifyResult            [5] INTEGER OPTIONAL,  -- one of X509_V_* codes
 *     hostName                [6] OCTET STRING OPTIONAL,
 *                                 -- from server_name extension
 *     pskIdentityHint         [7] OCTET STRING OPTIONAL,
 *     pskIdentity             [8] OCTET STRING OPTIONAL,
 *     ticketLifetimeHint      [9] INTEGER OPTIONAL,       -- client-only
 *     ticket                  [10] OCTET STRING OPTIONAL, -- client-only
 *     peerSHA256              [13] OCTET STRING OPTIONAL,
 *     originalHandshakeHash   [14] OCTET STRING OPTIONAL,
 *     signedCertTimestampList [15] OCTET STRING OPTIONAL,
 *                                  -- contents of SCT extension
 *     ocspResponse            [16] OCTET STRING OPTIONAL,
 *                                   -- stapled OCSP response from the server
 * }
 *
 * Note: When the relevant features were #ifdef'd out, support for
 * parsing compressionMethod [11] and srpUsername [12] was lost. */

static const int kKeyArgTag = CBS_ASN1_CONTEXT_SPECIFIC | 0;
static const int kTimeTag =
    CBS_ASN1_CONSTRUCTED | CBS_ASN1_CONTEXT_SPECIFIC | 1;
static const int kTimeoutTag =
    CBS_ASN1_CONSTRUCTED | CBS_ASN1_CONTEXT_SPECIFIC | 2;
static const int kPeerTag =
    CBS_ASN1_CONSTRUCTED | CBS_ASN1_CONTEXT_SPECIFIC | 3;
static const int kSessionIDContextTag =
    CBS_ASN1_CONSTRUCTED | CBS_ASN1_CONTEXT_SPECIFIC | 4;
static const int kVerifyResultTag =
    CBS_ASN1_CONSTRUCTED | CBS_ASN1_CONTEXT_SPECIFIC | 5;
static const int kHostNameTag =
    CBS_ASN1_CONSTRUCTED | CBS_ASN1_CONTEXT_SPECIFIC | 6;
static const int kPSKIdentityHintTag =
    CBS_ASN1_CONSTRUCTED | CBS_ASN1_CONTEXT_SPECIFIC | 7;
static const int kPSKIdentityTag =
    CBS_ASN1_CONSTRUCTED | CBS_ASN1_CONTEXT_SPECIFIC | 8;
static const int kTicketLifetimeHintTag =
    CBS_ASN1_CONSTRUCTED | CBS_ASN1_CONTEXT_SPECIFIC | 9;
static const int kTicketTag =
    CBS_ASN1_CONSTRUCTED | CBS_ASN1_CONTEXT_SPECIFIC | 10;
static const int kPeerSHA256Tag =
    CBS_ASN1_CONSTRUCTED | CBS_ASN1_CONTEXT_SPECIFIC | 13;
static const int kOriginalHandshakeHashTag =
    CBS_ASN1_CONSTRUCTED | CBS_ASN1_CONTEXT_SPECIFIC | 14;
static const int kSignedCertTimestampListTag =
    CBS_ASN1_CONSTRUCTED | CBS_ASN1_CONTEXT_SPECIFIC | 15;
static const int kOCSPResponseTag =
    CBS_ASN1_CONSTRUCTED | CBS_ASN1_CONTEXT_SPECIFIC | 16;

typedef struct ssl_session_asn1_st
	{
	ASN1_INTEGER version;
	ASN1_INTEGER ssl_version;
	ASN1_OCTET_STRING cipher;
	ASN1_OCTET_STRING comp_id;
	ASN1_OCTET_STRING master_key;
	ASN1_OCTET_STRING session_id;
	ASN1_OCTET_STRING session_id_context;
	ASN1_INTEGER time;
	ASN1_INTEGER timeout;
	ASN1_INTEGER verify_result;
	ASN1_OCTET_STRING tlsext_hostname;
	ASN1_INTEGER tlsext_tick_lifetime;
	ASN1_OCTET_STRING tlsext_tick;
	ASN1_OCTET_STRING psk_identity_hint;
	ASN1_OCTET_STRING psk_identity;
	ASN1_OCTET_STRING peer_sha256;
	ASN1_OCTET_STRING original_handshake_hash;
	ASN1_OCTET_STRING tlsext_signed_cert_timestamp_list;
	ASN1_OCTET_STRING ocsp_response;
	} SSL_SESSION_ASN1;

int i2d_SSL_SESSION(SSL_SESSION *in, unsigned char **pp)
	{
#define LSIZE2 (sizeof(long)*2)
	int v1=0,v2=0,v3=0,v4=0,v5=0,v7=0,v8=0,v13=0,v14=0,v15=0,v16=0;
	unsigned char buf[4],ibuf1[LSIZE2],ibuf2[LSIZE2];
	unsigned char ibuf3[LSIZE2],ibuf4[LSIZE2],ibuf5[LSIZE2];
	int v6=0,v9=0,v10=0;
	unsigned char ibuf6[LSIZE2];
	long l;
	SSL_SESSION_ASN1 a;
	M_ASN1_I2D_vars(in);

	if ((in == NULL) || ((in->cipher == NULL) && (in->cipher_id == 0)))
		return(0);

	/* Note that I cheat in the following 2 assignments.  I know
	 * that if the ASN1_INTEGER passed to ASN1_INTEGER_set
	 * is > sizeof(long)+1, the buffer will not be re-OPENSSL_malloc()ed.
	 * This is a bit evil but makes things simple, no dynamic allocation
	 * to clean up :-) */
	a.version.length=LSIZE2;
	a.version.type=V_ASN1_INTEGER;
	a.version.data=ibuf1;
	ASN1_INTEGER_set(&(a.version),SSL_SESSION_ASN1_VERSION);

	a.ssl_version.length=LSIZE2;
	a.ssl_version.type=V_ASN1_INTEGER;
	a.ssl_version.data=ibuf2;
	ASN1_INTEGER_set(&(a.ssl_version),in->ssl_version);

	a.cipher.type=V_ASN1_OCTET_STRING;
	a.cipher.data=buf;

	if (in->cipher == NULL)
		l=in->cipher_id;
	else
		l=in->cipher->id;
	if (in->ssl_version == SSL2_VERSION)
		{
		a.cipher.length=3;
		buf[0]=((unsigned char)(l>>16L))&0xff;
		buf[1]=((unsigned char)(l>> 8L))&0xff;
		buf[2]=((unsigned char)(l     ))&0xff;
		}
	else
		{
		a.cipher.length=2;
		buf[0]=((unsigned char)(l>>8L))&0xff;
		buf[1]=((unsigned char)(l    ))&0xff;
		}


	a.master_key.length=in->master_key_length;
	a.master_key.type=V_ASN1_OCTET_STRING;
	a.master_key.data=in->master_key;

	a.session_id.length=in->session_id_length;
	a.session_id.type=V_ASN1_OCTET_STRING;
	a.session_id.data=in->session_id;

	a.session_id_context.length=in->sid_ctx_length;
	a.session_id_context.type=V_ASN1_OCTET_STRING;
	a.session_id_context.data=in->sid_ctx;

	if (in->time != 0L)
		{
		a.time.length=LSIZE2;
		a.time.type=V_ASN1_INTEGER;
		a.time.data=ibuf3;
		ASN1_INTEGER_set(&(a.time),in->time);
		}

	if (in->timeout != 0L)
		{
		a.timeout.length=LSIZE2;
		a.timeout.type=V_ASN1_INTEGER;
		a.timeout.data=ibuf4;
		ASN1_INTEGER_set(&(a.timeout),in->timeout);
		}

	if (in->verify_result != X509_V_OK)
		{
		a.verify_result.length=LSIZE2;
		a.verify_result.type=V_ASN1_INTEGER;
		a.verify_result.data=ibuf5;
		ASN1_INTEGER_set(&a.verify_result,in->verify_result);
		}

	if (in->tlsext_hostname)
                {
                a.tlsext_hostname.length=strlen(in->tlsext_hostname);
                a.tlsext_hostname.type=V_ASN1_OCTET_STRING;
                a.tlsext_hostname.data=(unsigned char *)in->tlsext_hostname;
                }
	if (in->tlsext_tick)
                {
                a.tlsext_tick.length= in->tlsext_ticklen;
                a.tlsext_tick.type=V_ASN1_OCTET_STRING;
                a.tlsext_tick.data=(unsigned char *)in->tlsext_tick;
                }
	if (in->tlsext_tick_lifetime_hint > 0)
		{
		a.tlsext_tick_lifetime.length=LSIZE2;
		a.tlsext_tick_lifetime.type=V_ASN1_INTEGER;
		a.tlsext_tick_lifetime.data=ibuf6;
		ASN1_INTEGER_set(&a.tlsext_tick_lifetime,in->tlsext_tick_lifetime_hint);
		}
	if (in->psk_identity_hint)
		{
		a.psk_identity_hint.length=strlen(in->psk_identity_hint);
		a.psk_identity_hint.type=V_ASN1_OCTET_STRING;
		a.psk_identity_hint.data=(unsigned char *)(in->psk_identity_hint);
		}
	if (in->psk_identity)
		{
		a.psk_identity.length=strlen(in->psk_identity);
		a.psk_identity.type=V_ASN1_OCTET_STRING;
		a.psk_identity.data=(unsigned char *)(in->psk_identity);
		}

	if (in->peer_sha256_valid)
		{
		a.peer_sha256.length = sizeof(in->peer_sha256);
		a.peer_sha256.type = V_ASN1_OCTET_STRING;
		a.peer_sha256.data = in->peer_sha256;
		}

	if (in->original_handshake_hash_len > 0)
		{
		a.original_handshake_hash.length = in->original_handshake_hash_len;
		a.original_handshake_hash.type = V_ASN1_OCTET_STRING;
		a.original_handshake_hash.data = in->original_handshake_hash;
		}

	if (in->tlsext_signed_cert_timestamp_list_length > 0)
		{
		a.tlsext_signed_cert_timestamp_list.length =
				in->tlsext_signed_cert_timestamp_list_length;
		a.tlsext_signed_cert_timestamp_list.type = V_ASN1_OCTET_STRING;
		a.tlsext_signed_cert_timestamp_list.data =
				in->tlsext_signed_cert_timestamp_list;
		}

	if (in->ocsp_response_length > 0)
		{
		a.ocsp_response.length = in->ocsp_response_length;
		a.ocsp_response.type = V_ASN1_OCTET_STRING;
		a.ocsp_response.data = in->ocsp_response;
		}

	M_ASN1_I2D_len(&(a.version),		i2d_ASN1_INTEGER);
	M_ASN1_I2D_len(&(a.ssl_version),	i2d_ASN1_INTEGER);
	M_ASN1_I2D_len(&(a.cipher),		i2d_ASN1_OCTET_STRING);
	M_ASN1_I2D_len(&(a.session_id),		i2d_ASN1_OCTET_STRING);
	M_ASN1_I2D_len(&(a.master_key),		i2d_ASN1_OCTET_STRING);
	if (in->time != 0L)
		M_ASN1_I2D_len_EXP_opt(&(a.time),i2d_ASN1_INTEGER,1,v1);
	if (in->timeout != 0L)
		M_ASN1_I2D_len_EXP_opt(&(a.timeout),i2d_ASN1_INTEGER,2,v2);
	if (in->peer != NULL && in->peer_sha256_valid == 0)
		M_ASN1_I2D_len_EXP_opt(in->peer,i2d_X509,3,v3);
	M_ASN1_I2D_len_EXP_opt(&a.session_id_context,i2d_ASN1_OCTET_STRING,4,v4);
	if (in->verify_result != X509_V_OK)
		M_ASN1_I2D_len_EXP_opt(&(a.verify_result),i2d_ASN1_INTEGER,5,v5);

	if (in->tlsext_tick_lifetime_hint > 0)
      	 	M_ASN1_I2D_len_EXP_opt(&a.tlsext_tick_lifetime, i2d_ASN1_INTEGER,9,v9);
	if (in->tlsext_tick)
        	M_ASN1_I2D_len_EXP_opt(&(a.tlsext_tick), i2d_ASN1_OCTET_STRING,10,v10);
	if (in->tlsext_hostname)
        	M_ASN1_I2D_len_EXP_opt(&(a.tlsext_hostname), i2d_ASN1_OCTET_STRING,6,v6);
	if (in->psk_identity_hint)
        	M_ASN1_I2D_len_EXP_opt(&(a.psk_identity_hint), i2d_ASN1_OCTET_STRING,7,v7);
	if (in->psk_identity)
        	M_ASN1_I2D_len_EXP_opt(&(a.psk_identity), i2d_ASN1_OCTET_STRING,8,v8);
	if (in->peer_sha256_valid)
		M_ASN1_I2D_len_EXP_opt(&(a.peer_sha256),i2d_ASN1_OCTET_STRING,13,v13);
	if (in->original_handshake_hash_len > 0)
		M_ASN1_I2D_len_EXP_opt(&(a.original_handshake_hash),i2d_ASN1_OCTET_STRING,14,v14);
	if (in->tlsext_signed_cert_timestamp_list_length > 0)
		M_ASN1_I2D_len_EXP_opt(&(a.tlsext_signed_cert_timestamp_list),
				i2d_ASN1_OCTET_STRING, 15, v15);
	if (in->ocsp_response_length > 0)
		M_ASN1_I2D_len_EXP_opt(&(a.ocsp_response), i2d_ASN1_OCTET_STRING, 16, v16);

	M_ASN1_I2D_seq_total();

	M_ASN1_I2D_put(&(a.version),		i2d_ASN1_INTEGER);
	M_ASN1_I2D_put(&(a.ssl_version),	i2d_ASN1_INTEGER);
	M_ASN1_I2D_put(&(a.cipher),		i2d_ASN1_OCTET_STRING);
	M_ASN1_I2D_put(&(a.session_id),		i2d_ASN1_OCTET_STRING);
	M_ASN1_I2D_put(&(a.master_key),		i2d_ASN1_OCTET_STRING);
	if (in->time != 0L)
		M_ASN1_I2D_put_EXP_opt(&(a.time),i2d_ASN1_INTEGER,1,v1);
	if (in->timeout != 0L)
		M_ASN1_I2D_put_EXP_opt(&(a.timeout),i2d_ASN1_INTEGER,2,v2);
	if (in->peer != NULL && in->peer_sha256_valid == 0)
		M_ASN1_I2D_put_EXP_opt(in->peer,i2d_X509,3,v3);
	M_ASN1_I2D_put_EXP_opt(&a.session_id_context,i2d_ASN1_OCTET_STRING,4,
			       v4);
	if (in->verify_result != X509_V_OK)
		M_ASN1_I2D_put_EXP_opt(&a.verify_result,i2d_ASN1_INTEGER,5,v5);
	if (in->tlsext_hostname)
        	M_ASN1_I2D_put_EXP_opt(&(a.tlsext_hostname), i2d_ASN1_OCTET_STRING,6,v6);
	if (in->psk_identity_hint)
		M_ASN1_I2D_put_EXP_opt(&(a.psk_identity_hint), i2d_ASN1_OCTET_STRING,7,v7);
	if (in->psk_identity)
		M_ASN1_I2D_put_EXP_opt(&(a.psk_identity), i2d_ASN1_OCTET_STRING,8,v8);
	if (in->tlsext_tick_lifetime_hint > 0)
      	 	M_ASN1_I2D_put_EXP_opt(&a.tlsext_tick_lifetime, i2d_ASN1_INTEGER,9,v9);
	if (in->tlsext_tick)
        	M_ASN1_I2D_put_EXP_opt(&(a.tlsext_tick), i2d_ASN1_OCTET_STRING,10,v10);
	if (in->peer_sha256_valid)
		M_ASN1_I2D_put_EXP_opt(&(a.peer_sha256),i2d_ASN1_OCTET_STRING,13,v13);
	if (in->original_handshake_hash_len > 0)
		M_ASN1_I2D_put_EXP_opt(&(a.original_handshake_hash),i2d_ASN1_OCTET_STRING,14,v14);
	if (in->tlsext_signed_cert_timestamp_list_length > 0)
		M_ASN1_I2D_put_EXP_opt(&(a.tlsext_signed_cert_timestamp_list),
				i2d_ASN1_OCTET_STRING, 15, v15);
	if (in->ocsp_response > 0)
		M_ASN1_I2D_put_EXP_opt(&(a.ocsp_response), i2d_ASN1_OCTET_STRING, 16, v16);

	M_ASN1_I2D_finish();
	}

/* d2i_SSL_SESSION_get_string gets an optional ASN.1 OCTET STRING
 * explicitly tagged with |tag| from |cbs| and saves it in |*out|. On
 * entry, if |*out| is not NULL, it frees the existing contents. If
 * the element was not found, it sets |*out| to NULL. It returns one
 * on success, whether or not the element was found, and zero on
 * decode error. */
static int d2i_SSL_SESSION_get_string(CBS *cbs, char **out, unsigned tag) {
  CBS value;
  int present;
  if (!CBS_get_optional_asn1_octet_string(cbs, &value, &present, tag)) {
    OPENSSL_PUT_ERROR(SSL, d2i_SSL_SESSION, SSL_R_INVALID_SSL_SESSION);
    return 0;
  }
  if (present) {
    if (CBS_contains_zero_byte(&value)) {
      OPENSSL_PUT_ERROR(SSL, d2i_SSL_SESSION, SSL_R_INVALID_SSL_SESSION);
      return 0;
    }
    if (!CBS_strdup(&value, out)) {
      OPENSSL_PUT_ERROR(SSL, d2i_SSL_SESSION, ERR_R_MALLOC_FAILURE);
      return 0;
    }
  } else if (*out) {
    OPENSSL_free(*out);
    *out = NULL;
  }
  return 1;
}

/* d2i_SSL_SESSION_get_string gets an optional ASN.1 OCTET STRING
 * explicitly tagged with |tag| from |cbs| and stows it in |*out_ptr|
 * and |*out_len|. If |*out_ptr| is not NULL, it frees the existing
 * contents. On entry, if the element was not found, it sets
 * |*out_ptr| to NULL. It returns one on success, whether or not the
 * element was found, and zero on decode error. */
static int d2i_SSL_SESSION_get_octet_string(CBS *cbs, uint8_t **out_ptr,
                                            size_t *out_len, unsigned tag) {
  CBS value;
  if (!CBS_get_optional_asn1_octet_string(cbs, &value, NULL, tag)) {
    OPENSSL_PUT_ERROR(SSL, d2i_SSL_SESSION, SSL_R_INVALID_SSL_SESSION);
    return 0;
  }
  if (!CBS_stow(&value, out_ptr, out_len)) {
    OPENSSL_PUT_ERROR(SSL, d2i_SSL_SESSION, ERR_R_MALLOC_FAILURE);
    return 0;
  }
  return 1;
}

SSL_SESSION *d2i_SSL_SESSION(SSL_SESSION **a, const uint8_t **pp, long length) {
  SSL_SESSION *ret = NULL;
  CBS cbs, session, cipher, session_id, master_key;
  CBS key_arg, peer, sid_ctx, peer_sha256, original_handshake_hash;
  int has_key_arg, has_peer, has_peer_sha256;
  uint64_t version, ssl_version;
  uint64_t session_time, timeout, verify_result, ticket_lifetime_hint;

  if (a && *a) {
    ret = *a;
  } else {
    ret = SSL_SESSION_new();
    if (ret == NULL) {
      goto err;
    }
  }

  CBS_init(&cbs, *pp, length);
  if (!CBS_get_asn1(&cbs, &session, CBS_ASN1_SEQUENCE) ||
      !CBS_get_asn1_uint64(&session, &version) ||
      !CBS_get_asn1_uint64(&session, &ssl_version) ||
      !CBS_get_asn1(&session, &cipher, CBS_ASN1_OCTETSTRING) ||
      !CBS_get_asn1(&session, &session_id, CBS_ASN1_OCTETSTRING) ||
      !CBS_get_asn1(&session, &master_key, CBS_ASN1_OCTETSTRING) ||
      !CBS_get_optional_asn1(&session, &key_arg, &has_key_arg, kKeyArgTag) ||
      !CBS_get_optional_asn1_uint64(&session, &session_time, kTimeTag,
                                    time(NULL)) ||
      !CBS_get_optional_asn1_uint64(&session, &timeout, kTimeoutTag, 3) ||
      !CBS_get_optional_asn1(&session, &peer, &has_peer, kPeerTag) ||
      !CBS_get_optional_asn1_octet_string(&session, &sid_ctx, NULL,
                                          kSessionIDContextTag) ||
      !CBS_get_optional_asn1_uint64(&session, &verify_result, kVerifyResultTag,
                                    X509_V_OK)) {
    OPENSSL_PUT_ERROR(SSL, d2i_SSL_SESSION, SSL_R_INVALID_SSL_SESSION);
    goto err;
  }
  if (!d2i_SSL_SESSION_get_string(&session, &ret->tlsext_hostname,
                                  kHostNameTag) ||
      !d2i_SSL_SESSION_get_string(&session, &ret->psk_identity_hint,
                                  kPSKIdentityHintTag) ||
      !d2i_SSL_SESSION_get_string(&session, &ret->psk_identity,
                                  kPSKIdentityTag)) {
    goto err;
  }
  if (!CBS_get_optional_asn1_uint64(&session, &ticket_lifetime_hint,
                                    kTicketLifetimeHintTag, 0)) {
    OPENSSL_PUT_ERROR(SSL, d2i_SSL_SESSION, SSL_R_INVALID_SSL_SESSION);
    goto err;
  }
  if (!d2i_SSL_SESSION_get_octet_string(&session, &ret->tlsext_tick,
                                        &ret->tlsext_ticklen, kTicketTag)) {
    goto err;
  }
  if (!CBS_get_optional_asn1_octet_string(&session, &peer_sha256,
                                          &has_peer_sha256, kPeerSHA256Tag) ||
      !CBS_get_optional_asn1_octet_string(&session, &original_handshake_hash,
                                          NULL, kOriginalHandshakeHashTag)) {
    OPENSSL_PUT_ERROR(SSL, d2i_SSL_SESSION, SSL_R_INVALID_SSL_SESSION);
    goto err;
  }
  if (!d2i_SSL_SESSION_get_octet_string(
          &session, &ret->tlsext_signed_cert_timestamp_list,
          &ret->tlsext_signed_cert_timestamp_list_length,
          kSignedCertTimestampListTag) ||
      !d2i_SSL_SESSION_get_octet_string(
          &session, &ret->ocsp_response, &ret->ocsp_response_length,
          kOCSPResponseTag)) {
    goto err;
  }

  /* Ignore |version|. The structure version number is ignored. */

  /* Only support SSLv3/TLS and DTLS. */
  if ((ssl_version >> 8) != SSL3_VERSION_MAJOR &&
      (ssl_version >> 8) != (DTLS1_VERSION >> 8)) {
    OPENSSL_PUT_ERROR(SSL, d2i_SSL_SESSION, SSL_R_UNKNOWN_SSL_VERSION);
    goto err;
  }
  ret->ssl_version = ssl_version;

  if (CBS_len(&cipher) != 2) {
    OPENSSL_PUT_ERROR(SSL, d2i_SSL_SESSION, SSL_R_CIPHER_CODE_WRONG_LENGTH);
    goto err;
  }
  ret->cipher_id =
      0x03000000L | (CBS_data(&cipher)[0] << 8L) | CBS_data(&cipher)[1];
  ret->cipher = ssl3_get_cipher_by_value(ret->cipher_id & 0xffff);
  if (ret->cipher == NULL) {
    OPENSSL_PUT_ERROR(SSL, d2i_SSL_SESSION, SSL_R_UNSUPPORTED_CIPHER);
    goto err;
  }

  if (CBS_len(&session_id) > SSL3_MAX_SSL_SESSION_ID_LENGTH) {
    OPENSSL_PUT_ERROR(SSL, d2i_SSL_SESSION, SSL_R_INVALID_SSL_SESSION);
    goto err;
  }
  memcpy(ret->session_id, CBS_data(&session_id), CBS_len(&session_id));
  ret->session_id_length = CBS_len(&session_id);

  if (CBS_len(&master_key) > SSL_MAX_MASTER_KEY_LENGTH) {
    OPENSSL_PUT_ERROR(SSL, d2i_SSL_SESSION, SSL_R_INVALID_SSL_SESSION);
    goto err;
  }
  memcpy(ret->master_key, CBS_data(&master_key), CBS_len(&master_key));
  ret->master_key_length = CBS_len(&master_key);

  if (session_time > LONG_MAX ||
      timeout > LONG_MAX) {
    OPENSSL_PUT_ERROR(SSL, d2i_SSL_SESSION, SSL_R_INVALID_SSL_SESSION);
    goto err;
  }
  ret->time = session_time;
  ret->timeout = timeout;

  if (ret->peer != NULL) {
    X509_free(ret->peer);
    ret->peer = NULL;
  }
  if (has_peer) {
    const uint8_t *ptr;
    ptr = CBS_data(&peer);
    ret->peer = d2i_X509(NULL, &ptr, CBS_len(&peer));
    if (ret->peer == NULL) {
      goto err;
    }
    if (ptr != CBS_data(&peer) + CBS_len(&peer)) {
      OPENSSL_PUT_ERROR(SSL, d2i_SSL_SESSION, SSL_R_INVALID_SSL_SESSION);
      goto err;
    }
  }

  if (CBS_len(&sid_ctx) > sizeof(ret->sid_ctx)) {
    OPENSSL_PUT_ERROR(SSL, d2i_SSL_SESSION, SSL_R_INVALID_SSL_SESSION);
    goto err;
  }
  memcpy(ret->sid_ctx, CBS_data(&sid_ctx), CBS_len(&sid_ctx));
  ret->sid_ctx_length = CBS_len(&sid_ctx);

  if (verify_result > LONG_MAX ||
      ticket_lifetime_hint > 0xffffffff) {
    OPENSSL_PUT_ERROR(SSL, d2i_SSL_SESSION, SSL_R_INVALID_SSL_SESSION);
    goto err;
  }
  ret->verify_result = verify_result;
  ret->tlsext_tick_lifetime_hint = ticket_lifetime_hint;

  if (has_peer_sha256) {
    if (CBS_len(&peer_sha256) != sizeof(ret->peer_sha256)) {
      OPENSSL_PUT_ERROR(SSL, d2i_SSL_SESSION, SSL_R_INVALID_SSL_SESSION);
      goto err;
    }
    memcpy(ret->peer_sha256, CBS_data(&peer_sha256), sizeof(ret->peer_sha256));
    ret->peer_sha256_valid = 1;
  } else {
    ret->peer_sha256_valid = 0;
  }

  if (CBS_len(&original_handshake_hash) >
      sizeof(ret->original_handshake_hash)) {
    OPENSSL_PUT_ERROR(SSL, d2i_SSL_SESSION, SSL_R_INVALID_SSL_SESSION);
    goto err;
  }
  memcpy(ret->original_handshake_hash, CBS_data(&original_handshake_hash),
         CBS_len(&original_handshake_hash));
  ret->original_handshake_hash_len = CBS_len(&original_handshake_hash);

  if (a) {
    *a = ret;
  }
  *pp = CBS_data(&cbs);
  return ret;

err:
  if (a && *a != ret) {
    SSL_SESSION_free(ret);
  }
  return NULL;
}
