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
 * Copyright (c) 1998-2006 The OpenSSL Project.  All rights reserved.
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
#include <stdio.h>

#include <openssl/buf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/obj.h>
#include <openssl/rand.h>

#include "ssl_locl.h"

static const SSL_METHOD *ssl23_get_server_method(int ver);
static int ssl23_get_client_hello(SSL *s);
static int ssl23_get_v2_client_hello(SSL *s);

static const SSL_METHOD *ssl23_get_server_method(int ver)
	{
	if (ver == SSL3_VERSION)
		return(SSLv3_server_method());
	else if (ver == TLS1_VERSION)
		return(TLSv1_server_method());
	else if (ver == TLS1_1_VERSION)
		return(TLSv1_1_server_method());
	else if (ver == TLS1_2_VERSION)
		return(TLSv1_2_server_method());
	else
		return(NULL);
	}

IMPLEMENT_ssl23_meth_func(SSLv23_server_method,
			ssl23_accept,
			ssl_undefined_function,
			ssl23_get_server_method)

int ssl23_accept(SSL *s)
	{
	BUF_MEM *buf;
	void (*cb)(const SSL *ssl,int type,int val)=NULL;
	int ret= -1;
	int new_state,state;

	ERR_clear_error();
	ERR_clear_system_error();

	if (s->info_callback != NULL)
		cb=s->info_callback;
	else if (s->ctx->info_callback != NULL)
		cb=s->ctx->info_callback;
	
	s->in_handshake++;
	if (!SSL_in_init(s) || SSL_in_before(s)) SSL_clear(s); 

	for (;;)
		{
		state=s->state;

		switch(s->state)
			{
		case SSL_ST_BEFORE:
		case SSL_ST_ACCEPT:
		case SSL_ST_BEFORE|SSL_ST_ACCEPT:
		case SSL_ST_OK|SSL_ST_ACCEPT:

			s->server=1;
			if (cb != NULL) cb(s,SSL_CB_HANDSHAKE_START,1);

			/* s->version=SSL3_VERSION; */
			s->type=SSL_ST_ACCEPT;

			if (s->init_buf == NULL)
				{
				if ((buf=BUF_MEM_new()) == NULL)
					{
					ret= -1;
					goto end;
					}
				if (!BUF_MEM_grow(buf,SSL3_RT_MAX_PLAIN_LENGTH))
					{
					ret= -1;
					goto end;
					}
				s->init_buf=buf;
				}

			ssl3_init_finished_mac(s);

			s->state=SSL23_ST_SR_CLNT_HELLO;
			s->ctx->stats.sess_accept++;
			s->init_num=0;
			break;

		case SSL23_ST_SR_CLNT_HELLO:
			s->shutdown = 0;
			ret = ssl23_get_client_hello(s);
			if (ret <= 0) goto end;
			break;

		case SSL23_ST_SR_V2_CLNT_HELLO:
			ret = ssl23_get_v2_client_hello(s);
			if (ret <= 0) goto end;
			break;

		case SSL23_ST_SR_SWITCH_VERSION:
			if (!ssl_init_wbio_buffer(s, 1))
				{
				ret = -1;
				goto end;
				}

			s->state = SSL3_ST_SR_CLNT_HELLO_A;
			s->method = ssl23_get_server_method(s->version);
			assert(s->method != NULL);
			s->handshake_func = s->method->ssl_accept;
			s->init_num = 0;

			/* NULL the callback; SSL_accept will call it instead. */
			cb = NULL;
			ret = SSL_accept(s);
			goto end;
			/* break; */

		default:
			OPENSSL_PUT_ERROR(SSL, ssl23_accept, SSL_R_UNKNOWN_STATE);
			ret= -1;
			goto end;
			/* break; */
			}

		if ((cb != NULL) && (s->state != state))
			{
			new_state=s->state;
			s->state=state;
			cb(s,SSL_CB_ACCEPT_LOOP,1);
			s->state=new_state;
			}
		}
end:
	s->in_handshake--;
	if (cb != NULL)
		cb(s,SSL_CB_ACCEPT_EXIT,ret);
	return(ret);
	}

/* ssl23_get_mutual_version determines the highest supported version for a
 * client which reports a highest version of |client_version|. On success, it
 * returns 1 and sets |*out_version| to the negotiated version. Otherwise, it
 * returns 0. */
static int ssl23_get_mutual_version(SSL *s, int *out_version, uint16_t client_version)
	{
	if (client_version >= TLS1_2_VERSION && !(s->options & SSL_OP_NO_TLSv1_2))
		{
		*out_version = TLS1_2_VERSION;
		return 1;
		}
	if (client_version >= TLS1_1_VERSION && !(s->options & SSL_OP_NO_TLSv1_1))
		{
		*out_version = TLS1_1_VERSION;
		return 1;
		}
	if (client_version >= TLS1_VERSION && !(s->options & SSL_OP_NO_TLSv1))
		{
		*out_version = TLS1_VERSION;
		return 1;
		}
	if (client_version >= SSL3_VERSION && !(s->options & SSL_OP_NO_SSLv3))
		{
		*out_version = SSL3_VERSION;
		return 1;
		}
	return 0;
	}

static int ssl23_get_client_hello(SSL *s)
	{
	uint8_t *p;
	int n = 0;

	/* Sniff enough of the input to determine ClientHello type and the
	 * client version. */
	if (!ssl3_setup_buffers(s)) goto err;

	/* Read the initial 11 bytes of the input. This is sufficient to
	 * determine the client version for a ClientHello or a
	 * V2ClientHello.
	 *
	 * ClientHello (assuming client_version is unfragmented):
	 * Byte  Content
	 *  0     type            \
	 *  1-2   version          > record header
	 *  3-4   length          /
	 *  5     msg_type        \
	 *  6-8   length           > Client Hello message
	 *  9-10  client_version  /
	 *
	 * V2ClientHello:
	 * Byte  Content
	 *  0-1   msg_length
	 *  2     msg_type
	 *  3-4   version
	 *  5-6   cipher_spec_length
	 *  7-8   session_id_length
	 *  9-10  challenge_length
	 */
	n = ssl23_read_bytes(s, 11);
	if (n <= 0)
		return n;
	assert(n == 11);

	p = s->packet;

	/* Some dedicated error codes for protocol mixups should the application
	 * wish to interpret them differently. (These do not overlap with
	 * ClientHello or V2ClientHello.) */
	if ((strncmp("GET ", (char *)p, 4) == 0) ||
		(strncmp("POST ",(char *)p, 5) == 0) ||
		(strncmp("HEAD ",(char *)p, 5) == 0) ||
		(strncmp("PUT ", (char *)p, 4) == 0))
		{
		OPENSSL_PUT_ERROR(SSL, ssl23_get_client_hello, SSL_R_HTTP_REQUEST);
		goto err;
		}
	if (strncmp("CONNECT",(char *)p, 7) == 0)
		{
		OPENSSL_PUT_ERROR(SSL, ssl23_get_client_hello, SSL_R_HTTPS_PROXY_REQUEST);
		goto err;
		}

	/* Determine if this is a ClientHello or V2ClientHello. */
	if ((p[0] & 0x80) && (p[2] == SSL2_MT_CLIENT_HELLO))
		{
		/* This is a V2ClientHello. Determine the version to
		 * use. */
		uint16_t client_version = (p[3] << 8) | p[4];
		if (!ssl23_get_mutual_version(s, &s->version, client_version))
			{
			OPENSSL_PUT_ERROR(SSL, ssl23_get_client_hello, SSL_R_UNSUPPORTED_PROTOCOL);
			goto err;
			}
		/* Parse the entire V2ClientHello. */
		s->state = SSL23_ST_SR_V2_CLNT_HELLO;
		}
	else if ((p[0] == SSL3_RT_HANDSHAKE) &&
		 (p[1] >= SSL3_VERSION_MAJOR) &&
		 (p[5] == SSL3_MT_CLIENT_HELLO))
		{
		/* This is a fragment of a ClientHello. We look at the
		 * client_hello to negotiate the version. However, this
		 * is difficult if we have only a pathologically small
		 * fragment. No known client fragments ClientHello like
		 * this, so we simply reject such connections to avoid
		 * protocol version downgrade attacks. */
		uint16_t record_length = (p[3] << 8) | p[4];
		uint16_t client_version;
		if (record_length < 6)
			{
			OPENSSL_PUT_ERROR(SSL, ssl23_get_client_hello, SSL_R_RECORD_TOO_SMALL);
			goto err;
			}

		client_version = (p[9] << 8) | p[10];
		if (!ssl23_get_mutual_version(s, &s->version, client_version))
			{
			OPENSSL_PUT_ERROR(SSL, ssl23_get_client_hello, SSL_R_UNSUPPORTED_PROTOCOL);
			goto err;
			}

                /* Reset the record-layer state for SSL3. */
                assert(s->rstate == SSL_ST_READ_HEADER);
                s->s3->rbuf.left = s->packet_length;
                s->s3->rbuf.offset = 0;
                s->packet_length = 0;

		/* Ready to switch versions. */
		s->state = SSL23_ST_SR_SWITCH_VERSION;
		}

	return 1;
err:
	return -1;
	}

static int ssl23_get_v2_client_hello(SSL *s)
	{
	uint8_t *p;
	size_t i;
	int n = 0;

	CBS v2_client_hello, cipher_specs, session_id, challenge;
	size_t msg_length, len;
	uint8_t msg_type;
	uint16_t version, cipher_spec_length, session_id_length, challenge_length;
	CBB client_hello, hello_body, cipher_suites;
	uint8_t random[SSL3_RANDOM_SIZE];

	/* Read the remainder of the V2ClientHello. We have previously read 11
	 * bytes in ssl23_get_client_hello. */
	p = s->packet;
	msg_length = ((p[0] & 0x7f) << 8) | p[1];
	if (msg_length > (1024 * 4))
		{
		OPENSSL_PUT_ERROR(SSL, ssl23_get_v2_client_hello, SSL_R_RECORD_TOO_LARGE);
		goto err;
		}
	if (msg_length < 11 - 2)
		{
		/* Reject lengths that are too short early. We have already read
		 * 11 bytes, so we should not attempt to process an (invalid)
		 * V2ClientHello which would be shorter than that. */
		OPENSSL_PUT_ERROR(SSL, ssl23_get_v2_client_hello, SSL_R_RECORD_LENGTH_MISMATCH);
		goto err;
		}
	n = ssl23_read_bytes(s, msg_length + 2);
	if (n <= 0)
		return n;
	assert(n == s->packet_length);

	/* The V2ClientHello without the length is incorporated into the
	 * Finished hash. */
	ssl3_finish_mac(s, s->packet + 2, s->packet_length - 2);
	if (s->msg_callback)
		s->msg_callback(0, SSL2_VERSION, 0, s->packet+2, s->packet_length-2, s, s->msg_callback_arg); /* CLIENT-HELLO */

	CBS_init(&v2_client_hello, s->packet + 2, s->packet_length - 2);
	if (!CBS_get_u8(&v2_client_hello, &msg_type) ||
		!CBS_get_u16(&v2_client_hello, &version) ||
		!CBS_get_u16(&v2_client_hello, &cipher_spec_length) ||
		!CBS_get_u16(&v2_client_hello, &session_id_length) ||
		!CBS_get_u16(&v2_client_hello, &challenge_length) ||
		!CBS_get_bytes(&v2_client_hello, &cipher_specs, cipher_spec_length) ||
		!CBS_get_bytes(&v2_client_hello, &session_id, session_id_length) ||
		!CBS_get_bytes(&v2_client_hello, &challenge, challenge_length) ||
		CBS_len(&v2_client_hello) != 0)
		{
		OPENSSL_PUT_ERROR(SSL, ssl23_get_v2_client_hello, SSL_R_DECODE_ERROR);
		goto err;
		}

	/* msg_type has already been checked. */
	assert(msg_type == SSL2_MT_CLIENT_HELLO);

	/* The client_random is the V2ClientHello challenge. Truncate or
	 * left-pad with zeros as needed. */
	memset(random, 0, SSL3_RANDOM_SIZE);
	i = (CBS_len(&challenge) > SSL3_RANDOM_SIZE) ? SSL3_RANDOM_SIZE : CBS_len(&challenge);
	memcpy(random, CBS_data(&challenge), i);

	/* Write out an equivalent SSLv3 ClientHello. */
	if (!CBB_init_fixed(&client_hello, (uint8_t *)s->init_buf->data, s->init_buf->max))
		{
		OPENSSL_PUT_ERROR(SSL, ssl23_get_v2_client_hello, ERR_R_MALLOC_FAILURE);
		goto err;
		}
	if (!CBB_add_u8(&client_hello, SSL3_MT_CLIENT_HELLO) ||
		!CBB_add_u24_length_prefixed(&client_hello, &hello_body) ||
		!CBB_add_u16(&hello_body, version) ||
		!CBB_add_bytes(&hello_body, random, SSL3_RANDOM_SIZE) ||
		/* No session id. */
		!CBB_add_u8(&hello_body, 0) ||
		!CBB_add_u16_length_prefixed(&hello_body, &cipher_suites))
		{
		CBB_cleanup(&client_hello);
		OPENSSL_PUT_ERROR(SSL, ssl23_get_v2_client_hello, ERR_R_INTERNAL_ERROR);
		goto err;
		}

	/* Copy the cipher suites. */
	while (CBS_len(&cipher_specs) > 0)
		{
		uint32_t cipher_spec;
		if (!CBS_get_u24(&cipher_specs, &cipher_spec))
			{
			CBB_cleanup(&client_hello);
			OPENSSL_PUT_ERROR(SSL, ssl23_get_v2_client_hello, SSL_R_DECODE_ERROR);
			goto err;
			}

		/* Skip SSLv2 ciphers. */
		if ((cipher_spec & 0xff0000) != 0)
			continue;
		if (!CBB_add_u16(&cipher_suites, cipher_spec))
			{
			CBB_cleanup(&client_hello);
			OPENSSL_PUT_ERROR(SSL, ssl23_get_v2_client_hello, ERR_R_INTERNAL_ERROR);
			goto err;
			}
		}

	/* Add the null compression scheme and finish. */
	if (!CBB_add_u8(&hello_body, 1) ||
		!CBB_add_u8(&hello_body, 0) ||
		!CBB_finish(&client_hello, NULL, &len))
		{
		CBB_cleanup(&client_hello);
		OPENSSL_PUT_ERROR(SSL, ssl23_get_v2_client_hello, ERR_R_INTERNAL_ERROR);
		goto err;
		}

	/* Mark the message for "re"-use by the version-specific
	 * method. */
	s->s3->tmp.reuse_message = 1;
	s->s3->tmp.message_type = SSL3_MT_CLIENT_HELLO;
	/* The handshake message header is 4 bytes. */
	s->s3->tmp.message_size = len - 4;

	/* Reset the record layer for SSL3. */
	assert(s->rstate == SSL_ST_READ_HEADER);
	s->packet_length = 0;
	s->s3->rbuf.left = 0;
	s->s3->rbuf.offset = 0;

	s->state = SSL23_ST_SR_SWITCH_VERSION;
	return 1;
err:
	return -1;
	}
