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
#include <openssl/obj.h>
#include <openssl/rand.h>

#include "ssl_locl.h"

static int ssl23_client_hello(SSL *s);
static int ssl23_get_server_hello(SSL *s);

IMPLEMENT_ssl23_meth_func(SSLv23_client_method,
			ssl23_accept,
			ssl23_connect)

int ssl23_connect(SSL *s)
	{
	BUF_MEM *buf=NULL;
	void (*cb)(const SSL *ssl,int type,int val)=NULL;
	int ret= -1;
	int new_state,state;

	assert(s->handshake_func == ssl23_connect);
	assert(!s->server);

	ERR_clear_error();
	ERR_clear_system_error();

	if (s->info_callback != NULL)
		cb=s->info_callback;
	else if (s->ctx->info_callback != NULL)
		cb=s->ctx->info_callback;
	
	s->in_handshake++;

	for (;;)
		{
		state=s->state;

		switch(s->state)
			{
		case SSL_ST_CONNECT:
		case SSL_ST_BEFORE|SSL_ST_CONNECT:

			if (cb != NULL) cb(s,SSL_CB_HANDSHAKE_START,1);

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
				buf=NULL;
				}

			if (!ssl3_setup_buffers(s)) { ret= -1; goto end; }

			if (!ssl3_init_finished_mac(s))
				{
				OPENSSL_PUT_ERROR(SSL, ssl23_connect, ERR_R_INTERNAL_ERROR);
				ret = -1;
				goto end;
				}

			s->state=SSL23_ST_CW_CLNT_HELLO_A;
			s->ctx->stats.sess_connect++;
			s->init_num=0;
			break;

		case SSL23_ST_CW_CLNT_HELLO_A:
		case SSL23_ST_CW_CLNT_HELLO_B:

			s->shutdown=0;
			ret=ssl23_client_hello(s);
			if (ret <= 0) goto end;
			s->state=SSL23_ST_CR_SRVR_HELLO_A;
			s->init_num=0;

			break;

		case SSL23_ST_CR_SRVR_HELLO_A:
		case SSL23_ST_CR_SRVR_HELLO_B:
			ret=ssl23_get_server_hello(s);
			if (ret >= 0) cb=NULL;
			goto end;
			/* break; */

		default:
			OPENSSL_PUT_ERROR(SSL, ssl23_connect, SSL_R_UNKNOWN_STATE);
			ret= -1;
			goto end;
			/* break; */
			}

		if (s->debug) { (void)BIO_flush(s->wbio); }

		if ((cb != NULL) && (s->state != state))
			{
			new_state=s->state;
			s->state=state;
			cb(s,SSL_CB_CONNECT_LOOP,1);
			s->state=new_state;
			}
		}
end:
	s->in_handshake--;
	if (buf != NULL)
		BUF_MEM_free(buf);
	if (cb != NULL)
		cb(s,SSL_CB_CONNECT_EXIT,ret);
	return(ret);
	}

/* Fill a ClientRandom or ServerRandom field of length len. Returns 0
 * on failure, 1 on success. */
int ssl_fill_hello_random(SSL *s, int server, unsigned char *result, int len)
	{
		int send_time = 0;
		if (len < 4)
			return 0;
		if (server)
			send_time = (s->mode & SSL_MODE_SEND_SERVERHELLO_TIME) != 0;
		else
			send_time = (s->mode & SSL_MODE_SEND_CLIENTHELLO_TIME) != 0;
		if (send_time)
			{
			unsigned long Time = (unsigned long)time(NULL);
			unsigned char *p = result;
			l2n(Time, p);
			return RAND_bytes(p, len-4);
			}
		else
			return RAND_bytes(result, len);
	}

static int ssl23_client_hello(SSL *s)
	{
	unsigned char *buf;
	unsigned char *p,*d;
	int i;
	unsigned long l;
	uint16_t version;
	uint8_t version_major, version_minor;
	int ret;

	version = ssl3_get_max_client_version(s);
	if (version == 0)
		{
		OPENSSL_PUT_ERROR(SSL, ssl23_client_hello, SSL_R_WRONG_SSL_VERSION);
		return -1;
		}

	buf=(unsigned char *)s->init_buf->data;
	if (s->state == SSL23_ST_CW_CLNT_HELLO_A)
		{
		/* If the configured session was created at a version
		 * higher than our maximum version, drop it. */
		if (s->session &&
			(s->session->ssl_version > version ||
				s->session->session_id_length == 0 ||
				s->session->not_resumable))
			{
			SSL_set_session(s, NULL);
			}

		p=s->s3->client_random;
		if (ssl_fill_hello_random(s, 0, p, SSL3_RANDOM_SIZE) <= 0)
			return -1;

		if (version == TLS1_2_VERSION)
			{
			version_major = TLS1_2_VERSION_MAJOR;
			version_minor = TLS1_2_VERSION_MINOR;
			}
		else if (version == TLS1_1_VERSION)
			{
			version_major = TLS1_1_VERSION_MAJOR;
			version_minor = TLS1_1_VERSION_MINOR;
			}
		else if (version == TLS1_VERSION)
			{
			version_major = TLS1_VERSION_MAJOR;
			version_minor = TLS1_VERSION_MINOR;
			}
		else if (version == SSL3_VERSION)
			{
			version_major = SSL3_VERSION_MAJOR;
			version_minor = SSL3_VERSION_MINOR;
			}
		else
			{
			OPENSSL_PUT_ERROR(SSL, ssl23_client_hello, SSL_R_NO_PROTOCOLS_AVAILABLE);
			return(-1);
			}

		s->client_version = version;

		/* create Client Hello in SSL 3.0/TLS 1.0 format */

		/* do the record header (5 bytes) and handshake message
		 * header (4 bytes) last. Note: the final argument to
		 * ssl_add_clienthello_tlsext below depends on the size
		 * of this prefix. */
		d = p = &(buf[9]);
			
		*(p++) = version_major;
		*(p++) = version_minor;

		/* Random stuff */
		memcpy(p, s->s3->client_random, SSL3_RANDOM_SIZE);
		p += SSL3_RANDOM_SIZE;

		/* Session ID */
		if (s->new_session || s->session == NULL)
			i=0;
		else
			i=s->session->session_id_length;
		*(p++)=i;
		if (i != 0)
			{
			if (i > (int)sizeof(s->session->session_id))
				{
				OPENSSL_PUT_ERROR(SSL, ssl23_client_hello, ERR_R_INTERNAL_ERROR);
				return -1;
				}
			memcpy(p,s->session->session_id,i);
			p+=i;
			}

		/* Ciphers supported (using SSL 3.0/TLS 1.0 format) */
		i = ssl_cipher_list_to_bytes(s, SSL_get_ciphers(s), &p[2]);
		if (i == 0)
			{
			OPENSSL_PUT_ERROR(SSL, ssl23_client_hello, SSL_R_NO_CIPHERS_AVAILABLE);
			return -1;
			}
		s2n(i,p);
		p+=i;

		/* COMPRESSION */
		*(p++)=1;
		*(p++)=0; /* Add the NULL method */

		/* TLS extensions*/
		if (ssl_prepare_clienthello_tlsext(s) <= 0)
			{
			OPENSSL_PUT_ERROR(SSL, ssl23_client_hello, SSL_R_CLIENTHELLO_TLSEXT);
			return -1;
			}

		/* The buffer includes the 5 byte record header, so
		 * subtract it to compute hlen for
		 * ssl_add_clienthello_tlsext. */
		if ((p = ssl_add_clienthello_tlsext(s, p, buf+SSL3_RT_MAX_PLAIN_LENGTH, p-buf-5)) == NULL)
			{
			OPENSSL_PUT_ERROR(SSL, ssl23_client_hello, ERR_R_INTERNAL_ERROR);
			return -1;
			}
			
		l = p-d;

		/* fill in 4-byte handshake header */
		d=&(buf[5]);
		*(d++)=SSL3_MT_CLIENT_HELLO;
		l2n3(l,d);

		l += 4;

		if (l > SSL3_RT_MAX_PLAIN_LENGTH)
			{
			OPENSSL_PUT_ERROR(SSL, ssl23_client_hello, ERR_R_INTERNAL_ERROR);
			return -1;
			}

		/* fill in 5-byte record header */
		d=buf;
		*(d++) = SSL3_RT_HANDSHAKE;
		*(d++) = version_major;
		/* Some servers hang if we use long client hellos
		 * and a record number > TLS 1.0.
		 */
		if (TLS1_get_client_version(s) > TLS1_VERSION)
			*(d++) = 1;
		else
			*(d++) = version_minor;
		s2n((int)l,d);

		/* number of bytes to write */
		s->init_num=p-buf;
		s->init_off=0;

		ssl3_finish_mac(s,&(buf[5]), s->init_num - 5);

		s->state=SSL23_ST_CW_CLNT_HELLO_B;
		s->init_off=0;
		}

	/* SSL3_ST_CW_CLNT_HELLO_B */
	ret = ssl23_write_bytes(s);

	if ((ret >= 2) && s->msg_callback)
		{
		/* Client Hello has been sent; tell msg_callback */

		s->msg_callback(1, version, SSL3_RT_HEADER, s->init_buf->data, 5, s, s->msg_callback_arg);
		s->msg_callback(1, version, SSL3_RT_HANDSHAKE, s->init_buf->data+5, ret-5, s, s->msg_callback_arg);
		}

	return ret;
	}

static int ssl23_get_server_hello(SSL *s)
	{
	char buf[8];
	unsigned char *p;
	int i;
	int n;

	n=ssl23_read_bytes(s,7);

	if (n != 7) return(n);
	p=s->packet;

	memcpy(buf,p,n);

	if ((p[0] & 0x80) && (p[2] == SSL2_MT_SERVER_HELLO) &&
		(p[5] == 0x00) && (p[6] == 0x02))
		{
		OPENSSL_PUT_ERROR(SSL, ssl23_get_server_hello, SSL_R_UNSUPPORTED_PROTOCOL);
		goto err;
		}
	else if (p[1] == SSL3_VERSION_MAJOR &&
	         p[2] <= TLS1_2_VERSION_MINOR &&
	         ((p[0] == SSL3_RT_HANDSHAKE && p[5] == SSL3_MT_SERVER_HELLO) ||
	          (p[0] == SSL3_RT_ALERT && p[3] == 0 && p[4] == 2)))
		{
		/* we have sslv3 or tls1 (server hello or alert) */

		if ((p[2] == SSL3_VERSION_MINOR) &&
			!(s->options & SSL_OP_NO_SSLv3))
			{
			s->version=SSL3_VERSION;
			s->method=SSLv3_client_method();
			}
		else if ((p[2] == TLS1_VERSION_MINOR) &&
			!(s->options & SSL_OP_NO_TLSv1))
			{
			s->version=TLS1_VERSION;
			s->method=TLSv1_client_method();
			}
		else if ((p[2] == TLS1_1_VERSION_MINOR) &&
			!(s->options & SSL_OP_NO_TLSv1_1))
			{
			s->version=TLS1_1_VERSION;
			s->method=TLSv1_1_client_method();
			}
		else if ((p[2] == TLS1_2_VERSION_MINOR) &&
			!(s->options & SSL_OP_NO_TLSv1_2))
			{
			s->version=TLS1_2_VERSION;
			s->method=TLSv1_2_client_method();
			}
		else
			{
			OPENSSL_PUT_ERROR(SSL, ssl23_get_server_hello, SSL_R_UNSUPPORTED_PROTOCOL);
			goto err;
			}

		if (p[0] == SSL3_RT_ALERT && p[5] != SSL3_AL_WARNING)
			{
			/* fatal alert */

			void (*cb)(const SSL *ssl,int type,int val)=NULL;
			int j;

			if (s->info_callback != NULL)
				cb=s->info_callback;
			else if (s->ctx->info_callback != NULL)
				cb=s->ctx->info_callback;
 
			i=p[5];
			if (cb != NULL)
				{
				j=(i<<8)|p[6];
				cb(s,SSL_CB_READ_ALERT,j);
				}
			
			if (s->msg_callback)
				{
				s->msg_callback(0, s->version, SSL3_RT_HEADER, p, 5, s, s->msg_callback_arg);
				s->msg_callback(0, s->version, SSL3_RT_ALERT, p+5, 2, s, s->msg_callback_arg);
				}

			s->rwstate=SSL_NOTHING;
			OPENSSL_PUT_ERROR(SSL, ssl23_get_server_hello, SSL_AD_REASON_OFFSET + p[6]);
			goto err;
			}

		if (!ssl_init_wbio_buffer(s,1)) goto err;

		/* we are in this state */
		s->state=SSL3_ST_CR_SRVR_HELLO_A;

		/* put the 7 bytes we have read into the input buffer
		 * for SSLv3 */
		s->rstate=SSL_ST_READ_HEADER;
		s->packet_length=n;
		if (s->s3->rbuf.buf == NULL)
			if (!ssl3_setup_read_buffer(s))
				goto err;
		s->packet= &(s->s3->rbuf.buf[0]);
		memcpy(s->packet,buf,n);
		s->s3->rbuf.left=n;
		s->s3->rbuf.offset=0;

		s->handshake_func=s->method->ssl_connect;
		}
	else
		{
		OPENSSL_PUT_ERROR(SSL, ssl23_get_server_hello, SSL_R_UNKNOWN_PROTOCOL);
		goto err;
		}
	s->init_num=0;
	return(SSL_connect(s));
err:
	return(-1);
	}
