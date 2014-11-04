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
 * Copyright (c) 1998-2007 The OpenSSL Project.  All rights reserved.
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

#include <stdio.h>
#include <assert.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <openssl/mem.h>
#include <openssl/obj.h>
#include <openssl/rand.h>

#include "ssl_locl.h"

/* seed1 through seed5 are virtually concatenated */
static int tls1_P_hash(const EVP_MD *md, const unsigned char *sec,
			int sec_len,
			const void *seed1, int seed1_len,
			const void *seed2, int seed2_len,
			const void *seed3, int seed3_len,
			unsigned char *out, int olen)
	{
	int chunk;
	size_t j;
	EVP_MD_CTX ctx, ctx_tmp, ctx_init;
	EVP_PKEY *mac_key;
	unsigned char A1[EVP_MAX_MD_SIZE];
	size_t A1_len;
	int ret = 0;
	
	chunk=EVP_MD_size(md);

	EVP_MD_CTX_init(&ctx);
	EVP_MD_CTX_init(&ctx_tmp);
	EVP_MD_CTX_init(&ctx_init);
	mac_key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, sec, sec_len);
	if (!mac_key)
		goto err;
	if (!EVP_DigestSignInit(&ctx_init,NULL,md, NULL, mac_key))
		goto err;
	if (!EVP_MD_CTX_copy_ex(&ctx,&ctx_init))
		goto err;
	if (seed1 && !EVP_DigestSignUpdate(&ctx,seed1,seed1_len))
		goto err;
	if (seed2 && !EVP_DigestSignUpdate(&ctx,seed2,seed2_len))
		goto err;
	if (seed3 && !EVP_DigestSignUpdate(&ctx,seed3,seed3_len))
		goto err;
	A1_len = EVP_MAX_MD_SIZE;
	if (!EVP_DigestSignFinal(&ctx,A1,&A1_len))
		goto err;

	for (;;)
		{
		/* Reinit mac contexts */
		if (!EVP_MD_CTX_copy_ex(&ctx,&ctx_init))
			goto err;
		if (!EVP_DigestSignUpdate(&ctx,A1,A1_len))
			goto err;
		if (olen>chunk && !EVP_MD_CTX_copy_ex(&ctx_tmp,&ctx))
			goto err;
		if (seed1 && !EVP_DigestSignUpdate(&ctx,seed1,seed1_len))
			goto err;
		if (seed2 && !EVP_DigestSignUpdate(&ctx,seed2,seed2_len))
			goto err;
		if (seed3 && !EVP_DigestSignUpdate(&ctx,seed3,seed3_len))
			goto err;

		if (olen > chunk)
			{
			j = olen;
			if (!EVP_DigestSignFinal(&ctx,out,&j))
				goto err;
			out+=j;
			olen-=j;
			/* calc the next A1 value */
			A1_len = EVP_MAX_MD_SIZE;
			if (!EVP_DigestSignFinal(&ctx_tmp,A1,&A1_len))
				goto err;
			}
		else	/* last one */
			{
			A1_len = EVP_MAX_MD_SIZE;
			if (!EVP_DigestSignFinal(&ctx,A1,&A1_len))
				goto err;
			memcpy(out,A1,olen);
			break;
			}
		}
	ret = 1;
err:
	EVP_PKEY_free(mac_key);
	EVP_MD_CTX_cleanup(&ctx);
	EVP_MD_CTX_cleanup(&ctx_tmp);
	EVP_MD_CTX_cleanup(&ctx_init);
	OPENSSL_cleanse(A1,sizeof(A1));
	return ret;
	}

/* seed1 through seed5 are virtually concatenated */
static int tls1_PRF(long digest_mask,
		     const void *seed1, int seed1_len,
		     const void *seed2, int seed2_len,
		     const void *seed3, int seed3_len,
		     const unsigned char *sec, int slen,
		     unsigned char *out1,
		     unsigned char *out2, int olen)
	{
	int len,i,idx,count;
	const unsigned char *S1;
	long m;
	const EVP_MD *md;
	int ret = 0;

	/* Count number of digests and partition sec evenly */
	count=0;
	for (idx=0;ssl_get_handshake_digest(idx,&m,&md);idx++) {
		if ((m<<TLS1_PRF_DGST_SHIFT) & digest_mask) count++;
	}	
	len=slen/count;
	if (count == 1)
		slen = 0;
	S1=sec;
	memset(out1,0,olen);
	for (idx=0;ssl_get_handshake_digest(idx,&m,&md);idx++) {
		if ((m<<TLS1_PRF_DGST_SHIFT) & digest_mask) {
			if (!md) {
				OPENSSL_PUT_ERROR(SSL, tls1_PRF, SSL_R_UNSUPPORTED_DIGEST_TYPE);
				goto err;				
			}
			if (!tls1_P_hash(md ,S1,len+(slen&1),
					seed1,seed1_len,seed2,seed2_len,seed3,seed3_len,
					out2,olen))
				goto err;
			S1+=len;
			for (i=0; i<olen; i++)
			{
				out1[i]^=out2[i];
			}
		}
	}
	ret = 1;
err:
	return ret;
}

static int tls1_generate_key_block(SSL *s, unsigned char *km,
	     unsigned char *tmp, int num)
	{
	int ret;
	ret = tls1_PRF(ssl_get_algorithm2(s),
		 TLS_MD_KEY_EXPANSION_CONST,TLS_MD_KEY_EXPANSION_CONST_SIZE,
		 s->s3->server_random,SSL3_RANDOM_SIZE,
		 s->s3->client_random,SSL3_RANDOM_SIZE,
		 s->session->master_key,s->session->master_key_length,
		 km,tmp,num);
	return ret;
	}

/* tls1_aead_ctx_init allocates |*aead_ctx|, if needed and returns 1. It
 * returns 0 on malloc error. */
static int tls1_aead_ctx_init(SSL_AEAD_CTX **aead_ctx)
	{
	if (*aead_ctx != NULL)
		EVP_AEAD_CTX_cleanup(&(*aead_ctx)->ctx);
	else
		{
		*aead_ctx = (SSL_AEAD_CTX*) OPENSSL_malloc(sizeof(SSL_AEAD_CTX));
		if (*aead_ctx == NULL)
			{
			OPENSSL_PUT_ERROR(SSL, tls1_aead_ctx_init, ERR_R_MALLOC_FAILURE);
			return 0;
			}
		}

	return 1;
	}

static void tls1_cleanup_enc_ctx(EVP_CIPHER_CTX **ctx)
	{
	if (*ctx != NULL)
		EVP_CIPHER_CTX_free(*ctx);
	*ctx = NULL;
	}

static void tls1_cleanup_hash_ctx(EVP_MD_CTX **ctx)
	{
	if (*ctx != NULL)
		EVP_MD_CTX_destroy(*ctx);
	*ctx = NULL;
	}

static int tls1_change_cipher_state_aead(SSL *s, char is_read,
	const unsigned char *key, unsigned key_len,
	const unsigned char *iv, unsigned iv_len,
	const unsigned char *mac_secret, unsigned mac_secret_len)
	{
	const EVP_AEAD *aead = s->s3->tmp.new_aead;
	SSL_AEAD_CTX *aead_ctx;
	/* mac_key_and_key is used to merge the MAC and cipher keys for an AEAD
	 * which simulates pre-AEAD cipher suites. It needs to be large enough
	 * to cope with the largest pair of keys. */
	uint8_t mac_key_and_key[32 /* HMAC(SHA256) */ + 32 /* AES-256 */];

	if (is_read)
		{
		tls1_cleanup_enc_ctx(&s->enc_read_ctx);
		tls1_cleanup_hash_ctx(&s->read_hash);
		}
	else
		{
		tls1_cleanup_enc_ctx(&s->enc_write_ctx);
		tls1_cleanup_hash_ctx(&s->write_hash);
		}

	if (mac_secret_len > 0)
		{
		/* This is a "stateful" AEAD (for compatibility with pre-AEAD
		 * cipher suites). */
		if (mac_secret_len + key_len > sizeof(mac_key_and_key))
			{
			OPENSSL_PUT_ERROR(SSL, tls1_change_cipher_state_aead, ERR_R_INTERNAL_ERROR);
			return 0;
			}
		memcpy(mac_key_and_key, mac_secret, mac_secret_len);
		memcpy(mac_key_and_key + mac_secret_len, key, key_len);
		key = mac_key_and_key;
		key_len += mac_secret_len;
		}

	if (is_read)
		{
		if (!tls1_aead_ctx_init(&s->aead_read_ctx))
			return 0;
		aead_ctx = s->aead_read_ctx;
		}
	else
		{
		if (!tls1_aead_ctx_init(&s->aead_write_ctx))
			return 0;
		aead_ctx = s->aead_write_ctx;
		}

	if (!EVP_AEAD_CTX_init(&aead_ctx->ctx, aead, key, key_len,
			       EVP_AEAD_DEFAULT_TAG_LENGTH, NULL /* engine */))
		{
		OPENSSL_free(aead_ctx);
		if (is_read)
			s->aead_read_ctx = NULL;
		else
			s->aead_write_ctx = NULL;
		return 0;
		}
	if (iv_len > sizeof(aead_ctx->fixed_nonce))
		{
		OPENSSL_PUT_ERROR(SSL, tls1_change_cipher_state_aead, ERR_R_INTERNAL_ERROR);
		return 0;
		}
	memcpy(aead_ctx->fixed_nonce, iv, iv_len);
	aead_ctx->fixed_nonce_len = iv_len;
	aead_ctx->variable_nonce_len = 8;  /* correct for all true AEADs so far. */
	if (s->s3->tmp.new_cipher->algorithm2 & SSL_CIPHER_ALGORITHM2_STATEFUL_AEAD)
		aead_ctx->variable_nonce_len = 0;
	aead_ctx->variable_nonce_included_in_record =
		(s->s3->tmp.new_cipher->algorithm2 & SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_INCLUDED_IN_RECORD) != 0;
	if (aead_ctx->variable_nonce_len + aead_ctx->fixed_nonce_len != EVP_AEAD_nonce_length(aead))
		{
		OPENSSL_PUT_ERROR(SSL, tls1_change_cipher_state_aead, ERR_R_INTERNAL_ERROR);
		return 0;
		}
	aead_ctx->tag_len = EVP_AEAD_max_overhead(aead);

	return 1;
	}

static void tls1_cleanup_aead_ctx(SSL_AEAD_CTX **ctx)
	{
	if (*ctx != NULL)
		{
		EVP_AEAD_CTX_cleanup(&(*ctx)->ctx);
		OPENSSL_free(*ctx);
		}
	*ctx = NULL;
	}

/* tls1_change_cipher_state_cipher performs the work needed to switch cipher
 * states when using EVP_CIPHER. The argument |is_read| is true iff this
 * function is being called due to reading, as opposed to writing, a
 * ChangeCipherSpec message. In order to support export ciphersuites,
 * use_client_keys indicates whether the key material provided is in the
 * "client write" direction. */
static int tls1_change_cipher_state_cipher(
	SSL *s, char is_read, char use_client_keys,
	const unsigned char *mac_secret, unsigned mac_secret_len,
	const unsigned char *key, unsigned key_len,
	const unsigned char *iv, unsigned iv_len)
	{
	const EVP_CIPHER *cipher = s->s3->tmp.new_sym_enc;
	EVP_CIPHER_CTX *cipher_ctx;
	EVP_MD_CTX *mac_ctx;

	if (is_read)
		tls1_cleanup_aead_ctx(&s->aead_read_ctx);
	else
		tls1_cleanup_aead_ctx(&s->aead_write_ctx);

	if (is_read)
		{
		if (s->enc_read_ctx != NULL && !SSL_IS_DTLS(s))
			EVP_CIPHER_CTX_cleanup(s->enc_read_ctx);
		else if ((s->enc_read_ctx=EVP_CIPHER_CTX_new()) == NULL)
			goto err;

		cipher_ctx = s->enc_read_ctx;
		mac_ctx = ssl_replace_hash(&s->read_hash, NULL);

		memcpy(s->s3->read_mac_secret, mac_secret, mac_secret_len);
		s->s3->read_mac_secret_size = mac_secret_len;
		}
	else
		{
		/* When updating the write contexts for DTLS, we do not wish to
		 * free the old ones because DTLS stores pointers to them in
		 * order to implement retransmission. */

		if (s->enc_write_ctx != NULL && !SSL_IS_DTLS(s))
			EVP_CIPHER_CTX_cleanup(s->enc_write_ctx);
		else if ((s->enc_write_ctx=OPENSSL_malloc(sizeof(EVP_CIPHER_CTX))) == NULL)
			goto err;
		else
			/* make sure it's intialized in case we exit later with an error */
			EVP_CIPHER_CTX_init(s->enc_write_ctx);

		cipher_ctx = s->enc_write_ctx;
		if (SSL_IS_DTLS(s))
			{
			/* This is the same as ssl_replace_hash, but doesn't
			 * free the old |s->write_hash|. */
			mac_ctx = EVP_MD_CTX_create();
			if (!mac_ctx)
				goto err;
			s->write_hash = mac_ctx;
			}
		else
			mac_ctx = ssl_replace_hash(&s->write_hash, NULL);

		memcpy(s->s3->write_mac_secret, mac_secret, mac_secret_len);
		s->s3->write_mac_secret_size = mac_secret_len;
		}

	EVP_PKEY *mac_key =
		EVP_PKEY_new_mac_key(s->s3->tmp.new_mac_pkey_type,
				     NULL, mac_secret, mac_secret_len);
	if (!mac_key)
		return 0;
	EVP_DigestSignInit(mac_ctx, NULL, s->s3->tmp.new_hash, NULL, mac_key);
	EVP_PKEY_free(mac_key);

	EVP_CipherInit_ex(cipher_ctx, cipher, NULL /* engine */, key, iv, !is_read);

	return 1;

err:
	OPENSSL_PUT_ERROR(SSL, tls1_change_cipher_state_cipher, ERR_R_MALLOC_FAILURE);
	return 0;
	}

int tls1_change_cipher_state(SSL *s, int which)
	{
	/* is_read is true if we have just read a ChangeCipherSpec message -
	 * i.e. we need to update the read cipherspec. Otherwise we have just
	 * written one. */
	const char is_read = (which & SSL3_CC_READ) != 0;
	/* use_client_keys is true if we wish to use the keys for the "client
	 * write" direction. This is the case if we're a client sending a
	 * ChangeCipherSpec, or a server reading a client's ChangeCipherSpec. */
	const char use_client_keys = which == SSL3_CHANGE_CIPHER_CLIENT_WRITE ||
				     which == SSL3_CHANGE_CIPHER_SERVER_READ;
	const unsigned char *client_write_mac_secret, *server_write_mac_secret, *mac_secret;
	const unsigned char *client_write_key, *server_write_key, *key;
	const unsigned char *client_write_iv, *server_write_iv, *iv;
	const EVP_CIPHER *cipher = s->s3->tmp.new_sym_enc;
	const EVP_AEAD *aead = s->s3->tmp.new_aead;
	unsigned key_len, iv_len, mac_secret_len;
	const unsigned char *key_data;

	/* Reset sequence number to zero. */
	if (!SSL_IS_DTLS(s))
		memset(is_read ? s->s3->read_sequence : s->s3->write_sequence, 0, 8);

	mac_secret_len = s->s3->tmp.new_mac_secret_size;

	if (aead != NULL)
		{
		key_len = EVP_AEAD_key_length(aead);
		/* For "stateful" AEADs (i.e. compatibility with pre-AEAD
		 * cipher suites) the key length reported by
		 * |EVP_AEAD_key_length| will include the MAC key bytes. */
		if (key_len < mac_secret_len)
			{
			OPENSSL_PUT_ERROR(SSL, tls1_change_cipher_state, ERR_R_INTERNAL_ERROR);
			return 0;
			}
		key_len -= mac_secret_len;
		iv_len = SSL_CIPHER_AEAD_FIXED_NONCE_LEN(s->s3->tmp.new_cipher);
		}
	else
		{
		key_len = EVP_CIPHER_key_length(cipher);
		iv_len = EVP_CIPHER_iv_length(cipher);
		}

	key_data = s->s3->tmp.key_block;
	client_write_mac_secret = key_data; key_data += mac_secret_len;
	server_write_mac_secret = key_data; key_data += mac_secret_len;
	client_write_key =        key_data; key_data += key_len;
	server_write_key =        key_data; key_data += key_len;
	client_write_iv  =        key_data; key_data += iv_len;
	server_write_iv  =        key_data; key_data += iv_len;

	if (use_client_keys)
		{
		mac_secret = client_write_mac_secret;
		key = client_write_key;
		iv = client_write_iv;
		}
	else
		{
		mac_secret = server_write_mac_secret;
		key = server_write_key;
		iv = server_write_iv;
		}

	if (key_data - s->s3->tmp.key_block != s->s3->tmp.key_block_length)
		{
		OPENSSL_PUT_ERROR(SSL, tls1_change_cipher_state, ERR_R_INTERNAL_ERROR);
		return 0;
		}

	if (aead != NULL)
		{
		if (!tls1_change_cipher_state_aead(s, is_read,
						   key, key_len, iv, iv_len,
						   mac_secret, mac_secret_len))
			return 0;
		}
	else
		{
		if (!tls1_change_cipher_state_cipher(s, is_read, use_client_keys,
						     mac_secret, mac_secret_len,
						     key, key_len,
						     iv, iv_len))
			return 0;
		}

	return 1;
	}

int tls1_setup_key_block(SSL *s)
	{
	unsigned char *p1,*p2=NULL;
	const EVP_CIPHER *c = NULL;
	const EVP_MD *hash = NULL;
	const EVP_AEAD *aead = NULL;
	int num;
	int mac_type= NID_undef,mac_secret_size=0;
	int ret=0;
	unsigned key_len, iv_len;


	if (s->s3->tmp.key_block_length != 0)
		return(1);

	if (s->session->cipher &&
	    ((s->session->cipher->algorithm2 & SSL_CIPHER_ALGORITHM2_AEAD) ||
	     (s->session->cipher->algorithm2 & SSL_CIPHER_ALGORITHM2_STATEFUL_AEAD)))
		{
		if (!ssl_cipher_get_evp_aead(s->session, &aead))
			goto cipher_unavailable_err;
		key_len = EVP_AEAD_key_length(aead);
		iv_len = SSL_CIPHER_AEAD_FIXED_NONCE_LEN(s->session->cipher);
		if ((s->session->cipher->algorithm2 &
				SSL_CIPHER_ALGORITHM2_STATEFUL_AEAD) &&
			!ssl_cipher_get_mac(s->session, &hash, &mac_type, &mac_secret_size))
			goto cipher_unavailable_err;
		/* For "stateful" AEADs (i.e. compatibility with pre-AEAD
		 * cipher suites) the key length reported by
		 * |EVP_AEAD_key_length| will include the MAC key bytes. */
		if (key_len < (size_t)mac_secret_size)
			{
			OPENSSL_PUT_ERROR(SSL, tls1_change_cipher_state, ERR_R_INTERNAL_ERROR);
			return 0;
			}
		key_len -= mac_secret_size;
		}
	else
		{
		if (!ssl_cipher_get_evp(s->session,&c,&hash,&mac_type,&mac_secret_size))
			goto cipher_unavailable_err;
		key_len = EVP_CIPHER_key_length(c);
		iv_len = EVP_CIPHER_iv_length(c);
		}

	s->s3->tmp.new_aead=aead;
	s->s3->tmp.new_sym_enc=c;
	s->s3->tmp.new_hash=hash;
	s->s3->tmp.new_mac_pkey_type = mac_type;
	s->s3->tmp.new_mac_secret_size = mac_secret_size;

	num=key_len+mac_secret_size+iv_len;
	num*=2;

	ssl3_cleanup_key_block(s);

	if ((p1=(unsigned char *)OPENSSL_malloc(num)) == NULL)
		{
		OPENSSL_PUT_ERROR(SSL, tls1_setup_key_block, ERR_R_MALLOC_FAILURE);
		goto err;
		}

	s->s3->tmp.key_block_length=num;
	s->s3->tmp.key_block=p1;

	if ((p2=(unsigned char *)OPENSSL_malloc(num)) == NULL)
		{
		OPENSSL_PUT_ERROR(SSL, tls1_setup_key_block, ERR_R_MALLOC_FAILURE);
		goto err;
		}

#ifdef TLS_DEBUG
printf("client random\n");
{ int z; for (z=0; z<SSL3_RANDOM_SIZE; z++) printf("%02X%c",s->s3->client_random[z],((z+1)%16)?' ':'\n'); }
printf("server random\n");
{ int z; for (z=0; z<SSL3_RANDOM_SIZE; z++) printf("%02X%c",s->s3->server_random[z],((z+1)%16)?' ':'\n'); }
printf("pre-master\n");
{ int z; for (z=0; z<s->session->master_key_length; z++) printf("%02X%c",s->session->master_key[z],((z+1)%16)?' ':'\n'); }
#endif
	if (!tls1_generate_key_block(s,p1,p2,num))
		goto err;
#ifdef TLS_DEBUG
printf("\nkey block\n");
{ int z; for (z=0; z<num; z++) printf("%02X%c",p1[z],((z+1)%16)?' ':'\n'); }
#endif

	if (s->method->version <= TLS1_VERSION &&
	    (s->mode & SSL_MODE_CBC_RECORD_SPLITTING) != 0)
		{
		/* enable vulnerability countermeasure for CBC ciphers with
		 * known-IV problem (http://www.openssl.org/~bodo/tls-cbc.txt)
		 */
		s->s3->need_record_splitting = 1;

		if (s->session->cipher != NULL)
			{
			if (s->session->cipher->algorithm_enc == SSL_RC4)
				s->s3->need_record_splitting = 0;
			}
		}
		
	ret = 1;
err:
	if (p2)
		{
		OPENSSL_cleanse(p2,num);
		OPENSSL_free(p2);
		}
	return(ret);

cipher_unavailable_err:
	OPENSSL_PUT_ERROR(SSL, tls1_setup_key_block, SSL_R_CIPHER_OR_HASH_UNAVAILABLE);
	return 0;
	}

/* tls1_enc encrypts/decrypts the record in |s->wrec| / |s->rrec|, respectively.
 *
 * Returns:
 *   0: (in non-constant time) if the record is publically invalid (i.e. too
 *       short etc).
 *   1: if the record's padding is valid / the encryption was successful.
 *   -1: if the record's padding/AEAD-authenticator is invalid or, if sending,
 *       an internal error occured.
 */
int tls1_enc(SSL *s, int send)
	{
	SSL3_RECORD *rec;
	EVP_CIPHER_CTX *ds;
	unsigned long l;
	int bs,i,j,k,pad=0,ret,mac_size=0;
	const EVP_CIPHER *enc;
	const SSL_AEAD_CTX *aead;

	if (send)
		rec = &s->s3->wrec;
	else
		rec = &s->s3->rrec;

	if (send)
		aead = s->aead_write_ctx;
	else
		aead = s->aead_read_ctx;

	if (aead)
		{
		unsigned char ad[13], *seq, *in, *out, nonce[16];
		unsigned nonce_used;
		size_t n;

		seq = send ? s->s3->write_sequence : s->s3->read_sequence;

		if (SSL_IS_DTLS(s))
			{
			unsigned char dtlsseq[9], *p = dtlsseq;

			s2n(send ? s->d1->w_epoch : s->d1->r_epoch, p);
			memcpy(p, &seq[2], 6);
			memcpy(ad, dtlsseq, 8);
			}
		else
			{
			memcpy(ad, seq, 8);
			for (i=7; i>=0; i--)	/* increment */
				{
				++seq[i];
				if (seq[i] != 0)
					break;
				}
			}

		ad[8]  = rec->type;
		ad[9]  = (unsigned char)(s->version>>8);
		ad[10] = (unsigned char)(s->version);

		if (aead->fixed_nonce_len + aead->variable_nonce_len > sizeof(nonce) ||
		    aead->variable_nonce_len > 8)
			return -1;  /* internal error - should never happen. */

		memcpy(nonce, aead->fixed_nonce, aead->fixed_nonce_len);
		nonce_used = aead->fixed_nonce_len;

		if (send)
			{
			size_t len = rec->length;
			size_t eivlen = 0;
			in = rec->input;
			out = rec->data;

			/* When sending we use the sequence number as the
			 * variable part of the nonce. */
			if (aead->variable_nonce_len > 8)
				return -1;
			memcpy(nonce + nonce_used, ad, aead->variable_nonce_len);
			nonce_used += aead->variable_nonce_len;

			/* in do_ssl3_write, rec->input is moved forward by
			 * variable_nonce_len in order to leave space for the
			 * variable nonce. Thus we can copy the sequence number
			 * bytes into place without overwriting any of the
			 * plaintext. */
			if (aead->variable_nonce_included_in_record)
				{
				memcpy(out, ad, aead->variable_nonce_len);
				len -= aead->variable_nonce_len;
				eivlen = aead->variable_nonce_len;
				}

			ad[11] = len >> 8;
			ad[12] = len & 0xff;

			if (!EVP_AEAD_CTX_seal(
				&aead->ctx,
				out + eivlen, &n, len + aead->tag_len,
				nonce, nonce_used,
				in + eivlen, len,
				ad, sizeof(ad)))
				{
				return -1;
				}
			if (aead->variable_nonce_included_in_record)
				n += aead->variable_nonce_len;
			}
		else
			{
			/* receive */
			size_t len = rec->length;

			if (rec->data != rec->input)
				return -1;  /* internal error - should never happen. */
			out = in = rec->input;

			if (len < aead->variable_nonce_len)
				return 0;
			memcpy(nonce + nonce_used,
			       aead->variable_nonce_included_in_record ? in : ad,
			       aead->variable_nonce_len);
			nonce_used += aead->variable_nonce_len;

			if (aead->variable_nonce_included_in_record)
				{
				in += aead->variable_nonce_len;
				len -= aead->variable_nonce_len;
				out += aead->variable_nonce_len;
				}

			if (len < aead->tag_len)
				return 0;
			len -= aead->tag_len;

			ad[11] = len >> 8;
			ad[12] = len & 0xff;

			if (!EVP_AEAD_CTX_open(
				&aead->ctx,
				out, &n, len,
				nonce, nonce_used,
				in, len + aead->tag_len,
				ad, sizeof(ad)))
				{
				return -1;
				}

			rec->data = rec->input = out;
			}

		rec->length = n;
		return 1;
		}

	if (send)
		{
		ds=s->enc_write_ctx;
		rec= &(s->s3->wrec);
		if (s->enc_write_ctx == NULL)
			enc=NULL;
		else
			{
			int ivlen;
			enc=EVP_CIPHER_CTX_cipher(s->enc_write_ctx);
			/* For TLSv1.1 and later explicit IV */
			if (SSL_USE_EXPLICIT_IV(s)
				&& EVP_CIPHER_mode(enc) == EVP_CIPH_CBC_MODE)
				ivlen = EVP_CIPHER_iv_length(enc);
			else
				ivlen = 0;
			if (ivlen > 1)
				{
				if ( rec->data != rec->input)
					/* we can't write into the input stream:
					 * Can this ever happen?? (steve)
					 */
					fprintf(stderr,
						"%s:%d: rec->data != rec->input\n",
						__FILE__, __LINE__);
				else if (RAND_bytes(rec->input, ivlen) <= 0)
					return -1;
				}
			}
		}
	else
		{
		ds=s->enc_read_ctx;
		rec= &(s->s3->rrec);
		if (s->enc_read_ctx == NULL)
			enc=NULL;
		else
			enc=EVP_CIPHER_CTX_cipher(s->enc_read_ctx);
		}

	if ((s->session == NULL) || (ds == NULL) || (enc == NULL))
		{
		memmove(rec->data,rec->input,rec->length);
		rec->input=rec->data;
		ret = 1;
		}
	else
		{
		l=rec->length;
		bs=EVP_CIPHER_block_size(ds->cipher);

		if ((bs != 1) && send)
			{
			i=bs-((int)l%bs);

			/* Add weird padding of upto 256 bytes */

			/* we need to add 'i' padding bytes of value j */
			j=i-1;
			for (k=(int)l; k<(int)(l+i); k++)
				rec->input[k]=j;
			l+=i;
			rec->length+=i;
			}

		if (!send)
			{
			if (l == 0 || l%bs != 0)
				return 0;
			}
		
		i = EVP_Cipher(ds,rec->data,rec->input,l);
		if ((EVP_CIPHER_flags(ds->cipher)&EVP_CIPH_FLAG_CUSTOM_CIPHER)
						?(i<0)
						:(i==0))
			return -1;	/* AEAD can fail to verify MAC */

		ret = 1;
		if (EVP_MD_CTX_md(s->read_hash) != NULL)
			mac_size = EVP_MD_CTX_size(s->read_hash);
		if ((bs != 1) && !send)
			ret = tls1_cbc_remove_padding(s, rec, bs, mac_size);
		if (pad && !send)
			rec->length -= pad;
		}
	return ret;
	}

int tls1_cert_verify_mac(SSL *s, int md_nid, unsigned char *out)
	{
	unsigned int ret;
	EVP_MD_CTX ctx, *d=NULL;
	int i;

	if (s->s3->handshake_buffer)
		if (!ssl3_digest_cached_records(s, free_handshake_buffer))
			return 0;

	for (i=0;i<SSL_MAX_DIGEST;i++) 
		{
		  if (s->s3->handshake_dgst[i]&&EVP_MD_CTX_type(s->s3->handshake_dgst[i])==md_nid) 
		  	{
		  	d=s->s3->handshake_dgst[i];
			break;
			}
		}
	if (!d) {
		OPENSSL_PUT_ERROR(SSL, tls1_cert_verify_mac, SSL_R_NO_REQUIRED_DIGEST);
		return 0;
	}	

	EVP_MD_CTX_init(&ctx);
	EVP_MD_CTX_copy_ex(&ctx,d);
	EVP_DigestFinal_ex(&ctx,out,&ret);
	EVP_MD_CTX_cleanup(&ctx);
	return((int)ret);
	}

/* tls1_handshake_digest calculates the current handshake hash and writes it to
 * |out|, which has space for |out_len| bytes. It returns the number of bytes
 * written or -1 in the event of an error. This function works on a copy of the
 * underlying digests so can be called multiple times and prior to the final
 * update etc. */
int tls1_handshake_digest(SSL *s, unsigned char *out, size_t out_len)
	{
	const EVP_MD *md;
	EVP_MD_CTX ctx;
	int i, err = 0, len = 0;
	long mask;

	EVP_MD_CTX_init(&ctx);

	for (i = 0; ssl_get_handshake_digest(i, &mask, &md); i++)
		{
		int hash_size;
		unsigned int digest_len;
		EVP_MD_CTX *hdgst = s->s3->handshake_dgst[i];

		if ((mask & ssl_get_algorithm2(s)) == 0)
			continue;

		hash_size = EVP_MD_size(md);
		if (!hdgst || hash_size < 0 || (size_t)hash_size > out_len)
			{
			err = 1;
			break;
			}

		if (!EVP_MD_CTX_copy_ex(&ctx, hdgst) ||
		    !EVP_DigestFinal_ex(&ctx, out, &digest_len) ||
		    digest_len != (unsigned int)hash_size) /* internal error */
			{
			err = 1;
			break;
			}
		out += digest_len;
		out_len -= digest_len;
		len += digest_len;
		}

	EVP_MD_CTX_cleanup(&ctx);

	if (err != 0)
		return -1;
	return len;
	}

int tls1_final_finish_mac(SSL *s,
	     const char *str, int slen, unsigned char *out)
	{
	unsigned char buf[2*EVP_MAX_MD_SIZE];
	unsigned char buf2[12];
	int err=0;
	int digests_len;

	if (s->s3->handshake_buffer)
		if (!ssl3_digest_cached_records(s, free_handshake_buffer))
			return 0;

	digests_len = tls1_handshake_digest(s, buf, sizeof(buf));
	if (digests_len < 0)
		{
		err = 1;
		digests_len = 0;
		}
		
	if (!tls1_PRF(ssl_get_algorithm2(s),
			str,slen, buf, digests_len, NULL,0,
			s->session->master_key,s->session->master_key_length,
			out,buf2,sizeof buf2))
		err = 1;

	if (err)
		return 0;
	else
		return sizeof buf2;
	}

int tls1_mac(SSL *ssl, unsigned char *md, int send)
	{
	SSL3_RECORD *rec;
	unsigned char *seq;
	EVP_MD_CTX *hash;
	size_t md_size, orig_len;
	int i;
	EVP_MD_CTX hmac, *mac_ctx;
	unsigned char header[13];
	int t;

	if (send)
		{
		rec= &(ssl->s3->wrec);
		seq= &(ssl->s3->write_sequence[0]);
		hash=ssl->write_hash;
		}
	else
		{
		rec= &(ssl->s3->rrec);
		seq= &(ssl->s3->read_sequence[0]);
		hash=ssl->read_hash;
		}

	t=EVP_MD_CTX_size(hash);
	assert(t >= 0);
	md_size=t;

	if (!EVP_MD_CTX_copy(&hmac,hash))
		return -1;
	mac_ctx = &hmac;

	if (SSL_IS_DTLS(ssl))
		{
		unsigned char dtlsseq[8],*p=dtlsseq;

		s2n(send?ssl->d1->w_epoch:ssl->d1->r_epoch, p);
		memcpy (p,&seq[2],6);

		memcpy(header, dtlsseq, 8);
		}
	else
		memcpy(header, seq, 8);

	/* kludge: tls1_cbc_remove_padding passes padding length in rec->type */
	orig_len = rec->length+md_size+((unsigned int)rec->type>>8);
	rec->type &= 0xff;

	header[8]=rec->type;
	header[9]=(unsigned char)(ssl->version>>8);
	header[10]=(unsigned char)(ssl->version);
	header[11]=(rec->length)>>8;
	header[12]=(rec->length)&0xff;

	if (!send &&
	    EVP_CIPHER_CTX_mode(ssl->enc_read_ctx) == EVP_CIPH_CBC_MODE &&
	    ssl3_cbc_record_digest_supported(mac_ctx))
		{
		/* This is a CBC-encrypted record. We must avoid leaking any
		 * timing-side channel information about how many blocks of
		 * data we are hashing because that gives an attacker a
		 * timing-oracle. */
		ssl3_cbc_digest_record(
			mac_ctx,
			md, &md_size,
			header, rec->input,
			rec->length + md_size, orig_len,
			ssl->s3->read_mac_secret,
			ssl->s3->read_mac_secret_size,
			0 /* not SSLv3 */);
		}
	else
		{
		EVP_DigestSignUpdate(mac_ctx,header,sizeof(header));
		EVP_DigestSignUpdate(mac_ctx,rec->input,rec->length);
		t=EVP_DigestSignFinal(mac_ctx,md,&md_size);
		assert(t > 0);
		}
		
	EVP_MD_CTX_cleanup(&hmac);

	if (!SSL_IS_DTLS(ssl))
		{
		for (i=7; i>=0; i--)
			{
			++seq[i];
			if (seq[i] != 0) break; 
			}
		}

	return(md_size);
	}

int tls1_generate_master_secret(SSL *s, unsigned char *out, unsigned char *p,
	     int len)
	{
	unsigned char buff[SSL_MAX_MASTER_KEY_LENGTH];

	if (s->s3->tmp.extended_master_secret)
		{
		uint8_t digests[2*EVP_MAX_MD_SIZE];
		int digests_len;

		if (s->s3->handshake_buffer)
			{
			/* The master secret is based on the handshake hash
			 * just after sending the ClientKeyExchange. However,
			 * we might have a client certificate to send, in which
			 * case we might need different hashes for the
			 * verification and thus still need the handshake
			 * buffer around. Keeping both a handshake buffer *and*
			 * running hashes isn't yet supported so, when it comes
			 * to calculating the Finished hash, we'll have to hash
			 * the handshake buffer again. */
			if (!ssl3_digest_cached_records(s, dont_free_handshake_buffer))
				return 0;
			}

		digests_len = tls1_handshake_digest(s, digests, sizeof(digests));

		if (digests_len == -1)
			{
			return 0;
			}

		tls1_PRF(ssl_get_algorithm2(s),
			TLS_MD_EXTENDED_MASTER_SECRET_CONST,
			TLS_MD_EXTENDED_MASTER_SECRET_CONST_SIZE,
			digests, digests_len,
			NULL, 0,
			p, len,
			s->session->master_key,
			buff, sizeof(buff));
		}
	else
		{
		tls1_PRF(ssl_get_algorithm2(s),
			TLS_MD_MASTER_SECRET_CONST,TLS_MD_MASTER_SECRET_CONST_SIZE,
			s->s3->client_random,SSL3_RANDOM_SIZE,
			s->s3->server_random,SSL3_RANDOM_SIZE,
			p, len,
			s->session->master_key,buff,sizeof buff);
		}

#ifdef SSL_DEBUG
	fprintf(stderr, "Premaster Secret:\n");
	BIO_dump_fp(stderr, (char *)p, len);
	fprintf(stderr, "Client Random:\n");
	BIO_dump_fp(stderr, (char *)s->s3->client_random, SSL3_RANDOM_SIZE);
	fprintf(stderr, "Server Random:\n");
	BIO_dump_fp(stderr, (char *)s->s3->server_random, SSL3_RANDOM_SIZE);
	fprintf(stderr, "Master Secret:\n");
	BIO_dump_fp(stderr, (char *)s->session->master_key, SSL3_MASTER_SECRET_SIZE);
#endif

#ifdef OPENSSL_SSL_TRACE_CRYPTO
	if (s->msg_callback)
		{
		s->msg_callback(2, s->version, TLS1_RT_CRYPTO_PREMASTER,
						p, len, s, s->msg_callback_arg);
		s->msg_callback(2, s->version, TLS1_RT_CRYPTO_CLIENT_RANDOM,
					s->s3->client_random, SSL3_RANDOM_SIZE,
						s, s->msg_callback_arg);
		s->msg_callback(2, s->version, TLS1_RT_CRYPTO_SERVER_RANDOM,
					s->s3->server_random, SSL3_RANDOM_SIZE,
					s, s->msg_callback_arg);
		s->msg_callback(2, s->version, TLS1_RT_CRYPTO_MASTER,
					s->session->master_key,
					SSL3_MASTER_SECRET_SIZE,
					s, s->msg_callback_arg);
		}
#endif

	return(SSL3_MASTER_SECRET_SIZE);
	}

int tls1_export_keying_material(SSL *s, unsigned char *out, size_t olen,
	 const char *label, size_t llen, const unsigned char *context,
	 size_t contextlen, int use_context)
	{
	unsigned char *buff;
	unsigned char *val = NULL;
	size_t vallen, currentvalpos;
	int rv;

	buff = OPENSSL_malloc(olen);
	if (buff == NULL) goto err2;

	/* construct PRF arguments
	 * we construct the PRF argument ourself rather than passing separate
	 * values into the TLS PRF to ensure that the concatenation of values
	 * does not create a prohibited label.
	 */
	vallen = llen + SSL3_RANDOM_SIZE * 2;
	if (use_context)
		{
		vallen += 2 + contextlen;
		}

	val = OPENSSL_malloc(vallen);
	if (val == NULL) goto err2;
	currentvalpos = 0;
	memcpy(val + currentvalpos, (unsigned char *) label, llen);
	currentvalpos += llen;
	memcpy(val + currentvalpos, s->s3->client_random, SSL3_RANDOM_SIZE);
	currentvalpos += SSL3_RANDOM_SIZE;
	memcpy(val + currentvalpos, s->s3->server_random, SSL3_RANDOM_SIZE);
	currentvalpos += SSL3_RANDOM_SIZE;

	if (use_context)
		{
		val[currentvalpos] = (contextlen >> 8) & 0xff;
		currentvalpos++;
		val[currentvalpos] = contextlen & 0xff;
		currentvalpos++;
		if ((contextlen > 0) || (context != NULL))
			{
			memcpy(val + currentvalpos, context, contextlen);
			}
		}

	/* disallow prohibited labels
	 * note that SSL3_RANDOM_SIZE > max(prohibited label len) =
	 * 15, so size of val > max(prohibited label len) = 15 and the
	 * comparisons won't have buffer overflow
	 */
	if (memcmp(val, TLS_MD_CLIENT_FINISH_CONST,
		 TLS_MD_CLIENT_FINISH_CONST_SIZE) == 0) goto err1;
	if (memcmp(val, TLS_MD_SERVER_FINISH_CONST,
		 TLS_MD_SERVER_FINISH_CONST_SIZE) == 0) goto err1;
	if (memcmp(val, TLS_MD_MASTER_SECRET_CONST,
		 TLS_MD_MASTER_SECRET_CONST_SIZE) == 0) goto err1;
	if (memcmp(val, TLS_MD_KEY_EXPANSION_CONST,
		 TLS_MD_KEY_EXPANSION_CONST_SIZE) == 0) goto err1;

	rv = tls1_PRF(ssl_get_algorithm2(s),
		      val, vallen,
		      NULL, 0,
		      NULL, 0,
		      s->session->master_key,s->session->master_key_length,
		      out,buff,olen);

	goto ret;
err1:
	OPENSSL_PUT_ERROR(SSL, tls1_export_keying_material, SSL_R_TLS_ILLEGAL_EXPORTER_LABEL);
	rv = 0;
	goto ret;
err2:
	OPENSSL_PUT_ERROR(SSL, tls1_export_keying_material, ERR_R_MALLOC_FAILURE);
	rv = 0;
ret:
	if (buff != NULL) OPENSSL_free(buff);
	if (val != NULL) OPENSSL_free(val);
	return(rv);
	}

int tls1_alert_code(int code)
	{
	switch (code)
		{
	case SSL_AD_CLOSE_NOTIFY:	return(SSL3_AD_CLOSE_NOTIFY);
	case SSL_AD_UNEXPECTED_MESSAGE:	return(SSL3_AD_UNEXPECTED_MESSAGE);
	case SSL_AD_BAD_RECORD_MAC:	return(SSL3_AD_BAD_RECORD_MAC);
	case SSL_AD_DECRYPTION_FAILED:	return(TLS1_AD_DECRYPTION_FAILED);
	case SSL_AD_RECORD_OVERFLOW:	return(TLS1_AD_RECORD_OVERFLOW);
	case SSL_AD_DECOMPRESSION_FAILURE:return(SSL3_AD_DECOMPRESSION_FAILURE);
	case SSL_AD_HANDSHAKE_FAILURE:	return(SSL3_AD_HANDSHAKE_FAILURE);
	case SSL_AD_NO_CERTIFICATE:	return(-1);
	case SSL_AD_BAD_CERTIFICATE:	return(SSL3_AD_BAD_CERTIFICATE);
	case SSL_AD_UNSUPPORTED_CERTIFICATE:return(SSL3_AD_UNSUPPORTED_CERTIFICATE);
	case SSL_AD_CERTIFICATE_REVOKED:return(SSL3_AD_CERTIFICATE_REVOKED);
	case SSL_AD_CERTIFICATE_EXPIRED:return(SSL3_AD_CERTIFICATE_EXPIRED);
	case SSL_AD_CERTIFICATE_UNKNOWN:return(SSL3_AD_CERTIFICATE_UNKNOWN);
	case SSL_AD_ILLEGAL_PARAMETER:	return(SSL3_AD_ILLEGAL_PARAMETER);
	case SSL_AD_UNKNOWN_CA:		return(TLS1_AD_UNKNOWN_CA);
	case SSL_AD_ACCESS_DENIED:	return(TLS1_AD_ACCESS_DENIED);
	case SSL_AD_DECODE_ERROR:	return(TLS1_AD_DECODE_ERROR);
	case SSL_AD_DECRYPT_ERROR:	return(TLS1_AD_DECRYPT_ERROR);
	case SSL_AD_EXPORT_RESTRICTION:	return(TLS1_AD_EXPORT_RESTRICTION);
	case SSL_AD_PROTOCOL_VERSION:	return(TLS1_AD_PROTOCOL_VERSION);
	case SSL_AD_INSUFFICIENT_SECURITY:return(TLS1_AD_INSUFFICIENT_SECURITY);
	case SSL_AD_INTERNAL_ERROR:	return(TLS1_AD_INTERNAL_ERROR);
	case SSL_AD_USER_CANCELLED:	return(TLS1_AD_USER_CANCELLED);
	case SSL_AD_NO_RENEGOTIATION:	return(TLS1_AD_NO_RENEGOTIATION);
	case SSL_AD_UNSUPPORTED_EXTENSION: return(TLS1_AD_UNSUPPORTED_EXTENSION);
	case SSL_AD_CERTIFICATE_UNOBTAINABLE: return(TLS1_AD_CERTIFICATE_UNOBTAINABLE);
	case SSL_AD_UNRECOGNIZED_NAME:	return(TLS1_AD_UNRECOGNIZED_NAME);
	case SSL_AD_BAD_CERTIFICATE_STATUS_RESPONSE: return(TLS1_AD_BAD_CERTIFICATE_STATUS_RESPONSE);
	case SSL_AD_BAD_CERTIFICATE_HASH_VALUE: return(TLS1_AD_BAD_CERTIFICATE_HASH_VALUE);
	case SSL_AD_UNKNOWN_PSK_IDENTITY:return(TLS1_AD_UNKNOWN_PSK_IDENTITY);
	case SSL_AD_INAPPROPRIATE_FALLBACK:return(SSL3_AD_INAPPROPRIATE_FALLBACK);
	default:			return(-1);
		}
	}
