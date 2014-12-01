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
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 * ECC cipher suite support in OpenSSL originally developed by
 * SUN MICROSYSTEMS, INC., and contributed to the OpenSSL project.
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
 * OTHERWISE.
 */

#ifndef HEADER_SSL_LOCL_H
#define HEADER_SSL_LOCL_H

#include <openssl/base.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/aead.h>
#include <openssl/bio.h>
#include <openssl/buf.h>
#include <openssl/dsa.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/stack.h>

#define c2l(c,l)	(l = ((unsigned long)(*((c)++)))     , \
			 l|=(((unsigned long)(*((c)++)))<< 8), \
			 l|=(((unsigned long)(*((c)++)))<<16), \
			 l|=(((unsigned long)(*((c)++)))<<24))

/* NOTE - c is not incremented as per c2l */
#define c2ln(c,l1,l2,n)	{ \
			c+=n; \
			l1=l2=0; \
			switch (n) { \
			case 8: l2 =((unsigned long)(*(--(c))))<<24; \
			case 7: l2|=((unsigned long)(*(--(c))))<<16; \
			case 6: l2|=((unsigned long)(*(--(c))))<< 8; \
			case 5: l2|=((unsigned long)(*(--(c))));     \
			case 4: l1 =((unsigned long)(*(--(c))))<<24; \
			case 3: l1|=((unsigned long)(*(--(c))))<<16; \
			case 2: l1|=((unsigned long)(*(--(c))))<< 8; \
			case 1: l1|=((unsigned long)(*(--(c))));     \
				} \
			}

#define l2c(l,c)	(*((c)++)=(unsigned char)(((l)    )&0xff), \
			 *((c)++)=(unsigned char)(((l)>> 8)&0xff), \
			 *((c)++)=(unsigned char)(((l)>>16)&0xff), \
			 *((c)++)=(unsigned char)(((l)>>24)&0xff))

#define n2l(c,l)	(l =((unsigned long)(*((c)++)))<<24, \
			 l|=((unsigned long)(*((c)++)))<<16, \
			 l|=((unsigned long)(*((c)++)))<< 8, \
			 l|=((unsigned long)(*((c)++))))

#define l2n(l,c)	(*((c)++)=(unsigned char)(((l)>>24)&0xff), \
			 *((c)++)=(unsigned char)(((l)>>16)&0xff), \
			 *((c)++)=(unsigned char)(((l)>> 8)&0xff), \
			 *((c)++)=(unsigned char)(((l)    )&0xff))

#define l2n6(l,c)	(*((c)++)=(unsigned char)(((l)>>40)&0xff), \
			 *((c)++)=(unsigned char)(((l)>>32)&0xff), \
			 *((c)++)=(unsigned char)(((l)>>24)&0xff), \
			 *((c)++)=(unsigned char)(((l)>>16)&0xff), \
			 *((c)++)=(unsigned char)(((l)>> 8)&0xff), \
			 *((c)++)=(unsigned char)(((l)    )&0xff))

#define l2n8(l,c)	(*((c)++)=(unsigned char)(((l)>>56)&0xff), \
			 *((c)++)=(unsigned char)(((l)>>48)&0xff), \
			 *((c)++)=(unsigned char)(((l)>>40)&0xff), \
			 *((c)++)=(unsigned char)(((l)>>32)&0xff), \
			 *((c)++)=(unsigned char)(((l)>>24)&0xff), \
			 *((c)++)=(unsigned char)(((l)>>16)&0xff), \
			 *((c)++)=(unsigned char)(((l)>> 8)&0xff), \
			 *((c)++)=(unsigned char)(((l)    )&0xff))

#define n2l6(c,l)	(l =((BN_ULLONG)(*((c)++)))<<40, \
			 l|=((BN_ULLONG)(*((c)++)))<<32, \
			 l|=((BN_ULLONG)(*((c)++)))<<24, \
			 l|=((BN_ULLONG)(*((c)++)))<<16, \
			 l|=((BN_ULLONG)(*((c)++)))<< 8, \
			 l|=((BN_ULLONG)(*((c)++))))

/* NOTE - c is not incremented as per l2c */
#define l2cn(l1,l2,c,n)	{ \
			c+=n; \
			switch (n) { \
			case 8: *(--(c))=(unsigned char)(((l2)>>24)&0xff); \
			case 7: *(--(c))=(unsigned char)(((l2)>>16)&0xff); \
			case 6: *(--(c))=(unsigned char)(((l2)>> 8)&0xff); \
			case 5: *(--(c))=(unsigned char)(((l2)    )&0xff); \
			case 4: *(--(c))=(unsigned char)(((l1)>>24)&0xff); \
			case 3: *(--(c))=(unsigned char)(((l1)>>16)&0xff); \
			case 2: *(--(c))=(unsigned char)(((l1)>> 8)&0xff); \
			case 1: *(--(c))=(unsigned char)(((l1)    )&0xff); \
				} \
			}

#define n2s(c,s)	((s=(((unsigned int)(c[0]))<< 8)| \
			    (((unsigned int)(c[1]))    )),c+=2)
#define s2n(s,c)	((c[0]=(unsigned char)(((s)>> 8)&0xff), \
			  c[1]=(unsigned char)(((s)    )&0xff)),c+=2)

#define n2l3(c,l)	((l =(((unsigned long)(c[0]))<<16)| \
			     (((unsigned long)(c[1]))<< 8)| \
			     (((unsigned long)(c[2]))    )),c+=3)

#define l2n3(l,c)	((c[0]=(unsigned char)(((l)>>16)&0xff), \
			  c[1]=(unsigned char)(((l)>> 8)&0xff), \
			  c[2]=(unsigned char)(((l)    )&0xff)),c+=3)

/* LOCAL STUFF */

#define SSL_DECRYPT	0
#define SSL_ENCRYPT	1

#define TWO_BYTE_BIT	0x80
#define SEC_ESC_BIT	0x40
#define TWO_BYTE_MASK	0x7fff
#define THREE_BYTE_MASK	0x3fff

#define INC32(a)	((a)=((a)+1)&0xffffffffL)
#define DEC32(a)	((a)=((a)-1)&0xffffffffL)
#define MAX_MAC_SIZE	20 /* up from 16 for SSLv3 */

/*
 * Define the Bitmasks for SSL_CIPHER.algorithms.
 * This bits are used packed as dense as possible. If new methods/ciphers
 * etc will be added, the bits a likely to change, so this information
 * is for internal library use only, even though SSL_CIPHER.algorithms
 * can be publicly accessed.
 * Use the according functions for cipher management instead.
 *
 * The bit mask handling in the selection and sorting scheme in
 * ssl_create_cipher_list() has only limited capabilities, reflecting
 * that the different entities within are mutually exclusive:
 * ONLY ONE BIT PER MASK CAN BE SET AT A TIME.
 */

/* Bits for algorithm_mkey (key exchange algorithm) */
#define SSL_kRSA		0x00000001L /* RSA key exchange */
#define SSL_kEDH		0x00000002L /* tmp DH key no DH cert */
#define SSL_kEECDH		0x00000004L /* ephemeral ECDH */
#define SSL_kPSK		0x00000008L /* PSK */

/* Bits for algorithm_auth (server authentication) */
#define SSL_aRSA		0x00000001L /* RSA auth */
#define SSL_aNULL 		0x00000002L /* no auth (i.e. use ADH or AECDH) */
#define SSL_aECDSA              0x00000004L /* ECDSA auth*/
#define SSL_aPSK                0x00000008L /* PSK auth */


/* Bits for algorithm_enc (symmetric encryption) */
#define SSL_3DES		0x00000001L
#define SSL_RC4			0x00000002L
#define SSL_AES128		0x00000004L
#define SSL_AES256		0x00000008L
#define SSL_AES128GCM		0x00000010L
#define SSL_AES256GCM		0x00000020L
#define SSL_CHACHA20POLY1305	0x00000040L

#define SSL_AES        		(SSL_AES128|SSL_AES256|SSL_AES128GCM|SSL_AES256GCM)


/* Bits for algorithm_mac (symmetric authentication) */

#define SSL_MD5			0x00000001L
#define SSL_SHA1		0x00000002L
#define SSL_SHA256		0x00000004L
#define SSL_SHA384		0x00000008L
/* Not a real MAC, just an indication it is part of cipher */
#define SSL_AEAD		0x00000010L

/* Bits for algorithm_ssl (protocol version) */
#define SSL_SSLV3		0x00000002L
#define SSL_TLSV1		SSL_SSLV3	/* for now */
#define SSL_TLSV1_2		0x00000004L


/* Bits for algorithm2 (handshake digests and other extra flags) */

#define SSL_HANDSHAKE_MAC_MD5 0x10
#define SSL_HANDSHAKE_MAC_SHA 0x20
#define SSL_HANDSHAKE_MAC_SHA256 0x40
#define SSL_HANDSHAKE_MAC_SHA384 0x80
#define SSL_HANDSHAKE_MAC_DEFAULT (SSL_HANDSHAKE_MAC_MD5 | SSL_HANDSHAKE_MAC_SHA)

/* When adding new digest in the ssl_ciph.c and increment SSM_MD_NUM_IDX
 * make sure to update this constant too */
#define SSL_MAX_DIGEST 4

#define TLS1_PRF_DGST_MASK	(0xff << TLS1_PRF_DGST_SHIFT)

#define TLS1_PRF_DGST_SHIFT 10
#define TLS1_PRF_MD5 (SSL_HANDSHAKE_MAC_MD5 << TLS1_PRF_DGST_SHIFT)
#define TLS1_PRF_SHA1 (SSL_HANDSHAKE_MAC_SHA << TLS1_PRF_DGST_SHIFT)
#define TLS1_PRF_SHA256 (SSL_HANDSHAKE_MAC_SHA256 << TLS1_PRF_DGST_SHIFT)
#define TLS1_PRF_SHA384 (SSL_HANDSHAKE_MAC_SHA384 << TLS1_PRF_DGST_SHIFT)
#define TLS1_PRF (TLS1_PRF_MD5 | TLS1_PRF_SHA1)

#define TLSEXT_CHANNEL_ID_SIZE 128

/* SSL_CIPHER_ALGORITHM2_AEAD is a flag in SSL_CIPHER.algorithm2 which
 * indicates that the cipher is implemented via an EVP_AEAD. */
#define SSL_CIPHER_ALGORITHM2_AEAD (1<<23)

/* SSL_CIPHER_AEAD_FIXED_NONCE_LEN returns the number of bytes of fixed nonce
 * for an SSL_CIPHER* with the SSL_CIPHER_ALGORITHM2_AEAD flag. */
#define SSL_CIPHER_AEAD_FIXED_NONCE_LEN(ssl_cipher) \
	(((ssl_cipher->algorithm2 >> 24) & 0xf)*2)

/* SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_INCLUDED_IN_RECORD is a flag in
 * SSL_CIPHER.algorithm2 which indicates that the variable part of the nonce is
 * included as a prefix of the record. (AES-GCM, for example, does with with an
 * 8-byte variable nonce.) */
#define SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_INCLUDED_IN_RECORD (1<<22)

/* SSL_CIPHER_ALGORITHM2_STATEFUL_AEAD is a flag in SSL_CIPHER.algorithm2 which
 * indicates that the AEAD is stateful and so doesn't take an nonce. This is
 * only true of legacy cipher suites. */
#define SSL_CIPHER_ALGORITHM2_STATEFUL_AEAD (1<<28)

/*
 * Cipher strength information.
 */
#define SSL_MEDIUM		0x00000001L
#define SSL_HIGH		0x00000002L
#define SSL_FIPS		0x00000004L

/* we have used 000001ff - 23 bits left to go */

/* Check if an SSL structure is using DTLS */
#define SSL_IS_DTLS(s)	(s->method->ssl3_enc->enc_flags & SSL_ENC_FLAG_DTLS)
/* See if we need explicit IV */
#define SSL_USE_EXPLICIT_IV(s)	\
		(s->method->ssl3_enc->enc_flags & SSL_ENC_FLAG_EXPLICIT_IV)
/* See if we use signature algorithms extension
 * and signature algorithm before signatures.
 */
#define SSL_USE_SIGALGS(s)	\
			(s->method->ssl3_enc->enc_flags & SSL_ENC_FLAG_SIGALGS)
/* Allow TLS 1.2 ciphersuites: applies to DTLS 1.2 as well as TLS 1.2:
 * may apply to others in future.
 */
#define SSL_USE_TLS1_2_CIPHERS(s)	\
		(s->method->ssl3_enc->enc_flags & SSL_ENC_FLAG_TLS1_2_CIPHERS)
/* Determine if a client can use TLS 1.2 ciphersuites: can't rely on method
 * flags because it may not be set to correct version yet.
 */
#define SSL_CLIENT_USE_TLS1_2_CIPHERS(s)	\
		((SSL_IS_DTLS(s) && s->client_version <= DTLS1_2_VERSION) || \
		(!SSL_IS_DTLS(s) && s->client_version >= TLS1_2_VERSION))

/* Mostly for SSLv3 */
#define SSL_PKEY_RSA_ENC	0
#define SSL_PKEY_RSA_SIGN	1
#define SSL_PKEY_ECC            2
#define SSL_PKEY_NUM		3

/* SSL_kRSA <- RSA_ENC | (RSA_TMP & RSA_SIGN) |
 * 	    <- (EXPORT & (RSA_ENC | RSA_TMP) & RSA_SIGN)
 * SSL_kDH  <- DH_ENC & (RSA_ENC | RSA_SIGN | DSA_SIGN)
 * SSL_kEDH <- RSA_ENC | RSA_SIGN | DSA_SIGN
 * SSL_aRSA <- RSA_ENC | RSA_SIGN
 * SSL_aDSS <- DSA_SIGN
 */

/*
#define CERT_INVALID		0
#define CERT_PUBLIC_KEY		1
#define CERT_PRIVATE_KEY	2
*/

#define PENDING_SESSION -10000
#define CERTIFICATE_SELECTION_PENDING -10001

/* From ECC-TLS draft, used in encoding the curve type in 
 * ECParameters
 */
#define EXPLICIT_PRIME_CURVE_TYPE  1   
#define EXPLICIT_CHAR2_CURVE_TYPE  2
#define NAMED_CURVE_TYPE           3

/* Values for the |hash_message| parameter of |s->method->ssl_get_message|. */
#define SSL_GET_MESSAGE_DONT_HASH_MESSAGE 0
#define SSL_GET_MESSAGE_HASH_MESSAGE 1

typedef struct cert_pkey_st
	{
	X509 *x509;
	EVP_PKEY *privatekey;
	/* Chain for this certificate */
	STACK_OF(X509) *chain;
	} CERT_PKEY;

typedef struct cert_st
	{
	/* Current active set */
	CERT_PKEY *key; /* ALWAYS points to an element of the pkeys array
			 * Probably it would make more sense to store
			 * an index, not a pointer. */
 
	/* For clients the following masks are of *disabled* key and auth
	 * algorithms based on the current session.
	 *
	 * TODO(davidben): Remove these. They get checked twice: when sending
	 * the ClientHello and when processing the ServerHello. However,
	 * mask_ssl is a different value both times. mask_k and mask_a are not,
	 * but is a round-about way of checking the server's cipher was one of
	 * the advertised ones. (Currently it checks the masks and then the list
	 * of ciphers prior to applying the masks in ClientHello.) */
	unsigned long mask_k;
	unsigned long mask_a;
	unsigned long mask_ssl;

	DH *dh_tmp;
	DH *(*dh_tmp_cb)(SSL *ssl,int is_export,int keysize);
	EC_KEY *ecdh_tmp;
	/* Callback for generating ephemeral ECDH keys */
	EC_KEY *(*ecdh_tmp_cb)(SSL *ssl,int is_export,int keysize);
	/* Select ECDH parameters automatically */
	int ecdh_tmp_auto;
	/* Flags related to certificates */
	unsigned int cert_flags;
	CERT_PKEY pkeys[SSL_PKEY_NUM];

	/* Server-only: client_certificate_types is list of certificate types to
	 * include in the CertificateRequest message.
	 */
	unsigned char *client_certificate_types;
	size_t num_client_certificate_types;

	/* signature algorithms peer reports: e.g. supported signature
	 * algorithms extension for server or as part of a certificate
	 * request for client.
	 */
	unsigned char *peer_sigalgs;
	/* Size of above array */
	size_t peer_sigalgslen;
	/* suppported signature algorithms.
	 * When set on a client this is sent in the client hello as the 
	 * supported signature algorithms extension. For servers
	 * it represents the signature algorithms we are willing to use.
	 */
	unsigned char *conf_sigalgs;
	/* Size of above array */
	size_t conf_sigalgslen;
	/* Client authentication signature algorithms, if not set then
	 * uses conf_sigalgs. On servers these will be the signature
	 * algorithms sent to the client in a cerificate request for TLS 1.2.
	 * On a client this represents the signature algortithms we are
	 * willing to use for client authentication.
	 */
	unsigned char *client_sigalgs;
	/* Size of above array */
	size_t client_sigalgslen;
	/* Signature algorithms shared by client and server: cached
	 * because these are used most often.
	 */
	TLS_SIGALGS *shared_sigalgs;
	size_t shared_sigalgslen;

	/* Certificate setup callback: if set is called whenever a
	 * certificate may be required (client or server). the callback
	 * can then examine any appropriate parameters and setup any
	 * certificates required. This allows advanced applications
	 * to select certificates on the fly: for example based on
	 * supported signature algorithms or curves.
	 */
	int (*cert_cb)(SSL *ssl, void *arg);
	void *cert_cb_arg;

	/* Optional X509_STORE for chain building or certificate validation
	 * If NULL the parent SSL_CTX store is used instead.
	 */
	X509_STORE *chain_store;
	X509_STORE *verify_store;

	/* Raw values of the cipher list from a client */
	unsigned char *ciphers_raw;
	size_t ciphers_rawlen;
	} CERT;


typedef struct sess_cert_st
	{
	STACK_OF(X509) *cert_chain; /* as received from peer (not for SSL2) */

	/* The 'peer_...' members are used only by clients. */
	int peer_cert_type;

	CERT_PKEY *peer_key; /* points to an element of peer_pkeys (never NULL!) */
	CERT_PKEY peer_pkeys[SSL_PKEY_NUM];
	/* Obviously we don't have the private keys of these,
	 * so maybe we shouldn't even use the CERT_PKEY type here. */

	DH *peer_dh_tmp;
	EC_KEY *peer_ecdh_tmp;
	} SESS_CERT;
/* Structure containing decoded values of signature algorithms extension */
struct tls_sigalgs_st
	{
	/* NID of hash algorithm */
	int hash_nid;
	/* NID of signature algorithm */
	int sign_nid;
	/* Combined hash and signature NID */
	int signandhash_nid;
	/* Raw values used in extension */
	unsigned char rsign;
	unsigned char rhash;
	};

/*#define MAC_DEBUG	*/

/*#define ERR_DEBUG	*/
/*#define ABORT_DEBUG	*/
/*#define PKT_DEBUG 1   */
/*#define DES_DEBUG	*/
/*#define DES_OFB_DEBUG	*/
/*#define SSL_DEBUG	*/
/*#define RSA_DEBUG	*/ 
/*#define IDEA_DEBUG	*/ 

#define FP_ICC  (int (*)(const void *,const void *))

enum should_add_to_finished_hash {
  add_to_finished_hash,
  dont_add_to_finished_hash,
};

/* This is for the SSLv3/TLSv1.0 differences in crypto/hash stuff
 * It is a bit of a mess of functions, but hell, think of it as
 * an opaque structure :-) */
typedef struct ssl3_enc_method
	{
	int (*enc)(SSL *, int);
	int (*mac)(SSL *, unsigned char *, int);
	int (*setup_key_block)(SSL *);
	int (*generate_master_secret)(SSL *, unsigned char *, unsigned char *, int);
	int (*change_cipher_state)(SSL *, int);
	int (*final_finish_mac)(SSL *,  const char *, int, unsigned char *);
	int finish_mac_length;
	int (*cert_verify_mac)(SSL *, int, unsigned char *);
	const char *client_finished_label;
	int client_finished_label_len;
	const char *server_finished_label;
	int server_finished_label_len;
	int (*alert_value)(int);
	int (*export_keying_material)(SSL *, unsigned char *, size_t,
				      const char *, size_t,
				      const unsigned char *, size_t,
				      int use_context);
	/* Various flags indicating protocol version requirements */
	unsigned int enc_flags;
	/* Handshake header length */
	unsigned int hhlen;
	/* Set the handshake header */
	void (*set_handshake_header)(SSL *s, int type, unsigned long len);
	/* Write out handshake message */
	int (*do_write)(SSL *s, enum should_add_to_finished_hash should_add_to_finished_hash);
	/* Add the current handshake message to the finished hash. */
	void (*add_to_finished_hash)(SSL *s);
	} SSL3_ENC_METHOD;

#define SSL_HM_HEADER_LENGTH(s)	s->method->ssl3_enc->hhlen
#define ssl_handshake_start(s) \
	(((unsigned char *)s->init_buf->data) + s->method->ssl3_enc->hhlen)
#define ssl_set_handshake_header(s, htype, len) \
	s->method->ssl3_enc->set_handshake_header(s, htype, len)
#define ssl_do_write(s)  s->method->ssl3_enc->do_write(s, add_to_finished_hash)

/* Values for enc_flags */

/* Uses explicit IV for CBC mode */
#define SSL_ENC_FLAG_EXPLICIT_IV	0x1
/* Uses signature algorithms extension */
#define SSL_ENC_FLAG_SIGALGS		0x2
/* Uses SHA256 default PRF */
#define SSL_ENC_FLAG_SHA256_PRF		0x4
/* Is DTLS */
#define SSL_ENC_FLAG_DTLS		0x8
/* Allow TLS 1.2 ciphersuites: applies to DTLS 1.2 as well as TLS 1.2:
 * may apply to others in future.
 */
#define SSL_ENC_FLAG_TLS1_2_CIPHERS	0x10

/* ssl_aead_ctx_st contains information about an AEAD that is being used to
 * encrypt an SSL connection. */
struct ssl_aead_ctx_st
	{
	EVP_AEAD_CTX ctx;
	/* fixed_nonce contains any bytes of the nonce that are fixed for all
	 * records. */
	unsigned char fixed_nonce[8];
	unsigned char fixed_nonce_len, variable_nonce_len, tag_len;
	/* variable_nonce_included_in_record is non-zero if the variable nonce
	 * for a record is included as a prefix before the ciphertext. */
	char variable_nonce_included_in_record;
	};


extern SSL3_ENC_METHOD ssl3_undef_enc_method;
extern const SSL_CIPHER ssl3_ciphers[];


extern SSL3_ENC_METHOD TLSv1_enc_data;
extern SSL3_ENC_METHOD TLSv1_1_enc_data;
extern SSL3_ENC_METHOD TLSv1_2_enc_data;
extern SSL3_ENC_METHOD SSLv3_enc_data;
extern SSL3_ENC_METHOD DTLSv1_enc_data;
extern SSL3_ENC_METHOD DTLSv1_2_enc_data;

#define IMPLEMENT_tls_meth_func(version, func_name, s_accept, s_connect, \
				enc_data) \
const SSL_METHOD *func_name(void)  \
	{ \
	static const SSL_METHOD func_name##_data= { \
		version, \
		ssl3_new, \
		ssl3_clear, \
		ssl3_free, \
		s_accept, \
		s_connect, \
		ssl3_read, \
		ssl3_peek, \
		ssl3_write, \
		ssl3_shutdown, \
		ssl3_renegotiate, \
		ssl3_renegotiate_check, \
		ssl3_get_message, \
		ssl3_read_bytes, \
		ssl3_write_bytes, \
		ssl3_dispatch_alert, \
		ssl3_ctrl, \
		ssl3_ctx_ctrl, \
		ssl3_pending, \
		ssl3_num_ciphers, \
		ssl3_get_cipher, \
		&enc_data, \
		ssl_undefined_void_function, \
		ssl3_callback_ctrl, \
		ssl3_ctx_callback_ctrl, \
	}; \
	return &func_name##_data; \
	}

#define IMPLEMENT_ssl23_meth_func(func_name, s_accept, s_connect) \
const SSL_METHOD *func_name(void)  \
	{ \
	static const SSL_METHOD func_name##_data= { \
	TLS1_2_VERSION, \
	ssl3_new, \
	ssl3_clear, \
	ssl3_free, \
	s_accept, \
	s_connect, \
	ssl23_read, \
	ssl23_peek, \
	ssl23_write, \
	ssl_undefined_function, \
	ssl_undefined_function, \
	ssl_ok, \
	ssl3_get_message, \
	ssl3_read_bytes, \
	ssl3_write_bytes, \
	ssl3_dispatch_alert, \
	ssl3_ctrl, \
	ssl3_ctx_ctrl, \
	ssl_undefined_const_function, \
	ssl3_num_ciphers, \
	ssl3_get_cipher, \
	&TLSv1_2_enc_data, \
	ssl_undefined_void_function, \
	ssl3_callback_ctrl, \
	ssl3_ctx_callback_ctrl, \
	}; \
	return &func_name##_data; \
	}

#define IMPLEMENT_dtls1_meth_func(version, func_name, s_accept, s_connect, \
					enc_data) \
const SSL_METHOD *func_name(void)  \
	{ \
	static const SSL_METHOD func_name##_data= { \
		version, \
		dtls1_new, \
		dtls1_clear, \
		dtls1_free, \
		s_accept, \
		s_connect, \
		ssl3_read, \
		ssl3_peek, \
		ssl3_write, \
		dtls1_shutdown, \
		ssl3_renegotiate, \
		ssl3_renegotiate_check, \
		dtls1_get_message, \
		dtls1_read_bytes, \
		dtls1_write_app_data_bytes, \
		dtls1_dispatch_alert, \
		dtls1_ctrl, \
		ssl3_ctx_ctrl, \
		ssl3_pending, \
		ssl3_num_ciphers, \
		dtls1_get_cipher, \
		&enc_data, \
		ssl_undefined_void_function, \
		ssl3_callback_ctrl, \
		ssl3_ctx_callback_ctrl, \
	}; \
	return &func_name##_data; \
	}

void ssl_clear_cipher_ctx(SSL *s);
int ssl_clear_bad_session(SSL *s);
CERT *ssl_cert_new(void);
CERT *ssl_cert_dup(CERT *cert);
int ssl_cert_inst(CERT **o);
void ssl_cert_clear_certs(CERT *c);
void ssl_cert_free(CERT *c);
SESS_CERT *ssl_sess_cert_new(void);
void ssl_sess_cert_free(SESS_CERT *sc);
int ssl_set_peer_cert_type(SESS_CERT *c, int type);
int ssl_get_prev_session(SSL *s, const struct ssl_early_callback_ctx *ctx);
int ssl_cipher_id_cmp(const void *in_a, const void *in_b);
int ssl_cipher_ptr_id_cmp(const SSL_CIPHER **ap, const SSL_CIPHER **bp);
STACK_OF(SSL_CIPHER) *ssl_bytes_to_cipher_list(SSL *s, const CBS *cbs);
int ssl_cipher_list_to_bytes(SSL *s, STACK_OF(SSL_CIPHER) *sk, uint8_t *p);
STACK_OF(SSL_CIPHER) *ssl_create_cipher_list(const SSL_METHOD *meth,
					     struct ssl_cipher_preference_list_st **pref,
					     STACK_OF(SSL_CIPHER) **sorted,
					     const char *rule_str, CERT *c);
struct ssl_cipher_preference_list_st* ssl_cipher_preference_list_dup(
	struct ssl_cipher_preference_list_st *cipher_list);
void ssl_cipher_preference_list_free(
	struct ssl_cipher_preference_list_st *cipher_list);
struct ssl_cipher_preference_list_st* ssl_cipher_preference_list_from_ciphers(
	STACK_OF(SSL_CIPHER) *ciphers);
struct ssl_cipher_preference_list_st* ssl_get_cipher_preferences(SSL *s);
int ssl_cipher_get_evp_aead(const SSL_SESSION *s, const EVP_AEAD **aead);
int ssl_cipher_get_evp(const SSL_SESSION *s,const EVP_CIPHER **enc,
		       const EVP_MD **md,int *mac_pkey_type,int *mac_secret_size);
int ssl_cipher_get_mac(const SSL_SESSION *s, const EVP_MD **md, int *mac_pkey_type, int *mac_secret_size);
int ssl_get_handshake_digest(int i,long *mask,const EVP_MD **md);
int ssl_cipher_get_cert_index(const SSL_CIPHER *c);
int ssl_cipher_has_server_public_key(const SSL_CIPHER *cipher);
int ssl_cipher_requires_server_key_exchange(const SSL_CIPHER *cipher);

int ssl_cert_set0_chain(CERT *c, STACK_OF(X509) *chain);
int ssl_cert_set1_chain(CERT *c, STACK_OF(X509) *chain);
int ssl_cert_add0_chain_cert(CERT *c, X509 *x);
int ssl_cert_add1_chain_cert(CERT *c, X509 *x);
int ssl_cert_select_current(CERT *c, X509 *x);
void ssl_cert_set_cert_cb(CERT *c, int (*cb)(SSL *ssl, void *arg), void *arg);

int ssl_verify_cert_chain(SSL *s,STACK_OF(X509) *sk);
int ssl_add_cert_chain(SSL *s, CERT_PKEY *cpk, unsigned long *l);
int ssl_build_cert_chain(CERT *c, X509_STORE *chain_store, int flags);
int ssl_cert_set_cert_store(CERT *c, X509_STORE *store, int chain, int ref);
int ssl_undefined_function(SSL *s);
int ssl_undefined_void_function(void);
int ssl_undefined_const_function(const SSL *s);
CERT_PKEY *ssl_get_server_send_pkey(const SSL *s);
EVP_PKEY *ssl_get_sign_pkey(SSL *s,const SSL_CIPHER *c);
int ssl_cert_type(X509 *x,EVP_PKEY *pkey);

/* ssl_get_compatible_server_ciphers determines the key exchange and
 * authentication cipher suite masks compatible with the server configuration
 * and current ClientHello parameters of |s|. It sets |*out_mask_k| to the key
 * exchange mask and |*out_mask_a| to the authentication mask. */
void ssl_get_compatible_server_ciphers(SSL *s, unsigned long *out_mask_k,
	unsigned long *out_mask_a);

STACK_OF(SSL_CIPHER) *ssl_get_ciphers_by_id(SSL *s);
int ssl_verify_alarm_type(long type);
int ssl_fill_hello_random(SSL *s, int server, unsigned char *field, int len);

const SSL_CIPHER *ssl3_get_cipher_by_value(uint16_t value);
uint16_t ssl3_get_cipher_value(const SSL_CIPHER *c);
int ssl3_init_finished_mac(SSL *s);
int ssl3_send_server_certificate(SSL *s);
int ssl3_send_new_session_ticket(SSL *s);
int ssl3_send_cert_status(SSL *s);
int ssl3_get_finished(SSL *s,int state_a,int state_b);
int ssl3_setup_key_block(SSL *s);
int ssl3_send_change_cipher_spec(SSL *s,int state_a,int state_b);
int ssl3_change_cipher_state(SSL *s,int which);
void ssl3_cleanup_key_block(SSL *s);
int ssl3_do_write(SSL *s,int type, enum should_add_to_finished_hash should_add_to_finished_hash);
int ssl3_send_alert(SSL *s,int level, int desc);
int ssl3_generate_master_secret(SSL *s, unsigned char *out,
	unsigned char *p, int len);
int ssl3_get_req_cert_type(SSL *s,unsigned char *p);
long ssl3_get_message(SSL *s, int st1, int stn, int mt, long max, int hash_message, int *ok);

/* ssl3_hash_current_message incorporates the current handshake message into
 * the handshake hash. */
void ssl3_hash_current_message(SSL *s);

/* ssl3_cert_verify_hash writes the CertificateVerify hash into the bytes
 * pointed to by |out| and writes the number of bytes to |*out_len|. |out| must
 * have room for EVP_MAX_MD_SIZE bytes. For TLS 1.2 and up, |*out_md| is used
 * for the hash function, otherwise the hash function depends on the type of
 * |pkey| and is written to |*out_md|. It returns one on success and zero on
 * failure. */
int ssl3_cert_verify_hash(SSL *s, uint8_t *out, size_t *out_len, const EVP_MD **out_md, EVP_PKEY *pkey);

int ssl3_send_finished(SSL *s, int a, int b, const char *sender,int slen);
int ssl3_num_ciphers(void);
const SSL_CIPHER *ssl3_get_cipher(unsigned int u);
int ssl3_renegotiate(SSL *ssl); 
int ssl3_renegotiate_check(SSL *ssl); 
int ssl3_dispatch_alert(SSL *s);
int ssl3_expect_change_cipher_spec(SSL *s);
int ssl3_read_bytes(SSL *s, int type, unsigned char *buf, int len, int peek);
int ssl3_write_bytes(SSL *s, int type, const void *buf, int len);
int ssl3_final_finish_mac(SSL *s, const char *sender, int slen,unsigned char *p);
int ssl3_cert_verify_mac(SSL *s, int md_nid, unsigned char *p);
void ssl3_finish_mac(SSL *s, const unsigned char *buf, int len);
int ssl3_enc(SSL *s, int send_data);
int n_ssl3_mac(SSL *ssl, unsigned char *md, int send_data);
void ssl3_free_digest_list(SSL *s);
unsigned long ssl3_output_cert_chain(SSL *s, CERT_PKEY *cpk);
const SSL_CIPHER *ssl3_choose_cipher(SSL *ssl,STACK_OF(SSL_CIPHER) *clnt,
			       struct ssl_cipher_preference_list_st *srvr);
int	ssl3_setup_buffers(SSL *s);
int	ssl3_setup_read_buffer(SSL *s);
int	ssl3_setup_write_buffer(SSL *s);
int	ssl3_release_read_buffer(SSL *s);
int	ssl3_release_write_buffer(SSL *s);

enum should_free_handshake_buffer_t {
	free_handshake_buffer,
	dont_free_handshake_buffer,
};
int	ssl3_digest_cached_records(SSL *s, enum should_free_handshake_buffer_t);

int	ssl3_new(SSL *s);
void	ssl3_free(SSL *s);
int	ssl3_accept(SSL *s);
int	ssl3_connect(SSL *s);
int	ssl3_read(SSL *s, void *buf, int len);
int	ssl3_peek(SSL *s, void *buf, int len);
int	ssl3_write(SSL *s, const void *buf, int len);
int	ssl3_shutdown(SSL *s);
void	ssl3_clear(SSL *s);
long	ssl3_ctrl(SSL *s,int cmd, long larg, void *parg);
long	ssl3_ctx_ctrl(SSL_CTX *s,int cmd, long larg, void *parg);
long	ssl3_callback_ctrl(SSL *s,int cmd, void (*fp)(void));
long	ssl3_ctx_callback_ctrl(SSL_CTX *s,int cmd, void (*fp)(void));
int	ssl3_pending(const SSL *s);

void ssl3_record_sequence_update(unsigned char *seq);
int ssl3_do_change_cipher_spec(SSL *ssl);

void ssl3_set_handshake_header(SSL *s, int htype, unsigned long len);
int ssl3_handshake_write(SSL *s, enum should_add_to_finished_hash should_add_to_finished_hash);
void ssl3_add_to_finished_hash(SSL *s);

int ssl23_read(SSL *s, void *buf, int len);
int ssl23_peek(SSL *s, void *buf, int len);
int ssl23_write(SSL *s, const void *buf, int len);

int dtls1_do_write(SSL *s,int type, enum should_add_to_finished_hash should_add_to_finished_hash);
int ssl3_read_n(SSL *s, int n, int max, int extend);
int dtls1_read_bytes(SSL *s, int type, unsigned char *buf, int len, int peek);
int ssl3_write_pending(SSL *s, int type, const unsigned char *buf,
	unsigned int len);
unsigned char *dtls1_set_message_header(SSL *s, 
	unsigned char *p, unsigned char mt,	unsigned long len, 
	unsigned long frag_off, unsigned long frag_len);

int dtls1_write_app_data_bytes(SSL *s, int type, const void *buf, int len);
int dtls1_write_bytes(SSL *s, int type, const void *buf, int len);

int dtls1_send_change_cipher_spec(SSL *s, int a, int b);
int dtls1_send_finished(SSL *s, int a, int b, const char *sender, int slen);
unsigned long dtls1_output_cert_chain(SSL *s, CERT_PKEY *cpk);
int dtls1_read_failed(SSL *s, int code);
int dtls1_buffer_message(SSL *s, int ccs);
int dtls1_retransmit_message(SSL *s, unsigned short seq, 
	unsigned long frag_off, int *found);
int dtls1_get_queue_priority(unsigned short seq, int is_ccs);
int dtls1_retransmit_buffered_messages(SSL *s);
void dtls1_clear_record_buffer(SSL *s);
void dtls1_get_message_header(unsigned char *data, struct hm_header_st *msg_hdr);
void dtls1_get_ccs_header(unsigned char *data, struct ccs_header_st *ccs_hdr);
void dtls1_reset_seq_numbers(SSL *s, int rw);
int dtls1_check_timeout_num(SSL *s);
int dtls1_handle_timeout(SSL *s);
const SSL_CIPHER *dtls1_get_cipher(unsigned int u);
void dtls1_start_timer(SSL *s);
void dtls1_stop_timer(SSL *s);
int dtls1_is_timer_expired(SSL *s);
void dtls1_double_timeout(SSL *s);
unsigned int dtls1_min_mtu(void);

/* some client-only functions */

/* ssl3_get_max_client_version returns the maximum protocol version configured
 * for the client. It is guaranteed that the set of allowed versions at or below
 * this maximum version is contiguous. If all versions are disabled, it returns
 * zero. */
uint16_t ssl3_get_max_client_version(SSL *s);

int ssl3_send_client_hello(SSL *s);
int ssl3_get_server_hello(SSL *s);
int ssl3_get_certificate_request(SSL *s);
int ssl3_get_new_session_ticket(SSL *s);
int ssl3_get_cert_status(SSL *s);
int ssl3_get_server_done(SSL *s);
int ssl3_send_cert_verify(SSL *s);
int ssl3_send_client_certificate(SSL *s);
int ssl_do_client_cert_cb(SSL *s, X509 **px509, EVP_PKEY **ppkey);
int ssl3_send_client_key_exchange(SSL *s);
int ssl3_get_server_key_exchange(SSL *s);
int ssl3_get_server_certificate(SSL *s);
int ssl3_check_cert_and_algorithm(SSL *s);
int ssl3_send_next_proto(SSL *s);
int ssl3_send_channel_id(SSL *s);

int dtls1_client_hello(SSL *s);

/* some server-only functions */
int ssl3_get_client_hello(SSL *s);
int ssl3_send_server_hello(SSL *s);
int ssl3_send_hello_request(SSL *s);
int ssl3_send_server_key_exchange(SSL *s);
int ssl3_send_certificate_request(SSL *s);
int ssl3_send_server_done(SSL *s);
int ssl3_get_client_certificate(SSL *s);
int ssl3_get_client_key_exchange(SSL *s);
int ssl3_get_cert_verify(SSL *s);
int ssl3_get_next_proto(SSL *s);
int ssl3_get_channel_id(SSL *s);

int ssl23_accept(SSL *s);
int ssl23_connect(SSL *s);
int ssl23_read_bytes(SSL *s, int n);
int ssl23_write_bytes(SSL *s);

int dtls1_new(SSL *s);
int	dtls1_accept(SSL *s);
int	dtls1_connect(SSL *s);
void dtls1_free(SSL *s);
void dtls1_clear(SSL *s);
long dtls1_ctrl(SSL *s,int cmd, long larg, void *parg);
int dtls1_shutdown(SSL *s);

long dtls1_get_message(SSL *s, int st1, int stn, int mt, long max, int hash_message, int *ok);
int dtls1_get_record(SSL *s);
int dtls1_dispatch_alert(SSL *s);
int dtls1_enc(SSL *s, int snd);

int ssl_init_wbio_buffer(SSL *s, int push);
void ssl_free_wbio_buffer(SSL *s);

int tls1_change_cipher_state(SSL *s, int which);
int tls1_setup_key_block(SSL *s);
int tls1_enc(SSL *s, int snd);
int tls1_handshake_digest(SSL *s, unsigned char *out, size_t out_len);
int tls1_final_finish_mac(SSL *s,
	const char *str, int slen, unsigned char *p);
int tls1_cert_verify_mac(SSL *s, int md_nid, unsigned char *p);
int tls1_mac(SSL *ssl, unsigned char *md, int snd);
int tls1_generate_master_secret(SSL *s, unsigned char *out,
	unsigned char *p, int len);
int tls1_export_keying_material(SSL *s, unsigned char *out, size_t olen,
	const char *label, size_t llen,
	const unsigned char *p, size_t plen, int use_context);
int tls1_alert_code(int code);
int ssl3_alert_code(int code);
int ssl_ok(SSL *s);

int ssl_check_srvr_ecc_cert_and_alg(X509 *x, SSL *s);

char ssl_early_callback_init(struct ssl_early_callback_ctx *ctx);
int tls1_ec_curve_id2nid(uint16_t curve_id);
uint16_t tls1_ec_nid2curve_id(int nid);

/* tls1_check_curve parses ECParameters out of |cbs|, modifying it. It
 * checks the curve is one of our preferences and writes the
 * NamedCurve value to |*out_curve_id|. It returns one on success and
 * zero on error. */
int tls1_check_curve(SSL *s, CBS *cbs, uint16_t *out_curve_id);

/* tls1_get_shared_curve returns the NID of the first preferred shared curve
 * between client and server preferences. If none can be found, it returns
 * NID_undef. */
int tls1_get_shared_curve(SSL *s);

/* tls1_set_curves converts the array of |ncurves| NIDs pointed to by |curves|
 * into a newly allocated array of TLS curve IDs. On success, the function
 * returns one and writes the array to |*out_curve_ids| and its size to
 * |*out_curve_ids_len|. Otherwise, it returns zero. */
int tls1_set_curves(uint16_t **out_curve_ids, size_t *out_curve_ids_len,
	const int *curves, size_t ncurves);

/* tls1_check_ec_cert returns one if |x| is an ECC certificate with curve and
 * point format compatible with the client's preferences. Otherwise it returns
 * zero. */
int tls1_check_ec_cert(SSL *s, X509 *x);

/* tls1_check_ec_tmp_key returns one if the EC temporary key is compatible with
 * client extensions and zero otherwise. */
int tls1_check_ec_tmp_key(SSL *s);

int tls1_shared_list(SSL *s,
			const unsigned char *l1, size_t l1len,
			const unsigned char *l2, size_t l2len,
			int nmatch);
unsigned char *ssl_add_clienthello_tlsext(SSL *s, unsigned char *buf, unsigned char *limit, size_t header_len);
unsigned char *ssl_add_serverhello_tlsext(SSL *s, unsigned char *buf, unsigned char *limit); 
int ssl_parse_clienthello_tlsext(SSL *s, CBS *cbs);
int ssl_parse_serverhello_tlsext(SSL *s, CBS *cbs);
int ssl_prepare_clienthello_tlsext(SSL *s);
int ssl_prepare_serverhello_tlsext(SSL *s);

#define tlsext_tick_md	EVP_sha256
int tls1_process_ticket(SSL *s, const struct ssl_early_callback_ctx *ctx,
			SSL_SESSION **ret);

int tls12_get_sigandhash(unsigned char *p, const EVP_PKEY *pk,
				const EVP_MD *md);
int tls12_get_sigid(const EVP_PKEY *pk);
const EVP_MD *tls12_get_hash(unsigned char hash_alg);

int tls1_channel_id_hash(EVP_MD_CTX *ctx, SSL *s);
int tls1_record_handshake_hashes_for_channel_id(SSL *s);

int tls1_set_sigalgs_list(CERT *c, const char *str, int client);
int tls1_set_sigalgs(CERT *c, const int *salg, size_t salglen, int client);

/* ssl_ctx_log_rsa_client_key_exchange logs |premaster| to |ctx|, if logging is
 * enabled. It returns one on success and zero on failure. The entry is
 * identified by the first 8 bytes of |encrypted_premaster|. */
int ssl_ctx_log_rsa_client_key_exchange(SSL_CTX *ctx,
	const uint8_t *encrypted_premaster, size_t encrypted_premaster_len,
	const uint8_t *premaster, size_t premaster_len);

/* ssl_ctx_log_master_secret logs |master| to |ctx|, if logging is enabled. It
 * returns one on success and zero on failure. The entry is identified by
 * |client_random|. */
int ssl_ctx_log_master_secret(SSL_CTX *ctx,
	const uint8_t *client_random, size_t client_random_len,
	const uint8_t *master, size_t master_len);

int ssl3_can_cutthrough(const SSL *s);
int ssl_get_max_version(const SSL *s);
EVP_MD_CTX* ssl_replace_hash(EVP_MD_CTX **hash,const EVP_MD *md) ;
void ssl_clear_hash_ctx(EVP_MD_CTX **hash);
int ssl_add_serverhello_renegotiate_ext(SSL *s, unsigned char *p, int *len,
					int maxlen);
int ssl_parse_serverhello_renegotiate_ext(SSL *s, CBS *cbs, int *out_alert);
int ssl_add_clienthello_renegotiate_ext(SSL *s, unsigned char *p, int *len,
					int maxlen);
int ssl_parse_clienthello_renegotiate_ext(SSL *s, CBS *cbs, int *out_alert);
long ssl_get_algorithm2(SSL *s);
int tls1_process_sigalgs(SSL *s, const CBS *sigalgs);

/* tls1_choose_signing_digest returns a digest for use with |pkey| based on the
 * peer's preferences recorded for |s| and the digests supported by |pkey|. */
const EVP_MD *tls1_choose_signing_digest(SSL *s, EVP_PKEY *pkey);

size_t tls12_get_psigalgs(SSL *s, const unsigned char **psigs);
int tls12_check_peer_sigalg(const EVP_MD **out_md, int *out_alert, SSL *s,
	CBS *cbs, EVP_PKEY *pkey);
void ssl_set_client_disabled(SSL *s);

int ssl_add_clienthello_use_srtp_ext(SSL *s, unsigned char *p, int *len, int maxlen);
int ssl_parse_clienthello_use_srtp_ext(SSL *s, CBS *cbs, int *out_alert);
int ssl_add_serverhello_use_srtp_ext(SSL *s, unsigned char *p, int *len, int maxlen);
int ssl_parse_serverhello_use_srtp_ext(SSL *s, CBS *cbs, int *out_alert);

/* s3_cbc.c */
void ssl3_cbc_copy_mac(unsigned char* out,
		       const SSL3_RECORD *rec,
		       unsigned md_size,unsigned orig_len);
int ssl3_cbc_remove_padding(const SSL* s,
			    SSL3_RECORD *rec,
			    unsigned block_size,
			    unsigned mac_size);
int tls1_cbc_remove_padding(const SSL* s,
			    SSL3_RECORD *rec,
			    unsigned block_size,
			    unsigned mac_size);
char ssl3_cbc_record_digest_supported(const EVP_MD_CTX *ctx);
int ssl3_cbc_digest_record(
	const EVP_MD_CTX *ctx,
	unsigned char* md_out,
	size_t* md_out_size,
	const unsigned char header[13],
	const unsigned char *data,
	size_t data_plus_mac_size,
	size_t data_plus_mac_plus_padding_size,
	const unsigned char *mac_secret,
	unsigned mac_secret_length,
	char is_sslv3);

#endif
