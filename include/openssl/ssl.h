/* ssl/ssl.h */
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

#ifndef HEADER_SSL_H
#define HEADER_SSL_H

#include <openssl/base.h>

#include <openssl/bio.h>
#include <openssl/buf.h>
#include <openssl/hmac.h>
#include <openssl/lhash.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

/* Some code expected to get the threading functions by including ssl.h. */
#include <openssl/thread.h>

#ifdef  __cplusplus
extern "C" {
#endif


/* SSLeay version number for ASN.1 encoding of the session information */
/* Version 0 - initial version
 * Version 1 - added the optional peer certificate
 */
#define SSL_SESSION_ASN1_VERSION 0x0001

/* text strings for the ciphers */
#define SSL_TXT_NULL_WITH_MD5		SSL2_TXT_NULL_WITH_MD5			
#define SSL_TXT_RC4_128_WITH_MD5	SSL2_TXT_RC4_128_WITH_MD5		
#define SSL_TXT_RC4_128_EXPORT40_WITH_MD5 SSL2_TXT_RC4_128_EXPORT40_WITH_MD5	
#define SSL_TXT_RC2_128_CBC_WITH_MD5	SSL2_TXT_RC2_128_CBC_WITH_MD5		
#define SSL_TXT_RC2_128_CBC_EXPORT40_WITH_MD5 SSL2_TXT_RC2_128_CBC_EXPORT40_WITH_MD5	
#define SSL_TXT_IDEA_128_CBC_WITH_MD5	SSL2_TXT_IDEA_128_CBC_WITH_MD5		
#define SSL_TXT_DES_64_CBC_WITH_MD5	SSL2_TXT_DES_64_CBC_WITH_MD5		
#define SSL_TXT_DES_64_CBC_WITH_SHA	SSL2_TXT_DES_64_CBC_WITH_SHA		
#define SSL_TXT_DES_192_EDE3_CBC_WITH_MD5 SSL2_TXT_DES_192_EDE3_CBC_WITH_MD5	
#define SSL_TXT_DES_192_EDE3_CBC_WITH_SHA SSL2_TXT_DES_192_EDE3_CBC_WITH_SHA	

#define SSL_MAX_SSL_SESSION_ID_LENGTH		32
#define SSL_MAX_SID_CTX_LENGTH			32

#define SSL_MIN_RSA_MODULUS_LENGTH_IN_BYTES	(512/8)
#define SSL_MAX_KEY_ARG_LENGTH			8
#define SSL_MAX_MASTER_KEY_LENGTH		48


/* These are used to specify which ciphers to use and not to use */

#define SSL_TXT_MEDIUM		"MEDIUM"
#define SSL_TXT_HIGH		"HIGH"
#define SSL_TXT_FIPS		"FIPS"

#define	SSL_TXT_aNULL		"aNULL"

#define SSL_TXT_kRSA		"kRSA"
#define SSL_TXT_kEDH		"kEDH"
#define SSL_TXT_kEECDH		"kEECDH"
#define SSL_TXT_kPSK            "kPSK"

#define	SSL_TXT_aRSA		"aRSA"
#define SSL_TXT_aECDSA		"aECDSA"
#define SSL_TXT_aPSK            "aPSK"

#define SSL_TXT_DH		"DH"
#define SSL_TXT_EDH		"EDH" /* same as "kEDH:-ADH" */
#define SSL_TXT_ADH		"ADH"
#define SSL_TXT_RSA		"RSA"
#define SSL_TXT_ECDH		"ECDH"
#define SSL_TXT_EECDH		"EECDH" /* same as "kEECDH:-AECDH" */
#define SSL_TXT_AECDH		"AECDH"
#define SSL_TXT_ECDSA		"ECDSA"
#define SSL_TXT_PSK             "PSK"

#define SSL_TXT_3DES		"3DES"
#define SSL_TXT_RC4		"RC4"
#define SSL_TXT_AES128		"AES128"
#define SSL_TXT_AES256		"AES256"
#define SSL_TXT_AES		"AES"
#define SSL_TXT_AES_GCM		"AESGCM"
#define SSL_TXT_CHACHA20	"CHACHA20"

#define SSL_TXT_MD5		"MD5"
#define SSL_TXT_SHA1		"SHA1"
#define SSL_TXT_SHA		"SHA" /* same as "SHA1" */
#define SSL_TXT_SHA256		"SHA256"
#define SSL_TXT_SHA384		"SHA384"

#define SSL_TXT_SSLV3		"SSLv3"
#define SSL_TXT_TLSV1		"TLSv1"
#define SSL_TXT_TLSV1_1		"TLSv1.1"
#define SSL_TXT_TLSV1_2		"TLSv1.2"

#define SSL_TXT_ALL		"ALL"

/*
 * COMPLEMENTOF* definitions. These identifiers are used to (de-select)
 * ciphers normally not being used.
 * Example: "RC4" will activate all ciphers using RC4 including ciphers
 * without authentication, which would normally disabled by DEFAULT (due
 * the "!ADH" being part of default). Therefore "RC4:!COMPLEMENTOFDEFAULT"
 * will make sure that it is also disabled in the specific selection.
 * COMPLEMENTOF* identifiers are portable between version, as adjustments
 * to the default cipher setup will also be included here.
 *
 * COMPLEMENTOFDEFAULT does not experience the same special treatment that
 * DEFAULT gets, as only selection is being done and no sorting as needed
 * for DEFAULT.
 */
#define SSL_TXT_CMPDEF		"COMPLEMENTOFDEFAULT"

/* The following cipher list is used by default.
 * It also is substituted when an application-defined cipher list string
 * starts with 'DEFAULT'. */
#define SSL_DEFAULT_CIPHER_LIST	"ALL:!aNULL:!eNULL:!SSLv2"
/* As of OpenSSL 1.0.0, ssl_create_cipher_list() in ssl/ssl_ciph.c always
 * starts with a reasonable order, and all we have to do for DEFAULT is
 * throwing out anonymous and unencrypted ciphersuites!
 * (The latter are not actually enabled by ALL, but "ALL:RSA" would enable
 * some of them.)
 */

/* Used in SSL_set_shutdown()/SSL_get_shutdown(); */
#define SSL_SENT_SHUTDOWN	1
#define SSL_RECEIVED_SHUTDOWN	2

#ifdef __cplusplus
}
#endif

#ifdef  __cplusplus
extern "C" {
#endif

#define SSL_FILETYPE_ASN1	X509_FILETYPE_ASN1
#define SSL_FILETYPE_PEM	X509_FILETYPE_PEM

/* This is needed to stop compilers complaining about the
 * 'struct ssl_st *' function parameters used to prototype callbacks
 * in SSL_CTX. */
typedef struct ssl_st *ssl_crock_st;
typedef struct tls_session_ticket_ext_st TLS_SESSION_TICKET_EXT;
typedef struct ssl_method_st SSL_METHOD;
typedef struct ssl_cipher_st SSL_CIPHER;
typedef struct ssl_session_st SSL_SESSION;
typedef struct tls_sigalgs_st TLS_SIGALGS;
typedef struct ssl_conf_ctx_st SSL_CONF_CTX;

DECLARE_STACK_OF(SSL_CIPHER)

/* SRTP protection profiles for use with the use_srtp extension (RFC 5764)*/
typedef struct srtp_protection_profile_st
       {
       const char *name;
       unsigned long id;
       } SRTP_PROTECTION_PROFILE;

DECLARE_STACK_OF(SRTP_PROTECTION_PROFILE)

typedef int (*tls_session_ticket_ext_cb_fn)(SSL *s, const unsigned char *data, int len, void *arg);
typedef int (*tls_session_secret_cb_fn)(SSL *s, void *secret, int *secret_len, STACK_OF(SSL_CIPHER) *peer_ciphers, const SSL_CIPHER **cipher, void *arg);

#ifndef OPENSSL_NO_SSL_INTERN

/* used to hold info on the particular ciphers used */
struct ssl_cipher_st
	{
	int valid;
	const char *name;		/* text name */
	unsigned long id;		/* id, 4 bytes, first is version */

	/* changed in 0.9.9: these four used to be portions of a single value 'algorithms' */
	unsigned long algorithm_mkey;	/* key exchange algorithm */
	unsigned long algorithm_auth;	/* server authentication */
	unsigned long algorithm_enc;	/* symmetric encryption */
	unsigned long algorithm_mac;	/* symmetric authentication */
	unsigned long algorithm_ssl;	/* (major) protocol version */

	unsigned long algo_strength;	/* strength and export flags */
	unsigned long algorithm2;	/* Extra flags. See SSL2_CF_* in ssl2.h
					   and algorithm2 section in
					   ssl_locl.h */
	int strength_bits;		/* Number of bits really used */
	int alg_bits;			/* Number of bits for algorithm */
	};


/* Used to hold functions for SSLv2 or SSLv3/TLSv1 functions */
struct ssl_method_st
	{
	int version;
	int (*ssl_new)(SSL *s);
	void (*ssl_clear)(SSL *s);
	void (*ssl_free)(SSL *s);
	int (*ssl_accept)(SSL *s);
	int (*ssl_connect)(SSL *s);
	int (*ssl_read)(SSL *s,void *buf,int len);
	int (*ssl_peek)(SSL *s,void *buf,int len);
	int (*ssl_write)(SSL *s,const void *buf,int len);
	int (*ssl_shutdown)(SSL *s);
	int (*ssl_renegotiate)(SSL *s);
	int (*ssl_renegotiate_check)(SSL *s);
	long (*ssl_get_message)(SSL *s, int st1, int stn, int mt, long
		max, int hash_message, int *ok);
	int (*ssl_read_bytes)(SSL *s, int type, unsigned char *buf, int len, 
		int peek);
	int (*ssl_write_bytes)(SSL *s, int type, const void *buf_, int len);
	int (*ssl_dispatch_alert)(SSL *s);
	long (*ssl_ctrl)(SSL *s,int cmd,long larg,void *parg);
	long (*ssl_ctx_ctrl)(SSL_CTX *ctx,int cmd,long larg,void *parg);
	int (*ssl_pending)(const SSL *s);
	int (*num_ciphers)(void);
	const SSL_CIPHER *(*get_cipher)(unsigned ncipher);
	const struct ssl_method_st *(*get_ssl_method)(int version);
	struct ssl3_enc_method *ssl3_enc; /* Extra SSLv3/TLS stuff */
	int (*ssl_version)(void);
	long (*ssl_callback_ctrl)(SSL *s, int cb_id, void (*fp)(void));
	long (*ssl_ctx_callback_ctrl)(SSL_CTX *s, int cb_id, void (*fp)(void));
	};

/* An SSL_SESSION represents an SSL session that may be resumed in an
 * abbreviated handshake. */
struct ssl_session_st
	{
	int ssl_version;	/* what ssl version session info is
				 * being kept in here? */

	int master_key_length;
	unsigned char master_key[SSL_MAX_MASTER_KEY_LENGTH];
	/* session_id - valid? */
	unsigned int session_id_length;
	unsigned char session_id[SSL_MAX_SSL_SESSION_ID_LENGTH];
	/* this is used to determine whether the session is being reused in
	 * the appropriate context. It is up to the application to set this,
	 * via SSL_new */
	unsigned int sid_ctx_length;
	unsigned char sid_ctx[SSL_MAX_SID_CTX_LENGTH];

	char *psk_identity_hint;
	char *psk_identity;
	/* Used to indicate that session resumption is not allowed.
	 * Applications can also set this bit for a new session via
	 * not_resumable_session_cb to disable session caching and tickets. */
	int not_resumable;

	/* The cert is the certificate used to establish this connection */
	struct sess_cert_st /* SESS_CERT */ *sess_cert;

	/* This is the cert for the other end.
	 * On clients, it will be the same as sess_cert->peer_key->x509
	 * (the latter is not enough as sess_cert is not retained
	 * in the external representation of sessions, see ssl_asn1.c). */
	X509 *peer;
	/* when app_verify_callback accepts a session where the peer's certificate
	 * is not ok, we must remember the error for session reuse: */
	long verify_result; /* only for servers */

	int references;
	long timeout;
	long time;

	const SSL_CIPHER *cipher;
	unsigned long cipher_id;	/* when ASN.1 loaded, this
					 * needs to be used to load
					 * the 'cipher' structure */

	CRYPTO_EX_DATA ex_data; /* application specific data */

	/* These are used to make removal of session-ids more
	 * efficient and to implement a maximum cache size. */
	struct ssl_session_st *prev,*next;
	char *tlsext_hostname;
	/* RFC4507 info */
	uint8_t *tlsext_tick;	/* Session ticket */
	size_t tlsext_ticklen;		/* Session ticket length */
	uint32_t tlsext_tick_lifetime_hint;	/* Session lifetime hint in seconds */

	size_t tlsext_signed_cert_timestamp_list_length;
	uint8_t *tlsext_signed_cert_timestamp_list; /* Server's list. */

	/* The OCSP response that came with the session. */
	size_t ocsp_response_length;
	uint8_t *ocsp_response;

	char peer_sha256_valid;		/* Non-zero if peer_sha256 is valid */
	unsigned char peer_sha256[SHA256_DIGEST_LENGTH];  /* SHA256 of peer certificate */

	/* original_handshake_hash contains the handshake hash (either
	 * SHA-1+MD5 or SHA-2, depending on TLS version) for the original, full
	 * handshake that created a session. This is used by Channel IDs during
	 * resumption. */
	unsigned char original_handshake_hash[EVP_MAX_MD_SIZE];
	unsigned int original_handshake_hash_len;

	/* extended_master_secret is true if the master secret in this session
	 * was generated using EMS and thus isn't vulnerable to the Triple
	 * Handshake attack. */
	char extended_master_secret;
	};

#endif

/* SSL_OP_LEGACY_SERVER_CONNECT allows initial connection to servers
 * that don't support RI */
#define SSL_OP_LEGACY_SERVER_CONNECT			0x00000004L

/* SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER allows for record sizes
 * SSL3_RT_MAX_EXTRA bytes above the maximum record size. */
#define SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER		0x00000020L

/* SSL_OP_TLS_D5_BUG accepts an RSAClientKeyExchange in TLS encoded as
 * SSL3, without a length prefix. */
#define SSL_OP_TLS_D5_BUG				0x00000100L

/* SSL_OP_ALL enables the above bug workarounds that should be rather
 * harmless. */
#define SSL_OP_ALL					0x00000BFFL

/* DTLS options */
#define SSL_OP_NO_QUERY_MTU                 0x00001000L
/* Turn on Cookie Exchange (on relevant for servers) */
#define SSL_OP_COOKIE_EXCHANGE              0x00002000L
/* Don't use RFC4507 ticket extension */
#define SSL_OP_NO_TICKET	            0x00004000L

/* As server, disallow session resumption on renegotiation */
#define SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION	0x00010000L
/* Don't use compression even if supported */
#define SSL_OP_NO_COMPRESSION				0x00020000L
/* Permit unsafe legacy renegotiation */
#define SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION	0x00040000L
/* If set, always create a new key when using tmp_ecdh parameters */
#define SSL_OP_SINGLE_ECDH_USE				0x00080000L
/* If set, always create a new key when using tmp_dh parameters */
#define SSL_OP_SINGLE_DH_USE				0x00100000L
/* Set to always use the tmp_rsa key when doing RSA operations,
 * even when this violates protocol specs */
#define SSL_OP_CIPHER_SERVER_PREFERENCE			0x00400000L
/* SSL_OP_TLS_ROLLBACK_BUG does nothing. */
#define SSL_OP_TLS_ROLLBACK_BUG				0x00800000L

#define SSL_OP_NO_SSLv2					0x01000000L
#define SSL_OP_NO_SSLv3					0x02000000L
#define SSL_OP_NO_TLSv1					0x04000000L
#define SSL_OP_NO_TLSv1_2				0x08000000L
#define SSL_OP_NO_TLSv1_1				0x10000000L

#define SSL_OP_NO_DTLSv1				0x04000000L
#define SSL_OP_NO_DTLSv1_2				0x08000000L

#define SSL_OP_NO_SSL_MASK (SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|\
	SSL_OP_NO_TLSv1|SSL_OP_NO_TLSv1_1|SSL_OP_NO_TLSv1_2)

/* The following flags do nothing and are included only to make it easier to
 * compile code with BoringSSL. */
#define SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS		0
#define SSL_OP_MICROSOFT_SESS_ID_BUG			0
#define SSL_OP_NETSCAPE_CHALLENGE_BUG			0
#define SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG		0
#define SSL_OP_TLS_BLOCK_PADDING_BUG			0

/* Allow SSL_write(..., n) to return r with 0 < r < n (i.e. report success
 * when just a single record has been written): */
#define SSL_MODE_ENABLE_PARTIAL_WRITE       0x00000001L
/* Make it possible to retry SSL_write() with changed buffer location
 * (buffer contents must stay the same!); this is not the default to avoid
 * the misconception that non-blocking SSL_write() behaves like
 * non-blocking write(): */
#define SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER 0x00000002L
/* Don't attempt to automatically build certificate chain */
#define SSL_MODE_NO_AUTO_CHAIN 0x00000008L
/* Save RAM by releasing read and write buffers when they're empty. (SSL3 and
 * TLS only.)  "Released" buffers are put onto a free-list in the context or
 * just freed (depending on the context's setting for freelist_max_len). */
#define SSL_MODE_RELEASE_BUFFERS 0x00000010L

/* The following flags do nothing and are included only to make it easier to
 * compile code with BoringSSL. */
#define SSL_MODE_AUTO_RETRY 0

/* Send the current time in the Random fields of the ClientHello and
 * ServerHello records for compatibility with hypothetical implementations
 * that require it.
 */
#define SSL_MODE_SEND_CLIENTHELLO_TIME 0x00000020L
#define SSL_MODE_SEND_SERVERHELLO_TIME 0x00000040L

/* Cert related flags */
/* Many implementations ignore some aspects of the TLS standards such as
 * enforcing certifcate chain algorithms. When this is set we enforce them.
 */
#define SSL_CERT_FLAG_TLS_STRICT		0x00000001L

/* Flags for building certificate chains */
/* Treat any existing certificates as untrusted CAs */
#define SSL_BUILD_CHAIN_FLAG_UNTRUSTED		0x1
/* Don't include root CA in chain */
#define SSL_BUILD_CHAIN_FLAG_NO_ROOT		0x2
/* Just check certificates already there */
#define SSL_BUILD_CHAIN_FLAG_CHECK		0x4
/* Ignore verification errors */
#define SSL_BUILD_CHAIN_FLAG_IGNORE_ERROR	0x8
/* Clear verification errors from queue */
#define SSL_BUILD_CHAIN_FLAG_CLEAR_ERROR	0x10

/* Flags returned by SSL_check_chain */
/* Certificate can be used with this session */
#define CERT_PKEY_VALID		0x1
/* Certificate can also be used for signing */
#define CERT_PKEY_SIGN		0x2
/* EE certificate signing algorithm OK */
#define CERT_PKEY_EE_SIGNATURE	0x10
/* CA signature algorithms OK */
#define CERT_PKEY_CA_SIGNATURE	0x20
/* EE certificate parameters OK */
#define CERT_PKEY_EE_PARAM	0x40
/* CA certificate parameters OK */
#define CERT_PKEY_CA_PARAM	0x80
/* Signing explicitly allowed as opposed to SHA1 fallback */
#define CERT_PKEY_EXPLICIT_SIGN	0x100
/* Client CA issuer names match (always set for server cert) */
#define CERT_PKEY_ISSUER_NAME	0x200
/* Cert type matches client types (always set for server cert) */
#define CERT_PKEY_CERT_TYPE	0x400
/* Cert chain suitable to Suite B */
#define CERT_PKEY_SUITEB	0x800

#define SSL_CONF_FLAG_CMDLINE		0x1
#define SSL_CONF_FLAG_FILE		0x2
#define SSL_CONF_FLAG_CLIENT		0x4
#define SSL_CONF_FLAG_SERVER		0x8
#define SSL_CONF_FLAG_SHOW_ERRORS	0x10
#define SSL_CONF_FLAG_CERTIFICATE	0x20
/* Configuration value types */
#define SSL_CONF_TYPE_UNKNOWN		0x0
#define SSL_CONF_TYPE_STRING		0x1
#define SSL_CONF_TYPE_FILE		0x2
#define SSL_CONF_TYPE_DIR		0x3

/* When set, clients may send application data before receipt of CCS
 * and Finished.  This mode enables full-handshakes to 'complete' in
 * one RTT. */
#define SSL_MODE_HANDSHAKE_CUTTHROUGH 0x00000080L

/* When set, TLS 1.0 and SSLv3, multi-byte, CBC records will be split in two:
 * the first record will contain a single byte and the second will contain the
 * rest of the bytes. This effectively randomises the IV and prevents BEAST
 * attacks. */
#define SSL_MODE_CBC_RECORD_SPLITTING 0x00000100L

/* SSL_MODE_NO_SESSION_CREATION will cause any attempts to create a session to
 * fail with SSL_R_SESSION_MAY_NOT_BE_CREATED. This can be used to enforce that
 * session resumption is used for a given SSL*. */
#define SSL_MODE_NO_SESSION_CREATION 0x00000200L

/* Note: SSL[_CTX]_set_{options,mode} use |= op on the previous value,
 * they cannot be used to clear bits. */

#define SSL_CTX_set_options(ctx,op) \
	SSL_CTX_ctrl((ctx),SSL_CTRL_OPTIONS,(op),NULL)
#define SSL_CTX_clear_options(ctx,op) \
	SSL_CTX_ctrl((ctx),SSL_CTRL_CLEAR_OPTIONS,(op),NULL)
#define SSL_CTX_get_options(ctx) \
	SSL_CTX_ctrl((ctx),SSL_CTRL_OPTIONS,0,NULL)
#define SSL_set_options(ssl,op) \
	SSL_ctrl((ssl),SSL_CTRL_OPTIONS,(op),NULL)
#define SSL_clear_options(ssl,op) \
	SSL_ctrl((ssl),SSL_CTRL_CLEAR_OPTIONS,(op),NULL)
#define SSL_get_options(ssl) \
        SSL_ctrl((ssl),SSL_CTRL_OPTIONS,0,NULL)

#define SSL_CTX_set_mode(ctx,op) \
	SSL_CTX_ctrl((ctx),SSL_CTRL_MODE,(op),NULL)
#define SSL_CTX_clear_mode(ctx,op) \
	SSL_CTX_ctrl((ctx),SSL_CTRL_CLEAR_MODE,(op),NULL)
#define SSL_CTX_get_mode(ctx) \
	SSL_CTX_ctrl((ctx),SSL_CTRL_MODE,0,NULL)
#define SSL_clear_mode(ssl,op) \
	SSL_ctrl((ssl),SSL_CTRL_CLEAR_MODE,(op),NULL)
#define SSL_set_mode(ssl,op) \
	SSL_ctrl((ssl),SSL_CTRL_MODE,(op),NULL)
#define SSL_get_mode(ssl) \
        SSL_ctrl((ssl),SSL_CTRL_MODE,0,NULL)
#define SSL_set_mtu(ssl, mtu) \
        SSL_ctrl((ssl),SSL_CTRL_SET_MTU,(mtu),NULL)

#define SSL_get_secure_renegotiation_support(ssl) \
	SSL_ctrl((SSL*) (ssl), SSL_CTRL_GET_RI_SUPPORT, 0, NULL)

#define SSL_CTX_set_cert_flags(ctx,op) \
	SSL_CTX_ctrl((ctx),SSL_CTRL_CERT_FLAGS,(op),NULL)
#define SSL_set_cert_flags(s,op) \
	SSL_ctrl((s),SSL_CTRL_CERT_FLAGS,(op),NULL)
#define SSL_CTX_clear_cert_flags(ctx,op) \
	SSL_CTX_ctrl((ctx),SSL_CTRL_CLEAR_CERT_FLAGS,(op),NULL)
#define SSL_clear_cert_flags(s,op) \
	SSL_ctrl((s),SSL_CTRL_CLEAR_CERT_FLAGS,(op),NULL)

OPENSSL_EXPORT void SSL_CTX_set_msg_callback(SSL_CTX *ctx, void (*cb)(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg));
OPENSSL_EXPORT void SSL_set_msg_callback(SSL *ssl, void (*cb)(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg));
#define SSL_CTX_set_msg_callback_arg(ctx, arg) SSL_CTX_ctrl((ctx), SSL_CTRL_SET_MSG_CALLBACK_ARG, 0, (arg))
#define SSL_set_msg_callback_arg(ssl, arg) SSL_ctrl((ssl), SSL_CTRL_SET_MSG_CALLBACK_ARG, 0, (arg))

/* SSL_CTX_set_keylog_bio sets configures all SSL objects attached to |ctx| to
 * log session material to |keylog_bio|. This is intended for debugging use with
 * tools like Wireshark. |ctx| takes ownership of |keylog_bio|.
 *
 * The format is described in
 * https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format. */
OPENSSL_EXPORT void SSL_CTX_set_keylog_bio(SSL_CTX *ctx, BIO *keylog_bio);


struct ssl_aead_ctx_st;
typedef struct ssl_aead_ctx_st SSL_AEAD_CTX;

#define SSL_MAX_CERT_LIST_DEFAULT 1024*100 /* 100k max cert list */

#define SSL_SESSION_CACHE_MAX_SIZE_DEFAULT	(1024*20)

#define SSL_DEFAULT_SESSION_TIMEOUT (2 * 60 * 60)

/* This callback type is used inside SSL_CTX, SSL, and in the functions that set
 * them. It is used to override the generation of SSL/TLS session IDs in a
 * server. Return value should be zero on an error, non-zero to proceed. Also,
 * callbacks should themselves check if the id they generate is unique otherwise
 * the SSL handshake will fail with an error - callbacks can do this using the
 * 'ssl' value they're passed by;
 *      SSL_has_matching_session_id(ssl, id, *id_len)
 * The length value passed in is set at the maximum size the session ID can be.
 * In SSLv2 this is 16 bytes, whereas SSLv3/TLSv1 it is 32 bytes. The callback
 * can alter this length to be less if desired, but under SSLv2 session IDs are
 * supposed to be fixed at 16 bytes so the id will be padded after the callback
 * returns in this case. It is also an error for the callback to set the size to
 * zero. */
typedef int (*GEN_SESSION_CB)(const SSL *ssl, unsigned char *id,
				unsigned int *id_len);

/* ssl_early_callback_ctx is passed to certain callbacks that are called very
 * early on during the server handshake. At this point, much of the SSL*
 * hasn't been filled out and only the ClientHello can be depended on. */
struct ssl_early_callback_ctx
	{
	SSL *ssl;
	const unsigned char *client_hello;       size_t client_hello_len;
	const unsigned char *session_id;         size_t session_id_len;
	const unsigned char *cipher_suites;      size_t cipher_suites_len;
	const unsigned char *compression_methods;size_t compression_methods_len;
	const unsigned char *extensions;         size_t extensions_len;
	};

/* SSL_early_callback_ctx_extension_get searches the extensions in |ctx| for
 * an extension of the given type. If not found, it returns zero. Otherwise
 * it sets |out_data| to point to the extension contents (not including the type
 * and length bytes), sets |out_len| to the length of the extension contents
 * and returns one. */
OPENSSL_EXPORT char
SSL_early_callback_ctx_extension_get(const struct ssl_early_callback_ctx *ctx,
				     uint16_t extension_type,
				     const unsigned char **out_data,
				     size_t *out_len);

typedef struct ssl_comp_st SSL_COMP;

#ifndef OPENSSL_NO_SSL_INTERN

struct ssl_comp_st
	{
	int id;
	const char *name;
	char *method;
	};

DECLARE_STACK_OF(SSL_COMP)
DECLARE_LHASH_OF(SSL_SESSION);

/* ssl_cipher_preference_list_st contains a list of SSL_CIPHERs with
 * equal-preference groups. For TLS clients, the groups are moot because the
 * server picks the cipher and groups cannot be expressed on the wire. However,
 * for servers, the equal-preference groups allow the client's preferences to
 * be partially respected. (This only has an effect with
 * SSL_OP_CIPHER_SERVER_PREFERENCE).
 *
 * The equal-preference groups are expressed by grouping SSL_CIPHERs together.
 * All elements of a group have the same priority: no ordering is expressed
 * within a group.
 *
 * The values in |ciphers| are in one-to-one correspondence with
 * |in_group_flags|. (That is, sk_SSL_CIPHER_num(ciphers) is the number of
 * bytes in |in_group_flags|.) The bytes in |in_group_flags| are either 1, to
 * indicate that the corresponding SSL_CIPHER is not the last element of a
 * group, or 0 to indicate that it is.
 *
 * For example, if |in_group_flags| contains all zeros then that indicates a
 * traditional, fully-ordered preference. Every SSL_CIPHER is the last element
 * of the group (i.e. they are all in a one-element group).
 *
 * For a more complex example, consider:
 *   ciphers:        A  B  C  D  E  F
 *   in_group_flags: 1  1  0  0  1  0
 *
 * That would express the following, order:
 *
 *    A         E
 *    B -> D -> F
 *    C
 */
struct ssl_cipher_preference_list_st
	{
	STACK_OF(SSL_CIPHER) *ciphers;
	uint8_t *in_group_flags;
	};

struct ssl_ctx_st
	{
	const SSL_METHOD *method;

	struct ssl_cipher_preference_list_st *cipher_list;
	/* same as above but sorted for lookup */
	STACK_OF(SSL_CIPHER) *cipher_list_by_id;
	/* cipher_list_tls11 is the list of ciphers when TLS 1.1 or greater is
	 * in use. This only applies to server connections as, for clients, the
	 * version number is known at connect time and so the cipher list can
	 * be set then. */
	struct ssl_cipher_preference_list_st *cipher_list_tls11;

	struct x509_store_st /* X509_STORE */ *cert_store;
	LHASH_OF(SSL_SESSION) *sessions;
	/* Most session-ids that will be cached, default is
	 * SSL_SESSION_CACHE_MAX_SIZE_DEFAULT. 0 is unlimited. */
	unsigned long session_cache_size;
	struct ssl_session_st *session_cache_head;
	struct ssl_session_st *session_cache_tail;

	/* This can have one of 2 values, ored together,
	 * SSL_SESS_CACHE_CLIENT,
	 * SSL_SESS_CACHE_SERVER,
	 * Default is SSL_SESSION_CACHE_SERVER, which means only
	 * SSL_accept which cache SSL_SESSIONS. */
	int session_cache_mode;

	/* If timeout is not 0, it is the default timeout value set
	 * when SSL_new() is called.  This has been put in to make
	 * life easier to set things up */
	long session_timeout;

	/* If this callback is not null, it will be called each
	 * time a session id is added to the cache.  If this function
	 * returns 1, it means that the callback will do a
	 * SSL_SESSION_free() when it has finished using it.  Otherwise,
	 * on 0, it means the callback has finished with it.
	 * If remove_session_cb is not null, it will be called when
	 * a session-id is removed from the cache.  After the call,
	 * OpenSSL will SSL_SESSION_free() it. */
	int (*new_session_cb)(struct ssl_st *ssl,SSL_SESSION *sess);
	void (*remove_session_cb)(struct ssl_ctx_st *ctx,SSL_SESSION *sess);
	SSL_SESSION *(*get_session_cb)(struct ssl_st *ssl,
		unsigned char *data,int len,int *copy);

	struct
		{
		int sess_connect;	/* SSL new conn - started */
		int sess_connect_renegotiate;/* SSL reneg - requested */
		int sess_connect_good;	/* SSL new conne/reneg - finished */
		int sess_accept;	/* SSL new accept - started */
		int sess_accept_renegotiate;/* SSL reneg - requested */
		int sess_accept_good;	/* SSL accept/reneg - finished */
		int sess_miss;		/* session lookup misses  */
		int sess_timeout;	/* reuse attempt on timeouted session */
		int sess_cache_full;	/* session removed due to full cache */
		int sess_hit;		/* session reuse actually done */
		int sess_cb_hit;	/* session-id that was not
					 * in the cache was
					 * passed back via the callback.  This
					 * indicates that the application is
					 * supplying session-id's from other
					 * processes - spooky :-) */
		} stats;

	int references;

	/* if defined, these override the X509_verify_cert() calls */
	int (*app_verify_callback)(X509_STORE_CTX *, void *);
	void *app_verify_arg;
	/* before OpenSSL 0.9.7, 'app_verify_arg' was ignored
	 * ('app_verify_callback' was called with just one argument) */

	/* Default password callback. */
	pem_password_cb *default_passwd_callback;

	/* Default password callback user data. */
	void *default_passwd_callback_userdata;

	/* get client cert callback */
	int (*client_cert_cb)(SSL *ssl, X509 **x509, EVP_PKEY **pkey);

	/* get channel id callback */
	void (*channel_id_cb)(SSL *ssl, EVP_PKEY **pkey);

	/* cookie generate callback */
	int (*app_gen_cookie_cb)(SSL *ssl, uint8_t *cookie, size_t *cookie_len);

	/* verify cookie callback */
	int (*app_verify_cookie_cb)(SSL *ssl, const uint8_t *cookie, size_t cookie_len);

	CRYPTO_EX_DATA ex_data;

	STACK_OF(X509) *extra_certs;


	/* Default values used when no per-SSL value is defined follow */

	void (*info_callback)(const SSL *ssl,int type,int val); /* used if SSL's info_callback is NULL */

	/* what we put in client cert requests */
	STACK_OF(X509_NAME) *client_CA;


	/* Default values to use in SSL structures follow (these are copied by SSL_new) */

	unsigned long options;
	unsigned long mode;
	long max_cert_list;

	struct cert_st /* CERT */ *cert;
	int read_ahead;

	/* callback that allows applications to peek at protocol messages */
	void (*msg_callback)(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg);
	void *msg_callback_arg;

	int verify_mode;
	unsigned int sid_ctx_length;
	unsigned char sid_ctx[SSL_MAX_SID_CTX_LENGTH];
	int (*default_verify_callback)(int ok,X509_STORE_CTX *ctx); /* called 'verify_callback' in the SSL */

	/* Default generate session ID callback. */
	GEN_SESSION_CB generate_session_id;

	X509_VERIFY_PARAM *param;

	/* select_certificate_cb is called before most ClientHello processing
	 * and before the decision whether to resume a session is made.
	 * It may return one to continue the handshake or zero to cause the
	 * handshake loop to return with an error and cause SSL_get_error to
	 * return SSL_ERROR_PENDING_CERTIFICATE. */
	int (*select_certificate_cb) (const struct ssl_early_callback_ctx *);

#if 0
	int purpose;		/* Purpose setting */
	int trust;		/* Trust setting */
#endif

	int quiet_shutdown;

	/* Maximum amount of data to send in one fragment.
	 * actual record size can be more than this due to
	 * padding and MAC overheads.
	 */
	unsigned int max_send_fragment;

	/* TLS extensions servername callback */
	int (*tlsext_servername_callback)(SSL*, int *, void *);
	void *tlsext_servername_arg;
	/* RFC 4507 session ticket keys */
	unsigned char tlsext_tick_key_name[16];
	unsigned char tlsext_tick_hmac_key[16];
	unsigned char tlsext_tick_aes_key[16];
	/* Callback to support customisation of ticket key setting */
	int (*tlsext_ticket_key_cb)(SSL *ssl,
					unsigned char *name, unsigned char *iv,
					EVP_CIPHER_CTX *ectx,
 					HMAC_CTX *hctx, int enc);

	/* certificate status request info */
	/* Callback for status request */
	int (*tlsext_status_cb)(SSL *ssl, void *arg);
	void *tlsext_status_arg;

	char *psk_identity_hint;
	unsigned int (*psk_client_callback)(SSL *ssl, const char *hint, char *identity,
		unsigned int max_identity_len, unsigned char *psk,
		unsigned int max_psk_len);
	unsigned int (*psk_server_callback)(SSL *ssl, const char *identity,
		unsigned char *psk, unsigned int max_psk_len);


	/* retain_only_sha256_of_client_certs is true if we should compute the
	 * SHA256 hash of the peer's certifiate and then discard it to save
	 * memory and session space. Only effective on the server side. */
	char retain_only_sha256_of_client_certs;

	/* Next protocol negotiation information */
	/* (for experimental NPN extension). */

	/* For a server, this contains a callback function by which the set of
	 * advertised protocols can be provided. */
	int (*next_protos_advertised_cb)(SSL *s, const unsigned char **buf,
			                 unsigned int *len, void *arg);
	void *next_protos_advertised_cb_arg;
	/* For a client, this contains a callback function that selects the
	 * next protocol from the list provided by the server. */
	int (*next_proto_select_cb)(SSL *s, unsigned char **out,
				    unsigned char *outlen,
				    const unsigned char *in,
				    unsigned int inlen,
				    void *arg);
	void *next_proto_select_cb_arg;

	/* ALPN information
	 * (we are in the process of transitioning from NPN to ALPN.) */

	/* For a server, this contains a callback function that allows the
	 * server to select the protocol for the connection.
	 *   out: on successful return, this must point to the raw protocol
	 *        name (without the length prefix).
	 *   outlen: on successful return, this contains the length of |*out|.
	 *   in: points to the client's list of supported protocols in
	 *       wire-format.
	 *   inlen: the length of |in|. */
	int (*alpn_select_cb)(SSL *s,
			      const unsigned char **out,
			      unsigned char *outlen,
			      const unsigned char* in,
			      unsigned int inlen,
			      void *arg);
	void *alpn_select_cb_arg;

	/* For a client, this contains the list of supported protocols in wire
	 * format. */
	unsigned char* alpn_client_proto_list;
	unsigned alpn_client_proto_list_len;

        /* SRTP profiles we are willing to do from RFC 5764 */
	STACK_OF(SRTP_PROTECTION_PROFILE) *srtp_profiles;
	/* EC extension values inherited by SSL structure */
	size_t tlsext_ecpointformatlist_length;
	uint8_t *tlsext_ecpointformatlist;
	size_t tlsext_ellipticcurvelist_length;
	uint16_t *tlsext_ellipticcurvelist;

	/* If true, a client will advertise the Channel ID extension and a
	 * server will echo it. */
	char tlsext_channel_id_enabled;
	/* tlsext_channel_id_enabled_new is a hack to support both old and new
	 * ChannelID signatures. It indicates that a client should advertise the
	 * new ChannelID extension number. */
	char tlsext_channel_id_enabled_new;
	/* The client's Channel ID private key. */
	EVP_PKEY *tlsext_channel_id_private;

	/* If true, a client will request certificate timestamps. */
	char signed_cert_timestamps_enabled;

	/* If true, a client will request a stapled OCSP response. */
	char ocsp_stapling_enabled;

	/* If not NULL, session key material will be logged to this BIO for
	 * debugging purposes. The format matches NSS's and is readable by
	 * Wireshark. */
	BIO *keylog_bio;
	};

#endif

#define SSL_SESS_CACHE_OFF			0x0000
#define SSL_SESS_CACHE_CLIENT			0x0001
#define SSL_SESS_CACHE_SERVER			0x0002
#define SSL_SESS_CACHE_BOTH	(SSL_SESS_CACHE_CLIENT|SSL_SESS_CACHE_SERVER)
#define SSL_SESS_CACHE_NO_AUTO_CLEAR		0x0080
/* enough comments already ... see SSL_CTX_set_session_cache_mode(3) */
#define SSL_SESS_CACHE_NO_INTERNAL_LOOKUP	0x0100
#define SSL_SESS_CACHE_NO_INTERNAL_STORE	0x0200
#define SSL_SESS_CACHE_NO_INTERNAL \
	(SSL_SESS_CACHE_NO_INTERNAL_LOOKUP|SSL_SESS_CACHE_NO_INTERNAL_STORE)

OPENSSL_EXPORT LHASH_OF(SSL_SESSION) *SSL_CTX_sessions(SSL_CTX *ctx);
#define SSL_CTX_sess_number(ctx) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_NUMBER,0,NULL)
#define SSL_CTX_sess_connect(ctx) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_CONNECT,0,NULL)
#define SSL_CTX_sess_connect_good(ctx) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_CONNECT_GOOD,0,NULL)
#define SSL_CTX_sess_connect_renegotiate(ctx) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_CONNECT_RENEGOTIATE,0,NULL)
#define SSL_CTX_sess_accept(ctx) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_ACCEPT,0,NULL)
#define SSL_CTX_sess_accept_renegotiate(ctx) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_ACCEPT_RENEGOTIATE,0,NULL)
#define SSL_CTX_sess_accept_good(ctx) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_ACCEPT_GOOD,0,NULL)
#define SSL_CTX_sess_hits(ctx) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_HIT,0,NULL)
#define SSL_CTX_sess_cb_hits(ctx) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_CB_HIT,0,NULL)
#define SSL_CTX_sess_misses(ctx) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_MISSES,0,NULL)
#define SSL_CTX_sess_timeouts(ctx) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_TIMEOUTS,0,NULL)
#define SSL_CTX_sess_cache_full(ctx) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_SESS_CACHE_FULL,0,NULL)
/* SSL_CTX_enable_tls_channel_id configures a TLS server to accept TLS client
 * IDs from clients. Returns 1 on success. */
#define SSL_CTX_enable_tls_channel_id(ctx) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_CHANNEL_ID,0,NULL)

OPENSSL_EXPORT void SSL_CTX_sess_set_new_cb(SSL_CTX *ctx, int (*new_session_cb)(struct ssl_st *ssl,SSL_SESSION *sess));
OPENSSL_EXPORT int (*SSL_CTX_sess_get_new_cb(SSL_CTX *ctx))(struct ssl_st *ssl, SSL_SESSION *sess);
OPENSSL_EXPORT void SSL_CTX_sess_set_remove_cb(SSL_CTX *ctx, void (*remove_session_cb)(struct ssl_ctx_st *ctx,SSL_SESSION *sess));
OPENSSL_EXPORT void (*SSL_CTX_sess_get_remove_cb(SSL_CTX *ctx))(struct ssl_ctx_st *ctx, SSL_SESSION *sess);
OPENSSL_EXPORT void SSL_CTX_sess_set_get_cb(SSL_CTX *ctx, SSL_SESSION *(*get_session_cb)(struct ssl_st *ssl, unsigned char *data,int len,int *copy));
OPENSSL_EXPORT SSL_SESSION *(*SSL_CTX_sess_get_get_cb(SSL_CTX *ctx))(struct ssl_st *ssl, unsigned char *Data, int len, int *copy);
/* SSL_magic_pending_session_ptr returns a magic SSL_SESSION* which indicates
 * that the session isn't currently unavailable. SSL_get_error will then return
 * SSL_ERROR_PENDING_SESSION and the handshake can be retried later when the
 * lookup has completed. */
OPENSSL_EXPORT SSL_SESSION *SSL_magic_pending_session_ptr(void);
OPENSSL_EXPORT void SSL_CTX_set_info_callback(SSL_CTX *ctx, void (*cb)(const SSL *ssl,int type,int val));
OPENSSL_EXPORT void (*SSL_CTX_get_info_callback(SSL_CTX *ctx))(const SSL *ssl,int type,int val);
OPENSSL_EXPORT void SSL_CTX_set_client_cert_cb(SSL_CTX *ctx, int (*client_cert_cb)(SSL *ssl, X509 **x509, EVP_PKEY **pkey));
OPENSSL_EXPORT int (*SSL_CTX_get_client_cert_cb(SSL_CTX *ctx))(SSL *ssl, X509 **x509, EVP_PKEY **pkey);
OPENSSL_EXPORT void SSL_CTX_set_channel_id_cb(SSL_CTX *ctx, void (*channel_id_cb)(SSL *ssl, EVP_PKEY **pkey));
OPENSSL_EXPORT void (*SSL_CTX_get_channel_id_cb(SSL_CTX *ctx))(SSL *ssl, EVP_PKEY **pkey);
OPENSSL_EXPORT void SSL_CTX_set_cookie_generate_cb(SSL_CTX *ctx, int (*app_gen_cookie_cb)(SSL *ssl, uint8_t *cookie, size_t *cookie_len));
OPENSSL_EXPORT void SSL_CTX_set_cookie_verify_cb(SSL_CTX *ctx, int (*app_verify_cookie_cb)(SSL *ssl, const uint8_t *cookie, size_t cookie_len));


/* SSL_enable_signed_cert_timestamps causes |ssl| (which must be the client
 * end of a connection) to request SCTs from the server.
 * See https://tools.ietf.org/html/rfc6962.
 * Returns 1 on success. */
OPENSSL_EXPORT int SSL_enable_signed_cert_timestamps(SSL *ssl);

/* SSL_CTX_enable_signed_cert_timestamps enables SCT requests on all
 * client SSL objects created from |ctx|. */
OPENSSL_EXPORT void SSL_CTX_enable_signed_cert_timestamps(SSL_CTX *ctx);

/* SSL_enable_signed_cert_timestamps causes |ssl| (which must be the client end
 * of a connection) to request a stapled OCSP response from the server. Returns
 * 1 on success. */
OPENSSL_EXPORT int SSL_enable_ocsp_stapling(SSL *ssl);

/* SSL_CTX_enable_ocsp_stapling enables OCSP stapling on all client SSL objects
 * created from |ctx|. */
OPENSSL_EXPORT void SSL_CTX_enable_ocsp_stapling(SSL_CTX *ctx);

/* SSL_get0_signed_cert_timestamp_list sets |*out| and |*out_len| to point to
 * |*out_len| bytes of SCT information from the server. This is only valid if
 * |ssl| is a client. The SCT information is a SignedCertificateTimestampList
 * (including the two leading length bytes).
 * See https://tools.ietf.org/html/rfc6962#section-3.3
 * If no SCT was received then |*out_len| will be zero on return.
 *
 * WARNING: the returned data is not guaranteed to be well formed. */
OPENSSL_EXPORT void SSL_get0_signed_cert_timestamp_list(const SSL *ssl, uint8_t **out, size_t *out_len);

/* SSL_get0_ocsp_response sets |*out| and |*out_len| to point to |*out_len|
 * bytes of an OCSP response from the server. This is the DER encoding of an
 * OCSPResponse type as defined in RFC 2560.
 *
 * WARNING: the returned data is not guaranteed to be well formed. */
OPENSSL_EXPORT void SSL_get0_ocsp_response(const SSL *ssl, uint8_t **out, size_t *out_len);

OPENSSL_EXPORT void SSL_CTX_set_next_protos_advertised_cb(SSL_CTX *s,
					   int (*cb) (SSL *ssl,
						      const unsigned char **out,
						      unsigned int *outlen,
						      void *arg), void *arg);
OPENSSL_EXPORT void SSL_CTX_set_next_proto_select_cb(SSL_CTX *s,
				      int (*cb) (SSL *ssl, unsigned char **out,
						 unsigned char *outlen,
						 const unsigned char *in,
						 unsigned int inlen, void *arg),
				      void *arg);
OPENSSL_EXPORT void SSL_get0_next_proto_negotiated(const SSL *s,
				    const uint8_t **data, unsigned *len);

OPENSSL_EXPORT int SSL_select_next_proto(unsigned char **out, unsigned char *outlen,
			  const unsigned char *in, unsigned int inlen,
			  const unsigned char *client, unsigned int client_len);

#define OPENSSL_NPN_UNSUPPORTED	0
#define OPENSSL_NPN_NEGOTIATED	1
#define OPENSSL_NPN_NO_OVERLAP	2

OPENSSL_EXPORT int SSL_CTX_set_alpn_protos(SSL_CTX *ctx, const unsigned char* protos,
			    unsigned protos_len);
OPENSSL_EXPORT int SSL_set_alpn_protos(SSL *ssl, const unsigned char* protos,
			unsigned protos_len);
OPENSSL_EXPORT void SSL_CTX_set_alpn_select_cb(SSL_CTX* ctx,
				int (*cb) (SSL *ssl,
					   const unsigned char **out,
					   unsigned char *outlen,
					   const unsigned char *in,
					   unsigned int inlen,
					   void *arg),
				void *arg);
OPENSSL_EXPORT void SSL_get0_alpn_selected(const SSL *ssl, const unsigned char **data,
			    unsigned *len); 
/* the maximum length of the buffer given to callbacks containing the
 * resulting identity/psk */
#define PSK_MAX_IDENTITY_LEN 128
#define PSK_MAX_PSK_LEN 256
OPENSSL_EXPORT void SSL_CTX_set_psk_client_callback(SSL_CTX *ctx, 
	unsigned int (*psk_client_callback)(SSL *ssl, const char *hint, 
		char *identity, unsigned int max_identity_len, unsigned char *psk,
		unsigned int max_psk_len));
OPENSSL_EXPORT void SSL_set_psk_client_callback(SSL *ssl, 
	unsigned int (*psk_client_callback)(SSL *ssl, const char *hint, 
		char *identity, unsigned int max_identity_len, unsigned char *psk,
		unsigned int max_psk_len));
OPENSSL_EXPORT void SSL_CTX_set_psk_server_callback(SSL_CTX *ctx, 
	unsigned int (*psk_server_callback)(SSL *ssl, const char *identity,
		unsigned char *psk, unsigned int max_psk_len));
OPENSSL_EXPORT void SSL_set_psk_server_callback(SSL *ssl,
	unsigned int (*psk_server_callback)(SSL *ssl, const char *identity,
		unsigned char *psk, unsigned int max_psk_len));
OPENSSL_EXPORT int SSL_CTX_use_psk_identity_hint(SSL_CTX *ctx, const char *identity_hint);
OPENSSL_EXPORT int SSL_use_psk_identity_hint(SSL *s, const char *identity_hint);
OPENSSL_EXPORT const char *SSL_get_psk_identity_hint(const SSL *s);
OPENSSL_EXPORT const char *SSL_get_psk_identity(const SSL *s);
OPENSSL_EXPORT void ssl_update_cache(SSL *s, int mode);
OPENSSL_EXPORT int ssl_get_new_session(SSL *s, int session);

#define SSL_NOTHING	1
#define SSL_WRITING	2
#define SSL_READING	3
#define SSL_X509_LOOKUP	4
#define SSL_CHANNEL_ID_LOOKUP	5
#define SSL_PENDING_SESSION	7
#define SSL_CERTIFICATE_SELECTION_PENDING	8

/* These will only be used when doing non-blocking IO */
#define SSL_want_nothing(s)	(SSL_want(s) == SSL_NOTHING)
#define SSL_want_read(s)	(SSL_want(s) == SSL_READING)
#define SSL_want_write(s)	(SSL_want(s) == SSL_WRITING)
#define SSL_want_x509_lookup(s)	(SSL_want(s) == SSL_X509_LOOKUP)
#define SSL_want_channel_id_lookup(s)	(SSL_want(s) == SSL_CHANNEL_ID_LOOKUP)
#define SSL_want_session(s)	(SSL_want(s) == SSL_PENDING_SESSION)
#define SSL_want_certificate(s)	(SSL_want(s) == SSL_CERTIFICATE_SELECTION_PENDING)

#ifndef OPENSSL_NO_SSL_INTERN

struct ssl_st
	{
	/* protocol version
	 * (one of SSL2_VERSION, SSL3_VERSION, TLS1_VERSION, DTLS1_VERSION)
	 */
	int version;
	int type; /* SSL_ST_CONNECT or SSL_ST_ACCEPT */

	const SSL_METHOD *method; /* SSLv3 */

	/* There are 2 BIO's even though they are normally both the
	 * same.  This is so data can be read and written to different
	 * handlers */

#ifndef OPENSSL_NO_BIO
	BIO *rbio; /* used by SSL_read */
	BIO *wbio; /* used by SSL_write */
	BIO *bbio; /* used during session-id reuse to concatenate
		    * messages */
#else
	char *rbio; /* used by SSL_read */
	char *wbio; /* used by SSL_write */
	char *bbio;
#endif
	/* This holds a variable that indicates what we were doing
	 * when a 0 or -1 is returned.  This is needed for
	 * non-blocking IO so we know what request needs re-doing when
	 * in SSL_accept or SSL_connect */
	int rwstate;

	/* true when we are actually in SSL_accept() or SSL_connect() */
	int in_handshake;
	int (*handshake_func)(SSL *);

	/* Imagine that here's a boolean member "init" that is
	 * switched as soon as SSL_set_{accept/connect}_state
	 * is called for the first time, so that "state" and
	 * "handshake_func" are properly initialized.  But as
	 * handshake_func is == 0 until then, we use this
	 * test instead of an "init" member.
	 */

	int server;	/* are we the server side? - mostly used by SSL_clear*/

	int new_session;/* Generate a new session or reuse an old one.
	                 * NB: For servers, the 'new' session may actually be a previously
	                 * cached session or even the previous session unless
	                 * SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION is set */
	int quiet_shutdown;/* don't send shutdown packets */
	int shutdown;	/* we have shut things down, 0x01 sent, 0x02
			 * for received */
	int state;	/* where we are */
	int rstate;	/* where we are when reading */

	BUF_MEM *init_buf;	/* buffer used during init */
	uint8_t *init_msg;   	/* pointer to handshake message body, set by ssl3_get_message() */
	int init_num;		/* amount read/written */
	int init_off;		/* amount read/written */

	/* used internally to point at a raw packet */
	unsigned char *packet;
	unsigned int packet_length;

	struct ssl3_state_st *s3; /* SSLv3 variables */
	struct dtls1_state_st *d1; /* DTLSv1 variables */

	int read_ahead;		/* Read as many input bytes as possible
	               	 	 * (for non-blocking reads) */

	/* callback that allows applications to peek at protocol messages */
	void (*msg_callback)(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg);
	void *msg_callback_arg;

	int hit;		/* reusing a previous session */

	X509_VERIFY_PARAM *param;

#if 0
	int purpose;		/* Purpose setting */
	int trust;		/* Trust setting */
#endif

	/* crypto */
	struct ssl_cipher_preference_list_st *cipher_list;
	STACK_OF(SSL_CIPHER) *cipher_list_by_id;

	/* These are the ones being used, the ones in SSL_SESSION are
	 * the ones to be 'copied' into these ones */
	SSL_AEAD_CTX *aead_read_ctx;	/* AEAD context. If non-NULL, then
					   |enc_read_ctx| and |read_hash| are
					   ignored. */
	EVP_CIPHER_CTX *enc_read_ctx;		/* cryptographic state */
	EVP_MD_CTX *read_hash;		/* used for mac generation */

	SSL_AEAD_CTX *aead_write_ctx;	/* AEAD context. If non-NULL, then
					   |enc_write_ctx| and |write_hash| are
					   ignored. */
	EVP_CIPHER_CTX *enc_write_ctx;		/* cryptographic state */
	EVP_MD_CTX *write_hash;		/* used for mac generation */

	/* session info */

	/* client cert? */
	/* This is used to hold the server certificate used */
	struct cert_st /* CERT */ *cert;

	/* the session_id_context is used to ensure sessions are only reused
	 * in the appropriate context */
	unsigned int sid_ctx_length;
	unsigned char sid_ctx[SSL_MAX_SID_CTX_LENGTH];

	/* This can also be in the session once a session is established */
	SSL_SESSION *session;

	/* Default generate session ID callback. */
	GEN_SESSION_CB generate_session_id;

	/* Used in SSL2 and SSL3 */
	int verify_mode;	/* 0 don't care about verify failure.
				 * 1 fail if verify fails */
	int (*verify_callback)(int ok,X509_STORE_CTX *ctx); /* fail if callback returns 0 */

	void (*info_callback)(const SSL *ssl,int type,int val); /* optional informational callback */

	/* PSK identity hint is stored here only to enable setting a hint on an SSL object before an
	 * SSL_SESSION is associated with it. Once an SSL_SESSION is associated with this SSL object,
	 * the psk_identity_hint from the session takes precedence over this one. */
	char *psk_identity_hint;
	unsigned int (*psk_client_callback)(SSL *ssl, const char *hint, char *identity,
		unsigned int max_identity_len, unsigned char *psk,
		unsigned int max_psk_len);
	unsigned int (*psk_server_callback)(SSL *ssl, const char *identity,
		unsigned char *psk, unsigned int max_psk_len);

	SSL_CTX *ctx;
	/* set this flag to 1 and a sleep(1) is put into all SSL_read()
	 * and SSL_write() calls, good for nbio debuging :-) */
	int debug;	

	/* extra application data */
	long verify_result;
	CRYPTO_EX_DATA ex_data;

	/* for server side, keep the list of CA_dn we can use */
	STACK_OF(X509_NAME) *client_CA;

	int references;
	unsigned long options; /* protocol behaviour */
	unsigned long mode; /* API behaviour */
	long max_cert_list;
	int first_packet;
	int client_version;	/* what was passed, used for
				 * SSLv3/TLS rollback check */
	unsigned int max_send_fragment;
	/* TLS extension debug callback */
	void (*tlsext_debug_cb)(SSL *s, int client_server, int type,
					unsigned char *data, int len,
					void *arg);
	void *tlsext_debug_arg;
	char *tlsext_hostname;
	/* should_ack_sni is true if the SNI extension should be acked. This is
	 * only used by a server. */
	char should_ack_sni;
	/* RFC4507 session ticket expected to be received or sent */
	int tlsext_ticket_expected;
	size_t tlsext_ecpointformatlist_length;
	uint8_t *tlsext_ecpointformatlist; /* our list */
	size_t tlsext_ellipticcurvelist_length;
	uint16_t *tlsext_ellipticcurvelist; /* our list */

	/* TLS Session Ticket extension override */
	TLS_SESSION_TICKET_EXT *tlsext_session_ticket;

	/* TLS Session Ticket extension callback */
	tls_session_ticket_ext_cb_fn tls_session_ticket_ext_cb;
	void *tls_session_ticket_ext_cb_arg;

	/* TLS pre-shared secret session resumption */
	tls_session_secret_cb_fn tls_session_secret_cb;
	void *tls_session_secret_cb_arg;

	SSL_CTX * initial_ctx; /* initial ctx, used to store sessions */

	/* Next protocol negotiation. For the client, this is the protocol that
	 * we sent in NextProtocol and is set when handling ServerHello
	 * extensions.
	 *
	 * For a server, this is the client's selected_protocol from
	 * NextProtocol and is set when handling the NextProtocol message,
	 * before the Finished message. */
	uint8_t *next_proto_negotiated;
	size_t next_proto_negotiated_len;

	STACK_OF(SRTP_PROTECTION_PROFILE) *srtp_profiles;  /* What we'll do */
	SRTP_PROTECTION_PROFILE *srtp_profile;            /* What's been chosen */

	/* Copied from the SSL_CTX. For a server, means that we'll accept
	 * Channel IDs from clients. For a client, means that we'll advertise
	 * support. */
	char tlsext_channel_id_enabled;
	/* The client's Channel ID private key. */
	EVP_PKEY *tlsext_channel_id_private;

	/* Enable signed certificate time stamps. Currently client only. */
	char signed_cert_timestamps_enabled;

	/* Enable OCSP stapling. Currently client only.
	 * TODO(davidben): Add a server-side implementation when it becomes
	 * necesary. */
	char ocsp_stapling_enabled;

	/* For a client, this contains the list of supported protocols in wire
	 * format. */
	unsigned char* alpn_client_proto_list;
	unsigned alpn_client_proto_list_len;

	int renegotiate;/* 1 if we are renegotiating.
	                 * 2 if we are a server and are inside a handshake
	                 * (i.e. not just sending a HelloRequest) */

	/* fallback_scsv is non-zero iff we are sending the TLS_FALLBACK_SCSV
	 * cipher suite value. Only applies to a client. */
	char fallback_scsv;
	};

#endif

#ifdef __cplusplus
}
#endif

#include <openssl/ssl2.h>
#include <openssl/ssl3.h>
#include <openssl/tls1.h> /* This is mostly sslv3 with a few tweaks */
#include <openssl/dtls1.h> /* Datagram TLS */
#include <openssl/ssl23.h>
#include <openssl/srtp.h>  /* Support for the use_srtp extension */

#ifdef  __cplusplus
extern "C" {
#endif

/* compatibility */
#define SSL_set_app_data(s,arg)		(SSL_set_ex_data(s,0,(char *)arg))
#define SSL_get_app_data(s)		(SSL_get_ex_data(s,0))
#define SSL_SESSION_set_app_data(s,a)	(SSL_SESSION_set_ex_data(s,0,(char *)a))
#define SSL_SESSION_get_app_data(s)	(SSL_SESSION_get_ex_data(s,0))
#define SSL_CTX_get_app_data(ctx)	(SSL_CTX_get_ex_data(ctx,0))
#define SSL_CTX_set_app_data(ctx,arg)	(SSL_CTX_set_ex_data(ctx,0,(char *)arg))

/* The following are the possible values for ssl->state are are
 * used to indicate where we are up to in the SSL connection establishment.
 * The macros that follow are about the only things you should need to use
 * and even then, only when using non-blocking IO.
 * It can also be useful to work out where you were when the connection
 * failed */

#define SSL_ST_CONNECT			0x1000
#define SSL_ST_ACCEPT			0x2000
#define SSL_ST_MASK			0x0FFF
#define SSL_ST_INIT			(SSL_ST_CONNECT|SSL_ST_ACCEPT)
#define SSL_ST_BEFORE			0x4000
#define SSL_ST_OK			0x03
#define SSL_ST_RENEGOTIATE		(0x04|SSL_ST_INIT)

#define SSL_CB_LOOP			0x01
#define SSL_CB_EXIT			0x02
#define SSL_CB_READ			0x04
#define SSL_CB_WRITE			0x08
#define SSL_CB_ALERT			0x4000 /* used in callback */
#define SSL_CB_READ_ALERT		(SSL_CB_ALERT|SSL_CB_READ)
#define SSL_CB_WRITE_ALERT		(SSL_CB_ALERT|SSL_CB_WRITE)
#define SSL_CB_ACCEPT_LOOP		(SSL_ST_ACCEPT|SSL_CB_LOOP)
#define SSL_CB_ACCEPT_EXIT		(SSL_ST_ACCEPT|SSL_CB_EXIT)
#define SSL_CB_CONNECT_LOOP		(SSL_ST_CONNECT|SSL_CB_LOOP)
#define SSL_CB_CONNECT_EXIT		(SSL_ST_CONNECT|SSL_CB_EXIT)
#define SSL_CB_HANDSHAKE_START		0x10
#define SSL_CB_HANDSHAKE_DONE		0x20

/* Is the SSL_connection established? */
#define SSL_get_state(a)		SSL_state(a)
#define SSL_is_init_finished(a)		(SSL_state(a) == SSL_ST_OK)
#define SSL_in_init(a)			((SSL_state(a)&SSL_ST_INIT) && \
					!SSL_cutthrough_complete(a))
#define SSL_in_before(a)		(SSL_state(a)&SSL_ST_BEFORE)
#define SSL_in_connect_init(a)		(SSL_state(a)&SSL_ST_CONNECT)
#define SSL_in_accept_init(a)		(SSL_state(a)&SSL_ST_ACCEPT)
OPENSSL_EXPORT int SSL_cutthrough_complete(const SSL *s);

/* The following 2 states are kept in ssl->rstate when reads fail,
 * you should not need these */
#define SSL_ST_READ_HEADER			0xF0
#define SSL_ST_READ_BODY			0xF1
#define SSL_ST_READ_DONE			0xF2

/* Obtain latest Finished message
 *   -- that we sent (SSL_get_finished)
 *   -- that we expected from peer (SSL_get_peer_finished).
 * Returns length (0 == no Finished so far), copies up to 'count' bytes. */
OPENSSL_EXPORT size_t SSL_get_finished(const SSL *s, void *buf, size_t count);
OPENSSL_EXPORT size_t SSL_get_peer_finished(const SSL *s, void *buf, size_t count);

/* use either SSL_VERIFY_NONE or SSL_VERIFY_PEER, the last 3 options
 * are 'ored' with SSL_VERIFY_PEER if they are desired */
#define SSL_VERIFY_NONE			0x00
#define SSL_VERIFY_PEER			0x01
#define SSL_VERIFY_FAIL_IF_NO_PEER_CERT	0x02
#define SSL_VERIFY_CLIENT_ONCE		0x04
#define SSL_VERIFY_PEER_IF_NO_OBC	0x08

#define OpenSSL_add_ssl_algorithms()	SSL_library_init()
#define SSLeay_add_ssl_algorithms()	SSL_library_init()

/* this is for backward compatibility */
#if 0 /* NEW_SSLEAY */
#define SSL_CTX_set_default_verify(a,b,c) SSL_CTX_set_verify(a,b,c)
#define SSL_set_pref_cipher(c,n)	SSL_set_cipher_list(c,n)
#define SSL_add_session(a,b)            SSL_CTX_add_session((a),(b))
#define SSL_remove_session(a,b)		SSL_CTX_remove_session((a),(b))
#define SSL_flush_sessions(a,b)		SSL_CTX_flush_sessions((a),(b))
#endif
/* More backward compatibility */
#define SSL_get_cipher(s) \
		SSL_CIPHER_get_name(SSL_get_current_cipher(s))
#define SSL_get_cipher_bits(s,np) \
		SSL_CIPHER_get_bits(SSL_get_current_cipher(s),np)
#define SSL_get_cipher_version(s) \
		SSL_CIPHER_get_version(SSL_get_current_cipher(s))
#define SSL_get_cipher_name(s) \
		SSL_CIPHER_get_name(SSL_get_current_cipher(s))
#define SSL_get_time(a)		SSL_SESSION_get_time(a)
#define SSL_set_time(a,b)	SSL_SESSION_set_time((a),(b))
#define SSL_get_timeout(a)	SSL_SESSION_get_timeout(a)
#define SSL_set_timeout(a,b)	SSL_SESSION_set_timeout((a),(b))

#define d2i_SSL_SESSION_bio(bp,s_id) ASN1_d2i_bio_of(SSL_SESSION,SSL_SESSION_new,d2i_SSL_SESSION,bp,s_id)
#define i2d_SSL_SESSION_bio(bp,s_id) ASN1_i2d_bio_of(SSL_SESSION,i2d_SSL_SESSION,bp,s_id)

DECLARE_PEM_rw(SSL_SESSION, SSL_SESSION)

/* make_errors.go reserves error codes above 1000 for manually-assigned
 * errors. This value must be kept in sync with reservedReasonCode in
 * make_errors.h */
#define SSL_AD_REASON_OFFSET		1000 /* offset to get SSL_R_... value from SSL_AD_... */

/* These alert types are for SSLv3 and TLSv1 */
#define SSL_AD_CLOSE_NOTIFY		SSL3_AD_CLOSE_NOTIFY
#define SSL_AD_UNEXPECTED_MESSAGE	SSL3_AD_UNEXPECTED_MESSAGE /* fatal */
#define SSL_AD_BAD_RECORD_MAC		SSL3_AD_BAD_RECORD_MAC     /* fatal */
#define SSL_AD_DECRYPTION_FAILED	TLS1_AD_DECRYPTION_FAILED
#define SSL_AD_RECORD_OVERFLOW		TLS1_AD_RECORD_OVERFLOW
#define SSL_AD_DECOMPRESSION_FAILURE	SSL3_AD_DECOMPRESSION_FAILURE/* fatal */
#define SSL_AD_HANDSHAKE_FAILURE	SSL3_AD_HANDSHAKE_FAILURE/* fatal */
#define SSL_AD_NO_CERTIFICATE		SSL3_AD_NO_CERTIFICATE /* Not for TLS */
#define SSL_AD_BAD_CERTIFICATE		SSL3_AD_BAD_CERTIFICATE
#define SSL_AD_UNSUPPORTED_CERTIFICATE	SSL3_AD_UNSUPPORTED_CERTIFICATE
#define SSL_AD_CERTIFICATE_REVOKED	SSL3_AD_CERTIFICATE_REVOKED
#define SSL_AD_CERTIFICATE_EXPIRED	SSL3_AD_CERTIFICATE_EXPIRED
#define SSL_AD_CERTIFICATE_UNKNOWN	SSL3_AD_CERTIFICATE_UNKNOWN
#define SSL_AD_ILLEGAL_PARAMETER	SSL3_AD_ILLEGAL_PARAMETER   /* fatal */
#define SSL_AD_UNKNOWN_CA		TLS1_AD_UNKNOWN_CA	/* fatal */
#define SSL_AD_ACCESS_DENIED		TLS1_AD_ACCESS_DENIED	/* fatal */
#define SSL_AD_DECODE_ERROR		TLS1_AD_DECODE_ERROR	/* fatal */
#define SSL_AD_DECRYPT_ERROR		TLS1_AD_DECRYPT_ERROR
#define SSL_AD_EXPORT_RESTRICTION	TLS1_AD_EXPORT_RESTRICTION/* fatal */
#define SSL_AD_PROTOCOL_VERSION		TLS1_AD_PROTOCOL_VERSION /* fatal */
#define SSL_AD_INSUFFICIENT_SECURITY	TLS1_AD_INSUFFICIENT_SECURITY/* fatal */
#define SSL_AD_INTERNAL_ERROR		TLS1_AD_INTERNAL_ERROR	/* fatal */
#define SSL_AD_USER_CANCELLED		TLS1_AD_USER_CANCELLED
#define SSL_AD_NO_RENEGOTIATION		TLS1_AD_NO_RENEGOTIATION
#define SSL_AD_UNSUPPORTED_EXTENSION	TLS1_AD_UNSUPPORTED_EXTENSION
#define SSL_AD_CERTIFICATE_UNOBTAINABLE TLS1_AD_CERTIFICATE_UNOBTAINABLE
#define SSL_AD_UNRECOGNIZED_NAME	TLS1_AD_UNRECOGNIZED_NAME
#define SSL_AD_BAD_CERTIFICATE_STATUS_RESPONSE TLS1_AD_BAD_CERTIFICATE_STATUS_RESPONSE
#define SSL_AD_BAD_CERTIFICATE_HASH_VALUE TLS1_AD_BAD_CERTIFICATE_HASH_VALUE
#define SSL_AD_UNKNOWN_PSK_IDENTITY     TLS1_AD_UNKNOWN_PSK_IDENTITY /* fatal */
#define SSL_AD_INAPPROPRIATE_FALLBACK	SSL3_AD_INAPPROPRIATE_FALLBACK /* fatal */

#define SSL_ERROR_NONE			0
#define SSL_ERROR_SSL			1
#define SSL_ERROR_WANT_READ		2
#define SSL_ERROR_WANT_WRITE		3
#define SSL_ERROR_WANT_X509_LOOKUP	4
#define SSL_ERROR_SYSCALL		5 /* look at error stack/return value/errno */
#define SSL_ERROR_ZERO_RETURN		6
#define SSL_ERROR_WANT_CONNECT		7
#define SSL_ERROR_WANT_ACCEPT		8
#define SSL_ERROR_WANT_CHANNEL_ID_LOOKUP	9
#define SSL_ERROR_PENDING_SESSION	11
#define SSL_ERROR_PENDING_CERTIFICATE	12

#define SSL_CTRL_NEED_TMP_RSA			1
#define SSL_CTRL_SET_TMP_RSA			2
#define SSL_CTRL_SET_TMP_DH			3
#define SSL_CTRL_SET_TMP_ECDH			4
#define SSL_CTRL_SET_TMP_RSA_CB			5
#define SSL_CTRL_SET_TMP_DH_CB			6
#define SSL_CTRL_SET_TMP_ECDH_CB		7

#define SSL_CTRL_GET_SESSION_REUSED		8
#define SSL_CTRL_GET_CLIENT_CERT_REQUEST	9
#define SSL_CTRL_GET_NUM_RENEGOTIATIONS		10
#define SSL_CTRL_CLEAR_NUM_RENEGOTIATIONS	11
#define SSL_CTRL_GET_TOTAL_RENEGOTIATIONS	12
#define SSL_CTRL_GET_FLAGS			13
#define SSL_CTRL_EXTRA_CHAIN_CERT		14

#define SSL_CTRL_SET_MSG_CALLBACK               15
#define SSL_CTRL_SET_MSG_CALLBACK_ARG           16

/* only applies to datagram connections */
#define SSL_CTRL_SET_MTU                17
/* Stats */
#define SSL_CTRL_SESS_NUMBER			20
#define SSL_CTRL_SESS_CONNECT			21
#define SSL_CTRL_SESS_CONNECT_GOOD		22
#define SSL_CTRL_SESS_CONNECT_RENEGOTIATE	23
#define SSL_CTRL_SESS_ACCEPT			24
#define SSL_CTRL_SESS_ACCEPT_GOOD		25
#define SSL_CTRL_SESS_ACCEPT_RENEGOTIATE	26
#define SSL_CTRL_SESS_HIT			27
#define SSL_CTRL_SESS_CB_HIT			28
#define SSL_CTRL_SESS_MISSES			29
#define SSL_CTRL_SESS_TIMEOUTS			30
#define SSL_CTRL_SESS_CACHE_FULL		31
#define SSL_CTRL_OPTIONS			32
#define SSL_CTRL_MODE				33

#define SSL_CTRL_GET_READ_AHEAD			40
#define SSL_CTRL_SET_READ_AHEAD			41
#define SSL_CTRL_SET_SESS_CACHE_SIZE		42
#define SSL_CTRL_GET_SESS_CACHE_SIZE		43
#define SSL_CTRL_SET_SESS_CACHE_MODE		44
#define SSL_CTRL_GET_SESS_CACHE_MODE		45

#define SSL_CTRL_GET_MAX_CERT_LIST		50
#define SSL_CTRL_SET_MAX_CERT_LIST		51

#define SSL_CTRL_SET_MAX_SEND_FRAGMENT		52

/* see tls1.h for macros based on these */
#define SSL_CTRL_SET_TLSEXT_SERVERNAME_CB	53
#define SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG	54
#define SSL_CTRL_SET_TLSEXT_HOSTNAME		55
#define SSL_CTRL_SET_TLSEXT_DEBUG_CB		56
#define SSL_CTRL_SET_TLSEXT_DEBUG_ARG		57
#define SSL_CTRL_GET_TLSEXT_TICKET_KEYS		58
#define SSL_CTRL_SET_TLSEXT_TICKET_KEYS		59
#define SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB	63
#define SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB_ARG	64

#define SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB	72

#define SSL_CTRL_SET_TLS_EXT_SRP_USERNAME_CB	75
#define SSL_CTRL_SET_SRP_VERIFY_PARAM_CB		76
#define SSL_CTRL_SET_SRP_GIVE_CLIENT_PWD_CB		77

#define SSL_CTRL_SET_SRP_ARG		78
#define SSL_CTRL_SET_TLS_EXT_SRP_USERNAME		79
#define SSL_CTRL_SET_TLS_EXT_SRP_STRENGTH		80
#define SSL_CTRL_SET_TLS_EXT_SRP_PASSWORD		81

#define DTLS_CTRL_GET_TIMEOUT		73
#define DTLS_CTRL_HANDLE_TIMEOUT	74
#define DTLS_CTRL_LISTEN			75

#define SSL_CTRL_GET_RI_SUPPORT			76
#define SSL_CTRL_CLEAR_OPTIONS			77
#define SSL_CTRL_CLEAR_MODE			78

#define SSL_CTRL_GET_EXTRA_CHAIN_CERTS		82
#define SSL_CTRL_CLEAR_EXTRA_CHAIN_CERTS	83

#define SSL_CTRL_CHAIN				88
#define SSL_CTRL_CHAIN_CERT			89

#define SSL_CTRL_GET_CURVES			90
#define SSL_CTRL_SET_CURVES			91
#define SSL_CTRL_SET_CURVES_LIST		92
#define SSL_CTRL_SET_ECDH_AUTO			94
#define SSL_CTRL_SET_SIGALGS			97
#define SSL_CTRL_SET_SIGALGS_LIST		98
#define SSL_CTRL_CERT_FLAGS			99
#define SSL_CTRL_CLEAR_CERT_FLAGS		100
#define SSL_CTRL_SET_CLIENT_SIGALGS		101
#define SSL_CTRL_SET_CLIENT_SIGALGS_LIST	102
#define SSL_CTRL_GET_CLIENT_CERT_TYPES		103
#define SSL_CTRL_SET_CLIENT_CERT_TYPES		104
#define SSL_CTRL_BUILD_CERT_CHAIN		105
#define SSL_CTRL_SET_VERIFY_CERT_STORE		106
#define SSL_CTRL_SET_CHAIN_CERT_STORE		107
#define SSL_CTRL_GET_PEER_SIGNATURE_NID		108
#define SSL_CTRL_GET_SERVER_TMP_KEY		109
#define SSL_CTRL_GET_RAW_CIPHERLIST		110
#define SSL_CTRL_GET_EC_POINT_FORMATS		111

#define SSL_CTRL_GET_CHAIN_CERTS		115
#define SSL_CTRL_SELECT_CURRENT_CERT		116

#define SSL_CTRL_CHANNEL_ID			117
#define SSL_CTRL_GET_CHANNEL_ID			118
#define SSL_CTRL_SET_CHANNEL_ID			119

#define SSL_CTRL_FALLBACK_SCSV			120

#define DTLSv1_get_timeout(ssl, arg) \
	SSL_ctrl(ssl,DTLS_CTRL_GET_TIMEOUT,0, (void *)arg)
#define DTLSv1_handle_timeout(ssl) \
	SSL_ctrl(ssl,DTLS_CTRL_HANDLE_TIMEOUT,0, NULL)
#define DTLSv1_listen(ssl, peer) \
	SSL_ctrl(ssl,DTLS_CTRL_LISTEN,0, (void *)peer)

#define SSL_session_reused(ssl) \
	SSL_ctrl((ssl),SSL_CTRL_GET_SESSION_REUSED,0,NULL)
#define SSL_num_renegotiations(ssl) \
	SSL_ctrl((ssl),SSL_CTRL_GET_NUM_RENEGOTIATIONS,0,NULL)
#define SSL_clear_num_renegotiations(ssl) \
	SSL_ctrl((ssl),SSL_CTRL_CLEAR_NUM_RENEGOTIATIONS,0,NULL)
#define SSL_total_renegotiations(ssl) \
	SSL_ctrl((ssl),SSL_CTRL_GET_TOTAL_RENEGOTIATIONS,0,NULL)

#define SSL_CTX_need_tmp_RSA(ctx) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_NEED_TMP_RSA,0,NULL)
#define SSL_CTX_set_tmp_rsa(ctx,rsa) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_SET_TMP_RSA,0,(char *)rsa)
#define SSL_CTX_set_tmp_dh(ctx,dh) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_SET_TMP_DH,0,(char *)dh)
#define SSL_CTX_set_tmp_ecdh(ctx,ecdh) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_SET_TMP_ECDH,0,(char *)ecdh)

#define SSL_need_tmp_RSA(ssl) \
	SSL_ctrl(ssl,SSL_CTRL_NEED_TMP_RSA,0,NULL)
#define SSL_set_tmp_rsa(ssl,rsa) \
	SSL_ctrl(ssl,SSL_CTRL_SET_TMP_RSA,0,(char *)rsa)
#define SSL_set_tmp_dh(ssl,dh) \
	SSL_ctrl(ssl,SSL_CTRL_SET_TMP_DH,0,(char *)dh)
#define SSL_set_tmp_ecdh(ssl,ecdh) \
	SSL_ctrl(ssl,SSL_CTRL_SET_TMP_ECDH,0,(char *)ecdh)

/* SSL_enable_tls_channel_id either configures a TLS server to accept TLS client
 * IDs from clients, or configure a client to send TLS client IDs to server.
 * Returns 1 on success. */
#define SSL_enable_tls_channel_id(s) \
	SSL_ctrl(s,SSL_CTRL_CHANNEL_ID,0,NULL)
/* SSL_set1_tls_channel_id configures a TLS client to send a TLS Channel ID to
 * compatible servers. private_key must be a P-256 EVP_PKEY*. Returns 1 on
 * success. */
#define SSL_set1_tls_channel_id(s, private_key) \
	SSL_ctrl(s,SSL_CTRL_SET_CHANNEL_ID,0,(void*)private_key)
#define SSL_CTX_set1_tls_channel_id(ctx, private_key) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CHANNEL_ID,0,(void*)private_key)
/* SSL_get_tls_channel_id gets the client's TLS Channel ID from a server SSL*
 * and copies up to the first |channel_id_len| bytes into |channel_id|. The
 * Channel ID consists of the client's P-256 public key as an (x,y) pair where
 * each is a 32-byte, big-endian field element. Returns 0 if the client didn't
 * offer a Channel ID and the length of the complete Channel ID otherwise. */
#define SSL_get_tls_channel_id(ctx, channel_id, channel_id_len) \
	SSL_ctrl(ctx,SSL_CTRL_GET_CHANNEL_ID,channel_id_len,(void*)channel_id)

#define SSL_CTX_add_extra_chain_cert(ctx,x509) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_EXTRA_CHAIN_CERT,0,(char *)x509)
#define SSL_CTX_get_extra_chain_certs(ctx,px509) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_GET_EXTRA_CHAIN_CERTS,0,px509)
#define SSL_CTX_get_extra_chain_certs_only(ctx,px509) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_GET_EXTRA_CHAIN_CERTS,1,px509)
#define SSL_CTX_clear_extra_chain_certs(ctx) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_CLEAR_EXTRA_CHAIN_CERTS,0,NULL)

#define SSL_CTX_set0_chain(ctx,sk) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_CHAIN,0,(char *)sk)
#define SSL_CTX_set1_chain(ctx,sk) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_CHAIN,1,(char *)sk)
#define SSL_CTX_add0_chain_cert(ctx,x509) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_CHAIN_CERT,0,(char *)x509)
#define SSL_CTX_add1_chain_cert(ctx,x509) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_CHAIN_CERT,1,(char *)x509)
#define SSL_CTX_get0_chain_certs(ctx,px509) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_GET_CHAIN_CERTS,0,px509)
#define SSL_CTX_clear_chain_certs(ctx) \
	SSL_CTX_set0_chain(ctx,NULL)
#define SSL_CTX_build_cert_chain(ctx, flags) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_BUILD_CERT_CHAIN, flags, NULL)
#define SSL_CTX_select_current_cert(ctx,x509) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_SELECT_CURRENT_CERT,0,(char *)x509)

#define SSL_CTX_set0_verify_cert_store(ctx,st) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_SET_VERIFY_CERT_STORE,0,(char *)st)
#define SSL_CTX_set1_verify_cert_store(ctx,st) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_SET_VERIFY_CERT_STORE,1,(char *)st)
#define SSL_CTX_set0_chain_cert_store(ctx,st) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CHAIN_CERT_STORE,0,(char *)st)
#define SSL_CTX_set1_chain_cert_store(ctx,st) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CHAIN_CERT_STORE,1,(char *)st)

#define SSL_set0_chain(ctx,sk) \
	SSL_ctrl(ctx,SSL_CTRL_CHAIN,0,(char *)sk)
#define SSL_set1_chain(ctx,sk) \
	SSL_ctrl(ctx,SSL_CTRL_CHAIN,1,(char *)sk)
#define SSL_add0_chain_cert(ctx,x509) \
	SSL_ctrl(ctx,SSL_CTRL_CHAIN_CERT,0,(char *)x509)
#define SSL_add1_chain_cert(ctx,x509) \
	SSL_ctrl(ctx,SSL_CTRL_CHAIN_CERT,1,(char *)x509)
#define SSL_get0_chain_certs(ctx,px509) \
	SSL_ctrl(ctx,SSL_CTRL_GET_CHAIN_CERTS,0,px509)
#define SSL_clear_chain_certs(ctx) \
	SSL_set0_chain(ctx,NULL)
#define SSL_build_cert_chain(s, flags) \
	SSL_ctrl(s,SSL_CTRL_BUILD_CERT_CHAIN, flags, NULL)
#define SSL_select_current_cert(ctx,x509) \
	SSL_ctrl(ctx,SSL_CTRL_SELECT_CURRENT_CERT,0,(char *)x509)

#define SSL_set0_verify_cert_store(s,st) \
	SSL_ctrl(s,SSL_CTRL_SET_VERIFY_CERT_STORE,0,(char *)st)
#define SSL_set1_verify_cert_store(s,st) \
	SSL_ctrl(s,SSL_CTRL_SET_VERIFY_CERT_STORE,1,(char *)st)
#define SSL_set0_chain_cert_store(s,st) \
	SSL_ctrl(s,SSL_CTRL_SET_CHAIN_CERT_STORE,0,(char *)st)
#define SSL_set1_chain_cert_store(s,st) \
	SSL_ctrl(s,SSL_CTRL_SET_CHAIN_CERT_STORE,1,(char *)st)

#define SSL_get1_curves(ctx, s) \
	SSL_ctrl(ctx,SSL_CTRL_GET_CURVES,0,(char *)s)
#define SSL_CTX_set1_curves(ctx, clist, clistlen) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CURVES,clistlen,(char *)clist)
#define SSL_CTX_set1_curves_list(ctx, s) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CURVES_LIST,0,(char *)s)
#define SSL_set1_curves(ctx, clist, clistlen) \
	SSL_ctrl(ctx,SSL_CTRL_SET_CURVES,clistlen,(char *)clist)
#define SSL_set1_curves_list(ctx, s) \
	SSL_ctrl(ctx,SSL_CTRL_SET_CURVES_LIST,0,(char *)s)
#define SSL_CTX_set_ecdh_auto(ctx, onoff) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_SET_ECDH_AUTO,onoff,NULL)
#define SSL_set_ecdh_auto(s, onoff) \
	SSL_ctrl(s,SSL_CTRL_SET_ECDH_AUTO,onoff,NULL)

#define SSL_CTX_set1_sigalgs(ctx, slist, slistlen) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_SET_SIGALGS,slistlen,(int *)slist)
#define SSL_CTX_set1_sigalgs_list(ctx, s) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_SET_SIGALGS_LIST,0,(char *)s)
#define SSL_set1_sigalgs(ctx, slist, slistlen) \
	SSL_ctrl(ctx,SSL_CTRL_SET_SIGALGS,clistlen,(int *)slist)
#define SSL_set1_sigalgs_list(ctx, s) \
	SSL_ctrl(ctx,SSL_CTRL_SET_SIGALGS_LIST,0,(char *)s)

#define SSL_CTX_set1_client_sigalgs(ctx, slist, slistlen) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CLIENT_SIGALGS,slistlen,(int *)slist)
#define SSL_CTX_set1_client_sigalgs_list(ctx, s) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CLIENT_SIGALGS_LIST,0,(char *)s)
#define SSL_set1_client_sigalgs(ctx, slist, slistlen) \
	SSL_ctrl(ctx,SSL_CTRL_SET_CLIENT_SIGALGS,clistlen,(int *)slist)
#define SSL_set1_client_sigalgs_list(ctx, s) \
	SSL_ctrl(ctx,SSL_CTRL_SET_CLIENT_SIGALGS_LIST,0,(char *)s)

#define SSL_get0_certificate_types(s, clist) \
	SSL_ctrl(s, SSL_CTRL_GET_CLIENT_CERT_TYPES, 0, (char *)clist)

#define SSL_CTX_set1_client_certificate_types(ctx, clist, clistlen) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_SET_CLIENT_CERT_TYPES,clistlen,(char *)clist)
#define SSL_set1_client_certificate_types(s, clist, clistlen) \
	SSL_ctrl(s,SSL_CTRL_SET_CLIENT_CERT_TYPES,clistlen,(char *)clist)

#define SSL_get_peer_signature_nid(s, pn) \
	SSL_ctrl(s,SSL_CTRL_GET_PEER_SIGNATURE_NID,0,pn)

#define SSL_get_server_tmp_key(s, pk) \
	SSL_ctrl(s,SSL_CTRL_GET_SERVER_TMP_KEY,0,pk)

#define SSL_get0_raw_cipherlist(s, plst) \
	SSL_ctrl(s,SSL_CTRL_GET_RAW_CIPHERLIST,0,(char *)plst)

#define SSL_get0_ec_point_formats(s, plst) \
	SSL_ctrl(s,SSL_CTRL_GET_EC_POINT_FORMATS,0,(char *)plst)

#define SSL_enable_fallback_scsv(s) \
	SSL_ctrl(s, SSL_CTRL_FALLBACK_SCSV, 0, NULL)

#ifndef OPENSSL_NO_BIO
OPENSSL_EXPORT BIO_METHOD *BIO_f_ssl(void);
OPENSSL_EXPORT BIO *BIO_new_ssl(SSL_CTX *ctx,int client);
OPENSSL_EXPORT BIO *BIO_new_ssl_connect(SSL_CTX *ctx);
OPENSSL_EXPORT BIO *BIO_new_buffer_ssl_connect(SSL_CTX *ctx);
OPENSSL_EXPORT void BIO_ssl_shutdown(BIO *ssl_bio);

#endif

OPENSSL_EXPORT int	SSL_CTX_set_cipher_list(SSL_CTX *,const char *str);
OPENSSL_EXPORT int	SSL_CTX_set_cipher_list_tls11(SSL_CTX *,const char *str);
OPENSSL_EXPORT SSL_CTX *SSL_CTX_new(const SSL_METHOD *meth);
OPENSSL_EXPORT void	SSL_CTX_free(SSL_CTX *);
OPENSSL_EXPORT long SSL_CTX_set_timeout(SSL_CTX *ctx,long t);
OPENSSL_EXPORT long SSL_CTX_get_timeout(const SSL_CTX *ctx);
OPENSSL_EXPORT X509_STORE *SSL_CTX_get_cert_store(const SSL_CTX *);
OPENSSL_EXPORT void SSL_CTX_set_cert_store(SSL_CTX *,X509_STORE *);
OPENSSL_EXPORT int SSL_want(const SSL *s);
OPENSSL_EXPORT int	SSL_clear(SSL *s);

OPENSSL_EXPORT void	SSL_CTX_flush_sessions(SSL_CTX *ctx,long tm);

OPENSSL_EXPORT const SSL_CIPHER *SSL_get_current_cipher(const SSL *s);
OPENSSL_EXPORT int	SSL_CIPHER_get_bits(const SSL_CIPHER *c,int *alg_bits);
OPENSSL_EXPORT const char *	SSL_CIPHER_get_version(const SSL_CIPHER *c);
OPENSSL_EXPORT const char *	SSL_CIPHER_get_name(const SSL_CIPHER *c);
/* SSL_CIPHER_get_kx_name returns a string that describes the key-exchange
 * method used by |c|. For example, "ECDHE-ECDSA". */
OPENSSL_EXPORT const char *	SSL_CIPHER_get_kx_name(const SSL_CIPHER *cipher);
OPENSSL_EXPORT unsigned long 	SSL_CIPHER_get_id(const SSL_CIPHER *c);

OPENSSL_EXPORT int	SSL_get_fd(const SSL *s);
OPENSSL_EXPORT int	SSL_get_rfd(const SSL *s);
OPENSSL_EXPORT int	SSL_get_wfd(const SSL *s);
OPENSSL_EXPORT const char  * SSL_get_cipher_list(const SSL *s,int n);
OPENSSL_EXPORT int	SSL_get_read_ahead(const SSL * s);
OPENSSL_EXPORT int	SSL_pending(const SSL *s);
#ifndef OPENSSL_NO_SOCK
OPENSSL_EXPORT int	SSL_set_fd(SSL *s, int fd);
OPENSSL_EXPORT int	SSL_set_rfd(SSL *s, int fd);
OPENSSL_EXPORT int	SSL_set_wfd(SSL *s, int fd);
#endif
#ifndef OPENSSL_NO_BIO
OPENSSL_EXPORT void	SSL_set_bio(SSL *s, BIO *rbio,BIO *wbio);
OPENSSL_EXPORT BIO *	SSL_get_rbio(const SSL *s);
OPENSSL_EXPORT BIO *	SSL_get_wbio(const SSL *s);
#endif
OPENSSL_EXPORT int	SSL_set_cipher_list(SSL *s, const char *str);
OPENSSL_EXPORT void	SSL_set_read_ahead(SSL *s, int yes);
OPENSSL_EXPORT int	SSL_get_verify_mode(const SSL *s);
OPENSSL_EXPORT int	SSL_get_verify_depth(const SSL *s);
OPENSSL_EXPORT int	(*SSL_get_verify_callback(const SSL *s))(int,X509_STORE_CTX *);
OPENSSL_EXPORT void	SSL_set_verify(SSL *s, int mode, int (*callback)(int ok,X509_STORE_CTX *ctx));
OPENSSL_EXPORT void	SSL_set_verify_depth(SSL *s, int depth);
OPENSSL_EXPORT void SSL_set_cert_cb(SSL *s, int (*cb)(SSL *ssl, void *arg), void *arg);
OPENSSL_EXPORT int	SSL_use_RSAPrivateKey(SSL *ssl, RSA *rsa);
OPENSSL_EXPORT int	SSL_use_RSAPrivateKey_ASN1(SSL *ssl, unsigned char *d, long len);
OPENSSL_EXPORT int	SSL_use_PrivateKey(SSL *ssl, EVP_PKEY *pkey);
OPENSSL_EXPORT int	SSL_use_PrivateKey_ASN1(int pk,SSL *ssl, const unsigned char *d, long len);
OPENSSL_EXPORT int	SSL_use_certificate(SSL *ssl, X509 *x);
OPENSSL_EXPORT int	SSL_use_certificate_ASN1(SSL *ssl, const unsigned char *d, int len);

#ifndef OPENSSL_NO_STDIO
OPENSSL_EXPORT int	SSL_use_RSAPrivateKey_file(SSL *ssl, const char *file, int type);
OPENSSL_EXPORT int	SSL_use_PrivateKey_file(SSL *ssl, const char *file, int type);
OPENSSL_EXPORT int	SSL_use_certificate_file(SSL *ssl, const char *file, int type);
OPENSSL_EXPORT int	SSL_CTX_use_RSAPrivateKey_file(SSL_CTX *ctx, const char *file, int type);
OPENSSL_EXPORT int	SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type);
OPENSSL_EXPORT int	SSL_CTX_use_certificate_file(SSL_CTX *ctx, const char *file, int type);
OPENSSL_EXPORT int	SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *file); /* PEM type */
OPENSSL_EXPORT STACK_OF(X509_NAME) *SSL_load_client_CA_file(const char *file);
OPENSSL_EXPORT int	SSL_add_file_cert_subjects_to_stack(STACK_OF(X509_NAME) *stackCAs, const char *file);
#ifndef OPENSSL_SYS_VMS
#ifndef OPENSSL_SYS_MACINTOSH_CLASSIC /* XXXXX: Better scheme needed! [was: #ifndef MAC_OS_pre_X] */
OPENSSL_EXPORT int	SSL_add_dir_cert_subjects_to_stack(STACK_OF(X509_NAME) *stackCAs, const char *dir);
#endif
#endif

#endif

OPENSSL_EXPORT void	SSL_load_error_strings(void );
OPENSSL_EXPORT const char *SSL_state_string(const SSL *s);
OPENSSL_EXPORT const char *SSL_rstate_string(const SSL *s);
OPENSSL_EXPORT const char *SSL_state_string_long(const SSL *s);
OPENSSL_EXPORT const char *SSL_rstate_string_long(const SSL *s);
OPENSSL_EXPORT long	SSL_SESSION_get_time(const SSL_SESSION *s);
OPENSSL_EXPORT long	SSL_SESSION_set_time(SSL_SESSION *s, long t);
OPENSSL_EXPORT long	SSL_SESSION_get_timeout(const SSL_SESSION *s);
OPENSSL_EXPORT long	SSL_SESSION_set_timeout(SSL_SESSION *s, long t);
OPENSSL_EXPORT X509 *SSL_SESSION_get0_peer(SSL_SESSION *s);
OPENSSL_EXPORT int SSL_SESSION_set1_id_context(SSL_SESSION *s,const unsigned char *sid_ctx, unsigned int sid_ctx_len);

OPENSSL_EXPORT SSL_SESSION *SSL_SESSION_new(void);
OPENSSL_EXPORT const unsigned char *SSL_SESSION_get_id(const SSL_SESSION *s, unsigned int *len);
#ifndef OPENSSL_NO_FP_API
OPENSSL_EXPORT int	SSL_SESSION_print_fp(FILE *fp,const SSL_SESSION *ses);
#endif
#ifndef OPENSSL_NO_BIO
OPENSSL_EXPORT int	SSL_SESSION_print(BIO *fp,const SSL_SESSION *ses);
#endif
OPENSSL_EXPORT void	SSL_SESSION_free(SSL_SESSION *ses);
OPENSSL_EXPORT int	SSL_set_session(SSL *to, SSL_SESSION *session);
OPENSSL_EXPORT int	SSL_CTX_add_session(SSL_CTX *s, SSL_SESSION *c);
OPENSSL_EXPORT int	SSL_CTX_remove_session(SSL_CTX *,SSL_SESSION *c);
OPENSSL_EXPORT int	SSL_CTX_set_generate_session_id(SSL_CTX *, GEN_SESSION_CB);
OPENSSL_EXPORT int	SSL_set_generate_session_id(SSL *, GEN_SESSION_CB);
OPENSSL_EXPORT int	SSL_has_matching_session_id(const SSL *ssl, const unsigned char *id, unsigned int id_len);

/* SSL_SESSION_to_bytes serializes |in| into a newly allocated buffer
 * and sets |*out_data| to that buffer and |*out_len| to its
 * length. The caller takes ownership of the buffer and must call
 * |OPENSSL_free| when done. It returns one on success and zero on
 * error. */
OPENSSL_EXPORT int SSL_SESSION_to_bytes(SSL_SESSION *in, uint8_t **out_data,
                                        size_t *out_len);

/* SSL_SESSION_to_bytes_for_ticket serializes |in|, but excludes the
 * session ID which is not necessary in a session ticket. */
OPENSSL_EXPORT int SSL_SESSION_to_bytes_for_ticket(SSL_SESSION *in,
                                                   uint8_t **out_data,
                                                   size_t *out_len);

/* Deprecated: i2d_SSL_SESSION serializes |in| to the bytes pointed to
 * by |*pp|. On success, it returns the number of bytes written and
 * advances |*pp| by that many bytes. On failure, it returns -1. If
 * |pp| is NULL, no bytes are written and only the length is
 * returned.
 *
 * Use SSL_SESSION_to_bytes instead. */
OPENSSL_EXPORT int i2d_SSL_SESSION(SSL_SESSION *in, uint8_t **pp);

/* d2i_SSL_SESSION deserializes a serialized buffer contained in the
 * |length| bytes pointed to by |*pp|. It returns the new SSL_SESSION
 * and advances |*pp| by the number of bytes consumed on success and
 * NULL on failure. If |a| is NULL, the caller takes ownership of the
 * new session and must call |SSL_SESSION_free| when done.
 *
 * If |a| and |*a| are not NULL, the SSL_SESSION at |*a| is overridden
 * with the deserialized session rather than allocating a new one. In
 * addition, |a| is not NULL, but |*a| is, |*a| is set to the new
 * SSL_SESSION.
 *
 * Passing a value other than NULL to |a| is deprecated. */
OPENSSL_EXPORT SSL_SESSION *d2i_SSL_SESSION(SSL_SESSION **a, const uint8_t **pp,
                                            long length);

OPENSSL_EXPORT X509 *	SSL_get_peer_certificate(const SSL *s);

OPENSSL_EXPORT STACK_OF(X509) *SSL_get_peer_cert_chain(const SSL *s);

OPENSSL_EXPORT int SSL_CTX_get_verify_mode(const SSL_CTX *ctx);
OPENSSL_EXPORT int SSL_CTX_get_verify_depth(const SSL_CTX *ctx);
OPENSSL_EXPORT int (*SSL_CTX_get_verify_callback(const SSL_CTX *ctx))(int,X509_STORE_CTX *);
OPENSSL_EXPORT void SSL_CTX_set_verify(SSL_CTX *ctx,int mode,
			int (*callback)(int, X509_STORE_CTX *));
OPENSSL_EXPORT void SSL_CTX_set_verify_depth(SSL_CTX *ctx,int depth);
OPENSSL_EXPORT void SSL_CTX_set_cert_verify_callback(SSL_CTX *ctx, int (*cb)(X509_STORE_CTX *,void *), void *arg);
OPENSSL_EXPORT void SSL_CTX_set_cert_cb(SSL_CTX *c, int (*cb)(SSL *ssl, void *arg), void *arg);
OPENSSL_EXPORT int SSL_CTX_use_RSAPrivateKey(SSL_CTX *ctx, RSA *rsa);
OPENSSL_EXPORT int SSL_CTX_use_RSAPrivateKey_ASN1(SSL_CTX *ctx, const unsigned char *d, long len);
OPENSSL_EXPORT int SSL_CTX_use_PrivateKey(SSL_CTX *ctx, EVP_PKEY *pkey);
OPENSSL_EXPORT int SSL_CTX_use_PrivateKey_ASN1(int pk,SSL_CTX *ctx,
	const unsigned char *d, long len);
OPENSSL_EXPORT int SSL_CTX_use_certificate(SSL_CTX *ctx, X509 *x);
OPENSSL_EXPORT int SSL_CTX_use_certificate_ASN1(SSL_CTX *ctx, int len, const unsigned char *d);

OPENSSL_EXPORT void SSL_CTX_set_default_passwd_cb(SSL_CTX *ctx, pem_password_cb *cb);
OPENSSL_EXPORT void SSL_CTX_set_default_passwd_cb_userdata(SSL_CTX *ctx, void *u);

OPENSSL_EXPORT int SSL_CTX_check_private_key(const SSL_CTX *ctx);
OPENSSL_EXPORT int SSL_check_private_key(const SSL *ctx);

OPENSSL_EXPORT int	SSL_CTX_set_session_id_context(SSL_CTX *ctx,const unsigned char *sid_ctx, unsigned int sid_ctx_len);

OPENSSL_EXPORT SSL *	SSL_new(SSL_CTX *ctx);
OPENSSL_EXPORT int	SSL_set_session_id_context(SSL *ssl,const unsigned char *sid_ctx, unsigned int sid_ctx_len);

OPENSSL_EXPORT int SSL_CTX_set_purpose(SSL_CTX *s, int purpose);
OPENSSL_EXPORT int SSL_set_purpose(SSL *s, int purpose);
OPENSSL_EXPORT int SSL_CTX_set_trust(SSL_CTX *s, int trust);
OPENSSL_EXPORT int SSL_set_trust(SSL *s, int trust);

OPENSSL_EXPORT int SSL_CTX_set1_param(SSL_CTX *ctx, X509_VERIFY_PARAM *vpm);
OPENSSL_EXPORT int SSL_set1_param(SSL *ssl, X509_VERIFY_PARAM *vpm);

OPENSSL_EXPORT X509_VERIFY_PARAM *SSL_CTX_get0_param(SSL_CTX *ctx);
OPENSSL_EXPORT X509_VERIFY_PARAM *SSL_get0_param(SSL *ssl);

OPENSSL_EXPORT void	SSL_certs_clear(SSL *s);
OPENSSL_EXPORT void	SSL_free(SSL *ssl);
OPENSSL_EXPORT int 	SSL_accept(SSL *ssl);
OPENSSL_EXPORT int 	SSL_connect(SSL *ssl);
OPENSSL_EXPORT int 	SSL_read(SSL *ssl,void *buf,int num);
OPENSSL_EXPORT int 	SSL_peek(SSL *ssl,void *buf,int num);
OPENSSL_EXPORT int 	SSL_write(SSL *ssl,const void *buf,int num);
OPENSSL_EXPORT long	SSL_ctrl(SSL *ssl,int cmd, long larg, void *parg);
OPENSSL_EXPORT long	SSL_callback_ctrl(SSL *, int, void (*)(void));
OPENSSL_EXPORT long	SSL_CTX_ctrl(SSL_CTX *ctx,int cmd, long larg, void *parg);
OPENSSL_EXPORT long	SSL_CTX_callback_ctrl(SSL_CTX *, int, void (*)(void));

OPENSSL_EXPORT int	SSL_get_error(const SSL *s,int ret_code);
/* SSL_get_version returns a string describing the TLS version used by |s|. For
 * example, "TLSv1.2" or "SSLv3". */
OPENSSL_EXPORT const char *SSL_get_version(const SSL *s);
/* SSL_SESSION_get_version returns a string describing the TLS version used by
 * |sess|. For example, "TLSv1.2" or "SSLv3". */
OPENSSL_EXPORT const char *SSL_SESSION_get_version(const SSL_SESSION *sess);

OPENSSL_EXPORT int SSL_CIPHER_is_AES(const SSL_CIPHER *c);
OPENSSL_EXPORT int SSL_CIPHER_has_MD5_HMAC(const SSL_CIPHER *c);
OPENSSL_EXPORT int SSL_CIPHER_is_AESGCM(const SSL_CIPHER *c);
OPENSSL_EXPORT int SSL_CIPHER_is_CHACHA20POLY1305(const SSL_CIPHER *c);

/* This sets the 'default' SSL version that SSL_new() will create */
OPENSSL_EXPORT int SSL_CTX_set_ssl_version(SSL_CTX *ctx, const SSL_METHOD *meth);

OPENSSL_EXPORT const SSL_METHOD *SSLv3_method(void);		/* SSLv3 */
OPENSSL_EXPORT const SSL_METHOD *SSLv3_server_method(void);	/* SSLv3 */
OPENSSL_EXPORT const SSL_METHOD *SSLv3_client_method(void);	/* SSLv3 */

OPENSSL_EXPORT const SSL_METHOD *SSLv23_method(void);	/* SSLv3 but can rollback to v2 */
OPENSSL_EXPORT const SSL_METHOD *SSLv23_server_method(void);	/* SSLv3 but can rollback to v2 */
OPENSSL_EXPORT const SSL_METHOD *SSLv23_client_method(void);	/* SSLv3 but can rollback to v2 */

OPENSSL_EXPORT const SSL_METHOD *TLSv1_method(void);		/* TLSv1.0 */
OPENSSL_EXPORT const SSL_METHOD *TLSv1_server_method(void);	/* TLSv1.0 */
OPENSSL_EXPORT const SSL_METHOD *TLSv1_client_method(void);	/* TLSv1.0 */

OPENSSL_EXPORT const SSL_METHOD *TLSv1_1_method(void);		/* TLSv1.1 */
OPENSSL_EXPORT const SSL_METHOD *TLSv1_1_server_method(void);	/* TLSv1.1 */
OPENSSL_EXPORT const SSL_METHOD *TLSv1_1_client_method(void);	/* TLSv1.1 */

OPENSSL_EXPORT const SSL_METHOD *TLSv1_2_method(void);		/* TLSv1.2 */
OPENSSL_EXPORT const SSL_METHOD *TLSv1_2_server_method(void);	/* TLSv1.2 */
OPENSSL_EXPORT const SSL_METHOD *TLSv1_2_client_method(void);	/* TLSv1.2 */


OPENSSL_EXPORT const SSL_METHOD *DTLSv1_method(void);		/* DTLSv1.0 */
OPENSSL_EXPORT const SSL_METHOD *DTLSv1_server_method(void);	/* DTLSv1.0 */
OPENSSL_EXPORT const SSL_METHOD *DTLSv1_client_method(void);	/* DTLSv1.0 */

OPENSSL_EXPORT const SSL_METHOD *DTLSv1_2_method(void);	/* DTLSv1.2 */
OPENSSL_EXPORT const SSL_METHOD *DTLSv1_2_server_method(void);	/* DTLSv1.2 */
OPENSSL_EXPORT const SSL_METHOD *DTLSv1_2_client_method(void);	/* DTLSv1.2 */

OPENSSL_EXPORT const SSL_METHOD *DTLS_method(void);		/* DTLS 1.0 and 1.2 */
OPENSSL_EXPORT const SSL_METHOD *DTLS_server_method(void);	/* DTLS 1.0 and 1.2 */
OPENSSL_EXPORT const SSL_METHOD *DTLS_client_method(void);	/* DTLS 1.0 and 1.2 */

OPENSSL_EXPORT STACK_OF(SSL_CIPHER) *SSL_get_ciphers(const SSL *s);

OPENSSL_EXPORT int SSL_do_handshake(SSL *s);
OPENSSL_EXPORT int SSL_renegotiate(SSL *s);
OPENSSL_EXPORT int SSL_renegotiate_abbreviated(SSL *s);
OPENSSL_EXPORT int SSL_renegotiate_pending(SSL *s);
OPENSSL_EXPORT int SSL_shutdown(SSL *s);

OPENSSL_EXPORT const SSL_METHOD *SSL_CTX_get_ssl_method(SSL_CTX *ctx);
OPENSSL_EXPORT const SSL_METHOD *SSL_get_ssl_method(SSL *s);
OPENSSL_EXPORT int SSL_set_ssl_method(SSL *s, const SSL_METHOD *method);
OPENSSL_EXPORT const char *SSL_alert_type_string_long(int value);
OPENSSL_EXPORT const char *SSL_alert_type_string(int value);
OPENSSL_EXPORT const char *SSL_alert_desc_string_long(int value);
OPENSSL_EXPORT const char *SSL_alert_desc_string(int value);

OPENSSL_EXPORT void SSL_set_client_CA_list(SSL *s, STACK_OF(X509_NAME) *name_list);
OPENSSL_EXPORT void SSL_CTX_set_client_CA_list(SSL_CTX *ctx, STACK_OF(X509_NAME) *name_list);
OPENSSL_EXPORT STACK_OF(X509_NAME) *SSL_get_client_CA_list(const SSL *s);
OPENSSL_EXPORT STACK_OF(X509_NAME) *SSL_CTX_get_client_CA_list(const SSL_CTX *s);
OPENSSL_EXPORT int SSL_add_client_CA(SSL *ssl,X509 *x);
OPENSSL_EXPORT int SSL_CTX_add_client_CA(SSL_CTX *ctx,X509 *x);

OPENSSL_EXPORT void SSL_set_connect_state(SSL *s);
OPENSSL_EXPORT void SSL_set_accept_state(SSL *s);

OPENSSL_EXPORT long SSL_get_default_timeout(const SSL *s);

OPENSSL_EXPORT int SSL_library_init(void );

OPENSSL_EXPORT const char *SSL_CIPHER_description(const SSL_CIPHER *,char *buf,int size);
OPENSSL_EXPORT STACK_OF(X509_NAME) *SSL_dup_CA_list(STACK_OF(X509_NAME) *sk);

OPENSSL_EXPORT X509 *SSL_get_certificate(const SSL *ssl);
OPENSSL_EXPORT /* EVP_PKEY */ struct evp_pkey_st *SSL_get_privatekey(const SSL *ssl);

OPENSSL_EXPORT X509 *SSL_CTX_get0_certificate(const SSL_CTX *ctx);
OPENSSL_EXPORT EVP_PKEY *SSL_CTX_get0_privatekey(const SSL_CTX *ctx);

OPENSSL_EXPORT void SSL_CTX_set_quiet_shutdown(SSL_CTX *ctx,int mode);
OPENSSL_EXPORT int SSL_CTX_get_quiet_shutdown(const SSL_CTX *ctx);
OPENSSL_EXPORT void SSL_set_quiet_shutdown(SSL *ssl,int mode);
OPENSSL_EXPORT int SSL_get_quiet_shutdown(const SSL *ssl);
OPENSSL_EXPORT void SSL_set_shutdown(SSL *ssl,int mode);
OPENSSL_EXPORT int SSL_get_shutdown(const SSL *ssl);
OPENSSL_EXPORT int SSL_version(const SSL *ssl);
OPENSSL_EXPORT int SSL_CTX_set_default_verify_paths(SSL_CTX *ctx);
OPENSSL_EXPORT int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile,
	const char *CApath);
#define SSL_get0_session SSL_get_session /* just peek at pointer */
OPENSSL_EXPORT SSL_SESSION *SSL_get_session(const SSL *ssl);
OPENSSL_EXPORT SSL_SESSION *SSL_get1_session(SSL *ssl); /* obtain a reference count */
OPENSSL_EXPORT SSL_CTX *SSL_get_SSL_CTX(const SSL *ssl);
OPENSSL_EXPORT SSL_CTX *SSL_set_SSL_CTX(SSL *ssl, SSL_CTX* ctx);
OPENSSL_EXPORT void SSL_set_info_callback(SSL *ssl,
			   void (*cb)(const SSL *ssl,int type,int val));
OPENSSL_EXPORT void (*SSL_get_info_callback(const SSL *ssl))(const SSL *ssl,int type,int val);
OPENSSL_EXPORT int SSL_state(const SSL *ssl);
OPENSSL_EXPORT void SSL_set_state(SSL *ssl, int state);

OPENSSL_EXPORT void SSL_set_verify_result(SSL *ssl,long v);
OPENSSL_EXPORT long SSL_get_verify_result(const SSL *ssl);

OPENSSL_EXPORT int SSL_set_ex_data(SSL *ssl,int idx,void *data);
OPENSSL_EXPORT void *SSL_get_ex_data(const SSL *ssl,int idx);
OPENSSL_EXPORT int SSL_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
	CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);

OPENSSL_EXPORT int SSL_SESSION_set_ex_data(SSL_SESSION *ss,int idx,void *data);
OPENSSL_EXPORT void *SSL_SESSION_get_ex_data(const SSL_SESSION *ss,int idx);
OPENSSL_EXPORT int SSL_SESSION_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
	CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);

OPENSSL_EXPORT int SSL_CTX_set_ex_data(SSL_CTX *ssl,int idx,void *data);
OPENSSL_EXPORT void *SSL_CTX_get_ex_data(const SSL_CTX *ssl,int idx);
OPENSSL_EXPORT int SSL_CTX_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
	CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);

OPENSSL_EXPORT int SSL_get_ex_data_X509_STORE_CTX_idx(void );

#define SSL_CTX_sess_set_cache_size(ctx,t) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_SET_SESS_CACHE_SIZE,t,NULL)
#define SSL_CTX_sess_get_cache_size(ctx) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_GET_SESS_CACHE_SIZE,0,NULL)
#define SSL_CTX_set_session_cache_mode(ctx,m) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_SET_SESS_CACHE_MODE,m,NULL)
#define SSL_CTX_get_session_cache_mode(ctx) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_GET_SESS_CACHE_MODE,0,NULL)

#define SSL_CTX_get_default_read_ahead(ctx) SSL_CTX_get_read_ahead(ctx)
#define SSL_CTX_set_default_read_ahead(ctx,m) SSL_CTX_set_read_ahead(ctx,m)
#define SSL_CTX_get_read_ahead(ctx) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_GET_READ_AHEAD,0,NULL)
#define SSL_CTX_set_read_ahead(ctx,m) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_SET_READ_AHEAD,m,NULL)
#define SSL_CTX_get_max_cert_list(ctx) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_GET_MAX_CERT_LIST,0,NULL)
#define SSL_CTX_set_max_cert_list(ctx,m) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_SET_MAX_CERT_LIST,m,NULL)
#define SSL_get_max_cert_list(ssl) \
	SSL_ctrl(ssl,SSL_CTRL_GET_MAX_CERT_LIST,0,NULL)
#define SSL_set_max_cert_list(ssl,m) \
	SSL_ctrl(ssl,SSL_CTRL_SET_MAX_CERT_LIST,m,NULL)

#define SSL_CTX_set_max_send_fragment(ctx,m) \
	SSL_CTX_ctrl(ctx,SSL_CTRL_SET_MAX_SEND_FRAGMENT,m,NULL)
#define SSL_set_max_send_fragment(ssl,m) \
	SSL_ctrl(ssl,SSL_CTRL_SET_MAX_SEND_FRAGMENT,m,NULL)

     /* NB: the keylength is only applicable when is_export is true */
OPENSSL_EXPORT void SSL_CTX_set_tmp_rsa_callback(SSL_CTX *ctx,
				  RSA *(*cb)(SSL *ssl,int is_export,
					     int keylength));

OPENSSL_EXPORT void SSL_set_tmp_rsa_callback(SSL *ssl,
				  RSA *(*cb)(SSL *ssl,int is_export,
					     int keylength));
OPENSSL_EXPORT void SSL_CTX_set_tmp_dh_callback(SSL_CTX *ctx,
				 DH *(*dh)(SSL *ssl,int is_export,
					   int keylength));
OPENSSL_EXPORT void SSL_set_tmp_dh_callback(SSL *ssl,
				 DH *(*dh)(SSL *ssl,int is_export,
					   int keylength));
OPENSSL_EXPORT void SSL_CTX_set_tmp_ecdh_callback(SSL_CTX *ctx,
				 EC_KEY *(*ecdh)(SSL *ssl,int is_export,
					   int keylength));
OPENSSL_EXPORT void SSL_set_tmp_ecdh_callback(SSL *ssl,
				 EC_KEY *(*ecdh)(SSL *ssl,int is_export,
					   int keylength));

OPENSSL_EXPORT const void *SSL_get_current_compression(SSL *s);
OPENSSL_EXPORT const void *SSL_get_current_expansion(SSL *s);
OPENSSL_EXPORT const char *SSL_COMP_get_name(const void *comp);
OPENSSL_EXPORT void *SSL_COMP_get_compression_methods(void);
OPENSSL_EXPORT int SSL_COMP_add_compression_method(int id,void *cm);

/* TLS extensions functions */
OPENSSL_EXPORT int SSL_set_session_ticket_ext(SSL *s, void *ext_data, int ext_len);

OPENSSL_EXPORT int SSL_set_session_ticket_ext_cb(SSL *s, tls_session_ticket_ext_cb_fn cb, void *arg);

/* Pre-shared secret session resumption functions */
OPENSSL_EXPORT int SSL_set_session_secret_cb(SSL *s, tls_session_secret_cb_fn tls_session_secret_cb, void *arg);

OPENSSL_EXPORT void SSL_set_debug(SSL *s, int debug);
OPENSSL_EXPORT int SSL_cache_hit(SSL *s);
OPENSSL_EXPORT int SSL_is_server(SSL *s);

/* SSL_get_structure_sizes returns the sizes of the SSL, SSL_CTX and
 * SSL_SESSION structures so that a test can ensure that outside code agrees on
 * these values. */
OPENSSL_EXPORT void SSL_get_structure_sizes(size_t* ssl_size, size_t* ssl_ctx_size, size_t* ssl_session_size);

OPENSSL_EXPORT SSL_CONF_CTX *SSL_CONF_CTX_new(void);
OPENSSL_EXPORT int SSL_CONF_CTX_finish(SSL_CONF_CTX *cctx);
OPENSSL_EXPORT void SSL_CONF_CTX_free(SSL_CONF_CTX *cctx);
OPENSSL_EXPORT unsigned int SSL_CONF_CTX_set_flags(SSL_CONF_CTX *cctx, unsigned int flags);
OPENSSL_EXPORT unsigned int SSL_CONF_CTX_clear_flags(SSL_CONF_CTX *cctx, unsigned int flags);
OPENSSL_EXPORT int SSL_CONF_CTX_set1_prefix(SSL_CONF_CTX *cctx, const char *pre);

OPENSSL_EXPORT void SSL_CONF_CTX_set_ssl(SSL_CONF_CTX *cctx, SSL *ssl);
OPENSSL_EXPORT void SSL_CONF_CTX_set_ssl_ctx(SSL_CONF_CTX *cctx, SSL_CTX *ctx);

OPENSSL_EXPORT int SSL_CONF_cmd(SSL_CONF_CTX *cctx, const char *cmd, const char *value);
OPENSSL_EXPORT int SSL_CONF_cmd_argv(SSL_CONF_CTX *cctx, int *pargc, char ***pargv);
OPENSSL_EXPORT int SSL_CONF_cmd_value_type(SSL_CONF_CTX *cctx, const char *cmd);

#ifndef OPENSSL_NO_SSL_TRACE
OPENSSL_EXPORT void SSL_trace(int write_p, int version, int content_type,
		const void *buf, size_t len, SSL *ssl, void *arg);
OPENSSL_EXPORT const char *SSL_CIPHER_standard_name(const SSL_CIPHER *c);
#endif

OPENSSL_EXPORT void ERR_load_SSL_strings(void);


#ifdef  __cplusplus
}
#endif

/* BEGIN ERROR CODES */
/* The following lines are auto generated by the script make_errors.go. Any
 * changes made after this point may be overwritten when the script is next run.
 */
#define SSL_F_SSL_use_PrivateKey_file 100
#define SSL_F_dtls1_write_app_data_bytes 101
#define SSL_F_ssl_cipher_process_rulestr 102
#define SSL_F_SSL_set_session_id_context 103
#define SSL_F_SSL_read 104
#define SSL_F_ssl_cert_new 105
#define SSL_F_dtls1_heartbeat 106
#define SSL_F_ssl3_digest_cached_records 107
#define SSL_F_SSL_set_wfd 108
#define SSL_F_ssl_set_pkey 110
#define SSL_F_SSL_CTX_use_certificate 111
#define SSL_F_dtls1_read_bytes 112
#define SSL_F_ssl23_write 113
#define SSL_F_ssl3_check_client_hello 114
#define SSL_F_SSL_use_certificate_ASN1 115
#define SSL_F_ssl_verify_cert_chain 116
#define SSL_F_ssl_parse_serverhello_renegotiate_ext 117
#define SSL_F_ssl_undefined_const_function 118
#define SSL_F_ssl3_get_server_certificate 119
#define SSL_F_tls1_get_server_supplemental_data 120
#define SSL_F_dtls1_buffer_record 121
#define SSL_F_ssl_prepare_clienthello_tlsext 122
#define SSL_F_ssl3_get_server_hello 123
#define SSL_F_ssl3_send_client_key_exchange 124
#define SSL_F_ssl3_write_bytes 125
#define SSL_F_SSL_use_RSAPrivateKey_file 126
#define SSL_F_ssl_bad_method 127
#define SSL_F_ssl3_connect 128
#define SSL_F_dtls1_connect 129
#define SSL_F_SSL_use_RSAPrivateKey 130
#define SSL_F_tls1_PRF 131
#define SSL_F_ssl_bytes_to_cipher_list 132
#define SSL_F_ssl3_do_change_cipher_spec 133
#define SSL_F_SSL_SESSION_set1_id_context 134
#define SSL_F_ssl_add_serverhello_tlsext 135
#define SSL_F_read_authz 136
#define SSL_F_ssl3_get_client_hello 137
#define SSL_F_ssl3_get_certificate_request 138
#define SSL_F_authz_find_data 139
#define SSL_F_ssl_add_cert_to_buf 140
#define SSL_F_ssl_add_serverhello_renegotiate_ext 141
#define SSL_F_ssl3_get_message 142
#define SSL_F_ssl_check_srvr_ecc_cert_and_alg 143
#define SSL_F_ssl_parse_clienthello_tlsext 144
#define SSL_F_SSL_add_file_cert_subjects_to_stack 145
#define SSL_F_ssl3_ctx_ctrl 146
#define SSL_F_ssl3_get_record 147
#define SSL_F_SSL_CTX_use_RSAPrivateKey 148
#define SSL_F_SSL_use_certificate_file 149
#define SSL_F_SSL_load_client_CA_file 151
#define SSL_F_dtls1_preprocess_fragment 152
#define SSL_F_SSL_CTX_check_private_key 153
#define SSL_F_ssl3_get_cert_status 154
#define SSL_F_printf 155
#define SSL_F_SSL_CTX_new 156
#define SSL_F_ssl23_accept 157
#define SSL_F_SSL_use_authz 158
#define SSL_F_ssl_undefined_function 159
#define SSL_F_dtls1_send_hello_verify_request 160
#define SSL_F_ssl_build_cert_chain 161
#define SSL_F_SSL_SESSION_print_fp 162
#define SSL_F_tls1_change_cipher_state 163
#define SSL_F_tls12_check_peer_sigalg 164
#define SSL_F_ssl_sess_cert_new 165
#define SSL_F_ssl3_read_bytes 166
#define SSL_F_dtls1_get_hello_verify 167
#define SSL_F_tls1_cert_verify_mac 168
#define SSL_F_ssl23_client_hello 169
#define SSL_F_SSL_shutdown 170
#define SSL_F_ssl_init_wbio_buffer 171
#define SSL_F_SSL_use_certificate 172
#define SSL_F_SSL_CTX_use_RSAPrivateKey_ASN1 173
#define SSL_F_ssl_set_authz 174
#define SSL_F_ssl23_peek 175
#define SSL_F_SSL_use_psk_identity_hint 176
#define SSL_F_ssl3_get_cert_verify 177
#define SSL_F_ssl_ctx_make_profiles 178
#define SSL_F_ssl_add_clienthello_use_srtp_ext 179
#define SSL_F_ssl3_get_client_key_exchange 180
#define SSL_F_do_ssl3_write 181
#define SSL_F_ssl3_handshake_mac 182
#define SSL_F_tls1_setup_key_block 183
#define SSL_F_SSL_set_fd 184
#define SSL_F_SSL_check_private_key 185
#define SSL_F_ssl3_send_cert_verify 186
#define SSL_F_ssl3_write_pending 187
#define SSL_F_ssl_cert_inst 188
#define SSL_F_ssl3_change_cipher_state 189
#define SSL_F_ssl23_get_server_hello 190
#define SSL_F_SSL_write 191
#define SSL_F_ssl_get_sign_pkey 192
#define SSL_F_ssl_set_cert 193
#define SSL_F_SSL_CTX_use_RSAPrivateKey_file 194
#define SSL_F_SSL_CTX_use_authz 195
#define SSL_F_ssl_get_new_session 196
#define SSL_F_SSL_set_session_ticket_ext 197
#define SSL_F_ssl_add_clienthello_renegotiate_ext 198
#define SSL_F_ssl3_send_server_key_exchange 199
#define SSL_F_fprintf 200
#define SSL_F_ssl3_get_new_session_ticket 201
#define SSL_F_SSL_CTX_use_certificate_ASN1 202
#define SSL_F_ssl_add_cert_chain 203
#define SSL_F_ssl_create_cipher_list 204
#define SSL_F_ssl3_callback_ctrl 205
#define SSL_F_SSL_CTX_set_cipher_list 206
#define SSL_F_ssl3_send_certificate_request 207
#define SSL_F_SSL_use_PrivateKey_ASN1 208
#define SSL_F_SSL_CTX_use_certificate_chain_file 209
#define SSL_F_SSL_SESSION_new 210
#define SSL_F_check_suiteb_cipher_list 211
#define SSL_F_ssl_scan_clienthello_tlsext 212
#define SSL_F_ssl3_send_client_hello 213
#define SSL_F_SSL_use_RSAPrivateKey_ASN1 214
#define SSL_F_ssl3_ctrl 215
#define SSL_F_ssl3_setup_write_buffer 216
#define SSL_F_ssl_parse_serverhello_use_srtp_ext 217
#define SSL_F_ssl3_get_server_key_exchange 218
#define SSL_F_ssl3_send_server_hello 219
#define SSL_F_SSL_add_dir_cert_subjects_to_stack 220
#define SSL_F_ssl_check_serverhello_tlsext 221
#define SSL_F_ssl3_get_server_done 222
#define SSL_F_ssl3_check_cert_and_algorithm 223
#define SSL_F_do_dtls1_write 224
#define SSL_F_dtls1_check_timeout_num 225
#define SSL_F_tls1_export_keying_material 226
#define SSL_F_SSL_CTX_set_session_id_context 227
#define SSL_F_SSL_set_rfd 228
#define SSL_F_ssl3_send_client_certificate 229
#define SSL_F_ssl_cert_dup 230
#define SSL_F_dtls1_process_record 231
#define SSL_F_ssl_new 232
#define SSL_F_ssl_get_server_cert_index 233
#define SSL_F_tls1_send_server_supplemental_data 234
#define SSL_F_D2I_SSL_SESSION 235
#define SSL_F_ssl_cipher_strength_sort 236
#define SSL_F_dtls1_get_message 237
#define SSL_F_ssl23_connect 238
#define SSL_F_tls1_heartbeat 239
#define SSL_F_ssl3_read_n 240
#define SSL_F_ssl_get_prev_session 241
#define SSL_F_ssl_parse_clienthello_renegotiate_ext 242
#define SSL_F_ssl3_setup_read_buffer 243
#define SSL_F_SSL_CTX_set_ssl_version 244
#define SSL_F_SSL_peek 245
#define SSL_F_ssl3_send_server_certificate 246
#define SSL_F_SSL_do_handshake 247
#define SSL_F_ssl_undefined_void_function 248
#define SSL_F_ssl_add_serverhello_use_srtp_ext 249
#define SSL_F_fclose 250
#define SSL_F_SSL_use_PrivateKey 251
#define SSL_F_SSL_CTX_use_certificate_file 252
#define SSL_F_SSL_CTX_use_PrivateKey 253
#define SSL_F_SSL_set_session 254
#define SSL_F_SSL_CTX_use_psk_identity_hint 255
#define SSL_F_ssl_scan_serverhello_tlsext 256
#define SSL_F_ssl23_read 257
#define SSL_F_ssl_parse_clienthello_use_srtp_ext 258
#define SSL_F_ssl3_accept 259
#define SSL_F_ssl3_get_client_certificate 260
#define SSL_F_SSL_CTX_use_PrivateKey_ASN1 261
#define SSL_F_dtls1_get_message_fragment 262
#define SSL_F_SSL_clear 263
#define SSL_F_dtls1_accept 264
#define SSL_F_ssl3_get_next_proto 265
#define SSL_F_SSL_set_cipher_list 266
#define SSL_F_ssl_add_clienthello_tlsext 267
#define SSL_F_ssl23_get_client_hello 268
#define SSL_F_SSL_CTX_use_PrivateKey_file 269
#define SSL_F_ssl3_get_finished 270
#define SSL_F_ssl3_generate_key_block 271
#define SSL_F_ssl3_setup_key_block 272
#define SSL_F_SSL_new 273
#define SSL_F_ssl_parse_serverhello_tlsext 274
#define SSL_F_ssl3_get_channel_id 275
#define SSL_F_ssl3_send_channel_id 276
#define SSL_F_SSL_CTX_set_cipher_list_tls11 277
#define SSL_F_tls1_change_cipher_state_cipher 278
#define SSL_F_tls1_change_cipher_state_aead 279
#define SSL_F_tls1_aead_ctx_init 280
#define SSL_F_tls1_check_duplicate_extensions 281
#define SSL_F_ssl3_expect_change_cipher_spec 282
#define SSL_F_ssl23_get_v2_client_hello 283
#define SSL_F_ssl3_cert_verify_hash 284
#define SSL_F_ssl_ctx_log_rsa_client_key_exchange 285
#define SSL_F_ssl_ctx_log_master_secret 286
#define SSL_F_d2i_SSL_SESSION 287
#define SSL_F_i2d_SSL_SESSION 288
#define SSL_F_d2i_SSL_SESSION_get_octet_string 289
#define SSL_F_d2i_SSL_SESSION_get_string 290
#define SSL_F_ssl3_send_new_session_ticket 291
#define SSL_F_SSL_SESSION_to_bytes_full 292
#define SSL_R_UNABLE_TO_FIND_ECDH_PARAMETERS 100
#define SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC 101
#define SSL_R_INVALID_NULL_CMD_NAME 102
#define SSL_R_BAD_RSA_DECRYPT 103
#define SSL_R_NO_SHARED_CIPHER 104
#define SSL_R_BAD_PSK_IDENTITY_HINT_LENGTH 105
#define SSL_R_SSL_HANDSHAKE_FAILURE 106
#define SSL_R_INVALID_TICKET_KEYS_LENGTH 107
#define SSL_R_PEER_ERROR 108
#define SSL_R_ECC_CERT_NOT_FOR_SIGNING 109
#define SSL_R_INCONSISTENT_COMPRESSION 110
#define SSL_R_BAD_HELLO_REQUEST 111
#define SSL_R_NULL_SSL_METHOD_PASSED 112
#define SSL_R_X509_VERIFICATION_SETUP_PROBLEMS 113
#define SSL_R_BAD_ECDSA_SIGNATURE 114
#define SSL_R_GOT_NEXT_PROTO_WITHOUT_EXTENSION 115
#define SSL_R_BAD_DH_PUB_KEY_LENGTH 116
#define SSL_R_COMPRESSED_LENGTH_TOO_LONG 117
#define SSL_R_APP_DATA_IN_HANDSHAKE 118
#define SSL_R_NO_PEM_EXTENSIONS 119
#define SSL_R_BAD_SRP_B_LENGTH 120
#define SSL_R_SSL_SESSION_ID_CONTEXT_TOO_LONG 121
#define SSL_R_UNABLE_TO_DECODE_DH_CERTS 122
#define SSL_R_MISSING_SRP_PARAM 123
#define SSL_R_MISSING_RSA_SIGNING_CERT 124
#define SSL_R_MISSING_DSA_SIGNING_CERT 125
#define SSL_R_ONLY_TLS_1_2_ALLOWED_IN_SUITEB_MODE 126
#define SSL_R_UNEXPECTED_RECORD 127
#define SSL_R_BAD_DIGEST_LENGTH 128
#define SSL_R_READ_TIMEOUT_EXPIRED 129
#define SSL_R_KRB5_C_GET_CRED 130
#define SSL_R_NULL_SSL_CTX 131
#define SSL_R_ERROR_GENERATING_TMP_RSA_KEY 134
#define SSL_R_SSL3_SESSION_ID_TOO_LONG 135
#define SSL_R_BAD_DATA_RETURNED_BY_CALLBACK 136
#define SSL_R_REUSE_CERT_LENGTH_NOT_ZERO 137
#define SSL_R_COOKIE_MISMATCH 139
#define SSL_R_UNINITIALIZED 140
#define SSL_R_BAD_CHANGE_CIPHER_SPEC 141
#define SSL_R_UNABLE_TO_LOAD_SSL3_SHA1_ROUTINES 142
#define SSL_R_BAD_SRP_G_LENGTH 143
#define SSL_R_NO_CERTIFICATE_ASSIGNED 144
#define SSL_R_UNABLE_TO_FIND_PUBLIC_KEY_PARAMETERS 145
#define SSL_R_PEM_NAME_TOO_SHORT 146
#define SSL_R_PROTOCOL_IS_SHUTDOWN 148
#define SSL_R_UNABLE_TO_FIND_SSL_METHOD 149
#define SSL_R_WRONG_MESSAGE_TYPE 150
#define SSL_R_BAD_RSA_MODULUS_LENGTH 151
#define SSL_R_PUBLIC_KEY_IS_NOT_RSA 152
#define SSL_R_COMPRESSION_ID_NOT_WITHIN_PRIVATE_RANGE 153
#define SSL_R_NO_CLIENT_CERT_RECEIVED 154
#define SSL_R_TLS_INVALID_ECPOINTFORMAT_LIST 155
#define SSL_R_CERT_LENGTH_MISMATCH 156
#define SSL_R_MISSING_EXPORT_TMP_DH_KEY 157
#define SSL_R_DUPLICATE_COMPRESSION_ID 158
#define SSL_R_SSL3_EXT_INVALID_ECPOINTFORMAT 159
#define SSL_R_REUSE_CIPHER_LIST_NOT_ZERO 160
#define SSL_R_DATA_LENGTH_TOO_LONG 161
#define SSL_R_ECGROUP_TOO_LARGE_FOR_CIPHER 162
#define SSL_R_WRONG_SIGNATURE_LENGTH 163
#define SSL_R_SSL2_CONNECTION_ID_TOO_LONG 164
#define SSL_R_WRONG_VERSION_NUMBER 165
#define SSL_R_RECORD_TOO_LARGE 166
#define SSL_R_BIO_NOT_SET 167
#define SSL_R_SRTP_COULD_NOT_ALLOCATE_PROFILES 168
#define SSL_R_UNKNOWN_PKEY_TYPE 170
#define SSL_R_CIPHER_CODE_WRONG_LENGTH 171
#define SSL_R_SSL_SESSION_ID_CONFLICT 172
#define SSL_R_INVALID_COMMAND 173
#define SSL_R_NO_PROTOCOLS_AVAILABLE 174
#define SSL_R_ERROR_IN_RECEIVED_CIPHER_LIST 175
#define SSL_R_LIBRARY_BUG 176
#define SSL_R_UNSUPPORTED_CIPHER 177
#define SSL_R_REUSE_CERT_TYPE_NOT_ZERO 178
#define SSL_R_WRONG_SIGNATURE_TYPE 179
#define SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST 180
#define SSL_R_PSK_NO_SERVER_CB 181
#define SSL_R_BLOCK_CIPHER_PAD_IS_WRONG 182
#define SSL_R_INVALID_TRUST 183
#define SSL_R_PARSE_TLSEXT 184
#define SSL_R_NO_SRTP_PROFILES 185
#define SSL_R_UNSUPPORTED_ELLIPTIC_CURVE 186
#define SSL_R_UNKNOWN_STATE 187
#define SSL_R_UNKNOWN_CERTIFICATE_TYPE 188
#define SSL_R_WRONG_CIPHER_RETURNED 189
#define SSL_R_BAD_DH_G_LENGTH 190
#define SSL_R_BAD_ALERT_RECORD 191
#define SSL_R_CIPHER_TABLE_SRC_ERROR 192
#define SSL_R_UNKNOWN_REMOTE_ERROR_TYPE 194
#define SSL_R_SSL3_EXT_INVALID_SERVERNAME_TYPE 195
#define SSL_R_MESSAGE_TOO_LONG 196
#define SSL_R_BAD_RSA_SIGNATURE 197
#define SSL_R_X509_LIB 198
#define SSL_R_BAD_SRP_N_LENGTH 199
#define SSL_R_BAD_SSL_SESSION_ID_LENGTH 200
#define SSL_R_UNKNOWN_CIPHER_TYPE 201
#define SSL_R_BAD_DH_P_LENGTH 202
#define SSL_R_MISSING_DH_RSA_CERT 203
#define SSL_R_NO_METHOD_SPECIFIED 204
#define SSL_R_EMPTY_SRTP_PROTECTION_PROFILE_LIST 205
#define SSL_R_MULTIPLE_SGC_RESTARTS 206
#define SSL_R_UNABLE_TO_DECODE_ECDH_CERTS 207
#define SSL_R_ATTEMPT_TO_REUSE_SESSION_IN_DIFFERENT_CONTEXT 208
#define SSL_R_SSL3_EXT_INVALID_SERVERNAME 209
#define SSL_R_BAD_SRP_S_LENGTH 210
#define SSL_R_MISSING_TMP_RSA_KEY 211
#define SSL_R_PSK_NO_CLIENT_CB 212
#define SSL_R_PEM_NAME_BAD_PREFIX 213
#define SSL_R_BAD_CHECKSUM 214
#define SSL_R_NO_CIPHER_MATCH 216
#define SSL_R_MISSING_TMP_DH_KEY 217
#define SSL_R_UNSUPPORTED_STATUS_TYPE 218
#define SSL_R_UNKNOWN_AUTHZ_DATA_TYPE 219
#define SSL_R_CONNECTION_TYPE_NOT_SET 220
#define SSL_R_MISSING_DH_KEY 221
#define SSL_R_CHANNEL_ID_NOT_P256 222
#define SSL_R_UNKNOWN_SUPPLEMENTAL_DATA_TYPE 223
#define SSL_R_UNKNOWN_PROTOCOL 224
#define SSL_R_DATA_BETWEEN_CCS_AND_FINISHED 225
#define SSL_R_KRB5_S_TKT_SKEW 226
#define SSL_R_PUBLIC_KEY_NOT_RSA 227
#define SSL_R_SCSV_RECEIVED_WHEN_RENEGOTIATING 228
#define SSL_R_GOST_NOT_SUPPORTED 229
#define SSL_R_KRB5_C_CC_PRINC 230
#define SSL_R_INVALID_PURPOSE 234
#define SSL_R_KRB5_C_MK_REQ 235
#define SSL_R_BAD_SRTP_MKI_VALUE 237
#define SSL_R_EVP_DIGESTSIGNINIT_FAILED 238
#define SSL_R_DIGEST_CHECK_FAILED 239
#define SSL_R_BAD_SRP_A_LENGTH 240
#define SSL_R_SERVERHELLO_TLSEXT 241
#define SSL_R_TLS_RSA_ENCRYPTED_VALUE_LENGTH_IS_WRONG 242
#define SSL_R_NO_CIPHERS_AVAILABLE 243
#define SSL_R_COMPRESSION_FAILURE 244
#define SSL_R_SSL_CTX_HAS_NO_DEFAULT_SSL_VERSION 245
#define SSL_R_OLD_SESSION_CIPHER_NOT_RETURNED 246
#define SSL_R_BAD_RSA_ENCRYPT 247
#define SSL_R_EXCESSIVE_MESSAGE_SIZE 248
#define SSL_R_INVALID_COMPRESSION_ALGORITHM 249
#define SSL_R_SHORT_READ 250
#define SSL_R_CA_DN_LENGTH_MISMATCH 252
#define SSL_R_BAD_ECC_CERT 253
#define SSL_R_NON_SSLV2_INITIAL_PACKET 254
#define SSL_R_SSL_SESSION_ID_IS_DIFFERENT 255
#define SSL_R_MISSING_TMP_RSA_PKEY 256
#define SSL_R_BN_LIB 257
#define SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE 258
#define SSL_R_MISSING_RSA_ENCRYPTING_CERT 259
#define SSL_R_NO_RENEGOTIATION 260
#define SSL_R_NO_COMPRESSION_SPECIFIED 261
#define SSL_R_WRONG_CERTIFICATE_TYPE 262
#define SSL_R_CHANNEL_ID_SIGNATURE_INVALID 264
#define SSL_R_READ_BIO_NOT_SET 265
#define SSL_R_SSL23_DOING_SESSION_ID_REUSE 266
#define SSL_R_RENEGOTIATE_EXT_TOO_LONG 267
#define SSL_R_INVALID_CHALLENGE_LENGTH 268
#define SSL_R_LIBRARY_HAS_NO_CIPHERS 270
#define SSL_R_WRONG_CURVE 271
#define SSL_R_SESSION_ID_CONTEXT_UNINITIALIZED 272
#define SSL_R_ECC_CERT_NOT_FOR_KEY_AGREEMENT 275
#define SSL_R_MISSING_RSA_CERTIFICATE 276
#define SSL_R_NO_P256_SUPPORT 277
#define SSL_R_UNSUPPORTED_COMPRESSION_ALGORITHM 278
#define SSL_R_INVALID_SERVERINFO_DATA 279
#define SSL_R_GOT_CHANNEL_ID_BEFORE_A_CCS 280
#define SSL_R_DH_PUBLIC_VALUE_LENGTH_IS_WRONG 281
#define SSL_R_KRB5_S_BAD_TICKET 282
#define SSL_R_EVP_DIGESTSIGNFINAL_FAILED 283
#define SSL_R_PACKET_LENGTH_TOO_LONG 284
#define SSL_R_BAD_STATE 285
#define SSL_R_USE_SRTP_NOT_NEGOTIATED 286
#define SSL_R_BAD_RSA_E_LENGTH 287
#define SSL_R_ILLEGAL_PADDING 288
#define SSL_R_SIGNATURE_FOR_NON_SIGNING_CERTIFICATE 289
#define SSL_R_BAD_VALUE 290
#define SSL_R_ECC_CERT_SHOULD_HAVE_RSA_SIGNATURE 291
#define SSL_R_COMPRESSION_DISABLED 292
#define SSL_R_BAD_DECOMPRESSION 293
#define SSL_R_CHALLENGE_IS_DIFFERENT 294
#define SSL_R_NO_CLIENT_CERT_METHOD 295
#define SSL_R_SRTP_PROTECTION_PROFILE_LIST_TOO_LONG 296
#define SSL_R_INVALID_MESSAGE 297
#define SSL_R_HTTPS_PROXY_REQUEST 298
#define SSL_R_AUTHZ_DATA_TOO_LARGE 299
#define SSL_R_KRB5_S_TKT_EXPIRED 300
#define SSL_R_NO_CERTIFICATE_SPECIFIED 301
#define SSL_R_ECC_CERT_SHOULD_HAVE_SHA1_SIGNATURE 302
#define SSL_R_TLS_PEER_DID_NOT_RESPOND_WITH_CERTIFICATE_LIST 303
#define SSL_R_INVALID_STATUS_RESPONSE 304
#define SSL_R_TLS_ILLEGAL_EXPORTER_LABEL 305
#define SSL_R_ONLY_DTLS_1_2_ALLOWED_IN_SUITEB_MODE 306
#define SSL_R_MISSING_TMP_ECDH_KEY 307
#define SSL_R_CERTIFICATE_VERIFY_FAILED 308
#define SSL_R_TRIED_TO_USE_UNSUPPORTED_CIPHER 309
#define SSL_R_RENEGOTIATION_ENCODING_ERR 310
#define SSL_R_NO_PRIVATEKEY 311
#define SSL_R_READ_WRONG_PACKET_TYPE 313
#define SSL_R_SSL3_SESSION_ID_TOO_SHORT 314
#define SSL_R_UNABLE_TO_LOAD_SSL2_MD5_ROUTINES 315
#define SSL_R_GOT_NEXT_PROTO_BEFORE_A_CCS 316
#define SSL_R_HTTP_REQUEST 317
#define SSL_R_KRB5_S_INIT 318
#define SSL_R_RECORD_LENGTH_MISMATCH 320
#define SSL_R_BAD_LENGTH 321
#define SSL_R_NO_REQUIRED_DIGEST 322
#define SSL_R_KRB5 323
#define SSL_R_CCS_RECEIVED_EARLY 325
#define SSL_R_MISSING_ECDSA_SIGNING_CERT 326
#define SSL_R_D2I_ECDSA_SIG 327
#define SSL_R_PATH_TOO_LONG 328
#define SSL_R_CIPHER_OR_HASH_UNAVAILABLE 329
#define SSL_R_UNSUPPORTED_DIGEST_TYPE 330
#define SSL_R_OLD_SESSION_COMPRESSION_ALGORITHM_NOT_RETURNED 331
#define SSL_R_PEER_ERROR_CERTIFICATE 332
#define SSL_R_UNABLE_TO_FIND_DH_PARAMETERS 333
#define SSL_R_NO_CERTIFICATE_SET 334
#define SSL_R_SSL_SESSION_ID_CALLBACK_FAILED 335
#define SSL_R_NO_CERTIFICATES_RETURNED 337
#define SSL_R_BAD_WRITE_RETRY 338
#define SSL_R_BAD_SSL_FILETYPE 339
#define SSL_R_SRTP_UNKNOWN_PROTECTION_PROFILE 340
#define SSL_R_NO_CIPHERS_SPECIFIED 341
#define SSL_R_LENGTH_MISMATCH 342
#define SSL_R_NO_CIPHERS_PASSED 343
#define SSL_R_NO_VERIFY_CALLBACK 344
#define SSL_R_PEER_ERROR_UNSUPPORTED_CERTIFICATE_TYPE 345
#define SSL_R_WRONG_NUMBER_OF_KEY_BITS 347
#define SSL_R_UNEXPECTED_MESSAGE 348
#define SSL_R_MISSING_DH_DSA_CERT 349
#define SSL_R_SSL_SESSION_ID_HAS_BAD_LENGTH 350
#define SSL_R_OPAQUE_PRF_INPUT_TOO_LONG 351
#define SSL_R_UNABLE_TO_LOAD_SSL3_MD5_ROUTINES 352
#define SSL_R_ILLEGAL_SUITEB_DIGEST 353
#define SSL_R_NO_SHARED_SIGATURE_ALGORITHMS 354
#define SSL_R_CLIENTHELLO_TLSEXT 355
#define SSL_R_INVALID_AUTHZ_DATA 356
#define SSL_R_BAD_RESPONSE_ARGUMENT 357
#define SSL_R_PUBLIC_KEY_ENCRYPT_ERROR 358
#define SSL_R_REQUIRED_CIPHER_MISSING 359
#define SSL_R_INVALID_AUDIT_PROOF 360
#define SSL_R_PSK_IDENTITY_NOT_FOUND 361
#define SSL_R_UNKNOWN_ALERT_TYPE 362
#define SSL_R_NO_GOST_CERTIFICATE_SENT_BY_PEER 363
#define SSL_R_BAD_AUTHENTICATION_TYPE 365
#define SSL_R_DECRYPTION_FAILED 366
#define SSL_R_WRONG_SSL_VERSION 367
#define SSL_R_NO_CERTIFICATE_RETURNED 368
#define SSL_R_CA_DN_TOO_LONG 370
#define SSL_R_GOT_A_FIN_BEFORE_A_CCS 371
#define SSL_R_COMPRESSION_LIBRARY_ERROR 372
#define SSL_R_SSL_LIBRARY_HAS_NO_CIPHERS 374
#define SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED 375
#define SSL_R_BAD_ECPOINT 376
#define SSL_R_BAD_HANDSHAKE_LENGTH 377
#define SSL_R_KRB5_S_RD_REQ 380
#define SSL_R_PEER_ERROR_NO_CERTIFICATE 381
#define SSL_R_PRE_MAC_LENGTH_TOO_LONG 382
#define SSL_R_PROBLEMS_MAPPING_CIPHER_FUNCTIONS 383
#define SSL_R_UNKNOWN_DIGEST 384
#define SSL_R_WRONG_SIGNATURE_SIZE 385
#define SSL_R_SIGNATURE_ALGORITHMS_ERROR 386
#define SSL_R_REQUIRED_COMPRESSSION_ALGORITHM_MISSING 387
#define SSL_R_BAD_SIGNATURE 388
#define SSL_R_BAD_PACKET_LENGTH 389
#define SSL_R_CANNOT_SERIALIZE_PUBLIC_KEY 390
#define SSL_R_RENEGOTIATION_MISMATCH 391
#define SSL_R_BAD_MAC_LENGTH 392
#define SSL_R_NO_PUBLICKEY 393
#define SSL_R_UNKNOWN_KEY_EXCHANGE_TYPE 394
#define SSL_R_BAD_MAC_DECODE 395
#define SSL_R_NO_PRIVATE_KEY_ASSIGNED 396
#define SSL_R_EXTRA_DATA_IN_MESSAGE 397
#define SSL_R_TLS_CLIENT_CERT_REQ_WITH_ANON_CIPHER 398
#define SSL_R_CONNECTION_ID_IS_DIFFERENT 399
#define SSL_R_MISSING_VERIFY_MESSAGE 402
#define SSL_R_BAD_DSA_SIGNATURE 403
#define SSL_R_UNKNOWN_SSL_VERSION 404
#define SSL_R_KEY_ARG_TOO_LONG 405
#define SSL_R_KRB5_C_INIT 406
#define SSL_R_NO_CIPHER_LIST 407
#define SSL_R_PEER_ERROR_NO_CIPHER 408
#define SSL_R_UNKNOWN_CMD_NAME 409
#define SSL_R_UNKNOWN_CIPHER_RETURNED 410
#define SSL_R_RECORD_TOO_SMALL 411
#define SSL_R_ENCRYPTED_LENGTH_TOO_LONG 412
#define SSL_R_UNSUPPORTED_SSL_VERSION 413
#define SSL_R_UNABLE_TO_EXTRACT_PUBLIC_KEY 415
#define SSL_R_MISSING_EXPORT_TMP_RSA_KEY 416
#define SSL_R_BAD_DATA 417
#define SSL_R_KRB5_S_TKT_NYV 418
#define SSL_R_BAD_PROTOCOL_VERSION_NUMBER 420
#define SSL_R_BAD_MESSAGE_TYPE 421
#define SSL_R_MISSING_ECDH_CERT 422
#define SSL_R_UNSUPPORTED_PROTOCOL 423
#define SSL_R_SRP_A_CALC 424
#define SSL_R_WRITE_BIO_NOT_SET 425
#define SSL_R_ONLY_TLS_ALLOWED_IN_FIPS_MODE 426
#define SSL_R_LENGTH_TOO_SHORT 427
#define SSL_R_CERT_CB_ERROR 428
#define SSL_R_DTLS_MESSAGE_TOO_BIG 429
#define SSL_R_INVALID_SRP_USERNAME 430
#define SSL_R_TOO_MANY_EMPTY_FRAGMENTS 431
#define SSL_R_NESTED_GROUP 432
#define SSL_R_UNEXPECTED_GROUP_CLOSE 433
#define SSL_R_UNEXPECTED_OPERATOR_IN_GROUP 434
#define SSL_R_MIXED_SPECIAL_OPERATOR_WITH_GROUPS 435
#define SSL_R_INAPPROPRIATE_FALLBACK 436
#define SSL_R_CLIENTHELLO_PARSE_FAILED 437
#define SSL_R_CONNECTION_REJECTED 438
#define SSL_R_DECODE_ERROR 439
#define SSL_R_UNPROCESSED_HANDSHAKE_DATA 440
#define SSL_R_HANDSHAKE_RECORD_BEFORE_CCS 441
#define SSL_R_SESSION_MAY_NOT_BE_CREATED 442
#define SSL_R_INVALID_SSL_SESSION 443
#define SSL_R_SSLV3_ALERT_CLOSE_NOTIFY 1000
#define SSL_R_SSLV3_ALERT_UNEXPECTED_MESSAGE 1010
#define SSL_R_SSLV3_ALERT_BAD_RECORD_MAC 1020
#define SSL_R_TLSV1_ALERT_DECRYPTION_FAILED 1021
#define SSL_R_TLSV1_ALERT_RECORD_OVERFLOW 1022
#define SSL_R_SSLV3_ALERT_DECOMPRESSION_FAILURE 1030
#define SSL_R_SSLV3_ALERT_HANDSHAKE_FAILURE 1040
#define SSL_R_SSLV3_ALERT_NO_CERTIFICATE 1041
#define SSL_R_SSLV3_ALERT_BAD_CERTIFICATE 1042
#define SSL_R_SSLV3_ALERT_UNSUPPORTED_CERTIFICATE 1043
#define SSL_R_SSLV3_ALERT_CERTIFICATE_REVOKED 1044
#define SSL_R_SSLV3_ALERT_CERTIFICATE_EXPIRED 1045
#define SSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN 1046
#define SSL_R_SSLV3_ALERT_ILLEGAL_PARAMETER 1047
#define SSL_R_TLSV1_ALERT_UNKNOWN_CA 1048
#define SSL_R_TLSV1_ALERT_ACCESS_DENIED 1049
#define SSL_R_TLSV1_ALERT_DECODE_ERROR 1050
#define SSL_R_TLSV1_ALERT_DECRYPT_ERROR 1051
#define SSL_R_TLSV1_ALERT_EXPORT_RESTRICTION 1060
#define SSL_R_TLSV1_ALERT_PROTOCOL_VERSION 1070
#define SSL_R_TLSV1_ALERT_INSUFFICIENT_SECURITY 1071
#define SSL_R_TLSV1_ALERT_INTERNAL_ERROR 1080
#define SSL_R_TLSV1_ALERT_INAPPROPRIATE_FALLBACK 1086
#define SSL_R_TLSV1_ALERT_USER_CANCELLED 1090
#define SSL_R_TLSV1_ALERT_NO_RENEGOTIATION 1100
#define SSL_R_TLSV1_UNSUPPORTED_EXTENSION 1110
#define SSL_R_TLSV1_CERTIFICATE_UNOBTAINABLE 1111
#define SSL_R_TLSV1_UNRECOGNIZED_NAME 1112
#define SSL_R_TLSV1_BAD_CERTIFICATE_STATUS_RESPONSE 1113
#define SSL_R_TLSV1_BAD_CERTIFICATE_HASH_VALUE 1114

#endif
