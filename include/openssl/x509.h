/* crypto/x509/x509.h */
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
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 * ECDH support in OpenSSL originally developed by 
 * SUN MICROSYSTEMS, INC., and contributed to the OpenSSL project.
 */

#ifndef HEADER_X509_H
#define HEADER_X509_H

#include <openssl/base.h>

#include <openssl/asn1t.h>
#include <openssl/cipher.h>

#ifdef  __cplusplus
extern "C" {
#endif

typedef STACK_OF(X509_ALGOR) X509_ALGORS;

struct X509_pubkey_st
	{
	X509_ALGOR *algor;
	ASN1_BIT_STRING *public_key;
	EVP_PKEY *pkey;
	};

struct X509_sig_st
	{
	X509_ALGOR *algor;
	ASN1_OCTET_STRING *digest;
	} /* X509_SIG */;

/* a sequence of these are used */
struct x509_attributes_st
	{
	ASN1_OBJECT *object;
	int single; /* 0 for a set, 1 for a single item (which is wrong) */
	union	{
		char		*ptr;
/* 0 */		STACK_OF(ASN1_TYPE) *set;
/* 1 */		ASN1_TYPE	*single;
		} value;
	} /* X509_ATTRIBUTE */;

DECLARE_STACK_OF(X509_ATTRIBUTE)
DECLARE_ASN1_SET_OF(X509_ATTRIBUTE)

/* Password based encryption structure */

struct PBEPARAM_st {
ASN1_OCTET_STRING *salt;
ASN1_INTEGER *iter;
} /* PBEPARAM */;

/* Password based encryption V2 structures */

struct PBE2PARAM_st {
X509_ALGOR *keyfunc;
X509_ALGOR *encryption;
} /* PBE2PARAM */;

struct PBKDF2PARAM_st {
ASN1_TYPE *salt;	/* Usually OCTET STRING but could be anything */
ASN1_INTEGER *iter;
ASN1_INTEGER *keylength;
X509_ALGOR *prf;
} /* PBKDF2PARAM */;


/* PKCS#8 private key info structure */

struct pkcs8_priv_key_info_st
        {
        int broken;     /* Flag for various broken formats */
#define PKCS8_OK		0
#define PKCS8_NO_OCTET		1
#define PKCS8_EMBEDDED_PARAM	2
#define PKCS8_NS_DB		3
#define PKCS8_NEG_PRIVKEY	4
        ASN1_INTEGER *version;
        X509_ALGOR *pkeyalg;
        ASN1_TYPE *pkey; /* Should be OCTET STRING but some are broken */
        STACK_OF(X509_ATTRIBUTE) *attributes;
        };

#ifndef OPENSSL_NO_EVP
OPENSSL_EXPORT int X509_signature_dump(BIO *bp,const ASN1_STRING *sig, int indent);
OPENSSL_EXPORT int X509_signature_print(BIO *bp,X509_ALGOR *alg, ASN1_STRING *sig);
#endif

#ifndef OPENSSL_NO_FP_API
OPENSSL_EXPORT X509 *d2i_X509_fp(FILE *fp, X509 **x509);
OPENSSL_EXPORT int i2d_X509_fp(FILE *fp,X509 *x509);
OPENSSL_EXPORT X509_CRL *d2i_X509_CRL_fp(FILE *fp,X509_CRL **crl);
OPENSSL_EXPORT int i2d_X509_CRL_fp(FILE *fp,X509_CRL *crl);
OPENSSL_EXPORT X509_REQ *d2i_X509_REQ_fp(FILE *fp,X509_REQ **req);
OPENSSL_EXPORT int i2d_X509_REQ_fp(FILE *fp,X509_REQ *req);
OPENSSL_EXPORT RSA *d2i_RSAPrivateKey_fp(FILE *fp,RSA **rsa);
OPENSSL_EXPORT int i2d_RSAPrivateKey_fp(FILE *fp,RSA *rsa);
OPENSSL_EXPORT RSA *d2i_RSAPublicKey_fp(FILE *fp,RSA **rsa);
OPENSSL_EXPORT int i2d_RSAPublicKey_fp(FILE *fp,RSA *rsa);
OPENSSL_EXPORT RSA *d2i_RSA_PUBKEY_fp(FILE *fp,RSA **rsa);
OPENSSL_EXPORT int i2d_RSA_PUBKEY_fp(FILE *fp,RSA *rsa);
OPENSSL_EXPORT EC_KEY *d2i_EC_PUBKEY_fp(FILE *fp, EC_KEY **eckey);
OPENSSL_EXPORT int   i2d_EC_PUBKEY_fp(FILE *fp, EC_KEY *eckey);
OPENSSL_EXPORT EC_KEY *d2i_ECPrivateKey_fp(FILE *fp, EC_KEY **eckey);
OPENSSL_EXPORT int   i2d_ECPrivateKey_fp(FILE *fp, EC_KEY *eckey);
OPENSSL_EXPORT X509_SIG *d2i_PKCS8_fp(FILE *fp,X509_SIG **p8);
OPENSSL_EXPORT int i2d_PKCS8_fp(FILE *fp,X509_SIG *p8);
OPENSSL_EXPORT PKCS8_PRIV_KEY_INFO *d2i_PKCS8_PRIV_KEY_INFO_fp(FILE *fp,
						PKCS8_PRIV_KEY_INFO **p8inf);
OPENSSL_EXPORT int i2d_PKCS8_PRIV_KEY_INFO_fp(FILE *fp,PKCS8_PRIV_KEY_INFO *p8inf);
OPENSSL_EXPORT int i2d_PKCS8PrivateKeyInfo_fp(FILE *fp, EVP_PKEY *key);
OPENSSL_EXPORT int i2d_PrivateKey_fp(FILE *fp, EVP_PKEY *pkey);
OPENSSL_EXPORT EVP_PKEY *d2i_PrivateKey_fp(FILE *fp, EVP_PKEY **a);
OPENSSL_EXPORT int i2d_PUBKEY_fp(FILE *fp, EVP_PKEY *pkey);
OPENSSL_EXPORT EVP_PKEY *d2i_PUBKEY_fp(FILE *fp, EVP_PKEY **a);
#endif

OPENSSL_EXPORT X509_SIG *d2i_PKCS8_bio(BIO *bp,X509_SIG **p8);
OPENSSL_EXPORT int i2d_PKCS8_bio(BIO *bp,X509_SIG *p8);
OPENSSL_EXPORT PKCS8_PRIV_KEY_INFO *d2i_PKCS8_PRIV_KEY_INFO_bio(BIO *bp,
						PKCS8_PRIV_KEY_INFO **p8inf);
OPENSSL_EXPORT int i2d_PKCS8_PRIV_KEY_INFO_bio(BIO *bp,PKCS8_PRIV_KEY_INFO *p8inf);
OPENSSL_EXPORT int i2d_PKCS8PrivateKeyInfo_bio(BIO *bp, EVP_PKEY *key);
OPENSSL_EXPORT int i2d_PrivateKey_bio(BIO *bp, EVP_PKEY *pkey);
OPENSSL_EXPORT EVP_PKEY *d2i_PrivateKey_bio(BIO *bp, EVP_PKEY **a);
OPENSSL_EXPORT int i2d_PUBKEY_bio(BIO *bp, EVP_PKEY *pkey);
OPENSSL_EXPORT EVP_PKEY *d2i_PUBKEY_bio(BIO *bp, EVP_PKEY **a);

OPENSSL_EXPORT X509_ALGOR *X509_ALGOR_dup(X509_ALGOR *xn);
OPENSSL_EXPORT int X509_ALGOR_set0(X509_ALGOR *alg, const ASN1_OBJECT *aobj, int ptype, void *pval);
OPENSSL_EXPORT void X509_ALGOR_get0(ASN1_OBJECT **paobj, int *pptype, void **ppval,
						X509_ALGOR *algor);
OPENSSL_EXPORT void X509_ALGOR_set_md(X509_ALGOR *alg, const EVP_MD *md);
OPENSSL_EXPORT int X509_ALGOR_cmp(const X509_ALGOR *a, const X509_ALGOR *b);

DECLARE_ASN1_FUNCTIONS(X509_PUBKEY)

OPENSSL_EXPORT int		X509_PUBKEY_set(X509_PUBKEY **x, EVP_PKEY *pkey);
OPENSSL_EXPORT EVP_PKEY *	X509_PUBKEY_get(X509_PUBKEY *key);
OPENSSL_EXPORT int		i2d_PUBKEY(const EVP_PKEY *a,unsigned char **pp);
OPENSSL_EXPORT EVP_PKEY *	d2i_PUBKEY(EVP_PKEY **a,const unsigned char **pp,
			long length);
OPENSSL_EXPORT int		i2d_RSA_PUBKEY(const RSA *a,unsigned char **pp);
OPENSSL_EXPORT RSA *		d2i_RSA_PUBKEY(RSA **a,const unsigned char **pp,
			long length);
OPENSSL_EXPORT int		i2d_EC_PUBKEY(const EC_KEY *a, unsigned char **pp);
OPENSSL_EXPORT EC_KEY 		*d2i_EC_PUBKEY(EC_KEY **a, const unsigned char **pp,
			long length);

DECLARE_ASN1_FUNCTIONS(X509_SIG)

DECLARE_ASN1_FUNCTIONS(X509_ATTRIBUTE)
OPENSSL_EXPORT X509_ATTRIBUTE *X509_ATTRIBUTE_create(int nid, int atrtype, void *value);

DECLARE_ASN1_FUNCTIONS(PBEPARAM)
DECLARE_ASN1_FUNCTIONS(PBE2PARAM)
DECLARE_ASN1_FUNCTIONS(PBKDF2PARAM)

OPENSSL_EXPORT int PKCS5_pbe_set0_algor(X509_ALGOR *algor, int alg, int iter,
				const unsigned char *salt, int saltlen);

OPENSSL_EXPORT X509_ALGOR *PKCS5_pbe_set(int alg, int iter,
				const unsigned char *salt, int saltlen);
OPENSSL_EXPORT X509_ALGOR *PKCS5_pbe2_set(const EVP_CIPHER *cipher, int iter,
					 unsigned char *salt, int saltlen);
OPENSSL_EXPORT X509_ALGOR *PKCS5_pbe2_set_iv(const EVP_CIPHER *cipher, int iter,
				 unsigned char *salt, int saltlen,
				 unsigned char *aiv, int prf_nid);

OPENSSL_EXPORT X509_ALGOR *PKCS5_pbkdf2_set(int iter, unsigned char *salt, int saltlen,
				int prf_nid, int keylen);

/* PKCS#8 utilities */

DECLARE_ASN1_FUNCTIONS(PKCS8_PRIV_KEY_INFO)

OPENSSL_EXPORT EVP_PKEY *EVP_PKCS82PKEY(PKCS8_PRIV_KEY_INFO *p8);
OPENSSL_EXPORT PKCS8_PRIV_KEY_INFO *EVP_PKEY2PKCS8(EVP_PKEY *pkey);
OPENSSL_EXPORT PKCS8_PRIV_KEY_INFO *EVP_PKEY2PKCS8_broken(EVP_PKEY *pkey, int broken);
OPENSSL_EXPORT PKCS8_PRIV_KEY_INFO *PKCS8_set_broken(PKCS8_PRIV_KEY_INFO *p8, int broken);

OPENSSL_EXPORT int PKCS8_pkey_set0(PKCS8_PRIV_KEY_INFO *priv, ASN1_OBJECT *aobj,
			int version, int ptype, void *pval,
				unsigned char *penc, int penclen);
OPENSSL_EXPORT int PKCS8_pkey_get0(ASN1_OBJECT **ppkalg,
		const unsigned char **pk, int *ppklen,
		X509_ALGOR **pa,
		PKCS8_PRIV_KEY_INFO *p8);

OPENSSL_EXPORT int X509_PUBKEY_set0_param(X509_PUBKEY *pub, const ASN1_OBJECT *aobj,
					int ptype, void *pval,
					unsigned char *penc, int penclen);
OPENSSL_EXPORT int X509_PUBKEY_get0_param(ASN1_OBJECT **ppkalg,
		const unsigned char **pk, int *ppklen,
		X509_ALGOR **pa,
		X509_PUBKEY *pub);

#ifdef  __cplusplus
}
#endif

#define X509_R_METHOD_NOT_SUPPORTED 118
#define X509_R_PUBLIC_KEY_DECODE_ERROR 124
#define X509_R_PUBLIC_KEY_ENCODE_ERROR 125
#define X509_R_UNSUPPORTED_ALGORITHM 133

#endif
