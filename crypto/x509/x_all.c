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
 * [including the GNU Public Licence.] */

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>


#ifndef OPENSSL_NO_FP_API
RSA *d2i_RSAPrivateKey_fp(FILE *fp, RSA **rsa)
	{
	return ASN1_d2i_fp_of(RSA, RSA_new, d2i_RSAPrivateKey, fp, rsa);
	}

int i2d_RSAPrivateKey_fp(FILE *fp, RSA *rsa)
	{
	return ASN1_i2d_fp_of_const(RSA, i2d_RSAPrivateKey, fp, rsa);
	}

RSA *d2i_RSAPublicKey_fp(FILE *fp, RSA **rsa)
	{
	return ASN1_d2i_fp_of(RSA, RSA_new, d2i_RSAPublicKey, fp, rsa);
	}

RSA *d2i_RSA_PUBKEY_fp(FILE *fp, RSA **rsa)
	{
	return ASN1_d2i_fp((void *(*)(void))
			   RSA_new,(D2I_OF(void))d2i_RSA_PUBKEY, fp,
			   (void **)rsa);
	}

int i2d_RSAPublicKey_fp(FILE *fp, RSA *rsa)
	{
	return ASN1_i2d_fp_of_const(RSA, i2d_RSAPublicKey, fp, rsa);
	}

int i2d_RSA_PUBKEY_fp(FILE *fp, RSA *rsa)
	{
	return ASN1_i2d_fp((I2D_OF_const(void))i2d_RSA_PUBKEY,fp,rsa);
	}
#endif

RSA *d2i_RSAPrivateKey_bio(BIO *bp, RSA **rsa)
	{
	return ASN1_d2i_bio_of(RSA, RSA_new, d2i_RSAPrivateKey, bp, rsa);
	}

int i2d_RSAPrivateKey_bio(BIO *bp, RSA *rsa)
	{
	return ASN1_i2d_bio_of_const(RSA, i2d_RSAPrivateKey, bp, rsa);
	}

RSA *d2i_RSAPublicKey_bio(BIO *bp, RSA **rsa)
	{
	return ASN1_d2i_bio_of(RSA, RSA_new, d2i_RSAPublicKey, bp, rsa);
	}


RSA *d2i_RSA_PUBKEY_bio(BIO *bp, RSA **rsa)
	{
	return ASN1_d2i_bio_of(RSA,RSA_new,d2i_RSA_PUBKEY,bp,rsa);
	}

int i2d_RSAPublicKey_bio(BIO *bp, RSA *rsa)
	{
	return ASN1_i2d_bio_of_const(RSA, i2d_RSAPublicKey, bp, rsa);
	}

int i2d_RSA_PUBKEY_bio(BIO *bp, RSA *rsa)
	{
	return ASN1_i2d_bio_of_const(RSA,i2d_RSA_PUBKEY,bp,rsa);
	}

#ifndef OPENSSL_NO_FP_API
EC_KEY *d2i_EC_PUBKEY_fp(FILE *fp, EC_KEY **eckey)
	{
	return ASN1_d2i_fp_of(EC_KEY,EC_KEY_new,d2i_EC_PUBKEY,fp,eckey);
	}
  
int i2d_EC_PUBKEY_fp(FILE *fp, EC_KEY *eckey)
	{
	return ASN1_i2d_fp_of_const(EC_KEY,i2d_EC_PUBKEY,fp,eckey);
	}

EC_KEY *d2i_ECPrivateKey_fp(FILE *fp, EC_KEY **eckey)
	{
	return ASN1_d2i_fp_of(EC_KEY,EC_KEY_new,d2i_ECPrivateKey,fp,eckey);
	}
  
int i2d_ECPrivateKey_fp(FILE *fp, EC_KEY *eckey)
	{
	return ASN1_i2d_fp_of_const(EC_KEY,i2d_ECPrivateKey,fp,eckey);
	}
#endif
EC_KEY *d2i_EC_PUBKEY_bio(BIO *bp, EC_KEY **eckey)
	{
	return ASN1_d2i_bio_of(EC_KEY,EC_KEY_new,d2i_EC_PUBKEY,bp,eckey);
	}
  
int i2d_EC_PUBKEY_bio(BIO *bp, EC_KEY *ecdsa)
	{
	return ASN1_i2d_bio_of_const(EC_KEY,i2d_EC_PUBKEY,bp,ecdsa);
	}

EC_KEY *d2i_ECPrivateKey_bio(BIO *bp, EC_KEY **eckey)
	{
	return ASN1_d2i_bio_of(EC_KEY,EC_KEY_new,d2i_ECPrivateKey,bp,eckey);
	}
  
int i2d_ECPrivateKey_bio(BIO *bp, EC_KEY *eckey)
	{
	return ASN1_i2d_bio_of_const(EC_KEY,i2d_ECPrivateKey,bp,eckey);
	}


#ifndef OPENSSL_NO_FP_API
X509_SIG *d2i_PKCS8_fp(FILE *fp, X509_SIG **p8)
	{
	return ASN1_d2i_fp_of(X509_SIG,X509_SIG_new,d2i_X509_SIG,fp,p8);
	}

int i2d_PKCS8_fp(FILE *fp, X509_SIG *p8)
	{
	return ASN1_i2d_fp_of(X509_SIG,i2d_X509_SIG,fp,p8);
	}
#endif

X509_SIG *d2i_PKCS8_bio(BIO *bp, X509_SIG **p8)
	{
	return ASN1_d2i_bio_of(X509_SIG,X509_SIG_new,d2i_X509_SIG,bp,p8);
	}

int i2d_PKCS8_bio(BIO *bp, X509_SIG *p8)
	{
	return ASN1_i2d_bio_of(X509_SIG,i2d_X509_SIG,bp,p8);
	}

#ifndef OPENSSL_NO_FP_API
PKCS8_PRIV_KEY_INFO *d2i_PKCS8_PRIV_KEY_INFO_fp(FILE *fp,
						 PKCS8_PRIV_KEY_INFO **p8inf)
	{
	return ASN1_d2i_fp_of(PKCS8_PRIV_KEY_INFO,PKCS8_PRIV_KEY_INFO_new,
			      d2i_PKCS8_PRIV_KEY_INFO,fp,p8inf);
	}

int i2d_PKCS8_PRIV_KEY_INFO_fp(FILE *fp, PKCS8_PRIV_KEY_INFO *p8inf)
	{
	return ASN1_i2d_fp_of(PKCS8_PRIV_KEY_INFO,i2d_PKCS8_PRIV_KEY_INFO,fp,
			      p8inf);
	}

int i2d_PKCS8PrivateKeyInfo_fp(FILE *fp, EVP_PKEY *key)
	{
	PKCS8_PRIV_KEY_INFO *p8inf;
	int ret;
	p8inf = EVP_PKEY2PKCS8(key);
	if(!p8inf) return 0;
	ret = i2d_PKCS8_PRIV_KEY_INFO_fp(fp, p8inf);
	PKCS8_PRIV_KEY_INFO_free(p8inf);
	return ret;
	}

int i2d_PrivateKey_fp(FILE *fp, EVP_PKEY *pkey)
	{
	return ASN1_i2d_fp_of_const(EVP_PKEY,i2d_PrivateKey,fp,pkey);
	}

EVP_PKEY *d2i_PrivateKey_fp(FILE *fp, EVP_PKEY **a)
{
	return ASN1_d2i_fp_of(EVP_PKEY,EVP_PKEY_new,d2i_AutoPrivateKey,fp,a);
}

int i2d_PUBKEY_fp(FILE *fp, EVP_PKEY *pkey)
	{
	return ASN1_i2d_fp_of_const(EVP_PKEY,i2d_PUBKEY,fp,pkey);
	}

EVP_PKEY *d2i_PUBKEY_fp(FILE *fp, EVP_PKEY **a)
{
	return ASN1_d2i_fp_of(EVP_PKEY,EVP_PKEY_new,d2i_PUBKEY,fp,a);
}

PKCS8_PRIV_KEY_INFO *d2i_PKCS8_PRIV_KEY_INFO_bio(BIO *bp,
						 PKCS8_PRIV_KEY_INFO **p8inf)
	{
	return ASN1_d2i_bio_of(PKCS8_PRIV_KEY_INFO,PKCS8_PRIV_KEY_INFO_new,
			    d2i_PKCS8_PRIV_KEY_INFO,bp,p8inf);
	}

int i2d_PKCS8_PRIV_KEY_INFO_bio(BIO *bp, PKCS8_PRIV_KEY_INFO *p8inf)
	{
	return ASN1_i2d_bio_of(PKCS8_PRIV_KEY_INFO,i2d_PKCS8_PRIV_KEY_INFO,bp,
			       p8inf);
	}

int i2d_PKCS8PrivateKeyInfo_bio(BIO *bp, EVP_PKEY *key)
	{
	PKCS8_PRIV_KEY_INFO *p8inf;
	int ret;
	p8inf = EVP_PKEY2PKCS8(key);
	if(!p8inf) return 0;
	ret = i2d_PKCS8_PRIV_KEY_INFO_bio(bp, p8inf);
	PKCS8_PRIV_KEY_INFO_free(p8inf);
	return ret;
	}
#endif

int i2d_PrivateKey_bio(BIO *bp, EVP_PKEY *pkey)
	{
	return ASN1_i2d_bio_of_const(EVP_PKEY,i2d_PrivateKey,bp,pkey);
	}

EVP_PKEY *d2i_PrivateKey_bio(BIO *bp, EVP_PKEY **a)
	{
	return ASN1_d2i_bio_of(EVP_PKEY,EVP_PKEY_new,d2i_AutoPrivateKey,bp,a);
	}

int i2d_PUBKEY_bio(BIO *bp, EVP_PKEY *pkey)
	{
	return ASN1_i2d_bio_of_const(EVP_PKEY,i2d_PUBKEY,bp,pkey);
	}

EVP_PKEY *d2i_PUBKEY_bio(BIO *bp, EVP_PKEY **a)
	{
	return ASN1_d2i_bio_of(EVP_PKEY,EVP_PKEY_new,d2i_PUBKEY,bp,a);
	}
