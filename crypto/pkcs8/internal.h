/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project 1999.
 */
/* ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
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

#ifndef OPENSSL_HEADER_PKCS8_INTERNAL_H
#define OPENSSL_HEADER_PKCS8_INTERNAL_H

#include <openssl/base.h>

#if defined(__cplusplus)
extern "C" {
#endif


#define PKCS5_DEFAULT_ITERATIONS 2048
#define PKCS5_SALT_LEN 8

typedef struct {
  ASN1_OCTET_STRING *salt;
  ASN1_INTEGER *iter;
} PBEPARAM;

typedef struct {
  X509_ALGOR *keyfunc;
  X509_ALGOR *encryption;
} PBE2PARAM;

typedef struct {
  ASN1_TYPE *salt; /* Usually OCTET STRING but could be anything */
  ASN1_INTEGER *iter;
  ASN1_INTEGER *keylength;
  X509_ALGOR *prf;
} PBKDF2PARAM;

DECLARE_ASN1_FUNCTIONS(PBEPARAM)
DECLARE_ASN1_FUNCTIONS(PBE2PARAM)
DECLARE_ASN1_FUNCTIONS(PBKDF2PARAM)

/* PKCS5_v2_PBE_keyivgen intializes the supplied |ctx| for PBKDF v2, which must
 * be specified by |param|. The password is specified by |pass_raw| and
 * |pass_raw_len|. |cipher| and |md| are ignored.
 *
 * It returns one on success and zero on error. */
int PKCS5_v2_PBE_keyivgen(EVP_CIPHER_CTX *ctx, const uint8_t *pass_raw,
                          size_t pass_raw_len, ASN1_TYPE *param,
                          const EVP_CIPHER *cipher, const EVP_MD *md, int enc);

X509_ALGOR *PKCS5_pbe_set(int alg, int iter, const unsigned char *salt,
                          int saltlen);
X509_ALGOR *PKCS5_pbe2_set(const EVP_CIPHER *cipher, int iter,
                           unsigned char *salt, int saltlen);


#if defined(__cplusplus)
}  /* extern C */
#endif

#endif  /* OPENSSL_HEADER_PKCS8_INTERNAL_H */
