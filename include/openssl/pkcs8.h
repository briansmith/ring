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


#ifndef OPENSSL_HEADER_PKCS8_H
#define OPENSSL_HEADER_PKCS8_H

#include <openssl/base.h>

#include <openssl/x509.h>

#if defined(__cplusplus)
extern "C" {
#endif

X509_SIG *PKCS8_encrypt(int pbe_nid, const EVP_CIPHER *cipher, const char *pass,
                        int pass_len, uint8_t *salt, size_t salt_len, int iterations,
                        PKCS8_PRIV_KEY_INFO *p8inf);

PKCS8_PRIV_KEY_INFO *PKCS8_decrypt(X509_SIG *pkcs8, const char *pass,
                                   int pass_len);


#if defined(__cplusplus)
}  /* extern C */
#endif

#define PKCS8_F_PKCS8_encrypt 100
#define PKCS8_F_EVP_PKEY2PKCS8 101
#define PKCS8_F_EVP_PKCS82PKEY 102
#define PKCS8_F_PKCS5_pbe_set0_algor 103
#define PKCS8_F_pbe_crypt 104
#define PKCS8_F_pkcs12_item_decrypt_d2i 105
#define PKCS8_F_PKCS5_pbe_set 106
#define PKCS8_F_pkcs12_key_gen_uni 107
#define PKCS8_F_pkcs12_key_gen_asc 108
#define PKCS8_F_pkcs12_pbe_keyivgen 109
#define PKCS8_F_pbe_cipher_init 110
#define PKCS8_F_pkcs12_item_i2d_encrypt 111
#define PKCS8_F_PKCS5_pbe2_set_iv 112
#define PKCS8_F_PKCS5_pbkdf2_set 113
#define PKCS8_R_ERROR_SETTING_CIPHER_PARAMS 100
#define PKCS8_R_PRIVATE_KEY_ENCODE_ERROR 101
#define PKCS8_R_UNKNOWN_ALGORITHM 102
#define PKCS8_R_UNKNOWN_CIPHER 103
#define PKCS8_R_UNKNOWN_DIGEST 104
#define PKCS8_R_ENCODE_ERROR 105
#define PKCS8_R_DECODE_ERROR 106
#define PKCS8_R_ENCRYPT_ERROR 107
#define PKCS8_R_UNSUPPORTED_PRIVATE_KEY_ALGORITHM 108
#define PKCS8_R_PRIVATE_KEY_DECODE_ERROR 109
#define PKCS8_R_UNKNOWN_CIPHER_ALGORITHM 110
#define PKCS8_R_KEYGEN_FAILURE 111
#define PKCS8_R_TOO_LONG 112
#define PKCS8_R_CRYPT_ERROR 113
#define PKCS8_R_METHOD_NOT_SUPPORTED 114
#define PKCS8_R_CIPHER_HAS_NO_OBJECT_IDENTIFIER 115
#define PKCS8_R_KEY_GEN_ERROR 116

#endif  /* OPENSSL_HEADER_PKCS8_H */
