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
 *
 * Portions of the attached software ("Contribution") are developed by
 * SUN MICROSYSTEMS, INC., and are contributed to the OpenSSL project.
 *
 * The Contribution is licensed pursuant to the OpenSSL open source
 * license provided above.
 *
 * ECC cipher suite support in OpenSSL originally written by
 * Vipul Gupta and Sumit Gupta of Sun Microsystems Laboratories.
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

#include <assert.h>
#include <stdio.h>

#include <openssl/buf.h>
#include <openssl/dh.h>
#include <openssl/md5.h>
#include <openssl/mem.h>
#include <openssl/obj.h>

#include "ssl_locl.h"


#define SSL3_NUM_CIPHERS (sizeof(ssl3_ciphers) / sizeof(SSL_CIPHER))

/* list of available SSLv3 ciphers (sorted by id) */
const SSL_CIPHER ssl3_ciphers[] = {
    /* The RSA ciphers */
    /* Cipher 04 */
    {
     1, SSL3_TXT_RSA_RC4_128_MD5, SSL3_CK_RSA_RC4_128_MD5, SSL_kRSA, SSL_aRSA,
     SSL_RC4, SSL_MD5, SSL_SSLV3, SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF, 128, 128,
    },

    /* Cipher 05 */
    {
     1, SSL3_TXT_RSA_RC4_128_SHA, SSL3_CK_RSA_RC4_128_SHA, SSL_kRSA, SSL_aRSA,
     SSL_RC4, SSL_SHA1, SSL_SSLV3, SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF, 128, 128,
    },

    /* Cipher 0A */
    {
     1, SSL3_TXT_RSA_DES_192_CBC3_SHA, SSL3_CK_RSA_DES_192_CBC3_SHA, SSL_kRSA,
     SSL_aRSA, SSL_3DES, SSL_SHA1, SSL_SSLV3, SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF, 112, 168,
    },


    /* The Ephemeral DH ciphers */

    /* Cipher 18 */
    {
     1, SSL3_TXT_ADH_RC4_128_MD5, SSL3_CK_ADH_RC4_128_MD5, SSL_kEDH, SSL_aNULL,
     SSL_RC4, SSL_MD5, SSL_SSLV3, SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF, 128, 128,
    },


    /* New AES ciphersuites */

    /* Cipher 2F */
    {
     1, TLS1_TXT_RSA_WITH_AES_128_SHA, TLS1_CK_RSA_WITH_AES_128_SHA, SSL_kRSA,
     SSL_aRSA, SSL_AES128, SSL_SHA1, SSL_TLSV1, SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF, 128, 128,
    },

    /* Cipher 33 */
    {
     1, TLS1_TXT_DHE_RSA_WITH_AES_128_SHA, TLS1_CK_DHE_RSA_WITH_AES_128_SHA,
     SSL_kEDH, SSL_aRSA, SSL_AES128, SSL_SHA1, SSL_TLSV1, SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF, 128, 128,
    },

    /* Cipher 34 */
    {
     1, TLS1_TXT_ADH_WITH_AES_128_SHA, TLS1_CK_ADH_WITH_AES_128_SHA, SSL_kEDH,
     SSL_aNULL, SSL_AES128, SSL_SHA1, SSL_TLSV1, SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF, 128, 128,
    },

    /* Cipher 35 */
    {
     1, TLS1_TXT_RSA_WITH_AES_256_SHA, TLS1_CK_RSA_WITH_AES_256_SHA, SSL_kRSA,
     SSL_aRSA, SSL_AES256, SSL_SHA1, SSL_TLSV1, SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF, 256, 256,
    },

    /* Cipher 39 */
    {
     1, TLS1_TXT_DHE_RSA_WITH_AES_256_SHA, TLS1_CK_DHE_RSA_WITH_AES_256_SHA,
     SSL_kEDH, SSL_aRSA, SSL_AES256, SSL_SHA1, SSL_TLSV1, SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF, 256, 256,
    },

    /* Cipher 3A */
    {
     1, TLS1_TXT_ADH_WITH_AES_256_SHA, TLS1_CK_ADH_WITH_AES_256_SHA, SSL_kEDH,
     SSL_aNULL, SSL_AES256, SSL_SHA1, SSL_TLSV1, SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF, 256, 256,
    },


    /* TLS v1.2 ciphersuites */

    /* Cipher 3C */
    {
     1, TLS1_TXT_RSA_WITH_AES_128_SHA256, TLS1_CK_RSA_WITH_AES_128_SHA256,
     SSL_kRSA, SSL_aRSA, SSL_AES128, SSL_SHA256, SSL_TLSV1_2,
     SSL_HIGH | SSL_FIPS, SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256, 128, 128,
    },

    /* Cipher 3D */
    {
     1, TLS1_TXT_RSA_WITH_AES_256_SHA256, TLS1_CK_RSA_WITH_AES_256_SHA256,
     SSL_kRSA, SSL_aRSA, SSL_AES256, SSL_SHA256, SSL_TLSV1_2,
     SSL_HIGH | SSL_FIPS, SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256, 256, 256,
    },

    /* Cipher 67 */
    {
     1, TLS1_TXT_DHE_RSA_WITH_AES_128_SHA256,
     TLS1_CK_DHE_RSA_WITH_AES_128_SHA256, SSL_kEDH, SSL_aRSA, SSL_AES128,
     SSL_SHA256, SSL_TLSV1_2, SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256, 128, 128,
    },

    /* Cipher 6B */
    {
     1, TLS1_TXT_DHE_RSA_WITH_AES_256_SHA256,
     TLS1_CK_DHE_RSA_WITH_AES_256_SHA256, SSL_kEDH, SSL_aRSA, SSL_AES256,
     SSL_SHA256, SSL_TLSV1_2, SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256, 256, 256,
    },

    /* Cipher 6C */
    {
     1, TLS1_TXT_ADH_WITH_AES_128_SHA256, TLS1_CK_ADH_WITH_AES_128_SHA256,
     SSL_kEDH, SSL_aNULL, SSL_AES128, SSL_SHA256, SSL_TLSV1_2,
     SSL_HIGH | SSL_FIPS, SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256, 128, 128,
    },

    /* Cipher 6D */
    {
     1, TLS1_TXT_ADH_WITH_AES_256_SHA256, TLS1_CK_ADH_WITH_AES_256_SHA256,
     SSL_kEDH, SSL_aNULL, SSL_AES256, SSL_SHA256, SSL_TLSV1_2,
     SSL_HIGH | SSL_FIPS, SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256, 256, 256,
    },

    /* Cipher 8A */
    {
     1, TLS1_TXT_PSK_WITH_RC4_128_SHA, TLS1_CK_PSK_WITH_RC4_128_SHA, SSL_kPSK,
     SSL_aPSK, SSL_RC4, SSL_SHA1, SSL_TLSV1, SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF, 128, 128,
    },

    /* Cipher 8C */
    {
     1, TLS1_TXT_PSK_WITH_AES_128_CBC_SHA, TLS1_CK_PSK_WITH_AES_128_CBC_SHA,
     SSL_kPSK, SSL_aPSK, SSL_AES128, SSL_SHA1, SSL_TLSV1, SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF, 128, 128,
    },

    /* Cipher 8D */
    {
     1, TLS1_TXT_PSK_WITH_AES_256_CBC_SHA, TLS1_CK_PSK_WITH_AES_256_CBC_SHA,
     SSL_kPSK, SSL_aPSK, SSL_AES256, SSL_SHA1, SSL_TLSV1, SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF, 256, 256,
    },


    /* GCM ciphersuites from RFC5288 */

    /* Cipher 9C */
    {
     1, TLS1_TXT_RSA_WITH_AES_128_GCM_SHA256,
     TLS1_CK_RSA_WITH_AES_128_GCM_SHA256, SSL_kRSA, SSL_aRSA, SSL_AES128GCM,
     SSL_AEAD, SSL_TLSV1_2, SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256 | SSL_CIPHER_ALGORITHM2_AEAD |
         SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_INCLUDED_IN_RECORD,
     128, 128,
    },

    /* Cipher 9D */
    {
     1, TLS1_TXT_RSA_WITH_AES_256_GCM_SHA384,
     TLS1_CK_RSA_WITH_AES_256_GCM_SHA384, SSL_kRSA, SSL_aRSA, SSL_AES256GCM,
     SSL_AEAD, SSL_TLSV1_2, SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384 | SSL_CIPHER_ALGORITHM2_AEAD |
         SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_INCLUDED_IN_RECORD,
     256, 256,
    },

    /* Cipher 9E */
    {
     1, TLS1_TXT_DHE_RSA_WITH_AES_128_GCM_SHA256,
     TLS1_CK_DHE_RSA_WITH_AES_128_GCM_SHA256, SSL_kEDH, SSL_aRSA, SSL_AES128GCM,
     SSL_AEAD, SSL_TLSV1_2, SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256 | SSL_CIPHER_ALGORITHM2_AEAD |
         SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_INCLUDED_IN_RECORD,
     128, 128,
    },

    /* Cipher 9F */
    {
     1, TLS1_TXT_DHE_RSA_WITH_AES_256_GCM_SHA384,
     TLS1_CK_DHE_RSA_WITH_AES_256_GCM_SHA384, SSL_kEDH, SSL_aRSA, SSL_AES256GCM,
     SSL_AEAD, SSL_TLSV1_2, SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384 | SSL_CIPHER_ALGORITHM2_AEAD |
         SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_INCLUDED_IN_RECORD,
     256, 256,
    },

    /* Cipher A6 */
    {
     1, TLS1_TXT_ADH_WITH_AES_128_GCM_SHA256,
     TLS1_CK_ADH_WITH_AES_128_GCM_SHA256, SSL_kEDH, SSL_aNULL, SSL_AES128GCM,
     SSL_AEAD, SSL_TLSV1_2, SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256 | SSL_CIPHER_ALGORITHM2_AEAD |
         SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_INCLUDED_IN_RECORD,
     128, 128,
    },

    /* Cipher A7 */
    {
     1, TLS1_TXT_ADH_WITH_AES_256_GCM_SHA384,
     TLS1_CK_ADH_WITH_AES_256_GCM_SHA384, SSL_kEDH, SSL_aNULL, SSL_AES256GCM,
     SSL_AEAD, SSL_TLSV1_2, SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384 | SSL_CIPHER_ALGORITHM2_AEAD |
         SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_INCLUDED_IN_RECORD,
     256, 256,
    },

    /* Cipher C007 */
    {
     1, TLS1_TXT_ECDHE_ECDSA_WITH_RC4_128_SHA,
     TLS1_CK_ECDHE_ECDSA_WITH_RC4_128_SHA, SSL_kEECDH, SSL_aECDSA, SSL_RC4,
     SSL_SHA1, SSL_TLSV1, SSL_MEDIUM, SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF, 128,
     128,
    },

    /* Cipher C009 */
    {
     1, TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
     TLS1_CK_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, SSL_kEECDH, SSL_aECDSA,
     SSL_AES128, SSL_SHA1, SSL_TLSV1, SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF, 128, 128,
    },

    /* Cipher C00A */
    {
     1, TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
     TLS1_CK_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, SSL_kEECDH, SSL_aECDSA,
     SSL_AES256, SSL_SHA1, SSL_TLSV1, SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF, 256, 256,
    },

    /* Cipher C011 */
    {
     1, TLS1_TXT_ECDHE_RSA_WITH_RC4_128_SHA, TLS1_CK_ECDHE_RSA_WITH_RC4_128_SHA,
     SSL_kEECDH, SSL_aRSA, SSL_RC4, SSL_SHA1, SSL_TLSV1, SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF, 128, 128,
    },

    /* Cipher C013 */
    {
     1, TLS1_TXT_ECDHE_RSA_WITH_AES_128_CBC_SHA,
     TLS1_CK_ECDHE_RSA_WITH_AES_128_CBC_SHA, SSL_kEECDH, SSL_aRSA, SSL_AES128,
     SSL_SHA1, SSL_TLSV1, SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF, 128, 128,
    },

    /* Cipher C014 */
    {
     1, TLS1_TXT_ECDHE_RSA_WITH_AES_256_CBC_SHA,
     TLS1_CK_ECDHE_RSA_WITH_AES_256_CBC_SHA, SSL_kEECDH, SSL_aRSA, SSL_AES256,
     SSL_SHA1, SSL_TLSV1, SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF, 256, 256,
    },

    /* Cipher C016 */
    {
     1, TLS1_TXT_ECDH_anon_WITH_RC4_128_SHA, TLS1_CK_ECDH_anon_WITH_RC4_128_SHA,
     SSL_kEECDH, SSL_aNULL, SSL_RC4, SSL_SHA1, SSL_TLSV1, SSL_MEDIUM,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF, 128, 128,
    },

    /* Cipher C018 */
    {
     1, TLS1_TXT_ECDH_anon_WITH_AES_128_CBC_SHA,
     TLS1_CK_ECDH_anon_WITH_AES_128_CBC_SHA, SSL_kEECDH, SSL_aNULL, SSL_AES128,
     SSL_SHA1, SSL_TLSV1, SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF, 128, 128,
    },

    /* Cipher C019 */
    {
     1, TLS1_TXT_ECDH_anon_WITH_AES_256_CBC_SHA,
     TLS1_CK_ECDH_anon_WITH_AES_256_CBC_SHA, SSL_kEECDH, SSL_aNULL, SSL_AES256,
     SSL_SHA1, SSL_TLSV1, SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF, 256, 256,
    },


    /* HMAC based TLS v1.2 ciphersuites from RFC5289 */

    /* Cipher C023 */
    {
     1, TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_SHA256,
     TLS1_CK_ECDHE_ECDSA_WITH_AES_128_SHA256, SSL_kEECDH, SSL_aECDSA,
     SSL_AES128, SSL_SHA256, SSL_TLSV1_2, SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256, 128, 128,
    },

    /* Cipher C024 */
    {
     1, TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_SHA384,
     TLS1_CK_ECDHE_ECDSA_WITH_AES_256_SHA384, SSL_kEECDH, SSL_aECDSA,
     SSL_AES256, SSL_SHA384, SSL_TLSV1_2, SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384, 256, 256,
    },

    /* Cipher C027 */
    {
     1, TLS1_TXT_ECDHE_RSA_WITH_AES_128_SHA256,
     TLS1_CK_ECDHE_RSA_WITH_AES_128_SHA256, SSL_kEECDH, SSL_aRSA, SSL_AES128,
     SSL_SHA256, SSL_TLSV1_2, SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256, 128, 128,
    },

    /* Cipher C028 */
    {
     1, TLS1_TXT_ECDHE_RSA_WITH_AES_256_SHA384,
     TLS1_CK_ECDHE_RSA_WITH_AES_256_SHA384, SSL_kEECDH, SSL_aRSA, SSL_AES256,
     SSL_SHA384, SSL_TLSV1_2, SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384, 256, 256,
    },


    /* GCM based TLS v1.2 ciphersuites from RFC5289 */

    /* Cipher C02B */
    {
     1, TLS1_TXT_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
     TLS1_CK_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, SSL_kEECDH, SSL_aECDSA,
     SSL_AES128GCM, SSL_AEAD, SSL_TLSV1_2, SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256 | SSL_CIPHER_ALGORITHM2_AEAD |
         SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_INCLUDED_IN_RECORD,
     128, 128,
    },

    /* Cipher C02C */
    {
     1, TLS1_TXT_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
     TLS1_CK_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, SSL_kEECDH, SSL_aECDSA,
     SSL_AES256GCM, SSL_AEAD, SSL_TLSV1_2, SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384 | SSL_CIPHER_ALGORITHM2_AEAD |
         SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_INCLUDED_IN_RECORD,
     256, 256,
    },

    /* Cipher C02F */
    {
     1, TLS1_TXT_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
     TLS1_CK_ECDHE_RSA_WITH_AES_128_GCM_SHA256, SSL_kEECDH, SSL_aRSA,
     SSL_AES128GCM, SSL_AEAD, SSL_TLSV1_2, SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256 | SSL_CIPHER_ALGORITHM2_AEAD |
         SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_INCLUDED_IN_RECORD,
     128, 128,
    },

    /* Cipher C030 */
    {
     1, TLS1_TXT_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
     TLS1_CK_ECDHE_RSA_WITH_AES_256_GCM_SHA384, SSL_kEECDH, SSL_aRSA,
     SSL_AES256GCM, SSL_AEAD, SSL_TLSV1_2, SSL_HIGH | SSL_FIPS,
     SSL_HANDSHAKE_MAC_SHA384 | TLS1_PRF_SHA384 | SSL_CIPHER_ALGORITHM2_AEAD |
         SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_INCLUDED_IN_RECORD,
     256, 256,
    },


    /* ECDH PSK ciphersuites */

    /* Cipher CAFE */
    {
     1, TLS1_TXT_ECDHE_PSK_WITH_AES_128_GCM_SHA256,
     TLS1_CK_ECDHE_PSK_WITH_AES_128_GCM_SHA256, SSL_kEECDH, SSL_aPSK,
     SSL_AES128GCM, SSL_AEAD, SSL_TLSV1_2, SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256 | SSL_CIPHER_ALGORITHM2_AEAD |
         SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_INCLUDED_IN_RECORD,
     128, 128,
    },

    {
     1, TLS1_TXT_ECDHE_RSA_WITH_CHACHA20_POLY1305,
     TLS1_CK_ECDHE_RSA_CHACHA20_POLY1305, SSL_kEECDH, SSL_aRSA,
     SSL_CHACHA20POLY1305, SSL_AEAD, SSL_TLSV1_2, SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256 | SSL_CIPHER_ALGORITHM2_AEAD,
     256, 0,
    },

    {
     1, TLS1_TXT_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
     TLS1_CK_ECDHE_ECDSA_CHACHA20_POLY1305, SSL_kEECDH, SSL_aECDSA,
     SSL_CHACHA20POLY1305, SSL_AEAD, SSL_TLSV1_2, SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256 | SSL_CIPHER_ALGORITHM2_AEAD,
     256, 0,
    },

    {
     1, TLS1_TXT_DHE_RSA_WITH_CHACHA20_POLY1305,
     TLS1_CK_DHE_RSA_CHACHA20_POLY1305, SSL_kEDH, SSL_aRSA,
     SSL_CHACHA20POLY1305, SSL_AEAD, SSL_TLSV1_2, SSL_HIGH,
     SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256 | SSL_CIPHER_ALGORITHM2_AEAD,
     256, 0,
    },
};

const SSL3_ENC_METHOD SSLv3_enc_data = {
    tls1_enc,
    ssl3_prf,
    tls1_setup_key_block,
    tls1_generate_master_secret,
    tls1_change_cipher_state,
    ssl3_final_finish_mac,
    ssl3_cert_verify_mac,
    SSL3_MD_CLIENT_FINISHED_CONST, 4,
    SSL3_MD_SERVER_FINISHED_CONST, 4,
    ssl3_alert_code,
    (int (*)(SSL *, uint8_t *, size_t, const char *, size_t, const uint8_t *,
             size_t, int use_context)) ssl_undefined_function,
    0,
};

int ssl3_num_ciphers(void) { return SSL3_NUM_CIPHERS; }

const SSL_CIPHER *ssl3_get_cipher(unsigned int u) {
  if (u >= SSL3_NUM_CIPHERS) {
    return NULL;
  }

  return &ssl3_ciphers[SSL3_NUM_CIPHERS - 1 - u];
}

int ssl3_pending(const SSL *s) {
  if (s->rstate == SSL_ST_READ_BODY) {
    return 0;
  }

  return (s->s3->rrec.type == SSL3_RT_APPLICATION_DATA) ? s->s3->rrec.length
                                                        : 0;
}

int ssl3_set_handshake_header(SSL *s, int htype, unsigned long len) {
  uint8_t *p = (uint8_t *)s->init_buf->data;
  *(p++) = htype;
  l2n3(len, p);
  s->init_num = (int)len + SSL3_HM_HEADER_LENGTH;
  s->init_off = 0;

  /* Add the message to the handshake hash. */
  return ssl3_finish_mac(s, (uint8_t *)s->init_buf->data, s->init_num);
}

int ssl3_handshake_write(SSL *s) { return ssl3_do_write(s, SSL3_RT_HANDSHAKE); }

int ssl3_new(SSL *s) {
  SSL3_STATE *s3;

  s3 = OPENSSL_malloc(sizeof *s3);
  if (s3 == NULL) {
    goto err;
  }
  memset(s3, 0, sizeof *s3);
  memset(s3->rrec.seq_num, 0, sizeof(s3->rrec.seq_num));
  memset(s3->wrec.seq_num, 0, sizeof(s3->wrec.seq_num));

  s->s3 = s3;

  /* Set the version to the highest supported version for TLS. This controls the
   * initial state of |s->enc_method| and what the API reports as the version
   * prior to negotiation.
   *
   * TODO(davidben): This is fragile and confusing. */
  s->version = TLS1_2_VERSION;
  return 1;
err:
  return 0;
}

void ssl3_free(SSL *s) {
  if (s == NULL || s->s3 == NULL) {
    return;
  }

  if (s->s3->sniff_buffer != NULL) {
    BUF_MEM_free(s->s3->sniff_buffer);
  }
  ssl3_cleanup_key_block(s);
  if (s->s3->rbuf.buf != NULL) {
    ssl3_release_read_buffer(s);
  }
  if (s->s3->wbuf.buf != NULL) {
    ssl3_release_write_buffer(s);
  }
  if (s->s3->tmp.dh != NULL) {
    DH_free(s->s3->tmp.dh);
  }
  if (s->s3->tmp.ecdh != NULL) {
    EC_KEY_free(s->s3->tmp.ecdh);
  }

  if (s->s3->tmp.ca_names != NULL) {
    sk_X509_NAME_pop_free(s->s3->tmp.ca_names, X509_NAME_free);
  }
  if (s->s3->tmp.certificate_types != NULL) {
    OPENSSL_free(s->s3->tmp.certificate_types);
  }
  if (s->s3->tmp.peer_ecpointformatlist) {
    OPENSSL_free(s->s3->tmp.peer_ecpointformatlist);
  }
  if (s->s3->tmp.peer_ellipticcurvelist) {
    OPENSSL_free(s->s3->tmp.peer_ellipticcurvelist);
  }
  if (s->s3->tmp.peer_psk_identity_hint) {
    OPENSSL_free(s->s3->tmp.peer_psk_identity_hint);
  }
  if (s->s3->handshake_buffer) {
    BIO_free(s->s3->handshake_buffer);
  }
  if (s->s3->handshake_dgst) {
    ssl3_free_digest_list(s);
  }
  if (s->s3->alpn_selected) {
    OPENSSL_free(s->s3->alpn_selected);
  }

  OPENSSL_cleanse(s->s3, sizeof *s->s3);
  OPENSSL_free(s->s3);
  s->s3 = NULL;
}

static int ssl3_set_req_cert_type(CERT *c, const uint8_t *p, size_t len);

long ssl3_ctrl(SSL *s, int cmd, long larg, void *parg) {
  int ret = 0;

  if (cmd == SSL_CTRL_SET_TMP_RSA || cmd == SSL_CTRL_SET_TMP_RSA_CB ||
      cmd == SSL_CTRL_SET_TMP_DH || cmd == SSL_CTRL_SET_TMP_DH_CB) {
    if (!ssl_cert_inst(&s->cert)) {
      OPENSSL_PUT_ERROR(SSL, ssl3_ctrl, ERR_R_MALLOC_FAILURE);
      return 0;
    }
  }

  switch (cmd) {
    case SSL_CTRL_GET_SESSION_REUSED:
      ret = s->hit;
      break;

    case SSL_CTRL_GET_CLIENT_CERT_REQUEST:
      break;

    case SSL_CTRL_GET_NUM_RENEGOTIATIONS:
      ret = s->s3->num_renegotiations;
      break;

    case SSL_CTRL_CLEAR_NUM_RENEGOTIATIONS:
      ret = s->s3->num_renegotiations;
      s->s3->num_renegotiations = 0;
      break;

    case SSL_CTRL_GET_TOTAL_RENEGOTIATIONS:
      ret = s->s3->total_renegotiations;
      break;

    case SSL_CTRL_GET_FLAGS:
      ret = (int)(s->s3->flags);
      break;

    case SSL_CTRL_NEED_TMP_RSA:
      /* Temporary RSA keys are never used. */
      ret = 0;
      break;

    case SSL_CTRL_SET_TMP_RSA:
      /* Temporary RSA keys are never used. */
      OPENSSL_PUT_ERROR(SSL, ssl3_ctrl, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
      break;

    case SSL_CTRL_SET_TMP_RSA_CB:
      OPENSSL_PUT_ERROR(SSL, ssl3_ctrl, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
      return ret;

    case SSL_CTRL_SET_TMP_DH: {
      DH *dh = (DH *)parg;
      if (dh == NULL) {
        OPENSSL_PUT_ERROR(SSL, ssl3_ctrl, ERR_R_PASSED_NULL_PARAMETER);
        return ret;
      }
      dh = DHparams_dup(dh);
      if (dh == NULL) {
        OPENSSL_PUT_ERROR(SSL, ssl3_ctrl, ERR_R_DH_LIB);
        return ret;
      }
      if (!(s->options & SSL_OP_SINGLE_DH_USE) && !DH_generate_key(dh)) {
        DH_free(dh);
        OPENSSL_PUT_ERROR(SSL, ssl3_ctrl, ERR_R_DH_LIB);
        return ret;
      }
      if (s->cert->dh_tmp != NULL) {
        DH_free(s->cert->dh_tmp);
      }
      s->cert->dh_tmp = dh;
      ret = 1;
      break;
    }

    case SSL_CTRL_SET_TMP_DH_CB:
      OPENSSL_PUT_ERROR(SSL, ssl3_ctrl, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
      return ret;

    case SSL_CTRL_SET_TMP_ECDH: {
      EC_KEY *ecdh = NULL;

      if (parg == NULL) {
        OPENSSL_PUT_ERROR(SSL, ssl3_ctrl, ERR_R_PASSED_NULL_PARAMETER);
        return ret;
      }
      if (!EC_KEY_up_ref((EC_KEY *)parg)) {
        OPENSSL_PUT_ERROR(SSL, ssl3_ctrl, ERR_R_ECDH_LIB);
        return ret;
      }
      ecdh = (EC_KEY *)parg;
      if (!(s->options & SSL_OP_SINGLE_ECDH_USE) && !EC_KEY_generate_key(ecdh)) {
        EC_KEY_free(ecdh);
        OPENSSL_PUT_ERROR(SSL, ssl3_ctrl, ERR_R_ECDH_LIB);
        return ret;
      }
      if (s->cert->ecdh_tmp != NULL) {
        EC_KEY_free(s->cert->ecdh_tmp);
      }
      s->cert->ecdh_tmp = ecdh;
      ret = 1;
      break;
    }

    case SSL_CTRL_SET_TMP_ECDH_CB:
      OPENSSL_PUT_ERROR(SSL, ssl3_ctrl, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
      return ret;

    case SSL_CTRL_SET_TLSEXT_HOSTNAME:
      if (larg == TLSEXT_NAMETYPE_host_name) {
        if (s->tlsext_hostname != NULL) {
          OPENSSL_free(s->tlsext_hostname);
        }
        s->tlsext_hostname = NULL;

        ret = 1;
        if (parg == NULL) {
          break;
        }
        if (strlen((char *)parg) > TLSEXT_MAXLEN_host_name) {
          OPENSSL_PUT_ERROR(SSL, ssl3_ctrl, SSL_R_SSL3_EXT_INVALID_SERVERNAME);
          return 0;
        }
        s->tlsext_hostname = BUF_strdup((char *) parg);
        if (s->tlsext_hostname == NULL) {
          OPENSSL_PUT_ERROR(SSL, ssl3_ctrl, ERR_R_INTERNAL_ERROR);
          return 0;
        }
      } else {
        OPENSSL_PUT_ERROR(SSL, ssl3_ctrl,
                          SSL_R_SSL3_EXT_INVALID_SERVERNAME_TYPE);
        return 0;
      }
      break;

    case SSL_CTRL_SET_TLSEXT_DEBUG_ARG:
      s->tlsext_debug_arg = parg;
      ret = 1;
      break;

    case SSL_CTRL_CHAIN:
      if (larg) {
        return ssl_cert_set1_chain(s->cert, (STACK_OF(X509) *)parg);
      } else {
        return ssl_cert_set0_chain(s->cert, (STACK_OF(X509) *)parg);
      }

    case SSL_CTRL_CHAIN_CERT:
      if (larg) {
        return ssl_cert_add1_chain_cert(s->cert, (X509 *)parg);
      } else {
        return ssl_cert_add0_chain_cert(s->cert, (X509 *)parg);
      }

    case SSL_CTRL_GET_CHAIN_CERTS:
      *(STACK_OF(X509) **)parg = s->cert->key->chain;
      break;

    case SSL_CTRL_SELECT_CURRENT_CERT:
      return ssl_cert_select_current(s->cert, (X509 *)parg);

    case SSL_CTRL_GET_CURVES: {
      const uint16_t *clist = s->s3->tmp.peer_ellipticcurvelist;
      size_t clistlen = s->s3->tmp.peer_ellipticcurvelist_length;
      if (parg) {
        size_t i;
        int *cptr = parg;
        int nid;
        for (i = 0; i < clistlen; i++) {
          nid = tls1_ec_curve_id2nid(clist[i]);
          if (nid != NID_undef) {
            cptr[i] = nid;
          } else {
            cptr[i] = TLSEXT_nid_unknown | clist[i];
          }
        }
      }
      return (int)clistlen;
    }

    case SSL_CTRL_SET_CURVES:
      return tls1_set_curves(&s->tlsext_ellipticcurvelist,
                             &s->tlsext_ellipticcurvelist_length, parg, larg);

    case SSL_CTRL_SET_ECDH_AUTO:
      s->cert->ecdh_tmp_auto = larg;
      return 1;

    case SSL_CTRL_SET_SIGALGS:
      return tls1_set_sigalgs(s->cert, parg, larg, 0);

    case SSL_CTRL_SET_CLIENT_SIGALGS:
      return tls1_set_sigalgs(s->cert, parg, larg, 1);

    case SSL_CTRL_GET_CLIENT_CERT_TYPES: {
      const uint8_t **pctype = parg;
      if (s->server || !s->s3->tmp.cert_req) {
        return 0;
      }
      if (pctype) {
        *pctype = s->s3->tmp.certificate_types;
      }
      return (int)s->s3->tmp.num_certificate_types;
    }

    case SSL_CTRL_SET_CLIENT_CERT_TYPES:
      if (!s->server) {
        return 0;
      }
      return ssl3_set_req_cert_type(s->cert, parg, larg);

    case SSL_CTRL_BUILD_CERT_CHAIN:
      return ssl_build_cert_chain(s->cert, s->ctx->cert_store, larg);

    case SSL_CTRL_SET_VERIFY_CERT_STORE:
      return ssl_cert_set_cert_store(s->cert, parg, 0, larg);

    case SSL_CTRL_SET_CHAIN_CERT_STORE:
      return ssl_cert_set_cert_store(s->cert, parg, 1, larg);

    case SSL_CTRL_GET_SERVER_TMP_KEY:
      if (s->server || !s->session || !s->session->sess_cert) {
        return 0;
      } else {
        SESS_CERT *sc;
        EVP_PKEY *ptmp;
        int rv = 0;
        sc = s->session->sess_cert;
        if (!sc->peer_dh_tmp && !sc->peer_ecdh_tmp) {
          return 0;
        }
        ptmp = EVP_PKEY_new();
        if (!ptmp) {
          return 0;
        }
        if (sc->peer_dh_tmp) {
          rv = EVP_PKEY_set1_DH(ptmp, sc->peer_dh_tmp);
        } else if (sc->peer_ecdh_tmp) {
          rv = EVP_PKEY_set1_EC_KEY(ptmp, sc->peer_ecdh_tmp);
        }
        if (rv) {
          *(EVP_PKEY **)parg = ptmp;
          return 1;
        }
        EVP_PKEY_free(ptmp);
        return 0;
      }

    case SSL_CTRL_GET_EC_POINT_FORMATS: {
      const uint8_t **pformat = parg;
      if (!s->s3->tmp.peer_ecpointformatlist) {
        return 0;
      }
      *pformat = s->s3->tmp.peer_ecpointformatlist;
      return (int)s->s3->tmp.peer_ecpointformatlist_length;
    }

    case SSL_CTRL_CHANNEL_ID:
      s->tlsext_channel_id_enabled = 1;
      ret = 1;
      break;

    case SSL_CTRL_SET_CHANNEL_ID:
      s->tlsext_channel_id_enabled = 1;
      if (EVP_PKEY_bits(parg) != 256) {
        OPENSSL_PUT_ERROR(SSL, ssl3_ctrl, SSL_R_CHANNEL_ID_NOT_P256);
        break;
      }
      if (s->tlsext_channel_id_private) {
        EVP_PKEY_free(s->tlsext_channel_id_private);
      }
      s->tlsext_channel_id_private = EVP_PKEY_dup((EVP_PKEY *)parg);
      ret = 1;
      break;

    case SSL_CTRL_GET_CHANNEL_ID:
      if (!s->s3->tlsext_channel_id_valid) {
        break;
      }
      memcpy(parg, s->s3->tlsext_channel_id, larg < 64 ? larg : 64);
      return 64;

    default:
      break;
  }

  return ret;
}

long ssl3_callback_ctrl(SSL *s, int cmd, void (*fp)(void)) {
  int ret = 0;

  if ((cmd == SSL_CTRL_SET_TMP_RSA_CB || cmd == SSL_CTRL_SET_TMP_DH_CB) &&
      !ssl_cert_inst(&s->cert)) {
    OPENSSL_PUT_ERROR(SSL, ssl3_callback_ctrl, ERR_R_MALLOC_FAILURE);
    return 0;
  }

  switch (cmd) {
    case SSL_CTRL_SET_TMP_RSA_CB:
      /* Ignore the callback; temporary RSA keys are never used. */
      break;

    case SSL_CTRL_SET_TMP_DH_CB:
      s->cert->dh_tmp_cb = (DH * (*)(SSL *, int, int))fp;
      break;

    case SSL_CTRL_SET_TMP_ECDH_CB:
      s->cert->ecdh_tmp_cb = (EC_KEY * (*)(SSL *, int, int))fp;
      break;

    case SSL_CTRL_SET_TLSEXT_DEBUG_CB:
      s->tlsext_debug_cb =
          (void (*)(SSL *, int, int, uint8_t *, int, void *))fp;
      break;

    default:
      break;
  }

  return ret;
}

long ssl3_ctx_ctrl(SSL_CTX *ctx, int cmd, long larg, void *parg) {
  CERT *cert;

  cert = ctx->cert;

  switch (cmd) {
    case SSL_CTRL_NEED_TMP_RSA:
      /* Temporary RSA keys are never used. */
      return 0;

    case SSL_CTRL_SET_TMP_RSA:
      OPENSSL_PUT_ERROR(SSL, ssl3_ctx_ctrl, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
      return 0;

    case SSL_CTRL_SET_TMP_RSA_CB:
      OPENSSL_PUT_ERROR(SSL, ssl3_ctx_ctrl, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
      return 0;

    case SSL_CTRL_SET_TMP_DH: {
      DH *new = NULL, *dh;

      dh = (DH *)parg;
      new = DHparams_dup(dh);
      if (new == NULL) {
        OPENSSL_PUT_ERROR(SSL, ssl3_ctx_ctrl, ERR_R_DH_LIB);
        return 0;
      }
      if (!(ctx->options & SSL_OP_SINGLE_DH_USE) && !DH_generate_key(new)) {
        OPENSSL_PUT_ERROR(SSL, ssl3_ctx_ctrl, ERR_R_DH_LIB);
        DH_free(new);
        return 0;
      }
      if (cert->dh_tmp != NULL) {
        DH_free(cert->dh_tmp);
      }
      cert->dh_tmp = new;
      return 1;
    }

    case SSL_CTRL_SET_TMP_DH_CB:
      OPENSSL_PUT_ERROR(SSL, ssl3_ctx_ctrl, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
      return 0;

    case SSL_CTRL_SET_TMP_ECDH: {
      EC_KEY *ecdh = NULL;

      if (parg == NULL) {
        OPENSSL_PUT_ERROR(SSL, ssl3_ctx_ctrl, ERR_R_ECDH_LIB);
        return 0;
      }
      ecdh = EC_KEY_dup((EC_KEY *)parg);
      if (ecdh == NULL) {
        OPENSSL_PUT_ERROR(SSL, ssl3_ctx_ctrl, ERR_R_EC_LIB);
        return 0;
      }
      if (!(ctx->options & SSL_OP_SINGLE_ECDH_USE) &&
          !EC_KEY_generate_key(ecdh)) {
        EC_KEY_free(ecdh);
        OPENSSL_PUT_ERROR(SSL, ssl3_ctx_ctrl, ERR_R_ECDH_LIB);
        return 0;
      }

      if (cert->ecdh_tmp != NULL) {
        EC_KEY_free(cert->ecdh_tmp);
      }
      cert->ecdh_tmp = ecdh;
      return 1;
    }

    case SSL_CTRL_SET_TMP_ECDH_CB:
      OPENSSL_PUT_ERROR(SSL, ssl3_ctx_ctrl, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
      return 0;

    case SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG:
      ctx->tlsext_servername_arg = parg;
      break;

    case SSL_CTRL_SET_TLSEXT_TICKET_KEYS:
    case SSL_CTRL_GET_TLSEXT_TICKET_KEYS: {
      uint8_t *keys = parg;
      if (!keys) {
        return 48;
      }
      if (larg != 48) {
        OPENSSL_PUT_ERROR(SSL, ssl3_ctx_ctrl, SSL_R_INVALID_TICKET_KEYS_LENGTH);
        return 0;
      }
      if (cmd == SSL_CTRL_SET_TLSEXT_TICKET_KEYS) {
        memcpy(ctx->tlsext_tick_key_name, keys, 16);
        memcpy(ctx->tlsext_tick_hmac_key, keys + 16, 16);
        memcpy(ctx->tlsext_tick_aes_key, keys + 32, 16);
      } else {
        memcpy(keys, ctx->tlsext_tick_key_name, 16);
        memcpy(keys + 16, ctx->tlsext_tick_hmac_key, 16);
        memcpy(keys + 32, ctx->tlsext_tick_aes_key, 16);
      }
      return 1;
    }

    case SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB_ARG:
      ctx->tlsext_status_arg = parg;
      return 1;
      break;

    case SSL_CTRL_SET_CURVES:
      return tls1_set_curves(&ctx->tlsext_ellipticcurvelist,
                             &ctx->tlsext_ellipticcurvelist_length, parg, larg);

    case SSL_CTRL_SET_ECDH_AUTO:
      ctx->cert->ecdh_tmp_auto = larg;
      return 1;

    case SSL_CTRL_SET_SIGALGS:
      return tls1_set_sigalgs(ctx->cert, parg, larg, 0);

    case SSL_CTRL_SET_CLIENT_SIGALGS:
      return tls1_set_sigalgs(ctx->cert, parg, larg, 1);

    case SSL_CTRL_SET_CLIENT_CERT_TYPES:
      return ssl3_set_req_cert_type(ctx->cert, parg, larg);

    case SSL_CTRL_BUILD_CERT_CHAIN:
      return ssl_build_cert_chain(ctx->cert, ctx->cert_store, larg);

    case SSL_CTRL_SET_VERIFY_CERT_STORE:
      return ssl_cert_set_cert_store(ctx->cert, parg, 0, larg);

    case SSL_CTRL_SET_CHAIN_CERT_STORE:
      return ssl_cert_set_cert_store(ctx->cert, parg, 1, larg);

    case SSL_CTRL_EXTRA_CHAIN_CERT:
      if (ctx->extra_certs == NULL) {
        ctx->extra_certs = sk_X509_new_null();
        if (ctx->extra_certs == NULL) {
          return 0;
        }
      }
      sk_X509_push(ctx->extra_certs, (X509 *)parg);
      break;

    case SSL_CTRL_GET_EXTRA_CHAIN_CERTS:
      if (ctx->extra_certs == NULL && larg == 0) {
        *(STACK_OF(X509) **)parg = ctx->cert->key->chain;
      } else {
        *(STACK_OF(X509) **)parg = ctx->extra_certs;
      }
      break;

    case SSL_CTRL_CLEAR_EXTRA_CHAIN_CERTS:
      if (ctx->extra_certs) {
        sk_X509_pop_free(ctx->extra_certs, X509_free);
        ctx->extra_certs = NULL;
      }
      break;

    case SSL_CTRL_CHAIN:
      if (larg) {
        return ssl_cert_set1_chain(ctx->cert, (STACK_OF(X509) *)parg);
      } else {
        return ssl_cert_set0_chain(ctx->cert, (STACK_OF(X509) *)parg);
      }

    case SSL_CTRL_CHAIN_CERT:
      if (larg) {
        return ssl_cert_add1_chain_cert(ctx->cert, (X509 *)parg);
      } else {
        return ssl_cert_add0_chain_cert(ctx->cert, (X509 *)parg);
      }

    case SSL_CTRL_GET_CHAIN_CERTS:
      *(STACK_OF(X509) **)parg = ctx->cert->key->chain;
      break;

    case SSL_CTRL_SELECT_CURRENT_CERT:
      return ssl_cert_select_current(ctx->cert, (X509 *)parg);

    case SSL_CTRL_CHANNEL_ID:
      ctx->tlsext_channel_id_enabled = 1;
      return 1;

    case SSL_CTRL_SET_CHANNEL_ID:
      ctx->tlsext_channel_id_enabled = 1;
      if (EVP_PKEY_bits(parg) != 256) {
        OPENSSL_PUT_ERROR(SSL, ssl3_ctx_ctrl, SSL_R_CHANNEL_ID_NOT_P256);
        break;
      }
      if (ctx->tlsext_channel_id_private) {
        EVP_PKEY_free(ctx->tlsext_channel_id_private);
      }
      ctx->tlsext_channel_id_private = EVP_PKEY_dup((EVP_PKEY *)parg);
      break;

    default:
      return 0;
  }

  return 1;
}

long ssl3_ctx_callback_ctrl(SSL_CTX *ctx, int cmd, void (*fp)(void)) {
  CERT *cert;

  cert = ctx->cert;

  switch (cmd) {
    case SSL_CTRL_SET_TMP_RSA_CB:
      /* Ignore the callback; temporary RSA keys are never used. */
      break;

    case SSL_CTRL_SET_TMP_DH_CB:
      cert->dh_tmp_cb = (DH * (*)(SSL *, int, int))fp;
      break;

    case SSL_CTRL_SET_TMP_ECDH_CB:
      cert->ecdh_tmp_cb = (EC_KEY * (*)(SSL *, int, int))fp;
      break;

    case SSL_CTRL_SET_TLSEXT_SERVERNAME_CB:
      ctx->tlsext_servername_callback = (int (*)(SSL *, int *, void *))fp;
      break;

    case SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB:
      ctx->tlsext_status_cb = (int (*)(SSL *, void *))fp;
      break;

    case SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB:
      ctx->tlsext_ticket_key_cb = (int (
          *)(SSL *, uint8_t *, uint8_t *, EVP_CIPHER_CTX *, HMAC_CTX *, int))fp;
      break;

    default:
      return 0;
  }

  return 1;
}

/* ssl3_get_cipher_by_value returns the SSL_CIPHER with value |value| or NULL
 * if none exists.
 *
 * This function needs to check if the ciphers required are actually
 * available. */
const SSL_CIPHER *ssl3_get_cipher_by_value(uint16_t value) {
  SSL_CIPHER c;

  c.id = 0x03000000L | value;
  return bsearch(&c, ssl3_ciphers, SSL3_NUM_CIPHERS, sizeof(SSL_CIPHER),
                 ssl_cipher_id_cmp);
}

/* ssl3_get_cipher_by_value returns the cipher value of |c|. */
uint16_t ssl3_get_cipher_value(const SSL_CIPHER *c) {
  unsigned long id = c->id;
  /* All ciphers are SSLv3 now. */
  assert((id & 0xff000000) == 0x03000000);
  return id & 0xffff;
}

struct ssl_cipher_preference_list_st *ssl_get_cipher_preferences(SSL *s) {
  if (s->cipher_list != NULL) {
    return s->cipher_list;
  }

  if (s->version >= TLS1_1_VERSION && s->ctx != NULL &&
      s->ctx->cipher_list_tls11 != NULL) {
    return s->ctx->cipher_list_tls11;
  }

  if (s->ctx != NULL && s->ctx->cipher_list != NULL) {
    return s->ctx->cipher_list;
  }

  return NULL;
}

const SSL_CIPHER *ssl3_choose_cipher(
    SSL *s, STACK_OF(SSL_CIPHER) * clnt,
    struct ssl_cipher_preference_list_st *server_pref) {
  const SSL_CIPHER *c, *ret = NULL;
  STACK_OF(SSL_CIPHER) *srvr = server_pref->ciphers, *prio, *allow;
  size_t i;
  int ok;
  size_t cipher_index;
  unsigned long alg_k, alg_a, mask_k, mask_a;
  /* in_group_flags will either be NULL, or will point to an array of bytes
   * which indicate equal-preference groups in the |prio| stack. See the
   * comment about |in_group_flags| in the |ssl_cipher_preference_list_st|
   * struct. */
  const uint8_t *in_group_flags;
  /* group_min contains the minimal index so far found in a group, or -1 if no
   * such value exists yet. */
  int group_min = -1;

  if (s->options & SSL_OP_CIPHER_SERVER_PREFERENCE) {
    prio = srvr;
    in_group_flags = server_pref->in_group_flags;
    allow = clnt;
  } else {
    prio = clnt;
    in_group_flags = NULL;
    allow = srvr;
  }

  ssl_get_compatible_server_ciphers(s, &mask_k, &mask_a);

  for (i = 0; i < sk_SSL_CIPHER_num(prio); i++) {
    c = sk_SSL_CIPHER_value(prio, i);

    ok = 1;

    /* Skip TLS v1.2 only ciphersuites if not supported */
    if ((c->algorithm_ssl & SSL_TLSV1_2) && !SSL_USE_TLS1_2_CIPHERS(s)) {
      ok = 0;
    }

    alg_k = c->algorithm_mkey;
    alg_a = c->algorithm_auth;

    ok = ok && (alg_k & mask_k) && (alg_a & mask_a);

    if (ok && sk_SSL_CIPHER_find(allow, &cipher_index, c)) {
      if (in_group_flags != NULL && in_group_flags[i] == 1) {
        /* This element of |prio| is in a group. Update the minimum index found
         * so far and continue looking. */
        if (group_min == -1 || (size_t)group_min > cipher_index) {
          group_min = cipher_index;
        }
      } else {
        if (group_min != -1 && (size_t)group_min < cipher_index) {
          cipher_index = group_min;
        }
        ret = sk_SSL_CIPHER_value(allow, cipher_index);
        break;
      }
    }

    if (in_group_flags != NULL && in_group_flags[i] == 0 && group_min != -1) {
      /* We are about to leave a group, but we found a match in it, so that's
       * our answer. */
      ret = sk_SSL_CIPHER_value(allow, group_min);
      break;
    }
  }

  return ret;
}

int ssl3_get_req_cert_type(SSL *s, uint8_t *p) {
  int ret = 0;
  const uint8_t *sig;
  size_t i, siglen;
  int have_rsa_sign = 0;
  int have_ecdsa_sign = 0;

  /* If we have custom certificate types set, use them */
  if (s->cert->client_certificate_types) {
    memcpy(p, s->cert->client_certificate_types,
           s->cert->num_client_certificate_types);
    return s->cert->num_client_certificate_types;
  }

  /* get configured sigalgs */
  siglen = tls12_get_psigalgs(s, &sig);
  for (i = 0; i < siglen; i += 2, sig += 2) {
    switch (sig[1]) {
      case TLSEXT_signature_rsa:
        have_rsa_sign = 1;
        break;

      case TLSEXT_signature_ecdsa:
        have_ecdsa_sign = 1;
        break;
    }
  }

  if (have_rsa_sign) {
    p[ret++] = SSL3_CT_RSA_SIGN;
  }

  /* ECDSA certs can be used with RSA cipher suites as well so we don't need to
   * check for SSL_kECDH or SSL_kEECDH. */
  if (s->version >= TLS1_VERSION && have_ecdsa_sign) {
      p[ret++] = TLS_CT_ECDSA_SIGN;
  }

  return ret;
}

static int ssl3_set_req_cert_type(CERT *c, const uint8_t *p, size_t len) {
  if (c->client_certificate_types) {
    OPENSSL_free(c->client_certificate_types);
    c->client_certificate_types = NULL;
  }

  c->num_client_certificate_types = 0;
  if (!p || !len) {
    return 1;
  }

  if (len > 0xff) {
    return 0;
  }

  c->client_certificate_types = BUF_memdup(p, len);
  if (!c->client_certificate_types) {
    return 0;
  }

  c->num_client_certificate_types = len;
  return 1;
}

int ssl3_shutdown(SSL *s) {
  int ret;

  /* Do nothing if configured not to send a close_notify. */
  if (s->quiet_shutdown) {
    s->shutdown = SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN;
    return 1;
  }

  if (!(s->shutdown & SSL_SENT_SHUTDOWN)) {
    s->shutdown |= SSL_SENT_SHUTDOWN;
    ssl3_send_alert(s, SSL3_AL_WARNING, SSL_AD_CLOSE_NOTIFY);

    /* our shutdown alert has been sent now, and if it still needs to be
     * written, s->s3->alert_dispatch will be true */
    if (s->s3->alert_dispatch) {
      return -1; /* return WANT_WRITE */
    }
  } else if (s->s3->alert_dispatch) {
    /* resend it if not sent */
    ret = s->method->ssl_dispatch_alert(s);
    if (ret == -1) {
      /* we only get to return -1 here the 2nd/Nth invocation, we must  have
       * already signalled return 0 upon a previous invoation, return
       * WANT_WRITE */
      return ret;
    }
  } else if (!(s->shutdown & SSL_RECEIVED_SHUTDOWN)) {
    /* If we are waiting for a close from our peer, we are closed */
    s->method->ssl_read_bytes(s, 0, NULL, 0, 0);
    if (!(s->shutdown & SSL_RECEIVED_SHUTDOWN)) {
      return -1; /* return WANT_READ */
    }
  }

  if (s->shutdown == (SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN) &&
      !s->s3->alert_dispatch) {
    return 1;
  } else {
    return 0;
  }
}

int ssl3_write(SSL *s, const void *buf, int len) {
  ERR_clear_system_error();
  if (s->s3->renegotiate) {
    ssl3_renegotiate_check(s);
  }

  return s->method->ssl_write_bytes(s, SSL3_RT_APPLICATION_DATA, buf, len);
}

static int ssl3_read_internal(SSL *s, void *buf, int len, int peek) {
  ERR_clear_system_error();
  if (s->s3->renegotiate) {
    ssl3_renegotiate_check(s);
  }

  return s->method->ssl_read_bytes(s, SSL3_RT_APPLICATION_DATA, buf, len, peek);
}

int ssl3_read(SSL *s, void *buf, int len) {
  return ssl3_read_internal(s, buf, len, 0);
}

int ssl3_peek(SSL *s, void *buf, int len) {
  return ssl3_read_internal(s, buf, len, 1);
}

int ssl3_renegotiate(SSL *s) {
  if (s->handshake_func == NULL) {
    return 1;
  }

  s->s3->renegotiate = 1;
  return 1;
}

int ssl3_renegotiate_check(SSL *s) {
  if (s->s3->renegotiate && s->s3->rbuf.left == 0 && s->s3->wbuf.left == 0 &&
      !SSL_in_init(s)) {
    /* if we are the server, and we have sent a 'RENEGOTIATE' message, we
     * need to go to SSL_ST_ACCEPT. */
    s->state = SSL_ST_RENEGOTIATE;
    s->s3->renegotiate = 0;
    s->s3->num_renegotiations++;
    s->s3->total_renegotiations++;
    return 1;
  }

  return 0;
}

/* If we are using default SHA1+MD5 algorithms switch to new SHA256 PRF and
 * handshake macs if required. */
long ssl_get_algorithm2(SSL *s) {
  static const unsigned long kMask = SSL_HANDSHAKE_MAC_DEFAULT | TLS1_PRF;
  long alg2 = s->s3->tmp.new_cipher->algorithm2;
  if (s->enc_method->enc_flags & SSL_ENC_FLAG_SHA256_PRF &&
      (alg2 & kMask) == kMask) {
    return SSL_HANDSHAKE_MAC_SHA256 | TLS1_PRF_SHA256;
  }
  return alg2;
}
