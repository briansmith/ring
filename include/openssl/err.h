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

#ifndef OPENSSL_HEADER_ERR_H
#define OPENSSL_HEADER_ERR_H

#include <stdio.h>

#include <openssl/base.h>

#if defined(__cplusplus)
extern "C" {
#endif


/* Error queue handling functions.
 *
 * ring: No error state is maintained. The calls to |OPENSSL_PUT_ERROR| are
 * retained in the code to help with keeping *ring* in sync with upstream, but
 * they do nothing. All the functions and macros to read the error state have
 * been removed. */


/* Private functions. */

#define OPENSSL_PUT_ERROR(library, reason)
#define OPENSSL_PUT_SYSTEM_ERROR(func)
#define ERR_clear_error()


enum {
  ERR_LIB_NONE = 1,
  ERR_LIB_SYS,
  ERR_LIB_BN,
  ERR_LIB_RSA,
  ERR_LIB_DH,
  ERR_LIB_EVP,
  ERR_LIB_BUF,
  ERR_LIB_CRYPTO,
  ERR_LIB_EC,
  ERR_LIB_RAND,
  ERR_LIB_UI,
  ERR_LIB_COMP,
  ERR_LIB_ECDSA,
  ERR_LIB_ECDH,
  ERR_LIB_HMAC,
  ERR_LIB_DIGEST,
  ERR_LIB_CIPHER,
  ERR_LIB_USER,
  ERR_NUM_LIBS
};

#define ERR_R_SYS_LIB ERR_LIB_SYS
#define ERR_R_BN_LIB ERR_LIB_BN
#define ERR_R_RSA_LIB ERR_LIB_RSA
#define ERR_R_DH_LIB ERR_LIB_DH
#define ERR_R_EVP_LIB ERR_LIB_EVP
#define ERR_R_BUF_LIB ERR_LIB_BUF
#define ERR_R_CRYPTO_LIB ERR_LIB_CRYPTO
#define ERR_R_EC_LIB ERR_LIB_EC
#define ERR_R_RAND_LIB ERR_LIB_RAND
#define ERR_R_DSO_LIB ERR_LIB_DSO
#define ERR_R_UI_LIB ERR_LIB_UI
#define ERR_R_COMP_LIB ERR_LIB_COMP
#define ERR_R_ECDSA_LIB ERR_LIB_ECDSA
#define ERR_R_ECDH_LIB ERR_LIB_ECDH
#define ERR_R_STORE_LIB ERR_LIB_STORE
#define ERR_R_FIPS_LIB ERR_LIB_FIPS
#define ERR_R_CMS_LIB ERR_LIB_CMS
#define ERR_R_TS_LIB ERR_LIB_TS
#define ERR_R_HMAC_LIB ERR_LIB_HMAC
#define ERR_R_JPAKE_LIB ERR_LIB_JPAKE
#define ERR_R_USER_LIB ERR_LIB_USER
#define ERR_R_DIGEST_LIB ERR_LIB_DIGEST
#define ERR_R_CIPHER_LIB ERR_LIB_CIPHER

/* Global reasons. */
#define ERR_R_FATAL 64
#define ERR_R_MALLOC_FAILURE (1 | ERR_R_FATAL)
#define ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED (2 | ERR_R_FATAL)
#define ERR_R_PASSED_NULL_PARAMETER (3 | ERR_R_FATAL)
#define ERR_R_INTERNAL_ERROR (4 | ERR_R_FATAL)
#define ERR_R_OVERFLOW (5 | ERR_R_FATAL)


/* OPENSSL_DECLARE_ERROR_REASON is used by util/make_errors.h (which generates
 * the error defines) to recognise that an additional reason value is needed.
 * This is needed when the reason value is used outside of an
 * |OPENSSL_PUT_ERROR| macro. The resulting define will be
 * ${lib}_R_${reason}. */
#define OPENSSL_DECLARE_ERROR_REASON(lib, reason)


#if defined(__cplusplus)
} /* extern C */
#endif

#endif /* OPENSSL_HEADER_ERR_H */
