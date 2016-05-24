/* ====================================================================
 * Copyright (c) 1998-2005 The OpenSSL Project.  All rights reserved.
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
 *    openssl-core@OpenSSL.org.
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

#ifndef OPENSSL_HEADER_ECDSA_H
#define OPENSSL_HEADER_ECDSA_H

#include <openssl/base.h>
#include <openssl/ec.h>

#if defined(__cplusplus)
extern "C" {
#endif


/* ECDSA contains functions for signing and verifying with the Digital Signature
 * Algorithm over elliptic curves. */


/* Signing and verifing. */

/* ECDSA_verify_signed_digest verifies that the signature (|sig_r|, |sig_s|)
 * constitute a valid signature of |digest| for the public key |ec_key| for
 * the curve represented by the |EC_GROUP| created by |ec_group_new|.
 * |hash_nid| must be the identifier of the digest function used to calculate
 * |digest|. The caller must ensure that |sig_r| and |sig_s| are encodings of
 * *positive* integers. It returns one on success or zero if the signature is
 * invalid or on error. */
OPENSSL_EXPORT int ECDSA_verify_signed_digest(const EC_GROUP *group,
                                              int hash_nid,
                                              const uint8_t *digest,
                                              size_t digest_len,
                                              const uint8_t *sig_r,
                                              size_t sig_r_len,
                                              const uint8_t *sig_s,
                                              size_t sig_s_len,
                                              const uint8_t *ec_key,
                                              const size_t ec_key_len);


#if defined(__cplusplus)
}  /* extern C */
#endif

#define ECDSA_R_BAD_SIGNATURE 100
#define ECDSA_R_MISSING_PARAMETERS 101
#define ECDSA_R_NEED_NEW_SETUP_VALUES 102
#define ECDSA_R_NOT_IMPLEMENTED 103
#define ECDSA_R_RANDOM_NUMBER_GENERATION_FAILED 104
#define ECDSA_R_ENCODE_ERROR 105

#endif  /* OPENSSL_HEADER_ECDSA_H */
