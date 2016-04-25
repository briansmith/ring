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

#include <openssl/ec_key.h>

#if defined(__cplusplus)
extern "C" {
#endif


/* ECDSA contains functions for signing and verifying with the Digital Signature
 * Algorithm over elliptic curves. */


/* Signing and verifing. */

/* ECDSA_verify_signed_digest verifies that |sig_len| bytes from |sig|
 * constitute a valid signature of |digest| for the public key |ec_key| for
 * the curve represented by the |EC_GROUP| created by |ec_group_new|.
 * |hash_nid| must be the identifier of the digest function used to calculate
 * |digest|. It returns one on success or zero if the signature is invalid or
 * on error. */
OPENSSL_EXPORT int ECDSA_verify_signed_digest(const EC_GROUP *group,
                                              int hash_nid,
                                              const uint8_t *digest,
                                              size_t digest_len,
                                              const uint8_t *sig,
                                              size_t sig_len,
                                              const uint8_t *ec_key,
                                              const size_t ec_key_len);

/* ECDSA_sign signs |digest_len| bytes from |digest| with |key| and writes the
 * resulting signature to |sig|, which must have |ECDSA_size(key)| bytes of
 * space. On successful exit, |*sig_len| is set to the actual number of bytes
 * written. The |type| argument should be zero. It returns one on success and
 * zero otherwise. */
OPENSSL_EXPORT int ECDSA_sign(int type, const uint8_t *digest,
                              size_t digest_len, uint8_t *sig,
                              unsigned int *sig_len, EC_KEY *key, RAND *rng);

/* ECDSA_size returns the maximum size of an ECDSA signature using |key|. It
 * returns zero on error. */
OPENSSL_EXPORT size_t ECDSA_size(const EC_KEY *key);


/* Low-level signing and verification.
 *
 * Low-level functions handle signatures as |ECDSA_SIG| structures which allow
 * the two values in an ECDSA signature to be handled separately. */

struct ecdsa_sig_st {
  BIGNUM *r;
  BIGNUM *s;
};

/* ECDSA_SIG_new returns a fresh |ECDSA_SIG| structure or NULL on error. */
OPENSSL_EXPORT ECDSA_SIG *ECDSA_SIG_new(void);

/* ECDSA_SIG_free frees |sig| its member |BIGNUM|s. */
OPENSSL_EXPORT void ECDSA_SIG_free(ECDSA_SIG *sig);


/* ASN.1 functions. */

/* ECDSA_SIG_parse parses a DER-encoded ECDSA-Sig-Value structure from |cbs| and
 * advances |cbs|. It returns a newly-allocated |ECDSA_SIG| or NULL on error. */
OPENSSL_EXPORT ECDSA_SIG *ECDSA_SIG_parse(CBS *cbs);

/* ECDSA_SIG_from_bytes parses |in| as a DER-encoded ECDSA-Sig-Value structure.
 * It returns a newly-allocated |ECDSA_SIG| structure or NULL on error. */
OPENSSL_EXPORT ECDSA_SIG *ECDSA_SIG_from_bytes(const uint8_t *in,
                                               size_t in_len);

/* ECDSA_SIG_marshal marshals |sig| as a DER-encoded ECDSA-Sig-Value and appends
 * the result to |cbb|. It returns one on success and zero on error. */
OPENSSL_EXPORT int ECDSA_SIG_marshal(CBB *cbb, const ECDSA_SIG *sig);

/* ECDSA_SIG_to_bytes marshals |sig| as a DER-encoded ECDSA-Sig-Value and, on
 * success, sets |*out_bytes| to a newly allocated buffer containing the result
 * and returns one. Otherwise, it returns zero. The result should be freed with
 * |OPENSSL_free|. */
OPENSSL_EXPORT int ECDSA_SIG_to_bytes(uint8_t **out_bytes, size_t *out_len,
                                      const ECDSA_SIG *sig);

/* ECDSA_SIG_max_len returns the maximum length of a DER-encoded ECDSA-Sig-Value
 * structure for a group whose order is represented in |order_len| bytes, or
 * zero on overflow. */
OPENSSL_EXPORT size_t ECDSA_SIG_max_len(size_t order_len);


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
