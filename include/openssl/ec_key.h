/* Originally written by Bodo Moeller for the OpenSSL project.
 * ====================================================================
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
 * The elliptic curve binary polynomial software is originally written by
 * Sheueling Chang Shantz and Douglas Stebila of Sun Microsystems
 * Laboratories. */

#ifndef OPENSSL_HEADER_EC_KEY_H
#define OPENSSL_HEADER_EC_KEY_H

#include <openssl/base.h>

#include <openssl/ec.h>

#if defined(__cplusplus)
extern "C" {
#endif


/* ec_key.h contains functions that handle elliptic-curve points that are
 * public/private keys. */


/* EC key objects. */

/* EC_KEY_new_ex returns a fresh |EC_KEY| object for the group that is created
 * by the function |ec_group_new|. |ec_group_new| should be
 * |EC_GROUP_new_p256|, |EC_GROUP_new_p384|, etc. */
EC_KEY *EC_KEY_new_ex(EC_GROUP_new_fn ec_group_new);

/* EC_KEY_free frees all the data owned by |key| and |key| itself. */
OPENSSL_EXPORT void EC_KEY_free(EC_KEY *key);

/* EC_KEY_up_ref increases the reference count of |key|. It returns one on
 * success and zero otherwise. */
OPENSSL_EXPORT int EC_KEY_up_ref(EC_KEY *key);

/* EC_KEY_get0_group returns a pointer to the |EC_GROUP| object inside |key|. */
OPENSSL_EXPORT const EC_GROUP *EC_KEY_get0_group(const EC_KEY *key);

/* EC_KEY_get0_private_key returns a pointer to the private key inside |key|. */
OPENSSL_EXPORT const BIGNUM *EC_KEY_get0_private_key(const EC_KEY *key);

/* EC_KEY_get0_public_key returns a pointer to the public key point inside
 * |key|. */
OPENSSL_EXPORT const EC_POINT *EC_KEY_get0_public_key(const EC_KEY *key);

/* EC_KEY_set_public_key sets the public key of |key| to |pub|, by copying it.
 * It returns one on success and zero otherwise. */
OPENSSL_EXPORT int EC_KEY_set_public_key(EC_KEY *key, const EC_POINT *pub);

/* EC_KEY_check_key performs several checks on |key| (possibly including an
 * expensive check that the public key is in the primary subgroup). It returns
 * one if all checks pass and zero otherwise. If it returns zero then detail
 * about the problem can be found on the error stack. */
OPENSSL_EXPORT int EC_KEY_check_key(const EC_KEY *key);

/* EC_KEY_public_key_to_oct serialises the public key point of |key| into the
 * X9.62 uncompressed form at |out|, writing at most |out_len| bytes. It
 * returns the number of bytes written or zero on error if |out| is non-NULL,
 * else the number of bytes needed. */
OPENSSL_EXPORT size_t EC_KEY_public_key_to_oct(const EC_KEY *key, uint8_t *out,
                                               size_t out_len);


/* Key generation. */

/* EC_KEY_generate_key generates a random, private key, calculates the
 * corresponding public key and stores both in |key|. It returns one on success
 * or zero otherwise. */
OPENSSL_EXPORT int EC_KEY_generate_key(EC_KEY *key);

/* EC_KEY_generate_key_ex generates a random private key and calculates the
 * corresponding public key. It returns the generated key pair on success or
 * NULL on failure. */
OPENSSL_EXPORT EC_KEY *EC_KEY_generate_key_ex(EC_GROUP_new_fn ec_group_new);


#if defined(__cplusplus)
}  /* extern C */
#endif

#endif  /* OPENSSL_HEADER_EC_KEY_H */
