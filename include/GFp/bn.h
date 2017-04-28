/* Copyright (C) 1995-1997 Eric Young (eay@cryptsoft.com)
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
 * Hudson (tjh@cryptsoft.com).
 *
 */
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 *
 * Portions of the attached software ("Contribution") are developed by
 * SUN MICROSYSTEMS, INC., and are contributed to the OpenSSL project.
 *
 * The Contribution is licensed pursuant to the Eric Young open source
 * license provided above.
 *
 * The binary polynomial arithmetic software is originally written by
 * Sheueling Chang Shantz and Douglas Stebila of Sun Microsystems
 * Laboratories. */

#ifndef OPENSSL_HEADER_BN_H
#define OPENSSL_HEADER_BN_H

#include <GFp/base.h>

#if defined(__cplusplus)
extern "C" {
#endif


/* BN provides support for working with arbitrary sized integers. For example,
 * although the largest integer supported by the compiler might be 64 bits, BN
 * will allow you to work with numbers until you run out of memory. */


/* BN_ULONG is the native word size when working with big integers.
 *
 * Note: on some platforms, inttypes.h does not define print format macros in
 * C++ unless |__STDC_FORMAT_MACROS| defined. As this is a public header, bn.h
 * does not define |__STDC_FORMAT_MACROS| itself. C++ source files which use the
 * FMT macros must define it externally. */
#if defined(OPENSSL_64_BIT)
#define BN_ULONG uint64_t
#define BN_BITS2 64
#elif defined(OPENSSL_32_BIT)
#define BN_ULONG uint32_t
#define BN_BITS2 32
#else
#error "Must define either OPENSSL_32_BIT or OPENSSL_64_BIT"
#endif


/* Allocation and freeing. */

/* GFp_BN_init initialises a stack allocated |BIGNUM|. */
OPENSSL_EXPORT void GFp_BN_init(BIGNUM *bn);

/* GFp_BN_free frees the data referenced by |bn| and, if |bn| was originally
 * allocated on the heap, frees |bn| also. */
OPENSSL_EXPORT void GFp_BN_free(BIGNUM *bn);

/* GFp_BN_copy sets |dest| equal to |src| and returns one on success or zero on
 * failure. */
OPENSSL_EXPORT int GFp_BN_copy(BIGNUM *dest, const BIGNUM *src);


/* Basic functions. */

/* GFp_BN_zero sets |bn| to zero. */
OPENSSL_EXPORT void GFp_BN_zero(BIGNUM *bn);


/* Internal functions.
 *
 * These functions are useful for code that is doing low-level manipulations of
 * BIGNUM values. However, be sure that no other function in this file does
 * what you want before turning to these. */

/* bn_correct_top decrements |bn->top| until |bn->d[top-1]| is non-zero or
 * until |top| is zero. */
OPENSSL_EXPORT void GFp_bn_correct_top(BIGNUM *bn);

/* bn_wexpand ensures that |bn| has at least |words| works of space without
 * altering its value. It returns one on success and zero on allocation
 * failure. */
OPENSSL_EXPORT int GFp_bn_wexpand(BIGNUM *bn, size_t words);


/* Simple arithmetic */

/* GFp_BN_mul_no_alias sets |r| = |a| * |b|, where |r| must not be the same pointer
 * as |a| or |b|. Returns one on success and zero otherwise. */
OPENSSL_EXPORT int GFp_BN_mul_no_alias(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);


/* Comparison functions */

/* GFp_BN_is_odd returns one if |bn| is odd and zero otherwise. */
OPENSSL_EXPORT int GFp_BN_is_odd(const BIGNUM *bn);


/* Bitwise operations. */

/* GFp_BN_is_bit_set returns the value of the |n|th, least-significant bit in
 * |a|, or zero if the bit doesn't exist. */
OPENSSL_EXPORT int GFp_BN_is_bit_set(const BIGNUM *a, int n);


/* Modulo arithmetic. */

/* GFp_BN_mod_mul_mont set |r| equal to |a| * |b|, in the Montgomery domain.
 * Both |a| and |b| must already be in the Montgomery domain (by
 * |GFp_BN_to_mont|). In particular, |a| and |b| are assumed to be in the range
 * [0, n), where |n| is the Montgomery modulus. It returns one on success or
 * zero on error. */
OPENSSL_EXPORT int GFp_BN_mod_mul_mont(
    BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *n,
    const BN_ULONG n0[/*BN_MONT_CTX_N0_LIMBS*/]);

/* GFp_BN_reduce_montgomery returns |a % n| in constant-ish time using
 * Montgomery reduction. |a| is assumed to be in the range [0, n**2), where |n|
 * is the Montgomery modulus. It returns one on success or zero on error. */
int GFp_BN_reduce_mont(BIGNUM *r, const BIGNUM *a, const BIGNUM *n,
                       const BN_ULONG n0[/*BN_MONT_CTX_N0_LIMBS*/]);


/* Exponentiation. */

OPENSSL_EXPORT int GFp_BN_mod_exp_mont_consttime(
    BIGNUM *rr, const BIGNUM *a_mont, const BIGNUM *p, size_t p_bits,
    const BIGNUM *one_mont, const BIGNUM *n,
    const BN_ULONG n0[/*BN_MONT_CTX_N0_LIMBS*/]);


/* Private functions */

/* Keep in sync with `BIGNUM` in `ring::rsa::bigint`. */
struct bignum_st {
  BN_ULONG *d; /* Pointer to an array of 'BN_BITS2' bit chunks in little-endian
                  order. */
  int top;   /* Index of last used element in |d|, plus one. */
  int dmax;  /* Size of |d|, in words. */
  int flags; /* bitmask of BN_FLG_* values */
};

#define BN_FLG_MALLOCED 0x01
#define BN_FLG_STATIC_DATA 0x02


#if defined(__cplusplus)
}  /* extern C */
#endif

#endif  /* OPENSSL_HEADER_BN_H */
