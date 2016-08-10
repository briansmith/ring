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

#include <openssl/base.h>

#include <inttypes.h>  /* for PRIu64 and friends */

#if defined(__cplusplus)
extern "C" {
#endif


/* BN provides support for working with arbitary sized integers. For example,
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
#define BN_DEC_FMT1	"%" PRIu64
#define BN_DEC_FMT2	"%019" PRIu64
#define BN_HEX_FMT1	"%" PRIx64
#elif defined(OPENSSL_32_BIT)
#define BN_ULONG uint32_t
#define BN_BITS2 32
#define BN_DEC_FMT1	"%" PRIu32
#define BN_DEC_FMT2	"%09" PRIu32
#define BN_HEX_FMT1	"%" PRIx32
#else
#error "Must define either OPENSSL_32_BIT or OPENSSL_64_BIT"
#endif


/* Allocation and freeing. */

/* BN_new creates a new, allocated BIGNUM and initialises it. */
OPENSSL_EXPORT BIGNUM *BN_new(void);

/* BN_init initialises a stack allocated |BIGNUM|. */
OPENSSL_EXPORT void BN_init(BIGNUM *bn);

/* BN_free frees the data referenced by |bn| and, if |bn| was originally
 * allocated on the heap, frees |bn| also. */
OPENSSL_EXPORT void BN_free(BIGNUM *bn);

/* BN_copy sets |dest| equal to |src| and returns |dest| or NULL on allocation
 * failure. */
OPENSSL_EXPORT BIGNUM *BN_copy(BIGNUM *dest, const BIGNUM *src);

/* BN_value_one returns a static BIGNUM with value 1. */
OPENSSL_EXPORT const BIGNUM *BN_value_one(void);


/* Basic functions. */

/* BN_num_bits returns the minimum number of bits needed to represent the
 * absolute value of |bn|. */
OPENSSL_EXPORT unsigned BN_num_bits(const BIGNUM *bn);

/* BN_num_bytes returns the minimum number of bytes needed to represent the
 * absolute value of |bn|. */
OPENSSL_EXPORT unsigned BN_num_bytes(const BIGNUM *bn);

/* BN_zero sets |bn| to zero. */
OPENSSL_EXPORT void BN_zero(BIGNUM *bn);

/* BN_one sets |bn| to one. It returns one on success or zero on allocation
 * failure. */
OPENSSL_EXPORT int BN_one(BIGNUM *bn);

/* BN_set_word sets |bn| to |value|. It returns one on success or zero on
 * allocation failure. */
OPENSSL_EXPORT int BN_set_word(BIGNUM *bn, BN_ULONG value);

/* BN_is_negative returns one if |bn| is negative and zero otherwise. */
OPENSSL_EXPORT int BN_is_negative(const BIGNUM *bn);

/* BN_get_flags returns |bn->flags| & |flags|. */
OPENSSL_EXPORT int BN_get_flags(const BIGNUM *bn, int flags);

/* BN_set_flags sets |flags| on |bn|. */
OPENSSL_EXPORT void BN_set_flags(BIGNUM *bn, int flags);


/* Conversion functions. */

/* BN_bin2bn sets |*ret| to the value of |len| bytes from |in|, interpreted as
 * a big-endian number, and returns |ret|. If |ret| is NULL then a fresh
 * |BIGNUM| is allocated and returned. It returns NULL on allocation
 * failure. */
OPENSSL_EXPORT BIGNUM *BN_bin2bn(const uint8_t *in, size_t len, BIGNUM *ret);

/* BN_bn2bin_padded serialises the absolute value of |in| to |out| as a
 * big-endian integer. The integer is padded with leading zeros up to size
 * |len|. If |len| is smaller than |BN_num_bytes|, the function fails and
 * returns 0. Otherwise, it returns 1. */
OPENSSL_EXPORT int BN_bn2bin_padded(uint8_t *out, size_t len, const BIGNUM *in);


/* Internal functions.
 *
 * These functions are useful for code that is doing low-level manipulations of
 * BIGNUM values. However, be sure that no other function in this file does
 * what you want before turning to these. */

/* bn_correct_top decrements |bn->top| until |bn->d[top-1]| is non-zero or
 * until |top| is zero. If |bn| is zero, |bn->neg| is set to zero. */
OPENSSL_EXPORT void bn_correct_top(BIGNUM *bn);

/* bn_wexpand ensures that |bn| has at least |words| works of space without
 * altering its value. It returns one on success or zero on allocation
 * failure. */
OPENSSL_EXPORT BIGNUM *bn_wexpand(BIGNUM *bn, size_t words);


/* BIGNUM pools.
 *
 * Certain BIGNUM operations need to use many temporary variables and
 * allocating and freeing them can be quite slow. Thus such opertions typically
 * take a |BN_CTX| parameter, which contains a pool of |BIGNUMs|. The |ctx|
 * argument to a public function may be NULL, in which case a local |BN_CTX|
 * will be created just for the lifetime of that call.
 *
 * A function must call |BN_CTX_start| first. Then, |BN_CTX_get| may be called
 * repeatedly to obtain temporary |BIGNUM|s. All |BN_CTX_get| calls must be made
 * before calling any other functions that use the |ctx| as an argument.
 *
 * Finally, |BN_CTX_end| must be called before returning from the function.
 * When |BN_CTX_end| is called, the |BIGNUM| pointers obtained from
 * |BN_CTX_get| become invalid. */

/* BN_CTX_new returns a new, empty BN_CTX or NULL on allocation failure. */
OPENSSL_EXPORT BN_CTX *BN_CTX_new(void);

/* BN_CTX_free frees all BIGNUMs contained in |ctx| and then frees |ctx|
 * itself. */
OPENSSL_EXPORT void BN_CTX_free(BN_CTX *ctx);

/* BN_CTX_start "pushes" a new entry onto the |ctx| stack and allows future
 * calls to |BN_CTX_get|. */
OPENSSL_EXPORT void BN_CTX_start(BN_CTX *ctx);

/* BN_CTX_get returns a new |BIGNUM|, or NULL on allocation failure. Once
 * |BN_CTX_get| has returned NULL, all future calls will also return NULL until
 * |BN_CTX_end| is called. */
OPENSSL_EXPORT BIGNUM *BN_CTX_get(BN_CTX *ctx);

/* BN_CTX_end invalidates all |BIGNUM|s returned from |BN_CTX_get| since the
 * matching |BN_CTX_start| call. */
OPENSSL_EXPORT void BN_CTX_end(BN_CTX *ctx);


/* Simple arithmetic */

/* BN_add sets |r| = |a| + |b|, where |r| may be the same pointer as either |a|
 * or |b|. It returns one on success and zero on allocation failure. */
OPENSSL_EXPORT int BN_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);

/* BN_uadd sets |r| = |a| + |b|, where |a| and |b| are non-negative and |r| may
 * be the same pointer as either |a| or |b|. It returns one on success and zero
 * on allocation failure. */
OPENSSL_EXPORT int BN_uadd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);

/* BN_sub sets |r| = |a| - |b|, where |r| may be the same pointer as either |a|
 * or |b|. It returns one on success and zero on allocation failure. */
OPENSSL_EXPORT int BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);

/* BN_usub sets |r| = |a| - |b|, where |a| and |b| are non-negative integers,
 * |b| < |a| and |r| may be the same pointer as either |a| or |b|. It returns
 * one on success and zero on allocation failure. */
OPENSSL_EXPORT int BN_usub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);

/* BN_usub_unchecked is line |BN_usub| except it doesn't assert that the
 * preconditions are true. */
OPENSSL_EXPORT int BN_usub_unchecked(BIGNUM *r, const BIGNUM *a,
                                     const BIGNUM *b);

/* BN_mul sets |r| = |a| * |b|, where |r| may be the same pointer as |a| or
 * |b|. Returns one on success and zero otherwise. */
OPENSSL_EXPORT int BN_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                          BN_CTX *ctx);

/* BN_div divides |numerator| by |divisor| and places the result in |quotient|
 * and the remainder in |rem|. Either of |quotient| or |rem| may be NULL, in
 * which case the respective value is not returned. The result is rounded
 * towards zero; thus if |numerator| is negative, the remainder will be zero or
 * negative. It returns one on success or zero on error. */
OPENSSL_EXPORT int BN_div(BIGNUM *quotient, BIGNUM *rem,
                          const BIGNUM *numerator, const BIGNUM *divisor,
                          BN_CTX *ctx);


/* Comparison functions */

/* BN_cmp returns a value less than, equal to or greater than zero if |a| is
 * less than, equal to or greater than |b|, respectively. */
OPENSSL_EXPORT int BN_cmp(const BIGNUM *a, const BIGNUM *b);

/* BN_cmp_word is like |BN_cmp| except it takes its second argument as a
 * |BN_ULONG| instead of a |BIGNUM|. */
OPENSSL_EXPORT int BN_cmp_word(const BIGNUM *a, BN_ULONG b);

/* BN_ucmp returns a value less than, equal to or greater than zero if the
 * absolute value of |a| is less than, equal to or greater than the absolute
 * value of |b|, respectively. */
OPENSSL_EXPORT int BN_ucmp(const BIGNUM *a, const BIGNUM *b);

/* BN_abs_is_word returns one if the absolute value of |bn| equals |w| and zero
 * otherwise. */
OPENSSL_EXPORT int BN_abs_is_word(const BIGNUM *bn, BN_ULONG w);

/* BN_is_zero returns one if |bn| is zero and zero otherwise. */
OPENSSL_EXPORT int BN_is_zero(const BIGNUM *bn);

/* BN_is_one returns one if |bn| equals one and zero otherwise. */
OPENSSL_EXPORT int BN_is_one(const BIGNUM *bn);

/* BN_is_odd returns one if |bn| is odd and zero otherwise. */
OPENSSL_EXPORT int BN_is_odd(const BIGNUM *bn);


/* Bitwise operations. */

/* BN_lshift sets |r| equal to |a| << n. The |a| and |r| arguments may be the
 * same |BIGNUM|. It returns one on success and zero on allocation failure. */
OPENSSL_EXPORT int BN_lshift(BIGNUM *r, const BIGNUM *a, int n);

/* BN_lshift1 sets |r| equal to |a| << 1, where |r| and |a| may be the same
 * pointer. It returns one on success and zero on allocation failure. */
OPENSSL_EXPORT int BN_lshift1(BIGNUM *r, const BIGNUM *a);

/* BN_rshift sets |r| equal to |a| >> n, where |r| and |a| may be the same
 * pointer. It returns one on success and zero on allocation failure. */
OPENSSL_EXPORT int BN_rshift(BIGNUM *r, const BIGNUM *a, int n);

/* BN_rshift1 sets |r| equal to |a| >> 1, where |r| and |a| may be the same
 * pointer. It returns one on success and zero on allocation failure. */
OPENSSL_EXPORT int BN_rshift1(BIGNUM *r, const BIGNUM *a);

/* BN_set_bit sets the |n|th, least-significant bit in |a|. For example, if |a|
 * is 2 then setting bit zero will make it 3. It returns one on success or zero
 * on allocation failure. */
OPENSSL_EXPORT int BN_set_bit(BIGNUM *a, int n);

/* BN_is_bit_set returns the value of the |n|th, least-significant bit in |a|,
 * or zero if the bit doesn't exist. */
OPENSSL_EXPORT int BN_is_bit_set(const BIGNUM *a, int n);


/* Modulo arithmetic. */

/* BN_mod is a helper macro that calls |BN_div| and discards the quotient. */
#define BN_mod(rem, numerator, divisor, ctx) \
  BN_div(NULL, (rem), (numerator), (divisor), (ctx))

/* BN_nnmod is a non-negative modulo function. It acts like |BN_mod|, but 0 <=
 * |rem| < |divisor| is always true. It returns one on success and zero on
 * error. */
OPENSSL_EXPORT int BN_nnmod(BIGNUM *rem, const BIGNUM *numerator,
                            const BIGNUM *divisor, BN_CTX *ctx);

/* BN_mod_sub_quick acts like |BN_mod_sub| but requires that |a| and |b| be
 * non-negative and less than |m|. */
OPENSSL_EXPORT int BN_mod_sub_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
                                    const BIGNUM *m);


/* Random generation. */

/* BN_rand sets |rnd| to a random number of length |bits|. If |top| is zero, the
 * most-significant bit, if any, will be set. If |top| is one, the two most
 * significant bits, if any, will be set.
 *
 * If |top| is -1 then no extra action will be taken and |BN_num_bits(rnd)| may
 * not equal |bits| if the most significant bits randomly ended up as zeros.
 *
 * If |bottom| is non-zero, the least-significant bit, if any, will be set. The
 * function returns one on success or zero otherwise. */
OPENSSL_EXPORT int BN_rand(BIGNUM *rnd, int bits, int top, int bottom,
                           RAND *rng);

extern int GFp_rand_mod(BN_ULONG *dest, const BN_ULONG *max_exclusive,
                        size_t num_limbs, RAND *rand);

/* BN_rand_range_ex sets |rnd| to a random value in
 * [1..max_exclusive). It returns one on success and zero
 * otherwise. */
OPENSSL_EXPORT int BN_rand_range_ex(BIGNUM *r, const BIGNUM *max_exclusive,
                                    RAND *rng);


/* Number theory functions */

/* BN_mod_inverse_blinded sets |out| equal to |a|^-1, mod |n|, where |n| is the
 * Montgomery modulus for |mont|. |a| must be non-negative and must be less
 * than |n|. |n| must be greater than 1. |a| is blinded (masked by a random
 * value) to protect it against side-channel attacks. On failure, if the
 * failure was caused by |a| having no inverse mod |n| then |*out_no_inverse|
 * will be set to one; otherwise it will be set to zero. */
int BN_mod_inverse_blinded(BIGNUM *out, int *out_no_inverse, const BIGNUM *a,
                           const BN_MONT_CTX *mont, RAND *rng, BN_CTX *ctx);

/* BN_mod_inverse_odd sets |out| equal to |a|^-1, mod |n|. |a| must be
 * non-negative and must be less than |n|. |n| must be odd. This function
 * shouldn't be used for secret values; use |BN_mod_inverse_blinded| instead.
 * Or, if |n| is guaranteed to be prime, use
 * |BN_mod_exp_mont_consttime(out, a, m_minus_2, m, ctx, m_mont)|, taking
 * advantage of Fermat's Little Theorem. It returns one on success or zero on
 * failure. On failure, if the failure was caused by |a| having no inverse mod
 * |n| then |*out_no_inverse| will be set to one; otherwise it will be set to
 * zero. */
int BN_mod_inverse_odd(BIGNUM *out, int *out_no_inverse, const BIGNUM *a,
                       const BIGNUM *n, BN_CTX *ctx);


/* Montgomery arithmetic. */

/* BN_MONT_CTX contains the precomputed values needed to work in a specific
 * Montgomery domain. */

/* BN_MONT_CTX_new returns a fresh BN_MONT_CTX or NULL on allocation failure. */
OPENSSL_EXPORT BN_MONT_CTX *BN_MONT_CTX_new(void);

/* BN_MONT_CTX_free frees memory associated with |mont|. */
OPENSSL_EXPORT void BN_MONT_CTX_free(BN_MONT_CTX *mont);

/* BN_MONT_CTX_set sets up a Montgomery context given the modulus, |mod|. It
 * returns one on success and zero on error. */
OPENSSL_EXPORT int BN_MONT_CTX_set(BN_MONT_CTX *mont, const BIGNUM *mod,
                                   BN_CTX *ctx);

/* BN_to_montgomery sets |ret| equal to |a| in the Montgomery domain. |a| is
 * assumed to be in the range [0, n), where |n| is the Montgomery modulus. It
 * returns one on success or zero on error. */
OPENSSL_EXPORT int BN_to_montgomery(BIGNUM *ret, const BIGNUM *a,
                                    const BN_MONT_CTX *mont, BN_CTX *ctx);

/* BN_from_montgomery sets |ret| equal to |a| * R^-1, i.e. translates values out
 * of the Montgomery domain. |a| is assumed to be in the range [0, n), where |n|
 * is the Montgomery modulus. It returns one on success or zero on error. */
OPENSSL_EXPORT int BN_from_montgomery(BIGNUM *ret, const BIGNUM *a,
                                      const BN_MONT_CTX *mont, BN_CTX *ctx);

/* BN_mod_mul_montgomery set |r| equal to |a| * |b|, in the Montgomery domain.
 * Both |a| and |b| must already be in the Montgomery domain (by
 * |BN_to_montgomery|). In particular, |a| and |b| are assumed to be in the
 * range [0, n), where |n| is the Montgomery modulus. It returns one on success
 * or zero on error. */
OPENSSL_EXPORT int BN_mod_mul_montgomery(BIGNUM *r, const BIGNUM *a,
                                         const BIGNUM *b,
                                         const BN_MONT_CTX *mont, BN_CTX *ctx);

/* BN_reduce_montgomery returns |a % n| in constant-ish time using Montgomery
 * reduction. |a| is assumed to be in the range [0, n**2), where |n| is the
 * Montgomery modulus. It returns one on success or zero on error. */
int BN_reduce_montgomery(BIGNUM *r, const BIGNUM *a,
                         const BN_MONT_CTX *mod_mont, BN_CTX *ctx);


/* Exponentiation. */

OPENSSL_EXPORT int BN_mod_exp_mont_vartime(BIGNUM *r, const BIGNUM *a,
                                           const BIGNUM *p, const BIGNUM *m,
                                           BN_CTX *ctx,
                                           const BN_MONT_CTX *mont);

OPENSSL_EXPORT int BN_mod_exp_mont_consttime(BIGNUM *rr, const BIGNUM *a,
                                             const BIGNUM *p, BN_CTX *ctx,
                                             const BN_MONT_CTX *mont);


/* Private functions */

struct bignum_st {
  BN_ULONG *d; /* Pointer to an array of 'BN_BITS2' bit chunks in little-endian
                  order. */
  int top;   /* Index of last used element in |d|, plus one. */
  int dmax;  /* Size of |d|, in words. */
  int neg;   /* one if the number is negative */
  int flags; /* bitmask of BN_FLG_* values */
};

struct bn_mont_ctx_st {
  BIGNUM RR; /* used to convert to montgomery form */
  BIGNUM N;  /* The modulus */

  /* Least significant word(s) of the "magic" Montgomery constant. When
   * |BN_MONT_CTX_N0_LIMBS == 1|, n0[1] is probably unused, however it is safer
   * to always use two elements just in case any code from another OpenSSL
   * variant that assumes |n0| has two elements is imported. */
  BN_ULONG n0[2];
};

OPENSSL_EXPORT unsigned BN_num_bits_word(BN_ULONG l);

#define BN_FLG_MALLOCED 0x01
#define BN_FLG_STATIC_DATA 0x02


#if defined(__cplusplus)
}  /* extern C */
#endif

#define BN_R_ARG2_LT_ARG3 100
#define BN_R_BAD_RECIPROCAL 101
#define BN_R_BIGNUM_TOO_LONG 102
#define BN_R_BITS_TOO_SMALL 103
#define BN_R_CALLED_WITH_EVEN_MODULUS 104
#define BN_R_DIV_BY_ZERO 105
#define BN_R_EXPAND_ON_STATIC_BIGNUM_DATA 106
#define BN_R_INPUT_NOT_REDUCED 107
#define BN_R_INVALID_RANGE 108
#define BN_R_NEGATIVE_NUMBER 109
#define BN_R_NOT_A_SQUARE 110
#define BN_R_NOT_INITIALIZED 111
#define BN_R_NO_INVERSE 112
#define BN_R_PRIVATE_KEY_TOO_LARGE 113
#define BN_R_P_IS_NOT_PRIME 114
#define BN_R_TOO_MANY_ITERATIONS 115
#define BN_R_TOO_MANY_TEMPORARY_VARIABLES 116
#define BN_R_BAD_ENCODING 117
#define BN_R_ENCODE_ERROR 118

#endif  /* OPENSSL_HEADER_BN_H */
