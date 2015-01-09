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
 * Copyright (c) 1998-2001 The OpenSSL Project.  All rights reserved.
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

#ifndef OPENSSL_HEADER_CRYPTO_INTERNAL_H
#define OPENSSL_HEADER_CRYPTO_INTERNAL_H

#include <openssl/ex_data.h>

#if defined(__cplusplus)
extern "C" {
#endif


/* st_CRYPTO_EX_DATA_IMPL contains an ex_data implementation. See the comments
 * in ex_data.h for details of the behaviour of each of the functions. */
struct st_CRYPTO_EX_DATA_IMPL {
  int (*new_class)(void);
  void (*cleanup)(void);

  int (*get_new_index)(int class_value, long argl, void *argp,
                       CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func,
                       CRYPTO_EX_free *free_func);
  int (*new_ex_data)(int class_value, void *obj, CRYPTO_EX_DATA *ad);
  int (*dup_ex_data)(int class_value, CRYPTO_EX_DATA *to,
                     const CRYPTO_EX_DATA *from);
  void (*free_ex_data)(int class_value, void *obj, CRYPTO_EX_DATA *ad);
};


#if defined(_MSC_VER)
#define OPENSSL_U64(x) x##UI64
#else

#if defined(OPENSSL_64_BIT)
#define OPENSSL_U64(x) x##UL
#else
#define OPENSSL_U64(x) x##ULL
#endif

#endif  /* defined(_MSC_VER) */

#if defined(OPENSSL_X86) || defined(OPENSSL_X86_64) || defined(OPENSSL_ARM) || \
    defined(OPENSSL_AARCH64)
/* OPENSSL_cpuid_setup initializes OPENSSL_ia32cap_P. */
void OPENSSL_cpuid_setup(void);
#endif

#if !defined(inline)
#define inline __inline
#endif


/* Constant-time utility functions.
 *
 * The following methods return a bitmask of all ones (0xff...f) for true and 0
 * for false. This is useful for choosing a value based on the result of a
 * conditional in constant time. For example,
 *
 * if (a < b) {
 *   c = a;
 * } else {
 *   c = b;
 * }
 *
 * can be written as
 *
 * unsigned int lt = constant_time_lt(a, b);
 * c = constant_time_select(lt, a, b); */

/* constant_time_msb returns the given value with the MSB copied to all the
 * other bits. */
static inline unsigned int constant_time_msb(unsigned int a) {
  return (unsigned int)((int)(a) >> (sizeof(int) * 8 - 1));
}

/* constant_time_lt returns 0xff..f if a < b and 0 otherwise. */
static inline unsigned int constant_time_lt(unsigned int a, unsigned int b) {
  /* Consider the two cases of the problem:
   *   msb(a) == msb(b): a < b iff the MSB of a - b is set.
   *   msb(a) != msb(b): a < b iff the MSB of b is set.
   *
   * If msb(a) == msb(b) then the following evaluates as:
   *   msb(a^((a^b)|((a-b)^a))) ==
   *   msb(a^((a-b) ^ a))       ==   (because msb(a^b) == 0)
   *   msb(a^a^(a-b))           ==   (rearranging)
   *   msb(a-b)                      (because ∀x. x^x == 0)
   *
   * Else, if msb(a) != msb(b) then the following evaluates as:
   *   msb(a^((a^b)|((a-b)^a))) ==
   *   msb(a^(𝟙 | ((a-b)^a)))   ==   (because msb(a^b) == 1 and 𝟙
   *                                  represents a value s.t. msb(𝟙) = 1)
   *   msb(a^𝟙)                 ==   (because ORing with 1 results in 1)
   *   msb(b)
   *
   *
   * Here is an SMT-LIB verification of this formula:
   *
   * (define-fun lt ((a (_ BitVec 32)) (b (_ BitVec 32))) (_ BitVec 32)
   *   (bvxor a (bvor (bvxor a b) (bvxor (bvsub a b) a)))
   * )
   *
   * (declare-fun a () (_ BitVec 32))
   * (declare-fun b () (_ BitVec 32))
   *
   * (assert (not (= (= #x00000001 (bvlshr (lt a b) #x0000001f)) (bvult a b))))
   * (check-sat)
   * (get-model)
   */
  return constant_time_msb(a^((a^b)|((a-b)^a)));
}

/* constant_time_lt_8 acts like |constant_time_lt| but returns an 8-bit mask. */
static inline uint8_t constant_time_lt_8(unsigned int a, unsigned int b) {
  return (uint8_t)(constant_time_lt(a, b));
}

/* constant_time_gt returns 0xff..f if a >= b and 0 otherwise. */
static inline unsigned int constant_time_ge(unsigned int a, unsigned int b) {
  return ~constant_time_lt(a, b);
}

/* constant_time_ge_8 acts like |constant_time_ge| but returns an 8-bit mask. */
static inline uint8_t constant_time_ge_8(unsigned int a, unsigned int b) {
  return (uint8_t)(constant_time_ge(a, b));
}

/* constant_time_is_zero returns 0xff..f if a == 0 and 0 otherwise. */
static inline unsigned int constant_time_is_zero(unsigned int a) {
  /* Here is an SMT-LIB verification of this formula:
   *
   * (define-fun is_zero ((a (_ BitVec 32))) (_ BitVec 32)
   *   (bvand (bvnot a) (bvsub a #x00000001))
   * )
   *
   * (declare-fun a () (_ BitVec 32))
   *
   * (assert (not (= (= #x00000001 (bvlshr (is_zero a) #x0000001f)) (= a #x00000000))))
   * (check-sat)
   * (get-model)
   */
  return constant_time_msb(~a & (a - 1));
}

/* constant_time_is_zero_8 acts like constant_time_is_zero but returns an 8-bit
 * mask. */
static inline uint8_t constant_time_is_zero_8(unsigned int a) {
  return (uint8_t)(constant_time_is_zero(a));
}

/* constant_time_eq returns 0xff..f if a == b and 0 otherwise. */
static inline unsigned int constant_time_eq(unsigned int a, unsigned int b) {
  return constant_time_is_zero(a ^ b);
}

/* constant_time_eq_8 acts like |constant_time_eq| but returns an 8-bit mask. */
static inline uint8_t constant_time_eq_8(unsigned int a, unsigned int b) {
  return (uint8_t)(constant_time_eq(a, b));
}

/* constant_time_eq_int acts like |constant_time_eq| but works on int values. */
static inline unsigned int constant_time_eq_int(int a, int b) {
  return constant_time_eq((unsigned)(a), (unsigned)(b));
}

/* constant_time_eq_int_8 acts like |constant_time_eq_int| but returns an 8-bit
 * mask. */
static inline uint8_t constant_time_eq_int_8(int a, int b) {
  return constant_time_eq_8((unsigned)(a), (unsigned)(b));
}

/* constant_time_select returns (mask & a) | (~mask & b). When |mask| is all 1s
 * or all 0s (as returned by the methods above), the select methods return
 * either |a| (if |mask| is nonzero) or |b| (if |mask| is zero). */
static inline unsigned int constant_time_select(unsigned int mask,
                                                unsigned int a, unsigned int b) {
  return (mask & a) | (~mask & b);
}

/* constant_time_select_8 acts like |constant_time_select| but operates on
 * 8-bit values. */
static inline uint8_t constant_time_select_8(uint8_t mask, uint8_t a,
                                             uint8_t b) {
  return (uint8_t)(constant_time_select(mask, a, b));
}

/* constant_time_select_int acts like |constant_time_select| but operates on
 * ints. */
static inline int constant_time_select_int(unsigned int mask, int a, int b) {
  return (int)(constant_time_select(mask, (unsigned)(a), (unsigned)(b)));
}


#if defined(__cplusplus)
}  /* extern C */
#endif

#endif  /* OPENSSL_HEADER_CRYPTO_INTERNAL_H */
