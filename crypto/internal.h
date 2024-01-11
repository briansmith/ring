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

#include <ring-core/base.h> // Must be first.

#include "ring-core/arm_arch.h"
#include "ring-core/check.h"

#if defined(__clang__)
// Don't require prototypes for functions defined in C that are only
// used from Rust.
#pragma GCC diagnostic ignored "-Wmissing-prototypes"
#endif

#if defined(__GNUC__) && \
    (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__) < 40800
// |alignas| and |alignof| were added in C11. GCC added support in version 4.8.
// Testing for __STDC_VERSION__/__cplusplus doesn't work because 4.7 already
// reports support for C11.
#define alignas(x) __attribute__ ((aligned (x)))
#elif defined(_MSC_VER) && !defined(__clang__)
#define alignas(x) __declspec(align(x))
#else
#include <stdalign.h>
#endif

#if defined(__clang__) || defined(__GNUC__)
#define RING_NOINLINE __attribute__((noinline))
#elif defined(_MSC_VER)
#define RING_NOINLINE __declspec(noinline)
#else
#define RING_NOINLINE
#endif

// Some C compilers require a useless cast when dealing with arrays for the
// reason explained in
// https://gustedt.wordpress.com/2011/02/12/const-and-arrays/
#if defined(__clang__) || defined(_MSC_VER)
#define RING_CORE_POINTLESS_ARRAY_CONST_CAST(cast)
#else
#define RING_CORE_POINTLESS_ARRAY_CONST_CAST(cast) cast
#endif

// `uint8_t` isn't guaranteed to be 'unsigned char' and only 'char' and
// 'unsigned char' are allowed to alias according to ISO C.
typedef unsigned char aliasing_uint8_t;

#if (!defined(_MSC_VER) || defined(__clang__)) && defined(OPENSSL_64_BIT)
#define BORINGSSL_HAS_UINT128
typedef __int128_t int128_t;
typedef __uint128_t uint128_t;
#endif

// Pointer utility functions.

// buffers_alias returns one if |a| and |b| alias and zero otherwise.
static inline int buffers_alias(const void *a, size_t a_bytes,
                                const void *b, size_t b_bytes) {
  // Cast |a| and |b| to integers. In C, pointer comparisons between unrelated
  // objects are undefined whereas pointer to integer conversions are merely
  // implementation-defined. We assume the implementation defined it in a sane
  // way.
  uintptr_t a_u = (uintptr_t)a;
  uintptr_t b_u = (uintptr_t)b;
  return a_u + a_bytes > b_u && b_u + b_bytes > a_u;
}


// Constant-time utility functions.
//
// The following methods return a bitmask of all ones (0xff...f) for true and 0
// for false. This is useful for choosing a value based on the result of a
// conditional in constant time. For example,
//
// if (a < b) {
//   c = a;
// } else {
//   c = b;
// }
//
// can be written as
//
// crypto_word_t lt = constant_time_lt_w(a, b);
// c = constant_time_select_w(lt, a, b);

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#endif
#if defined(_MSC_VER) && !defined(__clang__)
#pragma warning(push)
// '=': conversion from 'crypto_word_t' to 'uint8_t', possible loss of data
#pragma warning(disable: 4242)
//  'initializing': conversion from 'crypto_word_t' to 'uint8_t', ...
#pragma warning(disable: 4244)
#endif

// crypto_word_t is the type that most constant-time functions use. Ideally we
// would like it to be |size_t|, but NaCl builds in 64-bit mode with 32-bit
// pointers, which means that |size_t| can be 32 bits when |BN_ULONG| is 64
// bits. Since we want to be able to do constant-time operations on a
// |BN_ULONG|, |crypto_word_t| is defined as an unsigned value with the native
// word length.
#if defined(OPENSSL_64_BIT)
typedef uint64_t crypto_word_t;
#define CRYPTO_WORD_BITS (64u)
#elif defined(OPENSSL_32_BIT)
typedef uint32_t crypto_word_t;
#define CRYPTO_WORD_BITS (32u)
#else
#error "Must define either OPENSSL_32_BIT or OPENSSL_64_BIT"
#endif

#define CONSTTIME_TRUE_W ~((crypto_word_t)0)
#define CONSTTIME_FALSE_W ((crypto_word_t)0)

// value_barrier_w returns |a|, but prevents GCC and Clang from reasoning about
// the returned value. This is used to mitigate compilers undoing constant-time
// code, until we can express our requirements directly in the language.
//
// Note the compiler is aware that |value_barrier_w| has no side effects and
// always has the same output for a given input. This allows it to eliminate
// dead code, move computations across loops, and vectorize.
static inline crypto_word_t value_barrier_w(crypto_word_t a) {
#if defined(__GNUC__) || defined(__clang__)
  __asm__("" : "+r"(a) : /* no inputs */);
#endif
  return a;
}

// |value_barrier_u8| could be defined as above, but compilers other than
// clang seem to still materialize 0x00..00MM instead of reusing 0x??..??MM.

// constant_time_msb_w returns the given value with the MSB copied to all the
// other bits.
static inline crypto_word_t constant_time_msb_w(crypto_word_t a) {
  return 0u - (a >> (sizeof(a) * 8 - 1));
}

// constant_time_is_zero returns 0xff..f if a == 0 and 0 otherwise.
static inline crypto_word_t constant_time_is_zero_w(crypto_word_t a) {
  // Here is an SMT-LIB verification of this formula:
  //
  // (define-fun is_zero ((a (_ BitVec 32))) (_ BitVec 32)
  //   (bvand (bvnot a) (bvsub a #x00000001))
  // )
  //
  // (declare-fun a () (_ BitVec 32))
  //
  // (assert (not (= (= #x00000001 (bvlshr (is_zero a) #x0000001f)) (= a #x00000000))))
  // (check-sat)
  // (get-model)
  return constant_time_msb_w(~a & (a - 1));
}

static inline crypto_word_t constant_time_is_nonzero_w(crypto_word_t a) {
  return ~constant_time_is_zero_w(a);
}

// constant_time_eq_w returns 0xff..f if a == b and 0 otherwise.
static inline crypto_word_t constant_time_eq_w(crypto_word_t a,
                                               crypto_word_t b) {
  return constant_time_is_zero_w(a ^ b);
}

// constant_time_select_w returns (mask & a) | (~mask & b). When |mask| is all
// 1s or all 0s (as returned by the methods above), the select methods return
// either |a| (if |mask| is nonzero) or |b| (if |mask| is zero).
static inline crypto_word_t constant_time_select_w(crypto_word_t mask,
                                                   crypto_word_t a,
                                                   crypto_word_t b) {
  // Clang recognizes this pattern as a select. While it usually transforms it
  // to a cmov, it sometimes further transforms it into a branch, which we do
  // not want.
  //
  // Hiding the value of the mask from the compiler evades this transformation.
  mask = value_barrier_w(mask);
  return (mask & a) | (~mask & b);
}

// constant_time_select_8 acts like |constant_time_select| but operates on
// 8-bit values.
static inline uint8_t constant_time_select_8(crypto_word_t mask, uint8_t a,
                                             uint8_t b) {
  // |mask| is a word instead of |uint8_t| to avoid materializing 0x000..0MM
  // Making both |mask| and its value barrier |uint8_t| would allow the compiler
  // to materialize 0x????..?MM instead, but only clang is that clever.
  // However, vectorization of bitwise operations seems to work better on
  // |uint8_t| than a mix of |uint64_t| and |uint8_t|, so |m| is cast to
  // |uint8_t| after the value barrier but before the bitwise operations.
  uint8_t m = value_barrier_w(mask);
  return (m & a) | (~m & b);
}

// constant_time_conditional_memcpy copies |n| bytes from |src| to |dst| if
// |mask| is 0xff..ff and does nothing if |mask| is 0. The |n|-byte memory
// ranges at |dst| and |src| must not overlap, as when calling |memcpy|.
static inline void constant_time_conditional_memcpy(void *dst, const void *src,
                                                    const size_t n,
                                                    const crypto_word_t mask) {
  debug_assert_nonsecret(!buffers_alias(dst, n, src, n));
  uint8_t *out = (uint8_t *)dst;
  const uint8_t *in = (const uint8_t *)src;
  for (size_t i = 0; i < n; i++) {
    out[i] = constant_time_select_8(mask, in[i], out[i]);
  }
}

// constant_time_conditional_memxor xors |n| bytes from |src| to |dst| if
// |mask| is 0xff..ff and does nothing if |mask| is 0. The |n|-byte memory
// ranges at |dst| and |src| must not overlap, as when calling |memcpy|.
static inline void constant_time_conditional_memxor(void *dst, const void *src,
                                                    const size_t n,
                                                    const crypto_word_t mask) {
  debug_assert_nonsecret(!buffers_alias(dst, n, src, n));
  aliasing_uint8_t *out = dst;
  const aliasing_uint8_t *in = src;
  for (size_t i = 0; i < n; i++) {
    out[i] ^= value_barrier_w(mask) & in[i];
  }
}

#if defined(_MSC_VER) && !defined(__clang__)
// '=': conversion from 'int64_t' to 'int32_t', possible loss of data
#pragma warning(pop)
#endif
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

#if defined(BORINGSSL_CONSTANT_TIME_VALIDATION)

// CONSTTIME_SECRET takes a pointer and a number of bytes and marks that region
// of memory as secret. Secret data is tracked as it flows to registers and
// other parts of a memory. If secret data is used as a condition for a branch,
// or as a memory index, it will trigger warnings in valgrind.
#define CONSTTIME_SECRET(ptr, len) VALGRIND_MAKE_MEM_UNDEFINED(ptr, len)

// CONSTTIME_DECLASSIFY takes a pointer and a number of bytes and marks that
// region of memory as public. Public data is not subject to constant-time
// rules.
#define CONSTTIME_DECLASSIFY(ptr, len) VALGRIND_MAKE_MEM_DEFINED(ptr, len)

#else

#define CONSTTIME_SECRET(ptr, len)
#define CONSTTIME_DECLASSIFY(ptr, len)

#endif  // BORINGSSL_CONSTANT_TIME_VALIDATION

static inline crypto_word_t constant_time_declassify_w(crypto_word_t v) {
  // Return |v| through a value barrier to be safe. Valgrind-based constant-time
  // validation is partly to check the compiler has not undone any constant-time
  // work. Any place |BORINGSSL_CONSTANT_TIME_VALIDATION| influences
  // optimizations, this validation is inaccurate.
  //
  // However, by sending pointers through valgrind, we likely inhibit escape
  // analysis. On local variables, particularly booleans, we likely
  // significantly impact optimizations.
  //
  // Thus, to be safe, stick a value barrier, in hopes of comparably inhibiting
  // compiler analysis.
  CONSTTIME_DECLASSIFY(&v, sizeof(v));
  return value_barrier_w(v);
}

// Endianness conversions.

#if defined(__GNUC__) && __GNUC__ >= 2
static inline uint32_t CRYPTO_bswap4(uint32_t x) {
  return __builtin_bswap32(x);
}

static inline uint64_t CRYPTO_bswap8(uint64_t x) {
  return __builtin_bswap64(x);
}
#elif defined(_MSC_VER)
#pragma warning(push, 3)
#include <stdlib.h>
#pragma warning(pop)
#pragma intrinsic(_byteswap_uint64, _byteswap_ulong)
static inline uint32_t CRYPTO_bswap4(uint32_t x) {
  return _byteswap_ulong(x);
}

static inline uint64_t CRYPTO_bswap8(uint64_t x) {
  return _byteswap_uint64(x);
}
#endif

#if !defined(RING_CORE_NOSTDLIBINC)
#include <string.h>
#endif

static inline void *OPENSSL_memcpy(void *dst, const void *src, size_t n) {
#if !defined(RING_CORE_NOSTDLIBINC)
  if (n == 0) {
    return dst;
  }
  return memcpy(dst, src, n);
#else
  aliasing_uint8_t *d = dst;
  const aliasing_uint8_t *s = src;
  for (size_t i = 0; i < n; ++i) {
    d[i] = s[i];
  }
  return dst;
#endif
}

static inline void *OPENSSL_memset(void *dst, int c, size_t n) {
#if !defined(RING_CORE_NOSTDLIBINC)
  if (n == 0) {
    return dst;
  }
  return memset(dst, c, n);
#else
  aliasing_uint8_t *d = dst;
  for (size_t i = 0; i < n; ++i) {
    d[i] = (aliasing_uint8_t)c;
  }
  return dst;
#endif
}


// Loads and stores.
//
// The following functions load and store sized integers with the specified
// endianness. They use |memcpy|, and so avoid alignment or strict aliasing
// requirements on the input and output pointers.

#if defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__)
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define RING_BIG_ENDIAN
#endif
#endif

static inline uint32_t CRYPTO_load_u32_le(const void *in) {
  uint32_t v;
  OPENSSL_memcpy(&v, in, sizeof(v));
#if defined(RING_BIG_ENDIAN)
  return CRYPTO_bswap4(v);
#else
  return v;
#endif
}

static inline void CRYPTO_store_u32_le(void *out, uint32_t v) {
#if defined(RING_BIG_ENDIAN)
  v = CRYPTO_bswap4(v);
#endif
  OPENSSL_memcpy(out, &v, sizeof(v));
}

static inline uint32_t CRYPTO_load_u32_be(const void *in) {
  uint32_t v;
  OPENSSL_memcpy(&v, in, sizeof(v));
#if !defined(RING_BIG_ENDIAN)
  return CRYPTO_bswap4(v);
#else
  return v;
#endif
}

static inline void CRYPTO_store_u32_be(void *out, uint32_t v) {
#if !defined(RING_BIG_ENDIAN)
  v = CRYPTO_bswap4(v);
#endif
  OPENSSL_memcpy(out, &v, sizeof(v));
}

static inline uint64_t CRYPTO_load_u64_le(const void *in) {
  uint64_t v;
  OPENSSL_memcpy(&v, in, sizeof(v));
#if defined(RING_BIG_ENDIAN)
  return CRYPTO_bswap8(v);
#else
  return v;
#endif
}

static inline void CRYPTO_store_u64_le(void *out, uint64_t v) {
#if defined(RING_BIG_ENDIAN)
  v = CRYPTO_bswap8(v);
#endif
  OPENSSL_memcpy(out, &v, sizeof(v));
}

static inline uint64_t CRYPTO_load_u64_be(const void *ptr) {
  uint64_t ret;
  OPENSSL_memcpy(&ret, ptr, sizeof(ret));
#if !defined(RING_BIG_ENDIAN)
  return CRYPTO_bswap8(ret);
#else
  return ret;
#endif
}

static inline void CRYPTO_store_u64_be(void *out, uint64_t v) {
#if !defined(RING_BIG_ENDIAN)
  v = CRYPTO_bswap8(v);
#endif
  OPENSSL_memcpy(out, &v, sizeof(v));
}


// Runtime CPU feature support

#if defined(OPENSSL_X86) || defined(OPENSSL_X86_64)
// OPENSSL_ia32cap_P contains the Intel CPUID bits when running on an x86 or
// x86-64 system.
//
//   Index 0:
//     EDX for CPUID where EAX = 1
//     Bit 20 is always zero
//     Bit 28 is adjusted to reflect whether the data cache is shared between
//       multiple logical cores
//     Bit 30 is used to indicate an Intel CPU
//   Index 1:
//     ECX for CPUID where EAX = 1
//     Bit 11 is used to indicate AMD XOP support, not SDBG
//   Index 2:
//     EBX for CPUID where EAX = 7
//   Index 3:
//     ECX for CPUID where EAX = 7
//
// Note: the CPUID bits are pre-adjusted for the OSXSAVE bit and the YMM and XMM
// bits in XCR0, so it is not necessary to check those.
extern uint32_t OPENSSL_ia32cap_P[4];
#endif

#endif  // OPENSSL_HEADER_CRYPTO_INTERNAL_H
