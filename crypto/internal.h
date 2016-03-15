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

#include <assert.h>

#if defined(__clang__) || defined(_MSC_VER)
#include <string.h>
#endif

#include <openssl/base.h>
#include <openssl/thread.h>

#if defined(_MSC_VER)
#pragma warning(push, 3)
#include <intrin.h>
#pragma warning(pop)
#if !defined(__cplusplus) || _MSC_VER < 1900
#define alignas(x) __declspec(align(x))
#define alignof __alignof
#endif
#elif !defined(__clang__) && defined(__GNUC__) && __GNUC__ == 4 && \
      __GNUC_MINOR__ <= 6
#define alignas(x) __attribute__((aligned (x)))
#define alignof __alignof__
#else
#include <stdalign.h>
#endif

#if defined(OPENSSL_NO_THREADS)
#elif defined(OPENSSL_WINDOWS)
#pragma warning(push, 3)
#include <windows.h>
#pragma warning(pop)
#else
#include <pthread.h>
#endif

#if defined(__cplusplus)
extern "C" {
#endif


#if defined(OPENSSL_X86) || defined(OPENSSL_X86_64) || defined(OPENSSL_ARM) || \
    defined(OPENSSL_AARCH64)
/* OPENSSL_cpuid_setup initializes OPENSSL_ia32cap_P. */
void OPENSSL_cpuid_setup(void);
#endif

#if defined(_MSC_VER)
#define inline __inline
#endif

#define OPENSSL_LITTLE_ENDIAN 1
#define OPENSSL_BIG_ENDIAN 2

#if defined(OPENSSL_X86_64) || defined(OPENSSL_X86) || \
    (defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && \
     __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
#define OPENSSL_ENDIAN OPENSSL_LITTLE_ENDIAN
#elif defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && \
      __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define OPENSSL_ENDIAN OPENSSL_BIG_ENDIAN
#else
#error "Cannot determine endianness"
#endif


#if defined(__GNUC__)
#define bswap_u32(x) __builtin_bswap32(x)
#define bswap_u64(x) __builtin_bswap64(x)
#elif defined(_MSC_VER)
#pragma intrinsic(_byteswap_ulong, _byteswap_uint64)
#define bswap_u32(x) _byteswap_ulong(x)
#define bswap_u64(x) _byteswap_uint64(x)
#endif


#if !defined(_MSC_VER) && defined(OPENSSL_64_BIT)
typedef __int128_t int128_t;
typedef __uint128_t uint128_t;
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


/* Thread-safe initialisation. */

#if defined(OPENSSL_NO_THREADS)
typedef uint32_t CRYPTO_once_t;
#define CRYPTO_ONCE_INIT 0
#elif defined(OPENSSL_WINDOWS)
typedef volatile LONG CRYPTO_once_t;
#define CRYPTO_ONCE_INIT 0
#else
typedef pthread_once_t CRYPTO_once_t;
#define CRYPTO_ONCE_INIT PTHREAD_ONCE_INIT
#endif

/* CRYPTO_once calls |init| exactly once per process. This is thread-safe: if
 * concurrent threads call |CRYPTO_once| with the same |CRYPTO_once_t| argument
 * then they will block until |init| completes, but |init| will have only been
 * called once.
 *
 * The |once| argument must be a |CRYPTO_once_t| that has been initialised with
 * the value |CRYPTO_ONCE_INIT|. */
OPENSSL_EXPORT void CRYPTO_once(CRYPTO_once_t *once, void (*init)(void));


/* Locks.
 *
 * |CRYPTO_MUTEX| can appear in public structures and so is defined in
 * thread.h. */

/* CRYPTO_MUTEX_init initialises |lock|. Do not use for static variables. */
OPENSSL_EXPORT void CRYPTO_MUTEX_init(CRYPTO_MUTEX *lock);

/* CRYPTO_MUTEX_lock_read locks |lock| such that other threads may also have a
 * read lock, but none may have a write lock. (On Windows, read locks are
 * actually fully exclusive.) */
OPENSSL_EXPORT void CRYPTO_MUTEX_lock_read(CRYPTO_MUTEX *lock);

/* CRYPTO_MUTEX_lock_write locks |lock| such that no other thread has any type
 * of lock on it. */
OPENSSL_EXPORT void CRYPTO_MUTEX_lock_write(CRYPTO_MUTEX *lock);

/* CRYPTO_MUTEX_unlock unlocks |lock|. */
OPENSSL_EXPORT void CRYPTO_MUTEX_unlock(CRYPTO_MUTEX *lock);

/* CRYPTO_MUTEX_cleanup releases all resources held by |lock|. */
OPENSSL_EXPORT void CRYPTO_MUTEX_cleanup(CRYPTO_MUTEX *lock);


/* Thread local storage. */

/* thread_local_data_t enumerates the types of thread-local data that can be
 * stored. */
typedef enum {
  OPENSSL_THREAD_LOCAL_ERR = 0,
  OPENSSL_THREAD_LOCAL_RAND,
  OPENSSL_THREAD_LOCAL_URANDOM_BUF,
  OPENSSL_THREAD_LOCAL_TEST,
  NUM_OPENSSL_THREAD_LOCALS
} thread_local_data_t;

/* thread_local_destructor_t is the type of a destructor function that will be
 * called when a thread exits and its thread-local storage needs to be freed. */
typedef void (*thread_local_destructor_t)(void *);

/* CRYPTO_get_thread_local gets the pointer value that is stored for the
 * current thread for the given index, or NULL if none has been set. */
OPENSSL_EXPORT void *CRYPTO_get_thread_local(thread_local_data_t value);

/* CRYPTO_set_thread_local sets a pointer value for the current thread at the
 * given index. This function should only be called once per thread for a given
 * |index|: rather than update the pointer value itself, update the data that
 * is pointed to.
 *
 * The destructor function will be called when a thread exits to free this
 * thread-local data. All calls to |CRYPTO_set_thread_local| with the same
 * |index| should have the same |destructor| argument. The destructor may be
 * called with a NULL argument if a thread that never set a thread-local
 * pointer for |index|, exits. The destructor may be called concurrently with
 * different arguments.
 *
 * This function returns one on success or zero on error. If it returns zero
 * then |destructor| has been called with |value| already. */
OPENSSL_EXPORT int CRYPTO_set_thread_local(
    thread_local_data_t index, void *value,
    thread_local_destructor_t destructor);


extern void SHA512_4(uint8_t *out, size_t out_len,
                     const uint8_t *part1, size_t part1_len,
                     const uint8_t *part2, size_t part2_len,
                     const uint8_t *part3, size_t part3_len,
                     const uint8_t *part4, size_t part4_len);

#define SHA512_DIGEST_LENGTH 64


/* from_be_u32_ptr returns the 32-bit big-endian-encoded value at |data|. */
static inline uint32_t from_be_u32_ptr(const uint8_t *data) {
#if defined(__clang__) || defined(_MSC_VER)
  /* XXX: Unlike GCC, Clang doesn't optimize compliant access to unaligned data
   * well. See https://llvm.org/bugs/show_bug.cgi?id=20605,
   * https://llvm.org/bugs/show_bug.cgi?id=17603,
   * http://blog.regehr.org/archives/702, and
   * http://blog.regehr.org/archives/1055. MSVC seems to have similar problems.
   */
  uint32_t value;
  memcpy(&value, data, sizeof(value));
#if OPENSSL_ENDIAN != OPENSSL_BIG_ENDIAN
  value = bswap_u32(value);
#endif
  return value;
#else
  return ((uint32_t)data[0] << 24) |
         ((uint32_t)data[1] << 16) |
         ((uint32_t)data[2] << 8) |
         ((uint32_t)data[3]);
#endif
}

/* from_be_u64_ptr returns the 64-bit big-endian-encoded value at |data|. */
static inline uint64_t from_be_u64_ptr(const uint8_t *data) {
#if defined(__clang__) || defined(_MSC_VER)
  /* XXX: Unlike GCC, Clang doesn't optimize compliant access to unaligned data
   * well. See https://llvm.org/bugs/show_bug.cgi?id=20605,
   * https://llvm.org/bugs/show_bug.cgi?id=17603,
   * http://blog.regehr.org/archives/702, and
   * http://blog.regehr.org/archives/1055. MSVC seems to have similar problems.
   */
  uint64_t value;
  memcpy(&value, data, sizeof(value));
#if OPENSSL_ENDIAN != OPENSSL_BIG_ENDIAN
  value = bswap_u64(value);
#endif
  return value;
#else
  return ((uint64_t)data[0] << 56) |
         ((uint64_t)data[1] << 48) |
         ((uint64_t)data[2] << 40) |
         ((uint64_t)data[3] << 32) |
         ((uint64_t)data[4] << 24) |
         ((uint64_t)data[5] << 16) |
         ((uint64_t)data[6] << 8) |
         ((uint64_t)data[7]);
#endif
}

/* to_be_u32_ptr writes the value |x| to the location |out| in big-endian
   order. */
static inline void to_be_u32_ptr(uint8_t *out, uint32_t value) {
#if defined(__clang__) || defined(_MSC_VER)
  /* XXX: Unlike GCC, Clang doesn't optimize compliant access to unaligned data
   * well. See https://llvm.org/bugs/show_bug.cgi?id=20605,
   * https://llvm.org/bugs/show_bug.cgi?id=17603,
   * http://blog.regehr.org/archives/702, and
   * http://blog.regehr.org/archives/1055. MSVC seems to have similar problems.
   */
#if  OPENSSL_ENDIAN != OPENSSL_BIG_ENDIAN
  value = bswap_u32(value);
#endif
  memcpy(out, &value, sizeof(value));
#else
  out[0] = (uint8_t)(value >> 24);
  out[1] = (uint8_t)(value >> 16);
  out[2] = (uint8_t)(value >> 8);
  out[3] = (uint8_t)value;
#endif
}

/* to_be_u64_ptr writes the value |value| to the location |out| in big-endian
   order. */
static inline void to_be_u64_ptr(uint8_t *out, uint64_t value) {
#if defined(__clang__) || defined(_MSC_VER)
  /* XXX: Unlike GCC, Clang doesn't optimize compliant access to unaligned data
   * well. See https://llvm.org/bugs/show_bug.cgi?id=20605,
   * https://llvm.org/bugs/show_bug.cgi?id=17603,
   * http://blog.regehr.org/archives/702, and
   * http://blog.regehr.org/archives/1055. MSVC seems to have similar problems.
   */
#if  OPENSSL_ENDIAN != OPENSSL_BIG_ENDIAN
  value = bswap_u64(value);
#endif
  memcpy(out, &value, sizeof(value));
#else
  out[0] = (uint8_t)(value >> 56);
  out[1] = (uint8_t)(value >> 48);
  out[2] = (uint8_t)(value >> 40);
  out[3] = (uint8_t)(value >> 32);
  out[4] = (uint8_t)(value >> 24);
  out[5] = (uint8_t)(value >> 16);
  out[6] = (uint8_t)(value >> 8);
  out[7] = (uint8_t)value;
#endif
}

/* from_be_u64 returns the native representation of the 64-bit
 * big-endian-encoded value |x|. */
static inline uint64_t from_be_u64(uint64_t x) {
#if OPENSSL_ENDIAN != OPENSSL_BIG_ENDIAN
  x = bswap_u64(x);
#endif
  return x;
}

/* to_le_u64_ptr stores the little-endian-encoded representation of |value| in
 * the 8 bytes at |out|. */
static inline void to_le_u64_ptr(uint8_t out[8], uint64_t value) {
  out[0] = (uint8_t)value;
  out[1] = (uint8_t)(value >> 8);
  out[2] = (uint8_t)(value >> 16);
  out[3] = (uint8_t)(value >> 24);
  out[4] = (uint8_t)(value >> 32);
  out[5] = (uint8_t)(value >> 40);
  out[6] = (uint8_t)(value >> 48);
  out[7] = (uint8_t)(value >> 56);
}


/* rotate_right_u64 returns |x| with its bits rotated |n| bits to the right. */
static inline uint64_t rotate_right_u64(uint64_t x, int n) {
  assert(n > 0);
  assert(n < 64);
  return (x >> n) | (x << (64 - n));
}


#if defined(__cplusplus)
}  /* extern C */
#endif

#endif  /* OPENSSL_HEADER_CRYPTO_INTERNAL_H */
