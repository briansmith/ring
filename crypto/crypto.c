/* Copyright (c) 2014, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include <stdint.h>

#include <openssl/cpu.h>

#include "internal.h"


#if !defined(OPENSSL_NO_ASM) && !defined(OPENSSL_STATIC_ARMCAP) && \
    (defined(OPENSSL_X86) || defined(OPENSSL_X86_64) || \
     defined(OPENSSL_ARM) || defined(OPENSSL_AARCH64))
/* x86, x86_64 and the ARMs need to record the result of a cpuid call for the
 * asm to work correctly, unless compiled without asm code. */
#define NEED_CPUID

#else

/* Otherwise, don't emit a static initialiser. */

#if !defined(BORINGSSL_NO_STATIC_INITIALIZER)
#define BORINGSSL_NO_STATIC_INITIALIZER
#endif

#endif  /* !OPENSSL_NO_ASM && (OPENSSL_X86 || OPENSSL_X86_64 ||
                               OPENSSL_ARM || OPENSSL_AARCH64) */


#if defined(OPENSSL_X86) || defined(OPENSSL_X86_64)
/* This value must be explicitly initialised to zero in order to work around a
 * bug in libtool or the linker on OS X.
 *
 * If not initialised then it becomes a "common symbol". When put into an
 * archive, linking on OS X will fail to resolve common symbols. By
 * initialising it to zero, it becomes a "data symbol", which isn't so
 * affected. */
uint32_t OPENSSL_ia32cap_P[4] = {0};
#elif defined(OPENSSL_ARM) || defined(OPENSSL_AARCH64)

#include <openssl/arm_arch.h>

#if defined(OPENSSL_STATIC_ARMCAP)

uint32_t OPENSSL_armcap_P =
#if defined(OPENSSL_STATIC_ARMCAP_NEON) || defined(__ARM_NEON__)
    ARMV7_NEON |
#endif
#if defined(OPENSSL_STATIC_ARMCAP_AES)
    ARMV8_AES |
#endif
#if defined(OPENSSL_STATIC_ARMCAP_SHA1)
    ARMV8_SHA1 |
#endif
#if defined(OPENSSL_STATIC_ARMCAP_SHA256)
    ARMV8_SHA256 |
#endif
#if defined(OPENSSL_STATIC_ARMCAP_PMULL)
    ARMV8_PMULL |
#endif
    0;

#else
uint32_t OPENSSL_armcap_P = 0;
#endif

#endif

/* These functions allow tests in other languages to verify that their
 * understanding of the C types matches the C compiler's understanding. */

#define DEFINE_METRICS_FUNCTIONS(ty) \
  /* Declarations to avoid -Wmissing-prototypes warnings. */ \
  OPENSSL_EXPORT uint16_t ring_##ty##_align(void); \
  OPENSSL_EXPORT uint16_t ring_##ty##_size(void); \
  \
  OPENSSL_EXPORT uint16_t ring_##ty##_align(void) { return alignof(ty); } \
  OPENSSL_EXPORT uint16_t ring_##ty##_size(void) { return sizeof(ty); }

DEFINE_METRICS_FUNCTIONS(int8_t)
DEFINE_METRICS_FUNCTIONS(uint8_t)

DEFINE_METRICS_FUNCTIONS(int16_t)
DEFINE_METRICS_FUNCTIONS(uint16_t)

DEFINE_METRICS_FUNCTIONS(int32_t)
DEFINE_METRICS_FUNCTIONS(uint32_t)

DEFINE_METRICS_FUNCTIONS(int64_t)
DEFINE_METRICS_FUNCTIONS(uint64_t)

DEFINE_METRICS_FUNCTIONS(int)

DEFINE_METRICS_FUNCTIONS(size_t)
