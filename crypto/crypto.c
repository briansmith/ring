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

#if defined(__linux__)
#define _GNU_SOURCE
#endif

#include <stdint.h>

#include <GFp/cpu.h>

#if defined(__linux__)
#include <sys/syscall.h>
#endif

#if defined(OPENSSL_WINDOWS)

#if defined(_MSC_VER)
#pragma warning(push, 3)
#endif

#include <windows.h>

#if defined(_MSC_VER)
#pragma warning(pop)
#endif

#endif

#include "internal.h"

// Our assembly does not use the GOT to reference symbols, which means
// references to visible symbols will often require a TEXTREL. This is
// undesirable, so all assembly-referenced symbols should be hidden. CPU
// capabilities are the only such symbols defined in C. Explicitly hide them,
// rather than rely on being built with -fvisibility=hidden.
#if defined(OPENSSL_WINDOWS)
#define HIDDEN
#else
#define HIDDEN __attribute__((visibility("hidden")))
#endif

#if defined(OPENSSL_X86) || defined(OPENSSL_X86_64)
// This value must be explicitly initialised to zero in order to work around a
// bug in libtool or the linker on OS X.
//
// If not initialised then it becomes a "common symbol". When put into an
// archive, linking on OS X will fail to resolve common symbols. By
// initialising it to zero, it becomes a "data symbol", which isn't so
// affected.
HIDDEN uint32_t GFp_ia32cap_P[4] = {0};
#elif defined(OPENSSL_ARM) || defined(OPENSSL_AARCH64)

#include <GFp/arm_arch.h>

#if defined(OPENSSL_STATIC_ARMCAP)

HIDDEN uint32_t GFp_armcap_P =
#if defined(OPENSSL_STATIC_ARMCAP_NEON) || defined(__ARM_NEON__)
    ARMV7_NEON |
#endif
#if defined(OPENSSL_STATIC_ARMCAP_AES) || defined(__ARM_FEATURE_CRYPTO)
    ARMV8_AES |
#endif
#if defined(OPENSSL_STATIC_ARMCAP_SHA1) || defined(__ARM_FEATURE_CRYPTO)
    ARMV8_SHA1 |
#endif
#if defined(OPENSSL_STATIC_ARMCAP_SHA256) || defined(__ARM_FEATURE_CRYPTO)
    ARMV8_SHA256 |
#endif
#if defined(OPENSSL_STATIC_ARMCAP_PMULL) || defined(__ARM_FEATURE_CRYPTO)
    ARMV8_PMULL |
#endif
    0;

#else
HIDDEN uint32_t GFp_armcap_P = 0;
#endif

#endif

#if defined(__linux__)

// The getrandom syscall was added in Linux 3.17. For some important platforms,
// we also support building against older kernels' headers. For other
// platforms, the newer kernel's headers are required. */
#if !defined(SYS_getrandom)
#if defined(OPENSSL_AARCH64)
#define SYS_getrandom 278
#elif defined(OPENSSL_ARM)
#define SYS_getrandom 384
#elif defined(OPENSSL_X86)
#define SYS_getrandom 355
#elif defined(OPENSSL_X86_64)
#define SYS_getrandom 318
#else
#error "Error: Kernel headers are too old; SYS_getrandom not defined."
#endif
#endif

const long GFp_SYS_GETRANDOM = SYS_getrandom;
#endif

// These allow tests in other languages to verify that their understanding of
// the C types matches the C compiler's understanding.

#define DEFINE_METRICS(ty) \
  OPENSSL_EXPORT uint16_t GFp_##ty##_align = alignof(ty); \
  OPENSSL_EXPORT uint16_t GFp_##ty##_size = sizeof(ty);

DEFINE_METRICS(int8_t)
DEFINE_METRICS(uint8_t)

DEFINE_METRICS(int16_t)
DEFINE_METRICS(uint16_t)

DEFINE_METRICS(int32_t)
DEFINE_METRICS(uint32_t)

DEFINE_METRICS(int64_t)
DEFINE_METRICS(uint64_t)

DEFINE_METRICS(int)
DEFINE_METRICS(long)

typedef unsigned int uint;
DEFINE_METRICS(uint)

DEFINE_METRICS(size_t)

#if defined(OPENSSL_WINDOWS)
DEFINE_METRICS(ULONG)
DEFINE_METRICS(BOOLEAN)
#endif
