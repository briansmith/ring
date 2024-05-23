/* Copyright (c) 2023, Google Inc.
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

#ifndef OPENSSL_HEADER_TARGET_H
#define OPENSSL_HEADER_TARGET_H

// Preprocessor symbols that define the target platform.
//
// This file may be included in C, C++, and assembler and must be compatible
// with each environment. It is separated out only to share code between
// <ring-core/base.h> and <ring-core/asm_base.h>. Prefer to include those headers
// instead.

#if defined(__x86_64) || defined(_M_AMD64) || defined(_M_X64)
#define OPENSSL_64_BIT
#define OPENSSL_X86_64
#elif defined(__x86) || defined(__i386) || defined(__i386__) || defined(_M_IX86)
#define OPENSSL_32_BIT
#define OPENSSL_X86
#elif defined(__AARCH64EL__) || defined(_M_ARM64)
#define OPENSSL_64_BIT
#define OPENSSL_AARCH64
#elif defined(__ARMEL__) || defined(_M_ARM)
#define OPENSSL_32_BIT
#define OPENSSL_ARM
#elif defined(__loongarch_lp64)
#define OPENSSL_64_BIT
#elif defined(__riscv) && __SIZEOF_POINTER__ == 8
#define OPENSSL_64_BIT
#elif defined(__wasm__)
#define OPENSSL_32_BIT
// All of following architectures are only supported when `__BYTE_ORDER__` can be used to detect
// endianness (in crypto/internal.h).
#elif !defined(__BYTE_ORDER__)
#error "Cannot determine endianness because __BYTE_ORDER__ is not defined"
// Targets are assumed to be little-endian unless __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__.
#elif !(defined(__ORDER_LITTLE_ENDIAN__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)) && \
      !(defined(__ORDER_BIG_ENDIAN__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__))
#error "Unsupported endianness"
#elif defined(__MIPSEL__) && !defined(__LP64__)
#define OPENSSL_32_BIT
#elif defined(__MIPSEL__) && defined(__LP64__)
#define OPENSSL_64_BIT
#elif defined(__MIPSEB__) && !defined(__LP64__)
#define OPENSSL_32_BIT
#elif defined(__PPC64__) || defined(__powerpc64__)
#define OPENSSL_64_BIT
#elif (defined(__PPC__) || defined(__powerpc__)) && defined(_BIG_ENDIAN)
#define OPENSSL_32_BIT
#elif defined(__s390x__)
#define OPENSSL_64_BIT
#elif defined(__sparc_v9__) && defined(__LP64__)
#define OPENSSL_64_BIT
#else
#error "Unknown target CPU"
#endif

#if defined(__APPLE__)
#define OPENSSL_APPLE
#endif

#if defined(_WIN32)
#define OPENSSL_WINDOWS
#endif

#if defined(__has_feature)
#if __has_feature(address_sanitizer)
#define OPENSSL_ASAN
#endif
#if __has_feature(thread_sanitizer)
#define OPENSSL_TSAN
#endif
#if __has_feature(memory_sanitizer)
#define OPENSSL_MSAN
#define OPENSSL_ASM_INCOMPATIBLE
#endif
#if __has_feature(hwaddress_sanitizer)
#define OPENSSL_HWASAN
#endif
#endif

#if defined(OPENSSL_ASM_INCOMPATIBLE)
#undef OPENSSL_ASM_INCOMPATIBLE
#if !defined(OPENSSL_NO_ASM)
#define OPENSSL_NO_ASM
#endif
#endif  // OPENSSL_ASM_INCOMPATIBLE

#if !defined(OPENSSL_X86_64) && !defined(OPENSSL_AARCH64)
#define OPENSSL_SMALL
#endif

#endif  // OPENSSL_HEADER_TARGET_H
