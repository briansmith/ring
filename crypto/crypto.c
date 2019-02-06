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

#include <GFp/cpu.h>
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

HIDDEN uint32_t GFp_armcap_P = 0;

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
#include <sys/syscall.h>
#if !defined(SYS_getrandom)
#error "Error: Kernel headers are too old; SYS_getrandom not defined."
#endif
#endif

#endif

const long GFp_SYS_GETRANDOM = SYS_getrandom;
#endif
