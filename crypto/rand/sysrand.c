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

/* Copyright 2016 Brian Smith.
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

#include <openssl/base.h>

#include <assert.h>
#include <stddef.h>

/* CRYPTO_sysrand_chunk fills |len| bytes at |buf| with entropy from the
 * operating system. |len| must be no more than |CRYPTO_sysrand_chunk_max_le|.
 * It returns one on success, -1 if it failed because the operating system
 * doesn't offer such an API, or zero otherwise. */
int CRYPTO_sysrand_chunk(void *buf, size_t len);

#if defined(OPENSSL_WINDOWS)

#include <limits.h>

#pragma warning(push, 3)

#include <windows.h>

/* #define needed to link in RtlGenRandom(), a.k.a. SystemFunction036.  See the
 * "Community Additions" comment on MSDN here:
 * http://msdn.microsoft.com/en-us/library/windows/desktop/aa387694.aspx */
#define SystemFunction036 NTAPI SystemFunction036
#include <ntsecapi.h>
#undef SystemFunction036

#pragma warning(pop)

const size_t CRYPTO_sysrand_chunk_max_len = ULONG_MAX;

int CRYPTO_sysrand_chunk(void *out, size_t requested) {
  assert(requested <= CRYPTO_sysrand_chunk_max_len);
  return RtlGenRandom(out, (ULONG)requested) ? 1 : 0;
}

#elif defined(__linux__)

#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

/* The getrandom syscall was added in Linux 3.17. For some important platforms,
 * we also support building against older kernels' headers. For other
 * platforms, the newer kernel's headers are required. */
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


/* http://man7.org/linux/man-pages/man2/getrandom.2.html: "Calling
 * getrandom() to read /dev/urandom for small values (<= 256) of buflen is
 * the preferred mode of usage." */
const size_t CRYPTO_sysrand_chunk_max_len = 256;

int CRYPTO_sysrand_chunk(void *out, size_t requested) {
  assert(requested <= CRYPTO_sysrand_chunk_max_len);
  if (syscall(SYS_getrandom, out, requested, 0u) < 0) {
    if (errno == ENOSYS) {
      return -1;
    }
    return 0;
  }
  return 1;
}

#endif
