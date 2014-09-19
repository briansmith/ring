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

#include <openssl/crypto.h>

#include "internal.h"

#if !defined(OPENSSL_NO_ASM) && \
    (defined(OPENSSL_X86) || defined(OPENSSL_X86_64))
/* x86 and x86_64 need to record the result of a cpuid call for the asm to work
 * correctly, unless compiled without asm code. */
#define NEED_CPUID

#else

/* Otherwise, don't emit a static initialiser. */

#if !defined(BORINGSSL_NO_STATIC_INITIALIZER)
#define BORINGSSL_NO_STATIC_INITIALIZER
#endif

#endif  /* !OPENSSL_NO_ASM && (OPENSSL_X86 || OPENSSL_X86_64) */

#if defined(OPENSSL_WINDOWS)
#define OPENSSL_CDECL __cdecl
#else
#define OPENSSL_CDECL
#endif

#if !defined(BORINGSSL_NO_STATIC_INITIALIZER)
#if !defined(OPENSSL_WINDOWS)
static void do_library_init(void) __attribute__ ((constructor));
#else
#pragma section(".CRT$XCU", read)
static void __cdecl do_library_init(void);
__declspec(allocate(".CRT$XCU")) void(*library_init_constructor)(void) =
    do_library_init;
#endif
#endif  /* !BORINGSSL_NO_STATIC_INITIALIZER */

/* do_library_init is the actual initialization function. If
 * BORINGSSL_NO_STATIC_INITIALIZER isn't defined, this is set as a static
 * initializer. Otherwise, it is called by CRYPTO_library_init. */
static void OPENSSL_CDECL do_library_init(void) {
#if defined(NEED_CPUID)
  OPENSSL_cpuid_setup();
#endif
}

void CRYPTO_library_init(void) {
  /* TODO(davidben): It would be tidier if this build knob could be replaced
   * with an internal lazy-init mechanism that would handle things correctly
   * in-library. */
#if defined(BORINGSSL_NO_STATIC_INITIALIZER)
  do_library_init();
#endif
}
