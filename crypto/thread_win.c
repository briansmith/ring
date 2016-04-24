/* Copyright (c) 2015, Google Inc.
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

#include "internal.h"

#if defined(OPENSSL_WINDOWS) && !defined(OPENSSL_NO_THREADS)

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/mem.h>
#include <openssl/type_check.h>


union run_once_arg_t {
  void (*func)(void);
  void *data;
};

static void run_once(CRYPTO_once_t *once, void (*init)(union run_once_arg_t),
                     union run_once_arg_t arg) {
  /* Values must be aligned. */
  assert((((uintptr_t) once) & 3) == 0);

  /* This assumes that reading *once has acquire semantics. This should be true
   * on x86 and x86-64, where we expect Windows to run. */
#if !defined(OPENSSL_X86) && !defined(OPENSSL_X86_64)
#error "Windows once code may not work on other platforms." \
       "You can use InitOnceBeginInitialize on >=Vista"
#endif
  if (*once == 1) {
    return;
  }

  for (;;) {
    switch (InterlockedCompareExchange(once, 2, 0)) {
      case 0:
        /* The value was zero so we are the first thread to call |CRYPTO_once|
         * on it. */
        init(arg);
        /* Write one to indicate that initialisation is complete. */
        InterlockedExchange(once, 1);
        return;

      case 1:
        /* Another thread completed initialisation between our fast-path check
         * and |InterlockedCompareExchange|. */
        return;

      case 2:
        /* Another thread is running the initialisation. Switch to it then try
         * again. */
        SwitchToThread();
        break;

      default:
        abort();
    }
  }
}

static void call_once_init(union run_once_arg_t arg) {
  arg.func();
}

void CRYPTO_once(CRYPTO_once_t *in_once, void (*init)(void)) {
  union run_once_arg_t arg;
  arg.func = init;
  run_once(in_once, call_once_init, arg);
}

void CRYPTO_MUTEX_init(CRYPTO_MUTEX *lock) {
  if (!InitializeCriticalSectionAndSpinCount(lock, 0x400)) {
    abort();
  }
}

void CRYPTO_MUTEX_lock_write(CRYPTO_MUTEX *lock) {
  EnterCriticalSection(lock);
}

void CRYPTO_MUTEX_unlock(CRYPTO_MUTEX *lock) {
  LeaveCriticalSection(lock);
}

void CRYPTO_MUTEX_cleanup(CRYPTO_MUTEX *lock) {
  DeleteCriticalSection(lock);
}

#endif  /* OPENSSL_WINDOWS && !OPENSSL_NO_THREADS */
