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

#include <stdio.h>


int bssl_thread_test_main(void);


#if !defined(OPENSSL_NO_THREADS)

struct thread_func_t {
  void (*thread_func)(void);
};

#if defined(OPENSSL_WINDOWS)

#pragma warning(push, 3)
#include <windows.h>
#pragma warning(pop)

typedef HANDLE thread_t;

static DWORD WINAPI thread_run(LPVOID arg) {
  const struct thread_func_t *thread_func = arg;
  thread_func->thread_func();
  return 0;
}

static int run_thread(thread_t *out_thread, struct thread_func_t *thread_func) {
  *out_thread = CreateThread(NULL /* security attributes */,
                             0 /* default stack size */, thread_run,
                             thread_func, 0 /* run immediately */,
                             NULL /* ignore id */);
  return *out_thread != NULL;
}

static int wait_for_thread(thread_t thread) {
  return WaitForSingleObject(thread, INFINITE) == 0;
}

#else

#include <string.h>
#include <time.h>

typedef pthread_t thread_t;

static void *thread_run(void *arg) {
  const struct thread_func_t *thread_func = arg;
  thread_func->thread_func();
  return NULL;
}

static int run_thread(thread_t *out_thread, struct thread_func_t *thread_func) {
  return pthread_create(out_thread, NULL /* default attributes */, thread_run,
                        thread_func) == 0;
}

static int wait_for_thread(thread_t thread) {
  return pthread_join(thread, NULL) == 0;
}

#endif  /* OPENSSL_WINDOWS */

static unsigned g_once_init_called = 0;

static void once_init(void) {
  g_once_init_called++;

  /* Sleep briefly so one |call_once_thread| instance will call |CRYPTO_once|
   * while the other is running this function. */
#if defined(OPENSSL_WINDOWS)
  Sleep(1 /* milliseconds */);
#else
  struct timespec req;
  memset(&req, 0, sizeof(req));
  req.tv_nsec = 1000000;
  nanosleep(&req, NULL);
#endif
}

static CRYPTO_once_t g_test_once = CRYPTO_ONCE_INIT;

static void call_once_thread(void) {
  CRYPTO_once(&g_test_once, once_init);
}

static int test_once(void) {
  if (g_once_init_called != 0) {
    fprintf(stderr, "g_once_init_called was non-zero at start.\n");
    return 0;
  }

  thread_t thread1, thread2;
  struct thread_func_t call_once_thread_func = { call_once_thread };

  if (!run_thread(&thread1, &call_once_thread_func) ||
      !run_thread(&thread2, &call_once_thread_func) ||
      !wait_for_thread(thread1) ||
      !wait_for_thread(thread2)) {
    fprintf(stderr, "thread failed.\n");
    return 0;
  }

  CRYPTO_once(&g_test_once, once_init);

  if (g_once_init_called != 1) {
    fprintf(stderr, "Expected init function to be called once, but found %u.\n",
            g_once_init_called);
    return 0;
  }

  return 1;
}


int bssl_thread_test_main(void) {
  if (!test_once()) {
    return 1;
  }

  return 0;
}

#else  /* OPENSSL_NO_THREADS */

int main(void) {
  return 0;
}

#endif
