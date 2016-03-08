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

#include <openssl/rand.h>

#if !defined(OPENSSL_WINDOWS) && !defined(BORINGSSL_UNSAFE_FUZZER_MODE)

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include "internal.h"
#include "../internal.h"


/* This file implements a PRNG by reading from /dev/urandom, optionally with a
 * buffer, which is unsafe across |fork|. */

#define BUF_SIZE 4096

/* rand_buffer contains unused, random bytes, some of which may have been
 * consumed already. */
struct rand_buffer {
  size_t used;
  uint8_t rand[BUF_SIZE];
};

/* urandom_fd is a file descriptor to /dev/urandom. It's protected by |once|. */
static int urandom_fd = -2;

static CRYPTO_once_t once = CRYPTO_ONCE_INIT;

/* init_once initializes the state of this module to values previously
 * requested. This is the only function that modifies |urandom_fd| and
 * |urandom_buffering|, whose values may be read safely after calling the
 * once. */
static void init_once(void) {
  int fd;

  do {
    fd = open("/dev/urandom", O_RDONLY);
  } while (fd == -1 && errno == EINTR);

  if (fd < 0) {
    abort();
  }

  int flags = fcntl(fd, F_GETFD);
  if (flags == -1) {
    /* Native Client doesn't implement |fcntl|. */
    if (errno != ENOSYS) {
      abort();
    }
  } else {
    flags |= FD_CLOEXEC;
    if (fcntl(fd, F_SETFD, flags) == -1) {
      abort();
    }
  }
  urandom_fd = fd;
}

void RAND_cleanup(void) {}

/* read_full reads exactly |len| bytes from |fd| into |out| and returns 1. In
 * the case of an error it returns 0. */
static char read_full(int fd, void *out, size_t len) {
  ssize_t r;

  while (len > 0) {
    do {
      r = read(fd, out, len);
    } while (r == -1 && errno == EINTR);

    if (r <= 0) {
      return 0;
    }
    out = (uint8_t *)out + r;
    len -= r;
  }

  return 1;
}

/* CRYPTO_sysrand puts |requested| random bytes into |out|. */
void CRYPTO_sysrand(void *out, size_t requested) {
  if (requested == 0) {
    return;
  }
  CRYPTO_once(&once, init_once);
  if (!read_full(urandom_fd, out, requested)) {
    abort();
  }
}

#endif  /* !OPENSSL_WINDOWS && !BORINGSSL_UNSAFE_FUZZER_MODE */
