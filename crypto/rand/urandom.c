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

#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE  /* needed for syscall() on Linux. */
#endif

#include <openssl/rand.h>

#if !defined(OPENSSL_WINDOWS) && !defined(OPENSSL_FUCHSIA) && \
    !defined(BORINGSSL_UNSAFE_DETERMINISTIC_MODE)

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#if defined(OPENSSL_LINUX)
#include <sys/syscall.h>
#endif

#include <openssl/thread.h>
#include <openssl/mem.h>

#include "internal.h"
#include "../internal.h"


#if defined(OPENSSL_LINUX)

#if defined(OPENSSL_X86_64)
#define EXPECTED_SYS_getrandom 318
#elif defined(OPENSSL_X86)
#define EXPECTED_SYS_getrandom 355
#elif defined(OPENSSL_AARCH64)
#define EXPECTED_SYS_getrandom 278
#elif defined(OPENSSL_ARM)
#define EXPECTED_SYS_getrandom 384
#elif defined(OPENSSL_PPC64LE)
#define EXPECTED_SYS_getrandom 359
#endif

#if defined(EXPECTED_SYS_getrandom)
#define USE_SYS_getrandom

#if defined(SYS_getrandom)

#if SYS_getrandom != EXPECTED_SYS_getrandom
#error "system call number for getrandom is not the expected value"
#endif

#else  /* SYS_getrandom */

#define SYS_getrandom EXPECTED_SYS_getrandom

#endif  /* SYS_getrandom */

#endif /* EXPECTED_SYS_getrandom */

#if !defined(GRND_NONBLOCK)
#define GRND_NONBLOCK 1
#endif

#endif  /* OPENSSL_LINUX */

/* This file implements a PRNG by reading from /dev/urandom, optionally with a
 * buffer, which is unsafe across |fork|. */

#define BUF_SIZE 4096

/* rand_buffer contains unused, random bytes, some of which may have been
 * consumed already. */
struct rand_buffer {
  size_t used;
  uint8_t rand[BUF_SIZE];
};

/* requested_lock is used to protect the |*_requested| variables. */
static struct CRYPTO_STATIC_MUTEX requested_lock = CRYPTO_STATIC_MUTEX_INIT;

/* The following constants are magic values of |urandom_fd|. */
static const int kUnset = -2;
static const int kHaveGetrandom = -3;

/* urandom_fd_requested is set by |RAND_set_urandom_fd|. It's protected by
 * |requested_lock|. */
static int urandom_fd_requested = -2 /* kUnset */;

/* urandom_fd is a file descriptor to /dev/urandom. It's protected by |once|. */
static int urandom_fd = -2 /* kUnset */;

/* urandom_buffering_requested is set by |RAND_enable_fork_unsafe_buffering|.
 * It's protected by |requested_lock|. */
static int urandom_buffering_requested = 0;

/* urandom_buffering controls whether buffering is enabled (1) or not (0). This
 * is protected by |once|. */
static int urandom_buffering = 0;

static CRYPTO_once_t once = CRYPTO_ONCE_INIT;

/* init_once initializes the state of this module to values previously
 * requested. This is the only function that modifies |urandom_fd| and
 * |urandom_buffering|, whose values may be read safely after calling the
 * once. */
static void init_once(void) {
  CRYPTO_STATIC_MUTEX_lock_read(&requested_lock);
  urandom_buffering = urandom_buffering_requested;
  int fd = urandom_fd_requested;
  CRYPTO_STATIC_MUTEX_unlock_read(&requested_lock);

#if defined(USE_SYS_getrandom)
  uint8_t dummy;
  long getrandom_ret =
      syscall(SYS_getrandom, &dummy, sizeof(dummy), GRND_NONBLOCK);

  if (getrandom_ret == 1) {
    urandom_fd = kHaveGetrandom;
    return;
  } else if (getrandom_ret == -1 && errno == EAGAIN) {
    fprintf(stderr,
            "getrandom indicates that the entropy pool has not been "
            "initialized. Rather than continue with poor entropy, this process "
            "will block until entropy is available.\n");
    do {
      getrandom_ret =
          syscall(SYS_getrandom, &dummy, sizeof(dummy), 0 /* no flags */);
    } while (getrandom_ret == -1 && errno == EINTR);

    if (getrandom_ret == 1) {
      urandom_fd = kHaveGetrandom;
      return;
    }
  }
#endif  /* USE_SYS_getrandom */

  if (fd == kUnset) {
    do {
      fd = open("/dev/urandom", O_RDONLY);
    } while (fd == -1 && errno == EINTR);
  }

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

void RAND_set_urandom_fd(int fd) {
  fd = dup(fd);
  if (fd < 0) {
    abort();
  }

  CRYPTO_STATIC_MUTEX_lock_write(&requested_lock);
  urandom_fd_requested = fd;
  CRYPTO_STATIC_MUTEX_unlock_write(&requested_lock);

  CRYPTO_once(&once, init_once);
  if (urandom_fd == kHaveGetrandom) {
    close(fd);
  } else if (urandom_fd != fd) {
    abort();  // Already initialized.
  }
}

void RAND_enable_fork_unsafe_buffering(int fd) {
  if (fd >= 0) {
    fd = dup(fd);
    if (fd < 0) {
      abort();
    }
  } else {
    fd = kUnset;
  }

  CRYPTO_STATIC_MUTEX_lock_write(&requested_lock);
  urandom_buffering_requested = 1;
  urandom_fd_requested = fd;
  CRYPTO_STATIC_MUTEX_unlock_write(&requested_lock);

  CRYPTO_once(&once, init_once);
  if (urandom_buffering != 1) {
    abort();  // Already initialized
  }

  if (fd >= 0) {
    if (urandom_fd == kHaveGetrandom) {
      close(fd);
    } else if (urandom_fd != fd) {
      abort();  // Already initialized.
    }
  }
}

static struct rand_buffer *get_thread_local_buffer(void) {
  struct rand_buffer *buf =
      CRYPTO_get_thread_local(OPENSSL_THREAD_LOCAL_URANDOM_BUF);
  if (buf != NULL) {
    return buf;
  }

  buf = OPENSSL_malloc(sizeof(struct rand_buffer));
  if (buf == NULL) {
    return NULL;
  }
  buf->used = BUF_SIZE;  /* To trigger a |fill_with_entropy| on first use. */
  if (!CRYPTO_set_thread_local(OPENSSL_THREAD_LOCAL_URANDOM_BUF, buf,
                               OPENSSL_free)) {
    OPENSSL_free(buf);
    return NULL;
  }

  return buf;
}

#if defined(USE_SYS_getrandom) && defined(__has_feature)
#if __has_feature(memory_sanitizer)
void __msan_unpoison(void *, size_t);
#endif
#endif

/* fill_with_entropy writes |len| bytes of entropy into |out|. It returns one
 * on success and zero on error. */
static char fill_with_entropy(uint8_t *out, size_t len) {
  while (len > 0) {
    ssize_t r;

    if (urandom_fd == kHaveGetrandom) {
#if defined(USE_SYS_getrandom)
      do {
        r = syscall(SYS_getrandom, out, len, 0 /* no flags */);
      } while (r == -1 && errno == EINTR);

#if defined(__has_feature)
#if __has_feature(memory_sanitizer)
      if (r > 0) {
        /* MSAN doesn't recognise |syscall| and thus doesn't notice that we
         * have initialised the output buffer. */
        __msan_unpoison(out, r);
      }
#endif /* memory_sanitizer */
#endif /*__has_feature */

#else /* USE_SYS_getrandom */
      abort();
#endif
    } else {
      do {
        r = read(urandom_fd, out, len);
      } while (r == -1 && errno == EINTR);
    }

    if (r <= 0) {
      return 0;
    }
    out += r;
    len -= r;
  }

  return 1;
}

/* read_from_buffer reads |requested| random bytes from the buffer into |out|,
 * refilling it if necessary to satisfy the request. */
static void read_from_buffer(struct rand_buffer *buf,
                             uint8_t *out, size_t requested) {
  size_t remaining = BUF_SIZE - buf->used;

  while (requested > remaining) {
    OPENSSL_memcpy(out, &buf->rand[buf->used], remaining);
    buf->used += remaining;
    out += remaining;
    requested -= remaining;

    if (!fill_with_entropy(buf->rand, BUF_SIZE)) {
      abort();
      return;
    }
    buf->used = 0;
    remaining = BUF_SIZE;
  }

  OPENSSL_memcpy(out, &buf->rand[buf->used], requested);
  buf->used += requested;
}

/* CRYPTO_sysrand puts |requested| random bytes into |out|. */
void CRYPTO_sysrand(uint8_t *out, size_t requested) {
  if (requested == 0) {
    return;
  }

  CRYPTO_once(&once, init_once);
  if (urandom_buffering && requested < BUF_SIZE) {
    struct rand_buffer *buf = get_thread_local_buffer();
    if (buf != NULL) {
      read_from_buffer(buf, out, requested);
      return;
    }
  }

  if (!fill_with_entropy(out, requested)) {
    abort();
  }
}

#endif /* !OPENSSL_WINDOWS && !defined(OPENSSL_FUCHSIA) && \
          !BORINGSSL_UNSAFE_DETERMINISTIC_MODE */
