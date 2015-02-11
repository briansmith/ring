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

#if !defined(OPENSSL_WINDOWS)

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/thread.h>
#include <openssl/mem.h>


/* This file implements a PRNG by reading from /dev/urandom, optionally with a
 * fork-safe buffer.
 *
 * If buffering is enabled then it maintains a global, linked list of buffers.
 * Threads which need random bytes grab a buffer from the list under a lock and
 * copy out the bytes that they need. In the rare case that the buffer is
 * empty, it's refilled from /dev/urandom outside of the lock.
 *
 * Large requests are always serviced from /dev/urandom directly.
 *
 * Each buffer contains the PID of the process that created it and it's tested
 * against the current PID each time. Thus processes that fork will discard all
 * the buffers filled by the parent process. There are two problems with this:
 *
 * 1) glibc maintains a cache of the current PID+PPID and, if this cache isn't
 *    correctly invalidated, the getpid() will continue to believe that
 *    it's the old process. Glibc depends on the glibc wrappers for fork,
 *    vfork and clone being used in order to invalidate the getpid() cache.
 *
 * 2) If a process forks, dies and then its child forks, it's possible that
 *    the third process will end up with the same PID as the original process.
 *    If the second process never used any random values then this will mean
 *    that the third process has stale, cached values and won't notice.
 */

/* BUF_SIZE is intended to be a 4K allocation with malloc overhead. struct
 * rand_buffer also fits in this space and the remainder is entropy. */
#define BUF_SIZE (4096 - 16)

/* rand_buffer contains unused, random bytes. These structures form a linked
 * list via the |next| pointer, which is NULL in the final element. */
struct rand_buffer {
  size_t used; /* used contains the number of bytes of |rand| that have
                  been consumed. */
  struct rand_buffer *next;
  pid_t pid; /* pid contains the pid at the time that the buffer was
                created so that data is not duplicated after a fork. */
  pid_t ppid; /* ppid contains the parent pid in order to try and reduce
                 the possibility of duplicated PID confusing the
                 detection of a fork. */
  uint8_t rand[];
};

/* rand_bytes_per_buf is the number of actual entropy bytes in a buffer. */
static const size_t rand_bytes_per_buf = BUF_SIZE - sizeof(struct rand_buffer);

/* list_head is the start of a global, linked-list of rand_buffer objects. It's
 * protected by CRYPTO_LOCK_RAND. */
static struct rand_buffer *list_head;

/* urandom_fd is a file descriptor to /dev/urandom. It's protected by
 * CRYPTO_LOCK_RAND. */
static int urandom_fd = -2;

/* urandom_buffering controls whether buffering is enabled (1) or not (0). This
 * is protected by CRYPTO_LOCK_RAND. */
static int urandom_buffering = 0;

/* urandom_get_fd_locked returns a file descriptor to /dev/urandom. The caller
 * of this function must hold CRYPTO_LOCK_RAND. */
static int urandom_get_fd_locked(void) {
  if (urandom_fd != -2) {
    return urandom_fd;
  }

  urandom_fd = open("/dev/urandom", O_RDONLY);
  return urandom_fd;
}

/* RAND_cleanup frees all buffers, closes any cached file descriptor
 * and resets the global state. */
void RAND_cleanup(void) {
  struct rand_buffer *cur;

  CRYPTO_w_lock(CRYPTO_LOCK_RAND);
  while ((cur = list_head)) {
    list_head = cur->next;
    OPENSSL_free(cur);
  }
  if (urandom_fd >= 0) {
    close(urandom_fd);
  }
  urandom_fd = -2;
  list_head = NULL;
  CRYPTO_w_unlock(CRYPTO_LOCK_RAND);
}

/* read_full reads exactly |len| bytes from |fd| into |out| and returns 1. In
 * the case of an error it returns 0. */
static char read_full(int fd, uint8_t *out, size_t len) {
  ssize_t r;

  while (len > 0) {
    do {
      r = read(fd, out, len);
    } while (r == -1 && errno == EINTR);

    if (r <= 0) {
      return 0;
    }
    out += r;
    len -= r;
  }

  return 1;
}

/* urandom_rand_pseudo_bytes puts |num| random bytes into |out|. It returns
 * one on success and zero otherwise. */
int RAND_bytes(uint8_t *out, size_t requested) {
  int fd;
  struct rand_buffer *buf;
  size_t todo;
  pid_t pid, ppid;

  if (requested == 0) {
    return 1;
  }

  CRYPTO_w_lock(CRYPTO_LOCK_RAND);
  fd = urandom_get_fd_locked();

  if (fd < 0) {
    CRYPTO_w_unlock(CRYPTO_LOCK_RAND);
    abort();
    return 0;
  }

  /* If buffering is not enabled, or if the request is large, then the
   * result comes directly from urandom. */
  if (!urandom_buffering || requested > BUF_SIZE / 2) {
    CRYPTO_w_unlock(CRYPTO_LOCK_RAND);
    if (!read_full(fd, out, requested)) {
      abort();
      return 0;
    }
    return 1;
  }

  pid = getpid();
  ppid = getppid();

  for (;;) {
    buf = list_head;
    if (buf && buf->pid == pid && buf->ppid == ppid &&
        rand_bytes_per_buf - buf->used >= requested) {
      memcpy(out, &buf->rand[buf->used], requested);
      buf->used += requested;
      CRYPTO_w_unlock(CRYPTO_LOCK_RAND);
      return 1;
    }

    /* If we don't immediately have enough entropy with the correct
     * PID, remove the buffer from the list in order to gain
     * exclusive access and unlock. */
    if (buf) {
      list_head = buf->next;
    }
    CRYPTO_w_unlock(CRYPTO_LOCK_RAND);

    if (!buf) {
      buf = (struct rand_buffer *)OPENSSL_malloc(BUF_SIZE);
      if (!buf) {
        abort();
        return 0;
      }
      /* The buffer doesn't contain any random bytes yet
       * so we mark it as fully used so that it will be
       * filled below. */
      buf->used = rand_bytes_per_buf;
      buf->next = NULL;
      buf->pid = pid;
      buf->ppid = ppid;
    }

    if (buf->pid == pid && buf->ppid == ppid) {
      break;
    }

    /* We have forked and so cannot use these bytes as they
     * may have been used in another process. */
    OPENSSL_free(buf);
    CRYPTO_w_lock(CRYPTO_LOCK_RAND);
  }

  while (requested > 0) {
    todo = rand_bytes_per_buf - buf->used;
    if (todo > requested) {
      todo = requested;
    }
    memcpy(out, &buf->rand[buf->used], todo);
    requested -= todo;
    out += todo;
    buf->used += todo;

    if (buf->used < rand_bytes_per_buf) {
      break;
    }

    if (!read_full(fd, buf->rand, rand_bytes_per_buf)) {
      OPENSSL_free(buf);
      abort();
      return 0;
    }

    buf->used = 0;
  }

  CRYPTO_w_lock(CRYPTO_LOCK_RAND);
  assert(list_head != buf);
  buf->next = list_head;
  list_head = buf;
  CRYPTO_w_unlock(CRYPTO_LOCK_RAND);
  return 1;
}

#endif  /* !OPENSSL_WINDOWS */
