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

#include "async_bio.h"

#include <errno.h>
#include <openssl/mem.h>

namespace {

extern const BIO_METHOD async_bio_method;

struct async_bio {
  bool datagram;
  size_t read_quota;
  size_t write_quota;
};

async_bio *get_data(BIO *bio) {
  if (bio->method != &async_bio_method) {
    return NULL;
  }
  return (async_bio *)bio->ptr;
}

static int async_write(BIO *bio, const char *in, int inl) {
  async_bio *a = get_data(bio);
  if (a == NULL || bio->next_bio == NULL) {
    return 0;
  }

  if (a->datagram) {
    // Perform writes synchronously; the DTLS implementation drops any packets
    // that failed to send.
    return BIO_write(bio->next_bio, in, inl);
  }

  BIO_clear_retry_flags(bio);

  if (a->write_quota == 0) {
    BIO_set_retry_write(bio);
    errno = EAGAIN;
    return -1;
  }

  if (!a->datagram && (size_t)inl > a->write_quota) {
    inl = a->write_quota;
  }
  int ret = BIO_write(bio->next_bio, in, inl);
  if (ret <= 0) {
    BIO_copy_next_retry(bio);
  } else {
    a->write_quota -= ret;
  }
  return ret;
}

static int async_read(BIO *bio, char *out, int outl) {
  async_bio *a = get_data(bio);
  if (a == NULL || bio->next_bio == NULL) {
    return 0;
  }

  BIO_clear_retry_flags(bio);

  if (a->read_quota == 0) {
    BIO_set_retry_read(bio);
    errno = EAGAIN;
    return -1;
  }

  if (!a->datagram && (size_t)outl > a->read_quota) {
    outl = a->read_quota;
  }
  int ret = BIO_read(bio->next_bio, out, outl);
  if (ret <= 0) {
    BIO_copy_next_retry(bio);
  } else {
    a->read_quota -= (a->datagram ? 1 : ret);
  }
  return ret;
}

static long async_ctrl(BIO *bio, int cmd, long num, void *ptr) {
  if (bio->next_bio == NULL) {
    return 0;
  }
  BIO_clear_retry_flags(bio);
  int ret = BIO_ctrl(bio->next_bio, cmd, num, ptr);
  BIO_copy_next_retry(bio);
  return ret;
}

static int async_new(BIO *bio) {
  async_bio *a = (async_bio *)OPENSSL_malloc(sizeof(*a));
  if (a == NULL) {
    return 0;
  }
  memset(a, 0, sizeof(*a));
  bio->init = 1;
  bio->ptr = (char *)a;
  return 1;
}

static int async_free(BIO *bio) {
  if (bio == NULL) {
    return 0;
  }

  OPENSSL_free(bio->ptr);
  bio->ptr = NULL;
  bio->init = 0;
  bio->flags = 0;
  return 1;
}

static long async_callback_ctrl(BIO *bio, int cmd, bio_info_cb fp) {
  if (bio->next_bio == NULL) {
    return 0;
  }
  return BIO_callback_ctrl(bio->next_bio, cmd, fp);
}

const BIO_METHOD async_bio_method = {
  BIO_TYPE_FILTER,
  "async bio",
  async_write,
  async_read,
  NULL /* puts */,
  NULL /* gets */,
  async_ctrl,
  async_new,
  async_free,
  async_callback_ctrl,
};

}  // namespace

BIO *async_bio_create() {
  return BIO_new(&async_bio_method);
}

BIO *async_bio_create_datagram() {
  BIO *ret = BIO_new(&async_bio_method);
  if (!ret) {
    return NULL;
  }
  get_data(ret)->datagram = true;
  return ret;
}

void async_bio_allow_read(BIO *bio, size_t count) {
  async_bio *a = get_data(bio);
  if (a == NULL) {
    return;
  }
  a->read_quota += count;
}

void async_bio_allow_write(BIO *bio, size_t count) {
  async_bio *a = get_data(bio);
  if (a == NULL) {
    return;
  }
  a->write_quota += count;
}
