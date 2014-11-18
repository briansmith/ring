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

#include "packeted_bio.h"

#include <assert.h>
#include <errno.h>
#include <openssl/mem.h>

namespace {

extern const BIO_METHOD packeted_bio_method;

static int packeted_write(BIO *bio, const char *in, int inl) {
  if (bio->next_bio == NULL) {
    return 0;
  }

  BIO_clear_retry_flags(bio);

  // Write the length prefix.
  uint8_t len_bytes[4];
  len_bytes[0] = (inl >> 24) & 0xff;
  len_bytes[1] = (inl >> 16) & 0xff;
  len_bytes[2] = (inl >> 8) & 0xff;
  len_bytes[3] = inl & 0xff;
  int ret = BIO_write(bio->next_bio, len_bytes, sizeof(len_bytes));
  if (ret <= 0) {
    BIO_copy_next_retry(bio);
    return ret;
  }

  // Write the buffer. BIOs for which this operation fails are not supported.
  ret = BIO_write(bio->next_bio, in, inl);
  assert(ret == inl);
  return ret;
}

static int packeted_read(BIO *bio, char *out, int outl) {
  if (bio->next_bio == NULL) {
    return 0;
  }

  BIO_clear_retry_flags(bio);

  // Read the length prefix.
  uint8_t len_bytes[4];
  int ret = BIO_read(bio->next_bio, &len_bytes, sizeof(len_bytes));
  if (ret <= 0) {
    BIO_copy_next_retry(bio);
    return ret;
  }
  // BIOs for which a partial length comes back are not supported.
  assert(ret == 4);

  uint32_t len = (len_bytes[0] << 24) | (len_bytes[1] << 16) |
      (len_bytes[2] << 8) | len_bytes[3];
  char *buf = (char *)OPENSSL_malloc(len);
  if (buf == NULL) {
    return -1;
  }
  ret = BIO_read(bio->next_bio, buf, len);
  assert(ret == (int)len);

  if (outl > (int)len) {
    outl = len;
  }
  memcpy(out, buf, outl);
  OPENSSL_free(buf);
  return outl;
}

static long packeted_ctrl(BIO *bio, int cmd, long num, void *ptr) {
  if (bio->next_bio == NULL) {
    return 0;
  }
  BIO_clear_retry_flags(bio);
  int ret = BIO_ctrl(bio->next_bio, cmd, num, ptr);
  BIO_copy_next_retry(bio);
  return ret;
}

static int packeted_new(BIO *bio) {
  bio->init = 1;
  return 1;
}

static int packeted_free(BIO *bio) {
  if (bio == NULL) {
    return 0;
  }

  bio->init = 0;
  return 1;
}

static long packeted_callback_ctrl(BIO *bio, int cmd, bio_info_cb fp) {
  if (bio->next_bio == NULL) {
    return 0;
  }
  return BIO_callback_ctrl(bio->next_bio, cmd, fp);
}

const BIO_METHOD packeted_bio_method = {
  BIO_TYPE_FILTER,
  "packeted bio",
  packeted_write,
  packeted_read,
  NULL /* puts */,
  NULL /* gets */,
  packeted_ctrl,
  packeted_new,
  packeted_free,
  packeted_callback_ctrl,
};

}  // namespace

BIO *packeted_bio_create() {
  return BIO_new(&packeted_bio_method);
}
