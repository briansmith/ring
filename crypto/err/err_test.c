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

#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/mem.h>


static int test_overflow(void) {
  unsigned i;

  for (i = 0; i < ERR_NUM_ERRORS*2; i++) {
    ERR_put_error(1, 2, i+1, "test", 1);
  }

  for (i = 0; i < ERR_NUM_ERRORS - 1; i++) {
    uint32_t err = ERR_get_error();
    /* Errors are returned in order they were pushed, with the least recent ones
     * removed, up to |ERR_NUM_ERRORS - 1| errors. So the errors returned are
     * |ERR_NUM_ERRORS + 2| through |ERR_NUM_ERRORS * 2|, inclusive. */
    if (err == 0 || ERR_GET_REASON(err) != i + ERR_NUM_ERRORS + 2) {
      fprintf(stderr, "ERR_get_error failed at %u\n", i);
      return 0;
    }
  }

  if (ERR_get_error() != 0) {
    fprintf(stderr, "ERR_get_error more than the expected number of values.\n");
    return 0;
  }

  return 1;
}

static int test_put_error(void) {
  uint32_t peeked_packed_error, packed_error;
  int peeked_line, line, peeked_flags, flags;
  const char *peeked_file, *file, *peeked_data, *data;

  if (ERR_get_error() != 0) {
    fprintf(stderr, "ERR_get_error returned value before an error was added.\n");
    return 0;
  }

  ERR_put_error(1, 2, 3, "test", 4);
  ERR_add_error_data(1, "testing");

  peeked_packed_error = ERR_peek_error_line_data(&peeked_file, &peeked_line,
                                                 &peeked_data, &peeked_flags);
  packed_error = ERR_get_error_line_data(&file, &line, &data, &flags);

  if (peeked_packed_error != packed_error ||
      peeked_file != file ||
      peeked_data != data ||
      peeked_flags != flags) {
    fprintf(stderr, "Bad peeked error data returned.\n");
    return 0;
  }

  if (strcmp(file, "test") != 0 ||
      line != 4 ||
      (flags & ERR_FLAG_STRING) == 0 ||
      ERR_GET_LIB(packed_error) != 1 ||
      ERR_GET_FUNC(packed_error) != 2 ||
      ERR_GET_REASON(packed_error) != 3 ||
      strcmp(data, "testing") != 0) {
    fprintf(stderr, "Bad error data returned.\n");
    return 0;
  }

  return 1;
}

static int test_clear_error(void) {
  if (ERR_get_error() != 0) {
    fprintf(stderr, "ERR_get_error returned value before an error was added.\n");
    return 0;
  }

  ERR_put_error(1, 2, 3, "test", 4);
  ERR_clear_error();

  if (ERR_get_error() != 0) {
    fprintf(stderr, "Error remained after clearing.\n");
    return 0;
  }

  return 1;
}

static int test_print(void) {
  size_t i;
  char buf[256];
  uint32_t packed_error;

  ERR_put_error(1, 2, 3, "test", 4);
  ERR_add_error_data(1, "testing");
  packed_error = ERR_get_error();

  for (i = 0; i <= sizeof(buf); i++) {
    ERR_error_string_n(packed_error, buf, i);
  }

  return 1;
}

static int test_release(void) {
  ERR_put_error(1, 2, 3, "test", 4);
  ERR_remove_thread_state(NULL);
  return 1;
}

int main(void) {
  CRYPTO_library_init();

  if (!test_overflow() ||
      !test_put_error() ||
      !test_clear_error() ||
      !test_print() ||
      !test_release()) {
    return 1;
  }

  printf("PASS\n");
  return 0;
}
