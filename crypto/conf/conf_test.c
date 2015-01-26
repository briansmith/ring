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

#include <openssl/conf.h>
#include <openssl/crypto.h>


static int stop_cb(const char *elem, int len, void *data) {
  int *count = (int *)data;
  (*count)++;
  return -42;
}

static int test_stop_iteration(void) {
  int count = 0;
  if (CONF_parse_list("foo|bar", '|', 0, stop_cb, &count) != -42) {
    fprintf(stderr, "CONF_parse_list returned incorrect value.\n");
    return 0;
  }

  if (count != 1) {
    fprintf(stderr, "stop_cb called incorrect number of times.\n");
    return 0;
  }

  return 1;
}

static int test_cb(const char *elem, int len, void *data) {
  const char ***ptr = data;
  const char **next = *ptr;
  if (*next == NULL) {
    /* The callback hit the trailing NULL early. */
    fprintf(stderr, "test_cb called too many times.\n");
    return 0;
  }
  if (len < 0 || (size_t)len != strlen(*next) ||
      strncmp(elem, *next, len) != 0) {
    fprintf(stderr, "test_cb called on '%.*s', wanted '%s'\n", len, elem, *next);
    return 0;
  }
  /* Advance to the next expectation. */
  *ptr = next + 1;
  return 1;
}

static int test_parse_list(const char *list, int remove_whitespace,
                           const char **expected) {
  const char **next = expected;
  if (!CONF_parse_list(list, ',', remove_whitespace, test_cb, &next)) {
    return 0;
  }
  if (*next != NULL) {
    fprintf(stderr, "test_cb called too few times.\n");
    return 0;
  }
  return 1;
}

/* Test basic parsing. Whitespace is not trimmed, empty entries are
 * preserved. */
static const char kList1[] = " foo ,, bar , baz ";
static const int kRemoveWhitespace1 = 0;
static const char *kExpected1[] = {
    " foo ",
    "",
    " bar ",
    " baz ",
    NULL,
};

/* Test that a trailing separator gives an empty entry. */
static const char kList2[] = "foo,bar,baz,";
static const int kRemoveWhitespace2 = 0;
static const char *kExpected2[] = {
    "foo",
    "bar",
    "baz",
    "",
    NULL,
};

/* Test whitespace removal. */
static const char kList3[] = " foo ,\n,bar\t, baz ";
static const int kRemoveWhitespace3 = 1;
static const char *kExpected3[] = {
    "foo",
    "",
    "bar",
    "baz",
    NULL,
};

/* Test empty string behavior. */
static const char kList4[] = "";
static const int kRemoveWhitespace4 = 0;
static const char *kExpected4[] = {
    "",
    NULL,
};

int main(void) {
  CRYPTO_library_init();

  if (!test_stop_iteration() ||
      !test_parse_list(kList1, kRemoveWhitespace1, kExpected1) ||
      !test_parse_list(kList2, kRemoveWhitespace2, kExpected2) ||
      !test_parse_list(kList3, kRemoveWhitespace3, kExpected3) ||
      !test_parse_list(kList4, kRemoveWhitespace4, kExpected4)) {
    return 1;
  }

  printf("PASS\n");
  return 0;
}
