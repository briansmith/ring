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

#include "openssl/ssl.h"

int main(void) {
  /* Some error codes are special, but the make_errors.go script doesn't know
   * this. This test will catch the case where something regenerates the error
   * codes with the script but doesn't fix up the special ones. */
  if (SSL_R_TLSV1_ALERT_NO_RENEGOTIATION != 100 + SSL_AD_REASON_OFFSET) {
    fprintf(stderr, "SSL alert errors don't match up.\n");
    return 1;
  }

  printf("PASS\n");
  return 0;
}
