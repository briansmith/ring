/* Copyright (c) 2016, Google Inc.
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

#include <math.h>
#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include "internal.h"


#define NTESTS 1

static int test_keys(void) {
  NEWHOPE_POLY *sk = NEWHOPE_POLY_new();
  uint8_t offer_key[SHA256_DIGEST_LENGTH], accept_key[SHA256_DIGEST_LENGTH];
  uint8_t offermsg[NEWHOPE_OFFERMSG_LENGTH];
  uint8_t acceptmsg[NEWHOPE_ACCEPTMSG_LENGTH];
  int i;

  for (i = 0; i < NTESTS; i++) {
    /* Alice generates a public key */
    NEWHOPE_offer(offermsg, sk);

    /* Bob derives a secret key and creates a response */
    if (!NEWHOPE_accept(accept_key, acceptmsg, offermsg, sizeof(offermsg))) {
      fprintf(stderr, "ERROR accept key exchange failed\n");
      return 0;
    }

    /* Alice uses Bob's response to get her secret key */
    if (!NEWHOPE_finish(offer_key, sk, acceptmsg, sizeof(acceptmsg))) {
      fprintf(stderr, "ERROR finish key exchange failed\n");
      return 0;
    }

    if (memcmp(offer_key, accept_key, SHA256_DIGEST_LENGTH) != 0) {
      fprintf(stderr, "ERROR keys did not agree\n");
      return 0;
    }
  }

  NEWHOPE_POLY_free(sk);
  return 1;
}

static int test_invalid_sk_a(void) {
  NEWHOPE_POLY *sk = NEWHOPE_POLY_new();
  uint8_t offer_key[SHA256_DIGEST_LENGTH], accept_key[SHA256_DIGEST_LENGTH];
  uint8_t offermsg[NEWHOPE_OFFERMSG_LENGTH];
  uint8_t acceptmsg[NEWHOPE_ACCEPTMSG_LENGTH];
  int i;

  for (i = 0; i < NTESTS; i++) {
    /* Alice generates a public key */
    NEWHOPE_offer(offermsg, sk);

    /* Bob derives a secret key and creates a response */
    if (!NEWHOPE_accept(accept_key, acceptmsg, offermsg, sizeof(offermsg))) {
      fprintf(stderr, "ERROR accept key exchange failed\n");
      return 0;
    }

    /* Corrupt the secret key */
    NEWHOPE_offer(offermsg /* not used below */, sk);

    /* Alice uses Bob's response to get her secret key */
    if (!NEWHOPE_finish(offer_key, sk, acceptmsg, sizeof(acceptmsg))) {
      fprintf(stderr, "ERROR finish key exchange failed\n");
      return 0;
    }

    if (memcmp(offer_key, accept_key, SHA256_DIGEST_LENGTH) == 0) {
      fprintf(stderr, "ERROR invalid sk_a\n");
      return 0;
    }
  }

  NEWHOPE_POLY_free(sk);
  return 1;
}

static int test_invalid_ciphertext(void) {
  NEWHOPE_POLY *sk = NEWHOPE_POLY_new();
  uint8_t offer_key[SHA256_DIGEST_LENGTH], accept_key[SHA256_DIGEST_LENGTH];
  uint8_t offermsg[NEWHOPE_OFFERMSG_LENGTH];
  uint8_t acceptmsg[NEWHOPE_ACCEPTMSG_LENGTH];
  int i;

  for (i = 0; i < 10; i++) {
    /* Alice generates a public key */
    NEWHOPE_offer(offermsg, sk);

    /* Bob derives a secret key and creates a response */
    if (!NEWHOPE_accept(accept_key, acceptmsg, offermsg, sizeof(offermsg))) {
      fprintf(stderr, "ERROR accept key exchange failed\n");
      return 0;
    }

    /* Change some byte in the "ciphertext" */
    acceptmsg[42] ^= 1;

    /* Alice uses Bob's response to get her secret key */
    if (!NEWHOPE_finish(offer_key, sk, acceptmsg, sizeof(acceptmsg))) {
      fprintf(stderr, "ERROR finish key exchange failed\n");
      return 0;
    }

    if (!memcmp(offer_key, accept_key, SHA256_DIGEST_LENGTH)) {
      fprintf(stderr, "ERROR invalid acceptmsg\n");
      return 0;
    }
  }

  NEWHOPE_POLY_free(sk);
  return 1;
}

int main(void) {
  if (!test_keys() || !test_invalid_sk_a() || !test_invalid_ciphertext()) {
    return 1;
  }
  printf("PASS\n");
  return 0;
}
