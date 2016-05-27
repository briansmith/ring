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

#include "../test/file_test.h"
#include "internal.h"


static bool TestNewhope(FileTest *t, void *arg) {
  if (t->GetType() == "OfferSK") {
    std::vector<uint8_t> offer_sk_bytes, accept_pk_bytes, accept_rec_bytes,
        expected_key;
    if (!t->GetBytes(&offer_sk_bytes, "OfferSK") ||
        !t->GetBytes(&accept_pk_bytes, "AcceptPK") ||
        !t->GetBytes(&accept_rec_bytes, "AcceptRec") ||
        !t->GetBytes(&expected_key, "Key")) {
      return false;
    }
    NEWHOPE_POLY offer_sk, accept_pk, accept_rec;
    NEWHOPE_POLY_frombytes(&offer_sk, offer_sk_bytes.data());
    NEWHOPE_POLY_frombytes(&accept_pk, accept_pk_bytes.data());
    NEWHOPE_POLY_frombytes(&accept_rec, accept_rec_bytes.data());

    uint8_t key[NEWHOPE_KEY_LENGTH];
    NEWHOPE_finish_computation(key, &offer_sk, &accept_pk, &accept_rec);
    return t->ExpectBytesEqual(expected_key.data(), expected_key.size(), key,
                               NEWHOPE_KEY_LENGTH);
  } else if (t->GetType() == "AcceptRand") {
    std::vector<uint8_t> accept_rand, offer_pk_bytes, offer_a_bytes,
        accept_sk_bytes, accept_epp_bytes, expected_key;
    if (!t->GetBytes(&accept_rand, "AcceptRand") ||
        !t->GetBytes(&offer_pk_bytes, "OfferPK") ||
        !t->GetBytes(&offer_a_bytes, "OfferA") ||
        !t->GetBytes(&accept_sk_bytes, "AcceptSK") ||
        !t->GetBytes(&accept_epp_bytes, "AcceptEPP") ||
        !t->GetBytes(&expected_key, "Key")) {
      return false;
    }
    NEWHOPE_POLY offer_pk, offer_a, accept_sk, accept_epp;
    NEWHOPE_POLY_frombytes(&offer_pk, offer_pk_bytes.data());
    NEWHOPE_POLY_frombytes(&offer_a, offer_a_bytes.data());
    NEWHOPE_POLY_frombytes(&accept_sk, accept_sk_bytes.data());
    NEWHOPE_POLY_frombytes(&accept_epp, accept_epp_bytes.data());

    uint8_t key[NEWHOPE_KEY_LENGTH];
    NEWHOPE_POLY bp, reconciliation;
    NEWHOPE_accept_computation(key, &bp, &reconciliation, &accept_sk,
                               &accept_epp, accept_rand.data(), &offer_pk,
                               &offer_a);
    t->ExpectBytesEqual(expected_key.data(), expected_key.size(), key,
                        NEWHOPE_KEY_LENGTH);
  } else {
    t->PrintLine("Unknown test '%s'", t->GetType().c_str());
    return false;
  }
  return true;
}

int main(int argc, char **argv) {
  CRYPTO_library_init();

  if (argc != 2) {
    fprintf(stderr, "%s <test file>\n", argv[0]);
    return 1;
  }

  return FileTestMain(TestNewhope, nullptr, argv[1]);
}
