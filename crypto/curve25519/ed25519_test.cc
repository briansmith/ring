/* Copyright (c) 2015, Google Inc.
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

#include <stdint.h>
#include <string.h>

#include <openssl/curve25519.h>

#include "../internal.h"
#include "../test/file_test.h"


static bool TestSignature(FileTest *t, void *arg) {
  std::vector<uint8_t> private_key, public_key, message, expected_signature;
  if (!t->GetBytes(&private_key, "PRIV") ||
      private_key.size() != 64 ||
      !t->GetBytes(&public_key, "PUB") ||
      public_key.size() != 32 ||
      !t->GetBytes(&message, "MESSAGE") ||
      !t->GetBytes(&expected_signature, "SIG") ||
      expected_signature.size() != 64) {
    return false;
  }

  uint8_t signature[64];
  if (!ED25519_sign(signature, message.data(), message.size(),
                    private_key.data())) {
    t->PrintLine("ED25519_sign failed");
    return false;
  }

  if (!t->ExpectBytesEqual(expected_signature.data(), expected_signature.size(),
                           signature, sizeof(signature))) {
    return false;
  }

  if (!ED25519_verify(message.data(), message.size(), signature,
                      public_key.data())) {
    t->PrintLine("ED25519_verify failed");
    return false;
  }

  return true;
}

static bool TestKeypairFromSeed() {
  uint8_t public_key1[32], private_key1[64];
  ED25519_keypair(public_key1, private_key1);

  uint8_t seed[32];
  OPENSSL_memcpy(seed, private_key1, sizeof(seed));

  uint8_t public_key2[32], private_key2[64];
  ED25519_keypair_from_seed(public_key2, private_key2, seed);

  if (OPENSSL_memcmp(public_key1, public_key2, sizeof(public_key1)) != 0 ||
      OPENSSL_memcmp(private_key1, private_key2, sizeof(private_key1)) != 0) {
    fprintf(stderr, "TestKeypairFromSeed: resulting keypairs did not match.\n");
    return false;
  }

  return true;
}

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "%s <test input.txt>\n", argv[0]);
    return 1;
  }

  return TestKeypairFromSeed() && FileTestMain(TestSignature, nullptr, argv[1]);
}
