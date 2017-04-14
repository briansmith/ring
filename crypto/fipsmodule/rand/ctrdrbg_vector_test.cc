/* Copyright (c) 2017, Google Inc.
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

#include <openssl/crypto.h>

#include "internal.h"
#include "../../test/test_util.h"
#include "../../test/file_test.h"


static bool TestCTRDRBG(FileTest *t, void *arg) {
  std::vector<uint8_t> seed, personalisation, reseed, ai_reseed, ai1, ai2,
    expected;
  if (!t->GetBytes(&seed, "EntropyInput") ||
      !t->GetBytes(&personalisation, "PersonalizationString") ||
      !t->GetBytes(&reseed, "EntropyInputReseed") ||
      !t->GetBytes(&ai_reseed, "AdditionalInputReseed") ||
      !t->GetBytes(&ai1, "AdditionalInput1") ||
      !t->GetBytes(&ai2, "AdditionalInput2") ||
      !t->GetBytes(&expected, "ReturnedBits")) {
    t->PrintLine("missing value");
    return false;
  }

  if (seed.size() != CTR_DRBG_ENTROPY_LEN ||
      reseed.size() != CTR_DRBG_ENTROPY_LEN) {
    t->PrintLine("bad seed length");
    return false;
  }

  CTR_DRBG_STATE drbg;
  CTR_DRBG_init(&drbg, seed.data(),
                personalisation.size() > 0 ? personalisation.data() : nullptr,
                personalisation.size());
  CTR_DRBG_reseed(&drbg, reseed.data(),
                  ai_reseed.size() > 0 ? ai_reseed.data() : nullptr,
                  ai_reseed.size());

  std::vector<uint8_t> out;
  out.resize(expected.size());

  CTR_DRBG_generate(&drbg, out.data(), out.size(),
                    ai1.size() > 0 ? ai1.data() : nullptr, ai1.size());
  CTR_DRBG_generate(&drbg, out.data(), out.size(),
                    ai2.size() > 0 ? ai2.data() : nullptr, ai2.size());

  return t->ExpectBytesEqual(expected.data(), expected.size(), out.data(),
                             out.size());
}

int main(int argc, char **argv) {
  CRYPTO_library_init();

  if (argc != 2) {
    fprintf(stderr, "%s <test file>\n", argv[0]);
    return 1;
  }

  return FileTestMain(TestCTRDRBG, nullptr, argv[1]);
}
