/* Copyright (c) 2023, Google Inc.
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

#include <gtest/gtest.h>

#include "../test/file_test.h"
#include "../test/test_util.h"
#include "./internal.h"


static void KeccakFileTest(FileTest *t) {
  std::vector<uint8_t> input, sha3_256_expected, sha3_512_expected,
      shake128_expected, shake256_expected;
  ASSERT_TRUE(t->GetBytes(&input, "Input"));
  ASSERT_TRUE(t->GetBytes(&sha3_256_expected, "SHA3-256"));
  ASSERT_TRUE(t->GetBytes(&sha3_512_expected, "SHA3-512"));
  ASSERT_TRUE(t->GetBytes(&shake128_expected, "SHAKE-128"));
  ASSERT_TRUE(t->GetBytes(&shake256_expected, "SHAKE-256"));

  uint8_t sha3_256_digest[32];
  BORINGSSL_keccak(sha3_256_digest, sizeof(sha3_256_digest), input.data(),
                   input.size(), boringssl_sha3_256);
  uint8_t sha3_512_digest[64];
  BORINGSSL_keccak(sha3_512_digest, sizeof(sha3_512_digest), input.data(),
                   input.size(), boringssl_sha3_512);
  uint8_t shake128_output[512];
  BORINGSSL_keccak(shake128_output, sizeof(shake128_output), input.data(),
                   input.size(), boringssl_shake128);
  uint8_t shake256_output[512];
  BORINGSSL_keccak(shake256_output, sizeof(shake256_output), input.data(),
                   input.size(), boringssl_shake256);

  EXPECT_EQ(Bytes(sha3_256_expected), Bytes(sha3_256_digest));
  EXPECT_EQ(Bytes(sha3_512_expected), Bytes(sha3_512_digest));
  EXPECT_EQ(Bytes(shake128_expected), Bytes(shake128_output));
  EXPECT_EQ(Bytes(shake256_expected), Bytes(shake256_output));

  struct BORINGSSL_keccak_st ctx;

  BORINGSSL_keccak_init(&ctx, input.data(), input.size(), boringssl_shake128);
  for (size_t i = 0; i < sizeof(shake128_output); i++) {
    BORINGSSL_keccak_squeeze(&ctx, &shake128_output[i], 1);
  }
  EXPECT_EQ(Bytes(shake128_expected), Bytes(shake128_output));

  BORINGSSL_keccak_init(&ctx, input.data(), input.size(), boringssl_shake256);
  for (size_t i = 0; i < sizeof(shake256_output); i++) {
    BORINGSSL_keccak_squeeze(&ctx, &shake256_output[i], 1);
  }
  EXPECT_EQ(Bytes(shake256_expected), Bytes(shake256_output));
}

TEST(KyberTest, Keccak) {
  FileTestGTest("crypto/kyber/keccak_tests.txt", KeccakFileTest);
}
