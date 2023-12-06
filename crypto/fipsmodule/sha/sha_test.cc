/* Copyright (c) 2018, Google Inc.
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

#include <openssl/sha.h>

#include <vector>

#include <gtest/gtest.h>

#include "internal.h"
#include "../../test/abi_test.h"
#include "../../test/test_util.h"


TEST(SHATest, FIPS1862PRF) {
  // From "Multiple Examples of DSA", section 2.2, fetched from archived copy at
  // https://web.archive.org/web/20041031124637/http://csrc.nist.gov/CryptoToolkit/dss/Examples-1024bit.pdf
  const uint8_t kSeed[] = {0xbd, 0x02, 0x9b, 0xbe, 0x7f, 0x51, 0x96,
                           0x0b, 0xcf, 0x9e, 0xdb, 0x2b, 0x61, 0xf0,
                           0x6f, 0x0f, 0xeb, 0x5a, 0x38, 0xb6};
  const uint8_t kExpected[] = {0x20, 0x70, 0xb3, 0x22, 0x3d, 0xba, 0x37, 0x2f,
                               0xde, 0x1c, 0x0f, 0xfc, 0x7b, 0x2e, 0x3b, 0x49,
                               0x8b, 0x26, 0x06, 0x14, 0x3c, 0x6c, 0x18, 0xba,
                               0xcb, 0x0f, 0x6c, 0x55, 0xba, 0xbb, 0x13, 0x78,
                               0x8e, 0x20, 0xd7, 0x37, 0xa3, 0x27, 0x51, 0x16};
  for (size_t len = 0; len <= sizeof(kExpected); len++) {
    SCOPED_TRACE(len);
    std::vector<uint8_t> out(len);
    CRYPTO_fips_186_2_prf(out.data(), out.size(), kSeed);
    EXPECT_EQ(Bytes(out), Bytes(kExpected, len));
  }
}

#if defined(SHA1_ASM) && defined(SUPPORTS_ABI_TEST)
TEST(SHATest, SHA1ABI) {
  SHA_CTX ctx;
  SHA1_Init(&ctx);

  static const uint8_t kBuf[SHA_CBLOCK * 8] = {0};
  CHECK_ABI(sha1_block_data_order, ctx.h, kBuf, 1);
  CHECK_ABI(sha1_block_data_order, ctx.h, kBuf, 2);
  CHECK_ABI(sha1_block_data_order, ctx.h, kBuf, 4);
  CHECK_ABI(sha1_block_data_order, ctx.h, kBuf, 8);
}
#endif  // SHA1_ASM && SUPPORTS_ABI_TEST

#if defined(SHA256_ASM) && defined(SUPPORTS_ABI_TEST)
TEST(SHATest, SHA256ABI) {
  SHA256_CTX ctx;
  SHA256_Init(&ctx);

  static const uint8_t kBuf[SHA256_CBLOCK * 8] = {0};
  CHECK_ABI(sha256_block_data_order, ctx.h, kBuf, 1);
  CHECK_ABI(sha256_block_data_order, ctx.h, kBuf, 2);
  CHECK_ABI(sha256_block_data_order, ctx.h, kBuf, 4);
  CHECK_ABI(sha256_block_data_order, ctx.h, kBuf, 8);
}
#endif  // SHA256_ASM && SUPPORTS_ABI_TEST

#if defined(SHA512_ASM) && defined(SUPPORTS_ABI_TEST)
TEST(SHATest, SHA512ABI) {
  SHA512_CTX ctx;
  SHA512_Init(&ctx);

  static const uint8_t kBuf[SHA512_CBLOCK * 4] = {0};
  CHECK_ABI(sha512_block_data_order, ctx.h, kBuf, 1);
  CHECK_ABI(sha512_block_data_order, ctx.h, kBuf, 2);
  CHECK_ABI(sha512_block_data_order, ctx.h, kBuf, 3);
  CHECK_ABI(sha512_block_data_order, ctx.h, kBuf, 4);
}
#endif  // SHA512_ASM && SUPPORTS_ABI_TEST
