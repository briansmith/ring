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

#include <gtest/gtest.h>

#include <openssl/aead.h>
#include <openssl/cipher.h>
#include <openssl/err.h>


// Test that EVP_aead_aes_128_gcm and EVP_aead_aes_256_gcm reject empty nonces.
// AES-GCM is not defined for those.
//
// TODO(davidben): Fold this into aead_test.cc, once it is converted to GTest.
TEST(AEADTest, AESGCMEmptyNonce) {
  static const uint8_t kZeros[32] = {0};

  // Test AES-128-GCM.
  uint8_t buf[16];
  size_t len;
  bssl::ScopedEVP_AEAD_CTX ctx;
  ASSERT_TRUE(EVP_AEAD_CTX_init(ctx.get(), EVP_aead_aes_128_gcm(), kZeros, 16,
                                EVP_AEAD_DEFAULT_TAG_LENGTH, nullptr));

  EXPECT_FALSE(EVP_AEAD_CTX_seal(ctx.get(), buf, &len, sizeof(buf),
                                 nullptr /* nonce */, 0, nullptr /* in */, 0,
                                 nullptr /* ad */, 0));
  uint32_t err = ERR_get_error();
  EXPECT_EQ(ERR_LIB_CIPHER, ERR_GET_LIB(err));
  EXPECT_EQ(CIPHER_R_INVALID_NONCE_SIZE, ERR_GET_REASON(err));

  EXPECT_FALSE(EVP_AEAD_CTX_open(ctx.get(), buf, &len, sizeof(buf),
                                 nullptr /* nonce */, 0, kZeros /* in */,
                                 sizeof(kZeros), nullptr /* ad */, 0));
  err = ERR_get_error();
  EXPECT_EQ(ERR_LIB_CIPHER, ERR_GET_LIB(err));
  EXPECT_EQ(CIPHER_R_INVALID_NONCE_SIZE, ERR_GET_REASON(err));

  // Test AES-256-GCM.
  ctx.Reset();
  ASSERT_TRUE(EVP_AEAD_CTX_init(ctx.get(), EVP_aead_aes_256_gcm(), kZeros, 32,
                                EVP_AEAD_DEFAULT_TAG_LENGTH, nullptr));

  EXPECT_FALSE(EVP_AEAD_CTX_seal(ctx.get(), buf, &len, sizeof(buf),
                                 nullptr /* nonce */, 0, nullptr /* in */, 0,
                                 nullptr /* ad */, 0));
  err = ERR_get_error();
  EXPECT_EQ(ERR_LIB_CIPHER, ERR_GET_LIB(err));
  EXPECT_EQ(CIPHER_R_INVALID_NONCE_SIZE, ERR_GET_REASON(err));

  EXPECT_FALSE(EVP_AEAD_CTX_open(ctx.get(), buf, &len, sizeof(buf),
                                 nullptr /* nonce */, 0, kZeros /* in */,
                                 sizeof(kZeros), nullptr /* ad */, 0));
  err = ERR_get_error();
  EXPECT_EQ(ERR_LIB_CIPHER, ERR_GET_LIB(err));
  EXPECT_EQ(CIPHER_R_INVALID_NONCE_SIZE, ERR_GET_REASON(err));
}
