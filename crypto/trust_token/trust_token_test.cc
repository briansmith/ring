/* Copyright (c) 2020, Google Inc.
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
#include <time.h>

#include <algorithm>
#include <limits>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include <openssl/bytestring.h>
#include <openssl/curve25519.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/rand.h>
#include <openssl/trust_token.h>

#include "../internal.h"
#include "internal.h"


BSSL_NAMESPACE_BEGIN

namespace {

TEST(TrustTokenTest, KeyGen) {
  uint8_t priv_key[TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE];
  uint8_t pub_key[TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE];
  size_t priv_key_len, pub_key_len;
  ASSERT_TRUE(TRUST_TOKEN_generate_key(
      priv_key, &priv_key_len, TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE, pub_key,
      &pub_key_len, TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE, 0x0001));
  ASSERT_EQ(400u, priv_key_len);
  ASSERT_EQ(409u, pub_key_len);
}

class TrustTokenProtocolTest : public ::testing::Test {
 public:
  // KeyID returns the key ID associated with key index |i|.
  static uint32_t KeyID(size_t i) {
    // Use a different value from the indices to that we do not mix them up.
    return 7 + i;
  }

 protected:
  void SetupContexts() {
    client.reset(TRUST_TOKEN_CLIENT_new(client_max_batchsize));
    ASSERT_TRUE(client);
    issuer.reset(TRUST_TOKEN_ISSUER_new(issuer_max_batchsize));
    ASSERT_TRUE(issuer);

    for (size_t i = 0; i < 3; i++) {
      uint8_t priv_key[TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE];
      uint8_t pub_key[TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE];
      size_t priv_key_len, pub_key_len, key_index;
      ASSERT_TRUE(TRUST_TOKEN_generate_key(
          priv_key, &priv_key_len, TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE, pub_key,
          &pub_key_len, TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE, KeyID(i)));
      ASSERT_TRUE(TRUST_TOKEN_CLIENT_add_key(client.get(), &key_index, pub_key,
                                             pub_key_len));
      ASSERT_EQ(i, key_index);
      ASSERT_TRUE(
          TRUST_TOKEN_ISSUER_add_key(issuer.get(), priv_key, priv_key_len));
    }

    uint8_t public_key[32], private_key[64];
    ED25519_keypair(public_key, private_key);
    bssl::UniquePtr<EVP_PKEY> priv(EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr, private_key, 32));
    ASSERT_TRUE(priv);
    bssl::UniquePtr<EVP_PKEY> pub(
        EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, public_key, 32));
    ASSERT_TRUE(pub);

    TRUST_TOKEN_CLIENT_set_srr_key(client.get(), pub.get());
    TRUST_TOKEN_ISSUER_set_srr_key(issuer.get(), priv.get());
    RAND_bytes(metadata_key, sizeof(metadata_key));
    ASSERT_TRUE(TRUST_TOKEN_ISSUER_set_metadata_key(issuer.get(), metadata_key,
                                                    sizeof(metadata_key)));
  }

  uint16_t client_max_batchsize = 10;
  uint16_t issuer_max_batchsize = 10;
  bssl::UniquePtr<TRUST_TOKEN_CLIENT> client;
  bssl::UniquePtr<TRUST_TOKEN_ISSUER> issuer;
  uint8_t metadata_key[32];
};

TEST_F(TrustTokenProtocolTest, InvalidToken) {
  ASSERT_NO_FATAL_FAILURE(SetupContexts());

  uint8_t *issue_msg = NULL, *issue_resp = NULL;
  size_t msg_len, resp_len;

  size_t key_index;
  uint8_t tokens_issued;
  ASSERT_TRUE(
      TRUST_TOKEN_CLIENT_begin_issuance(client.get(), &issue_msg, &msg_len, 1));
  bssl::UniquePtr<uint8_t> free_issue_msg(issue_msg);
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_issue(
      issuer.get(), &issue_resp, &resp_len, &tokens_issued, issue_msg, msg_len,
      /*public_metadata=*/KeyID(0), /*private_metadata=*/1,
      /*max_issuance=*/10));
  bssl::UniquePtr<uint8_t> free_msg(issue_resp);
  bssl::UniquePtr<STACK_OF(TRUST_TOKEN)> tokens(
      TRUST_TOKEN_CLIENT_finish_issuance(client.get(), &key_index, issue_resp,
                                         resp_len));
  ASSERT_TRUE(tokens);

  for (TRUST_TOKEN *token : tokens.get()) {
    // Corrupt the token.
    token->data[0] ^= 0x42;

    uint8_t *redeem_msg = NULL, *redeem_resp = NULL;
    ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_redemption(
        client.get(), &redeem_msg, &msg_len, token, NULL, 0, 0));
    bssl::UniquePtr<uint8_t> free_redeem_msg(redeem_msg);
    TRUST_TOKEN *rtoken;
    uint8_t *client_data;
    size_t client_data_len;
    uint64_t redemption_time;
    ASSERT_FALSE(TRUST_TOKEN_ISSUER_redeem(
        issuer.get(), &redeem_resp, &resp_len, &rtoken, &client_data,
        &client_data_len, &redemption_time, redeem_msg, msg_len, 600));
    bssl::UniquePtr<uint8_t> free_redeem_resp(redeem_resp);
  }
}

TEST_F(TrustTokenProtocolTest, TruncatedIssuanceRequest) {
  ASSERT_NO_FATAL_FAILURE(SetupContexts());

  uint8_t *issue_msg = NULL, *issue_resp = NULL;
  size_t msg_len, resp_len;
  ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_issuance(client.get(), &issue_msg,
                                                &msg_len, 10));
  bssl::UniquePtr<uint8_t> free_issue_msg(issue_msg);
  msg_len = 10;
  uint8_t tokens_issued;
  ASSERT_FALSE(TRUST_TOKEN_ISSUER_issue(
      issuer.get(), &issue_resp, &resp_len, &tokens_issued, issue_msg, msg_len,
      /*public_metadata=*/KeyID(0), /*private_metadata=*/0,
      /*max_issuance=*/10));
  bssl::UniquePtr<uint8_t> free_msg(issue_resp);
}

TEST_F(TrustTokenProtocolTest, TruncatedIssuanceResponse) {
  ASSERT_NO_FATAL_FAILURE(SetupContexts());

  uint8_t *issue_msg = NULL, *issue_resp = NULL;
  size_t msg_len, resp_len;
  ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_issuance(client.get(), &issue_msg,
                                                &msg_len, 10));
  bssl::UniquePtr<uint8_t> free_issue_msg(issue_msg);
  uint8_t tokens_issued;
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_issue(
      issuer.get(), &issue_resp, &resp_len, &tokens_issued, issue_msg, msg_len,
      /*public_metadata=*/KeyID(0), /*private_metadata=*/0,
      /*max_issuance=*/10));
  bssl::UniquePtr<uint8_t> free_msg(issue_resp);
  resp_len = 10;
  size_t key_index;
  bssl::UniquePtr<STACK_OF(TRUST_TOKEN)> tokens(
      TRUST_TOKEN_CLIENT_finish_issuance(client.get(), &key_index, issue_resp,
                                         resp_len));
  ASSERT_FALSE(tokens);
}

TEST_F(TrustTokenProtocolTest, TruncatedRedemptionRequest) {
  ASSERT_NO_FATAL_FAILURE(SetupContexts());

  uint8_t *issue_msg = NULL, *issue_resp = NULL;
  size_t msg_len, resp_len;
  ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_issuance(client.get(), &issue_msg,
                                                &msg_len, 10));
  bssl::UniquePtr<uint8_t> free_issue_msg(issue_msg);
  uint8_t tokens_issued;
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_issue(
      issuer.get(), &issue_resp, &resp_len, &tokens_issued, issue_msg, msg_len,
      /*public_metadata=*/KeyID(0), /*private_metadata=*/0,
      /*max_issuance=*/10));
  bssl::UniquePtr<uint8_t> free_msg(issue_resp);
  size_t key_index;
  bssl::UniquePtr<STACK_OF(TRUST_TOKEN)> tokens(
      TRUST_TOKEN_CLIENT_finish_issuance(client.get(), &key_index, issue_resp,
                                         resp_len));
  ASSERT_TRUE(tokens);

  for (TRUST_TOKEN *token : tokens.get()) {
    const uint8_t kClientData[] = "\x70TEST CLIENT DATA";
    uint64_t kRedemptionTime = 13374242;

    uint8_t *redeem_msg = NULL, *redeem_resp = NULL;
    ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_redemption(
        client.get(), &redeem_msg, &msg_len, token, kClientData,
        sizeof(kClientData) - 1, kRedemptionTime));
    bssl::UniquePtr<uint8_t> free_redeem_msg(redeem_msg);
    msg_len = 10;

    TRUST_TOKEN *rtoken;
    uint8_t *client_data;
    size_t client_data_len;
    uint64_t redemption_time;
    ASSERT_FALSE(TRUST_TOKEN_ISSUER_redeem(
        issuer.get(), &redeem_resp, &resp_len, &rtoken, &client_data,
        &client_data_len, &redemption_time, redeem_msg, msg_len, 600));
  }
}

TEST_F(TrustTokenProtocolTest, TruncatedRedemptionResponse) {
  ASSERT_NO_FATAL_FAILURE(SetupContexts());

  uint8_t *issue_msg = NULL, *issue_resp = NULL;
  size_t msg_len, resp_len;
  ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_issuance(client.get(), &issue_msg,
                                                &msg_len, 10));
  bssl::UniquePtr<uint8_t> free_issue_msg(issue_msg);
  uint8_t tokens_issued;
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_issue(
      issuer.get(), &issue_resp, &resp_len, &tokens_issued, issue_msg, msg_len,
      /*public_metadata=*/KeyID(0), /*private_metadata=*/0,
      /*max_issuance=*/10));
  bssl::UniquePtr<uint8_t> free_msg(issue_resp);
  size_t key_index;
  bssl::UniquePtr<STACK_OF(TRUST_TOKEN)> tokens(
      TRUST_TOKEN_CLIENT_finish_issuance(client.get(), &key_index, issue_resp,
                                         resp_len));
  ASSERT_TRUE(tokens);

  for (TRUST_TOKEN *token : tokens.get()) {
    const uint8_t kClientData[] = "\x70TEST CLIENT DATA";
    uint64_t kRedemptionTime = 13374242;

    uint8_t *redeem_msg = NULL, *redeem_resp = NULL;
    ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_redemption(
        client.get(), &redeem_msg, &msg_len, token, kClientData,
        sizeof(kClientData) - 1, kRedemptionTime));
    bssl::UniquePtr<uint8_t> free_redeem_msg(redeem_msg);
    TRUST_TOKEN *rtoken;
    uint8_t *client_data;
    size_t client_data_len;
    uint64_t redemption_time;
    ASSERT_TRUE(TRUST_TOKEN_ISSUER_redeem(
        issuer.get(), &redeem_resp, &resp_len, &rtoken, &client_data,
        &client_data_len, &redemption_time, redeem_msg, msg_len, 600));
    bssl::UniquePtr<uint8_t> free_redeem_resp(redeem_resp);
    bssl::UniquePtr<uint8_t> free_client_data(client_data);
    bssl::UniquePtr<TRUST_TOKEN> free_rtoken(rtoken);

    ASSERT_EQ(redemption_time, kRedemptionTime);
    ASSERT_TRUE(sizeof(kClientData) - 1 == client_data_len);
    ASSERT_EQ(OPENSSL_memcmp(kClientData, client_data, client_data_len), 0);
    resp_len = 10;

    uint8_t *srr = NULL, *sig = NULL;
    size_t srr_len, sig_len;
    ASSERT_FALSE(TRUST_TOKEN_CLIENT_finish_redemption(
        client.get(), &srr, &srr_len, &sig, &sig_len, redeem_resp, resp_len));
    bssl::UniquePtr<uint8_t> free_srr(srr);
    bssl::UniquePtr<uint8_t> free_sig(sig);
  }
}

TEST_F(TrustTokenProtocolTest, IssuedWithBadKeyID) {
  client.reset(TRUST_TOKEN_CLIENT_new(client_max_batchsize));
  ASSERT_TRUE(client);
  issuer.reset(TRUST_TOKEN_ISSUER_new(issuer_max_batchsize));
  ASSERT_TRUE(issuer);

  // We configure the client and the issuer with different key IDs and test
  // that the client notices.
  const uint32_t kClientKeyID = 0;
  const uint32_t kIssuerKeyID = 42;

  uint8_t priv_key[TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE];
  uint8_t pub_key[TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE];
  size_t priv_key_len, pub_key_len, key_index;
  ASSERT_TRUE(TRUST_TOKEN_generate_key(
      priv_key, &priv_key_len, TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE, pub_key,
      &pub_key_len, TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE, kClientKeyID));
  ASSERT_TRUE(TRUST_TOKEN_CLIENT_add_key(client.get(), &key_index, pub_key,
                                         pub_key_len));
  ASSERT_EQ(0UL, key_index);

  ASSERT_TRUE(TRUST_TOKEN_generate_key(
      priv_key, &priv_key_len, TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE, pub_key,
      &pub_key_len, TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE, kIssuerKeyID));
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_add_key(issuer.get(), priv_key, priv_key_len));


  uint8_t public_key[32], private_key[64];
  ED25519_keypair(public_key, private_key);
  bssl::UniquePtr<EVP_PKEY> priv(
      EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, private_key, 32));
  ASSERT_TRUE(priv);
  bssl::UniquePtr<EVP_PKEY> pub(
      EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, public_key, 32));
  ASSERT_TRUE(pub);

  TRUST_TOKEN_CLIENT_set_srr_key(client.get(), pub.get());
  TRUST_TOKEN_ISSUER_set_srr_key(issuer.get(), priv.get());
  RAND_bytes(metadata_key, sizeof(metadata_key));
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_set_metadata_key(issuer.get(), metadata_key,
                                                  sizeof(metadata_key)));


  uint8_t *issue_msg = NULL, *issue_resp = NULL;
  size_t msg_len, resp_len;
  ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_issuance(client.get(), &issue_msg,
                                                &msg_len, 10));
  bssl::UniquePtr<uint8_t> free_issue_msg(issue_msg);
  uint8_t tokens_issued;
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_issue(
      issuer.get(), &issue_resp, &resp_len, &tokens_issued, issue_msg, msg_len,
      /*public_metadata=*/42, /*private_metadata=*/0, /*max_issuance=*/10));
  bssl::UniquePtr<uint8_t> free_msg(issue_resp);
  bssl::UniquePtr<STACK_OF(TRUST_TOKEN)> tokens(
      TRUST_TOKEN_CLIENT_finish_issuance(client.get(), &key_index, issue_resp,
                                         resp_len));
  ASSERT_FALSE(tokens);
}

class TrustTokenMetadataTest
    : public TrustTokenProtocolTest,
      public testing::WithParamInterface<std::tuple<int, bool>> {};

TEST_P(TrustTokenMetadataTest, SetAndGetMetadata) {
  ASSERT_NO_FATAL_FAILURE(SetupContexts());

  uint8_t *issue_msg = NULL, *issue_resp = NULL;
  size_t msg_len, resp_len;
  ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_issuance(client.get(), &issue_msg,
                                                &msg_len, 10));
  bssl::UniquePtr<uint8_t> free_issue_msg(issue_msg);
  uint8_t tokens_issued;
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_issue(
      issuer.get(), &issue_resp, &resp_len, &tokens_issued, issue_msg, msg_len,
      std::get<0>(GetParam()), std::get<1>(GetParam()), /*max_issuance=*/1));
  bssl::UniquePtr<uint8_t> free_msg(issue_resp);
  size_t key_index;
  bssl::UniquePtr<STACK_OF(TRUST_TOKEN)> tokens(
      TRUST_TOKEN_CLIENT_finish_issuance(client.get(), &key_index, issue_resp,
                                         resp_len));
  ASSERT_TRUE(tokens);

  for (TRUST_TOKEN *token : tokens.get()) {
    const uint8_t kClientData[] = "\x70TEST CLIENT DATA";
    uint64_t kRedemptionTime = 13374242;

    const uint8_t kExpectedSRR[] =
        "\xa3\x68\x6d\x65\x74\x61\x64\x61\x74\x61\xa2\x66\x70\x75\x62\x6c\x69"
        "\x63\x00\x67\x70\x72\x69\x76\x61\x74\x65\x00\x6b\x63\x6c\x69\x65\x6e"
        "\x74\x2d\x64\x61\x74\x61\x70\x54\x45\x53\x54\x20\x43\x4c\x49\x45\x4e"
        "\x54\x20\x44\x41\x54\x41\x70\x65\x78\x70\x69\x72\x79\x2d\x74\x69\x6d"
        "\x65\x73\x74\x61\x6d\x70\x1a\x00\xcc\x15\x7a";

    uint8_t *redeem_msg = NULL, *redeem_resp = NULL;
    ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_redemption(
        client.get(), &redeem_msg, &msg_len, token, kClientData,
        sizeof(kClientData) - 1, kRedemptionTime));
    bssl::UniquePtr<uint8_t> free_redeem_msg(redeem_msg);
    TRUST_TOKEN *rtoken;
    uint8_t *client_data;
    size_t client_data_len;
    uint64_t redemption_time;
    ASSERT_TRUE(TRUST_TOKEN_ISSUER_redeem(
        issuer.get(), &redeem_resp, &resp_len, &rtoken, &client_data,
        &client_data_len, &redemption_time, redeem_msg, msg_len, 600));
    bssl::UniquePtr<uint8_t> free_redeem_resp(redeem_resp);
    bssl::UniquePtr<uint8_t> free_client_data(client_data);
    bssl::UniquePtr<TRUST_TOKEN> free_rtoken(rtoken);

    ASSERT_EQ(redemption_time, kRedemptionTime);
    ASSERT_TRUE(sizeof(kClientData) - 1 == client_data_len);
    ASSERT_EQ(OPENSSL_memcmp(kClientData, client_data, client_data_len), 0);

    uint8_t *srr = NULL, *sig = NULL;
    size_t srr_len, sig_len;
    ASSERT_TRUE(TRUST_TOKEN_CLIENT_finish_redemption(
        client.get(), &srr, &srr_len, &sig, &sig_len, redeem_resp, resp_len));
    bssl::UniquePtr<uint8_t> free_srr(srr);
    bssl::UniquePtr<uint8_t> free_sig(sig);

    uint8_t private_metadata;
    ASSERT_TRUE(TRUST_TOKEN_decode_private_metadata(
        &private_metadata, metadata_key, sizeof(metadata_key), kClientData,
        sizeof(kClientData) - 1, srr[27]));
    ASSERT_EQ(srr[18], std::get<0>(GetParam()));
    ASSERT_EQ(private_metadata, std::get<1>(GetParam()));

    // Clear out the metadata bits.
    srr[18] = 0;
    srr[27] = 0;

    ASSERT_TRUE(sizeof(kExpectedSRR) - 1 == srr_len);
    ASSERT_EQ(OPENSSL_memcmp(kExpectedSRR, srr, srr_len), 0);
  }
}

TEST_P(TrustTokenMetadataTest, TooManyRequests) {
  issuer_max_batchsize = 1;
  ASSERT_NO_FATAL_FAILURE(SetupContexts());

  uint8_t *issue_msg = NULL, *issue_resp = NULL;
  size_t msg_len, resp_len;
  ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_issuance(client.get(), &issue_msg,
                                                &msg_len, 10));
  bssl::UniquePtr<uint8_t> free_issue_msg(issue_msg);
  uint8_t tokens_issued;
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_issue(
      issuer.get(), &issue_resp, &resp_len, &tokens_issued, issue_msg, msg_len,
      std::get<0>(GetParam()), std::get<1>(GetParam()), /*max_issuance=*/1));
  bssl::UniquePtr<uint8_t> free_msg(issue_resp);
  ASSERT_EQ(tokens_issued, issuer_max_batchsize);
  size_t key_index;
  bssl::UniquePtr<STACK_OF(TRUST_TOKEN)> tokens(
      TRUST_TOKEN_CLIENT_finish_issuance(client.get(), &key_index, issue_resp,
                                         resp_len));
  ASSERT_TRUE(tokens);
  ASSERT_EQ(sk_TRUST_TOKEN_num(tokens.get()), 1UL);
}


TEST_P(TrustTokenMetadataTest, TruncatedProof) {
  ASSERT_NO_FATAL_FAILURE(SetupContexts());

  uint8_t *issue_msg = NULL, *issue_resp = NULL;
  size_t msg_len, resp_len;
  ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_issuance(client.get(), &issue_msg,
                                                &msg_len, 10));
  bssl::UniquePtr<uint8_t> free_issue_msg(issue_msg);
  uint8_t tokens_issued;
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_issue(
      issuer.get(), &issue_resp, &resp_len, &tokens_issued, issue_msg, msg_len,
      std::get<0>(GetParam()), std::get<1>(GetParam()), /*max_issuance=*/1));
  bssl::UniquePtr<uint8_t> free_msg(issue_resp);

  CBS real_response;
  CBS_init(&real_response, issue_resp, resp_len);
  uint16_t count;
  uint32_t public_metadata;
  bssl::ScopedCBB bad_response;
  ASSERT_TRUE(CBB_init(bad_response.get(), 0));
  ASSERT_TRUE(CBS_get_u16(&real_response, &count));
  ASSERT_TRUE(CBB_add_u16(bad_response.get(), count));
  ASSERT_TRUE(CBS_get_u32(&real_response, &public_metadata));
  ASSERT_TRUE(CBB_add_u32(bad_response.get(), public_metadata));

  for (size_t i = 0; i < count; i++) {
    uint8_t s[PMBTOKEN_NONCE_SIZE];
    CBS tmp;
    ASSERT_TRUE(CBS_copy_bytes(&real_response, s, PMBTOKEN_NONCE_SIZE));
    ASSERT_TRUE(CBB_add_bytes(bad_response.get(), s, PMBTOKEN_NONCE_SIZE));
    ASSERT_TRUE(CBS_get_u16_length_prefixed(&real_response, &tmp));
    ASSERT_TRUE(CBB_add_u16(bad_response.get(), CBS_len(&tmp)));
    ASSERT_TRUE(
        CBB_add_bytes(bad_response.get(), CBS_data(&tmp), CBS_len(&tmp)));
    ASSERT_TRUE(CBS_get_u16_length_prefixed(&real_response, &tmp));
    ASSERT_TRUE(CBB_add_u16(bad_response.get(), CBS_len(&tmp)));
    ASSERT_TRUE(
        CBB_add_bytes(bad_response.get(), CBS_data(&tmp), CBS_len(&tmp)));
    ASSERT_TRUE(CBS_get_u16_length_prefixed(&real_response, &tmp));
    ASSERT_TRUE(CBB_add_u16(bad_response.get(), CBS_len(&tmp) - 2));
    ASSERT_TRUE(
        CBB_add_bytes(bad_response.get(), CBS_data(&tmp), CBS_len(&tmp) - 2));
  }

  uint8_t *bad_buf;
  size_t bad_len;
  ASSERT_TRUE(CBB_finish(bad_response.get(), &bad_buf, &bad_len));
  bssl::UniquePtr<uint8_t> free_bad(bad_buf);

  size_t key_index;
  bssl::UniquePtr<STACK_OF(TRUST_TOKEN)> tokens(
      TRUST_TOKEN_CLIENT_finish_issuance(client.get(), &key_index, bad_buf, bad_len));
  ASSERT_FALSE(tokens);
}

TEST_P(TrustTokenMetadataTest, ExcessDataProof) {
  ASSERT_NO_FATAL_FAILURE(SetupContexts());

  uint8_t *issue_msg = NULL, *issue_resp = NULL;
  size_t msg_len, resp_len;
  ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_issuance(client.get(), &issue_msg,
                                                &msg_len, 10));
  bssl::UniquePtr<uint8_t> free_issue_msg(issue_msg);
  uint8_t tokens_issued;
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_issue(
      issuer.get(), &issue_resp, &resp_len, &tokens_issued, issue_msg, msg_len,
      std::get<0>(GetParam()), std::get<1>(GetParam()), /*max_issuance=*/1));
  bssl::UniquePtr<uint8_t> free_msg(issue_resp);

  CBS real_response;
  CBS_init(&real_response, issue_resp, resp_len);
  uint16_t count;
  uint32_t public_metadata;
  bssl::ScopedCBB bad_response;
  ASSERT_TRUE(CBB_init(bad_response.get(), 0));
  ASSERT_TRUE(CBS_get_u16(&real_response, &count));
  ASSERT_TRUE(CBB_add_u16(bad_response.get(), count));
  ASSERT_TRUE(CBS_get_u32(&real_response, &public_metadata));
  ASSERT_TRUE(CBB_add_u32(bad_response.get(), public_metadata));

  for (size_t i = 0; i < count; i++) {
    uint8_t s[PMBTOKEN_NONCE_SIZE];
    CBS tmp;
    ASSERT_TRUE(CBS_copy_bytes(&real_response, s, PMBTOKEN_NONCE_SIZE));
    ASSERT_TRUE(CBB_add_bytes(bad_response.get(), s, PMBTOKEN_NONCE_SIZE));
    ASSERT_TRUE(CBS_get_u16_length_prefixed(&real_response, &tmp));
    ASSERT_TRUE(CBB_add_u16(bad_response.get(), CBS_len(&tmp)));
    ASSERT_TRUE(
        CBB_add_bytes(bad_response.get(), CBS_data(&tmp), CBS_len(&tmp)));
    ASSERT_TRUE(CBS_get_u16_length_prefixed(&real_response, &tmp));
    ASSERT_TRUE(CBB_add_u16(bad_response.get(), CBS_len(&tmp)));
    ASSERT_TRUE(
        CBB_add_bytes(bad_response.get(), CBS_data(&tmp), CBS_len(&tmp)));
    ASSERT_TRUE(CBS_get_u16_length_prefixed(&real_response, &tmp));
    ASSERT_TRUE(CBB_add_u16(bad_response.get(), CBS_len(&tmp) + 2));
    ASSERT_TRUE(
        CBB_add_bytes(bad_response.get(), CBS_data(&tmp), CBS_len(&tmp)));
    ASSERT_TRUE(CBB_add_u16(bad_response.get(), 42));
  }

  uint8_t *bad_buf;
  size_t bad_len;
  ASSERT_TRUE(CBB_finish(bad_response.get(), &bad_buf, &bad_len));
  bssl::UniquePtr<uint8_t> free_bad(bad_buf);

  size_t key_index;
  bssl::UniquePtr<STACK_OF(TRUST_TOKEN)> tokens(
      TRUST_TOKEN_CLIENT_finish_issuance(client.get(), &key_index, bad_buf,
                                         bad_len));
  ASSERT_FALSE(tokens);
}

INSTANTIATE_TEST_SUITE_P(
    TrustTokenAllMetadataTest, TrustTokenMetadataTest,
    testing::Combine(testing::Values(TrustTokenProtocolTest::KeyID(0),
                                     TrustTokenProtocolTest::KeyID(1),
                                     TrustTokenProtocolTest::KeyID(2)),
                     testing::Bool()));


class TrustTokenBadKeyTest
    : public TrustTokenProtocolTest,
      public testing::WithParamInterface<std::tuple<bool, int>> {};

TEST_P(TrustTokenBadKeyTest, BadKey) {
  ASSERT_NO_FATAL_FAILURE(SetupContexts());

  uint8_t *issue_msg = NULL, *issue_resp = NULL;
  size_t msg_len, resp_len;
  ASSERT_TRUE(TRUST_TOKEN_CLIENT_begin_issuance(client.get(), &issue_msg,
                                                &msg_len, 10));
  bssl::UniquePtr<uint8_t> free_issue_msg(issue_msg);

  struct trust_token_issuer_key_st *key = &issuer->keys[0];
  EC_SCALAR *scalars[] = {&key->x0, &key->y0, &key->x1,
                          &key->y1, &key->xs, &key->ys};
  int corrupted_key = std::get<1>(GetParam());

  // Corrupt private key scalar.
  scalars[corrupted_key]->bytes[0] ^= 42;

  uint8_t tokens_issued;
  ASSERT_TRUE(TRUST_TOKEN_ISSUER_issue(
      issuer.get(), &issue_resp, &resp_len, &tokens_issued, issue_msg, msg_len,
      /*public_metadata=*/7, std::get<0>(GetParam()), /*max_issuance=*/1));
  bssl::UniquePtr<uint8_t> free_msg(issue_resp);
  size_t key_index;
  bssl::UniquePtr<STACK_OF(TRUST_TOKEN)> tokens(
      TRUST_TOKEN_CLIENT_finish_issuance(client.get(), &key_index, issue_resp,
                                         resp_len));

  // If the unused private key is corrupted, then the DLEQ proof should succeed.
  if ((corrupted_key / 2 == 0 && std::get<0>(GetParam()) == true) ||
      (corrupted_key / 2 == 1 && std::get<0>(GetParam()) == false)) {
    ASSERT_TRUE(tokens);
  } else {
    ASSERT_FALSE(tokens);
  }
}

INSTANTIATE_TEST_SUITE_P(
    TrustTokenAllBadKeyTest, TrustTokenBadKeyTest,
    testing::Combine(testing::Bool(),
                     testing::Values(0, 1, 2, 3, 4, 5)));

}  // namespace
BSSL_NAMESPACE_END
