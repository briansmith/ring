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

// cavp_aes_gcm_test processes a NIST CAVP AES GCM test vector request file and
// emits the corresponding response. An optional sample vector file can be
// passed to verify the result.

#include <stdlib.h>

#include <openssl/aead.h>
#include <openssl/cipher.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

#include "../test/file_test.h"
#include "cavp_test_util.h"


struct TestCtx {
  const EVP_AEAD *aead;
  std::unique_ptr<FileTest> response_sample;
};

static const EVP_AEAD *GetAEAD(const std::string &name, const bool enc) {
  if (name == "aes-128-gcm") {
    return EVP_aead_aes_128_gcm_fips_testonly();
  } else if (name == "aes-256-gcm") {
    return EVP_aead_aes_256_gcm_fips_testonly();
  }
  return nullptr;
}

static bool TestAEADEncrypt(FileTest *t, void *arg) {
  TestCtx *ctx = reinterpret_cast<TestCtx *>(arg);

  std::string key_len_str, iv_len_str, pt_len_str, aad_len_str, tag_len_str;
  if (!t->GetInstruction(&key_len_str, "Keylen") ||
      !t->GetInstruction(&iv_len_str, "IVlen") ||
      !t->GetInstruction(&pt_len_str, "PTlen") ||
      !t->GetInstruction(&aad_len_str, "AADlen") ||
      !t->GetInstruction(&tag_len_str, "Taglen")) {
    return false;
  }

  std::string count;
  std::vector<uint8_t> key, iv, pt, aad, tag, ct;
  if (!t->GetAttribute(&count, "Count") ||
      !t->GetBytes(&key, "Key") ||
      !t->GetBytes(&aad, "AAD") ||
      !t->GetBytes(&pt, "PT") ||
      key.size() * 8 != strtoul(key_len_str.c_str(), nullptr, 0) ||
      pt.size() * 8 != strtoul(pt_len_str.c_str(), nullptr, 0) ||
      aad.size() * 8 != strtoul(aad_len_str.c_str(), nullptr, 0)) {
    return false;
  }

  size_t tag_len = strtoul(tag_len_str.c_str(), nullptr, 0) / 8;
  if (!AEADEncrypt(ctx->aead, &ct, &tag, tag_len, key, pt, aad, &iv)) {
    return false;
  }
  printf("%s", t->CurrentTestToString().c_str());
  printf("IV = %s\r\n", EncodeHex(iv.data(), iv.size()).c_str());
  printf("CT = %s\r\n", EncodeHex(ct.data(), ct.size()).c_str());
  printf("Tag = %s\r\n\r\n", EncodeHex(tag.data(), tag.size()).c_str());

  // Check if sample response file matches.
  if (ctx->response_sample) {
    ctx->response_sample->ReadNext();
    std::string expected_count;
    std::vector<uint8_t> expected_iv, expected_ct, expected_tag;
    if (!ctx->response_sample->GetAttribute(&expected_count, "Count") ||
        count != expected_count ||
        !ctx->response_sample->GetBytes(&expected_iv, "IV") ||
        !t->ExpectBytesEqual(expected_iv.data(), expected_iv.size(), iv.data(),
                             iv.size()) ||
        !ctx->response_sample->GetBytes(&expected_ct, "CT") ||
        !t->ExpectBytesEqual(expected_ct.data(), expected_ct.size(), ct.data(),
                             ct.size()) ||
        !ctx->response_sample->GetBytes(&expected_tag, "Tag") ||
        !t->ExpectBytesEqual(expected_tag.data(), expected_tag.size(),
                             tag.data(), tag.size())) {
      t->PrintLine("result doesn't match");
      return false;
    }
  }

  return true;
}

static bool TestAEADDecrypt(FileTest *t, void *arg) {
  TestCtx *ctx = reinterpret_cast<TestCtx *>(arg);

  std::string key_len, iv_len, pt_len_str, aad_len_str, tag_len;
  if (!t->GetInstruction(&key_len, "Keylen") ||
      !t->GetInstruction(&iv_len, "IVlen") ||
      !t->GetInstruction(&pt_len_str, "PTlen") ||
      !t->GetInstruction(&aad_len_str, "AADlen") ||
      !t->GetInstruction(&tag_len, "Taglen")) {
    t->PrintLine("Invalid instruction block.");
    return false;
  }
  size_t aad_len = strtoul(aad_len_str.c_str(), nullptr, 0) / 8;
  size_t pt_len = strtoul(pt_len_str.c_str(), nullptr, 0) / 8;

  std::string count;
  std::vector<uint8_t> key, iv, ct, aad, tag, pt;
  if (!t->GetAttribute(&count, "Count") ||
      !t->GetBytes(&key, "Key") ||
      !t->GetBytes(&aad, "AAD") ||
      !t->GetBytes(&tag, "Tag") ||
      !t->GetBytes(&iv, "IV") ||
      !t->GetBytes(&ct, "CT") ||
      key.size() * 8 != strtoul(key_len.c_str(), nullptr, 0) ||
      iv.size() * 8 != strtoul(iv_len.c_str(), nullptr, 0) ||
      ct.size() != pt_len ||
      aad.size() != aad_len ||
      tag.size() * 8 != strtoul(tag_len.c_str(), nullptr, 0)) {
    t->PrintLine("Invalid test case");
    return false;
  }

  printf("%s", t->CurrentTestToString().c_str());
  bool aead_result =
      AEADDecrypt(ctx->aead, &pt, &aad, pt_len, aad_len, key, ct, tag, iv);
  if (aead_result) {
    printf("PT = %s\r\n\r\n", EncodeHex(pt.data(), pt.size()).c_str());
  } else {
    printf("FAIL\r\n\r\n");
  }

  // Check if sample response file matches.
  if (ctx->response_sample) {
    ctx->response_sample->ReadNext();
    std::string expected_count;
    std::vector<uint8_t> expected_pt;
    if (!ctx->response_sample->GetAttribute(&expected_count, "Count") ||
        count != expected_count ||
        (!aead_result && (ctx->response_sample->HasAttribute("PT") ||
                          !ctx->response_sample->HasAttribute("FAIL"))) ||
        (aead_result &&
         (ctx->response_sample->HasAttribute("FAIL") ||
          !ctx->response_sample->GetBytes(&expected_pt, "PT") ||
          !t->ExpectBytesEqual(expected_pt.data(), expected_pt.size(),
                               pt.data(), pt.size())))) {
      t->PrintLine("result doesn't match");
      return false;
    }
  }

  return true;
}

static int usage(char *arg) {
  fprintf(stderr,
          "usage: %s (enc|dec) <cipher> <test file> [<sample response file>]\n",
          arg);
  return 1;
}

int main(int argc, char **argv) {
  CRYPTO_library_init();

  if (argc < 4 || argc > 5) {
    return usage(argv[0]);
  }

  const std::string mode(argv[1]);
  bool (*test_fn)(FileTest * t, void *arg);
  if (mode == "enc") {
    test_fn = &TestAEADEncrypt;
  } else if (mode == "dec") {
    test_fn = &TestAEADDecrypt;
  } else {
    return usage(argv[0]);
  }

  const EVP_AEAD *aead = GetAEAD(argv[2], mode == "enc");
  if (aead == nullptr) {
    fprintf(stderr, "invalid aead: %s\n", argv[2]);
    return 1;
  }

  TestCtx ctx = {aead, nullptr};

  if (argc == 5) {
    ctx.response_sample.reset(new FileTest(argv[4]));
    if (!ctx.response_sample->is_open()) {
      return 1;
    }
    ctx.response_sample->SetIgnoreUnusedAttributes(true);
  }

  printf("# Generated by");
  for (int i = 0; i < argc; i++) {
    printf(" %s", argv[i]);
  }
  printf("\n\n");

  return FileTestMainSilent(test_fn, &ctx, argv[3]);
}
