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

// cavp_tdes_test processes a NIST TMOVS test vector request file and emits the
// corresponding response. An optional sample vector file can be passed to
// verify the result.

#include <stdlib.h>

#include <openssl/cipher.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

#include "../crypto/test/file_test.h"
#include "cavp_test_util.h"


struct TestCtx {
  const EVP_CIPHER *cipher;
  std::unique_ptr<FileTest> response_sample;
  enum Mode {
    kKAT,  // Known Answer Test
    kMCT,  // Monte Carlo Test
    kMMT,  // Multi Message Test
  };
  bool has_iv;
  Mode mode;
};

static bool TestKAT(FileTest *t, void *arg) {
  TestCtx *ctx = reinterpret_cast<TestCtx *>(arg);

  if (t->HasInstruction("ENCRYPT") == t->HasInstruction("DECRYPT")) {
    t->PrintLine("Want either ENCRYPT or DECRYPT");
    return false;
  }
  enum {
    kEncrypt,
    kDecrypt,
  } operation = t->HasInstruction("ENCRYPT") ? kEncrypt : kDecrypt;

  std::string count;
  std::vector<uint8_t> key, iv, in, result;
  const std::string op_label = operation == kEncrypt ? "PLAINTEXT" : "CIPHERTEXT";
  if (!t->GetAttribute(&count, "COUNT") ||
      !t->GetBytes(&key, "KEYs") ||
      (ctx->has_iv && !t->GetBytes(&iv, "IV")) ||
      !t->GetBytes(&in, op_label)) {
    return false;
  }
  std::vector<uint8_t> triple_key(key);
  triple_key.insert(triple_key.end(), key.begin(), key.end());
  triple_key.insert(triple_key.end(), key.begin(), key.end());

  const EVP_CIPHER *cipher = ctx->cipher;

  if (!CipherOperation(cipher, &result, operation == kEncrypt, triple_key, iv,
                       in)) {
    return false;
  }
  const std::string result_label =
      operation == kEncrypt ? "CIPHERTEXT" : "PLAINTEXT";

  // TDES fax files output format differs from its input format, so we
  // construct it manually rather than printing CurrentTestToString().
  if (t->IsAtNewInstructionBlock()) {
    std::string header = operation == kEncrypt ? "[ENCRYPT]" : "[DECRYPT]";
    printf("%s\r\n", header.c_str());
  }
  printf("COUNT = %s\r\nKEYs = %s\r\n", count.c_str(),
         EncodeHex(key.data(), key.size()).c_str());
  if (ctx->has_iv) {
    printf("IV = %s\r\n", EncodeHex(iv.data(), iv.size()).c_str());
  }
  printf("%s = %s\r\n%s = %s\r\n\r\n", op_label.c_str(),
         EncodeHex(in.data(), in.size()).c_str(), result_label.c_str(),
         EncodeHex(result.data(), result.size()).c_str());

  // Check if sample response file matches.
  if (ctx->response_sample) {
    if (ctx->response_sample->ReadNext() != FileTest::kReadSuccess) {
      t->PrintLine("invalid sample file");
      return false;
    }
    std::string expected_count;
    std::vector<uint8_t> expected_result;
    if (!ctx->response_sample->GetAttribute(&expected_count, "COUNT") ||
        count != expected_count ||
        (!ctx->response_sample->GetBytes(&expected_result, result_label)) ||
        !t->ExpectBytesEqual(expected_result.data(), expected_result.size(),
                             result.data(), result.size())) {
      t->PrintLine("result doesn't match");
      return false;
    }
  }

  return true;
}

static int usage(char *arg) {
  fprintf(
      stderr,
      "usage: %s (kat|mct|mmt) <cipher> <test file> [<sample response file>]\n",
      arg);
  return 1;
}

int main(int argc, char **argv) {
  CRYPTO_library_init();

  if (argc < 4 || argc > 5) {
    return usage(argv[0]);
  }

  const std::string tm(argv[1]);
  enum TestCtx::Mode test_mode;
  if (tm == "kat") {
    test_mode = TestCtx::kKAT;
  } else if (tm == "mmt") {
    test_mode = TestCtx::kMMT;
  } else if (tm == "mct") {
    test_mode = TestCtx::kMCT;
  } else {
    fprintf(stderr, "invalid test_mode: %s\n", tm.c_str());
    return usage(argv[0]);
  }

  const std::string cipher_name(argv[2]);
  const EVP_CIPHER *cipher = GetCipher(argv[2]);
  if (cipher == nullptr) {
    fprintf(stderr, "invalid cipher: %s\n", argv[2]);
    return 1;
  }
  bool has_iv = cipher_name != "des-ede3";
  TestCtx ctx = {cipher, nullptr, has_iv, test_mode};

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
  printf("\r\n\r\n");

  // TODO(martinkr): Add MMT, MCT.
  return FileTestMainSilent(TestKAT, &ctx, argv[3]);
}
