/* Copyright (c) 2014, Google Inc.
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

#include <openssl/base64.h>
#include <openssl/crypto.h>
#include <openssl/err.h>


typedef struct {
  const char *decoded;
  const char *encoded;
} TEST_VECTOR;

/* Test vectors from RFC 4648. */
static const TEST_VECTOR test_vectors[] = {
  { "", "" },
  { "f" , "Zg==" },
  { "fo", "Zm8=" },
  { "foo", "Zm9v" },
  { "foob", "Zm9vYg==" },
  { "fooba", "Zm9vYmE=" },
  { "foobar", "Zm9vYmFy" },
};

static const size_t kNumTests = sizeof(test_vectors) / sizeof(test_vectors[0]);

static int test_encode(void) {
  uint8_t out[9];
  size_t i, len;

  for (i = 0; i < kNumTests; i++) {
    const TEST_VECTOR *t = &test_vectors[i];
    len = EVP_EncodeBlock(out, (const uint8_t*)t->decoded, strlen(t->decoded));
    if (len != strlen(t->encoded) ||
        memcmp(out, t->encoded, len) != 0) {
      fprintf(stderr, "encode(\"%s\") = \"%.*s\", want \"%s\"\n",
              t->decoded, (int)len, (const char*)out, t->encoded);
      return 0;
    }
  }
  return 1;
}

static int test_decode(void) {
  uint8_t out[6];
  size_t i, len;
  int ret;

  for (i = 0; i < kNumTests; i++) {
    /* Test the normal API. */
    const TEST_VECTOR *t = &test_vectors[i];
    size_t expected_len = strlen(t->decoded);
    if (!EVP_DecodeBase64(out, &len, sizeof(out),
                          (const uint8_t*)t->encoded, strlen(t->encoded))) {
      fprintf(stderr, "decode(\"%s\") failed\n", t->encoded);
      return 0;
    }
    if (len != strlen(t->decoded) ||
        memcmp(out, t->decoded, len) != 0) {
      fprintf(stderr, "decode(\"%s\") = \"%.*s\", want \"%s\"\n",
              t->encoded, (int)len, (const char*)out, t->decoded);
      return 0;
    }

    /* Test that the padding behavior of the deprecated API is
     * preserved. */
    ret = EVP_DecodeBlock(out, (const uint8_t*)t->encoded, strlen(t->encoded));
    if (ret < 0) {
      fprintf(stderr, "decode(\"%s\") failed\n", t->encoded);
      return 0;
    }
    if (ret % 3 != 0) {
      fprintf(stderr, "EVP_DecodeBlock did not ignore padding\n");
      return 0;
    }
    if (expected_len % 3 != 0) {
      ret -= 3 - (expected_len % 3);
    }
    if (ret != strlen(t->decoded) ||
        memcmp(out, t->decoded, ret) != 0) {
      fprintf(stderr, "decode(\"%s\") = \"%.*s\", want \"%s\"\n",
              t->encoded, ret, (const char*)out, t->decoded);
      return 0;
    }
  }

  if (EVP_DecodeBase64(out, &len, sizeof(out), (const uint8_t*)"a!bc", 4)) {
    fprintf(stderr, "Failed to reject invalid characters in the middle.\n");
    return 0;
  }

  if (EVP_DecodeBase64(out, &len, sizeof(out), (const uint8_t*)"a=bc", 4)) {
    fprintf(stderr, "Failed to reject invalid characters in the middle.\n");
    return 0;
  }

  if (EVP_DecodeBase64(out, &len, sizeof(out), (const uint8_t*)"abc", 4)) {
    fprintf(stderr, "Failed to reject invalid input length.\n");
    return 0;
  }

  return 1;
}

int main(void) {
  CRYPTO_library_init();
  ERR_load_crypto_strings();

  if (!test_encode()) {
    return 1;
  }

  if (!test_decode()) {
    return 1;
  }

  printf("PASS\n");
  return 0;
}
