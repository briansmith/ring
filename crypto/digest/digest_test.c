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

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/digest.h>
#include <openssl/err.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/sha.h>


typedef struct {
  /* md_func is the digest to test. */
  const EVP_MD *(*md_func)(void);
  /* one_shot_func is the convenience one-shot version of the
   * digest. */
  uint8_t *(*one_shot_func)(const uint8_t *, size_t, uint8_t *);
  /* input is a NUL-terminated string to hash. */
  const char *input;
  /* repeat is the number of times to repeat input. */
  size_t repeat;
  /* expected_hex is the expected digest in hexadecimal. */
  const char *expected_hex;
} TEST_VECTOR;

static const TEST_VECTOR kTestVectors[] = {
    /* MD4 tests, from RFC 1320. (crypto/md4 does not provide a
     * one-shot MD4 function.) */
    { &EVP_md4, NULL, "", 1, "31d6cfe0d16ae931b73c59d7e0c089c0" },
    { &EVP_md4, NULL, "a", 1, "bde52cb31de33e46245e05fbdbd6fb24" },
    { &EVP_md4, NULL, "abc", 1, "a448017aaf21d8525fc10ae87aa6729d" },
    { &EVP_md4, NULL, "message digest", 1,
      "d9130a8164549fe818874806e1c7014b" },
    { &EVP_md4, NULL, "abcdefghijklmnopqrstuvwxyz", 1,
      "d79e1c308aa5bbcdeea8ed63df412da9" },
    { &EVP_md4, NULL,
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 1,
      "043f8582f241db351ce627e153e7f0e4" },
    { &EVP_md4, NULL, "1234567890", 8, "e33b4ddc9c38f2199c3e7b164fcc0536" },

    /* MD5 tests, from RFC 1321. */
    { &EVP_md5, &MD5, "", 1, "d41d8cd98f00b204e9800998ecf8427e" },
    { &EVP_md5, &MD5, "a", 1, "0cc175b9c0f1b6a831c399e269772661" },
    { &EVP_md5, &MD5, "abc", 1, "900150983cd24fb0d6963f7d28e17f72" },
    { &EVP_md5, &MD5, "message digest", 1, "f96b697d7cb7938d525a2f31aaf161d0" },
    { &EVP_md5, &MD5, "abcdefghijklmnopqrstuvwxyz", 1,
      "c3fcd3d76192e4007dfb496cca67e13b" },
    { &EVP_md5, &MD5,
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 1,
      "d174ab98d277d9f5a5611c2c9f419d9f" },
    { &EVP_md5, &MD5, "1234567890", 8, "57edf4a22be3c955ac49da2e2107b67a" },

    /* SHA-1 tests, from RFC 3174. */
    { &EVP_sha1, &SHA1, "abc", 1, "a9993e364706816aba3e25717850c26c9cd0d89d" },
    { &EVP_sha1, &SHA1,
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 1,
      "84983e441c3bd26ebaae4aa1f95129e5e54670f1" },
    { &EVP_sha1, &SHA1, "a", 1000000,
      "34aa973cd4c4daa4f61eeb2bdbad27316534016f" },
    { &EVP_sha1, &SHA1,
      "0123456701234567012345670123456701234567012345670123456701234567", 10,
      "dea356a2cddd90c7a7ecedc5ebb563934f460452" },

    /* SHA-224 tests, from RFC 3874. */
    { &EVP_sha224, &SHA224, "abc", 1,
      "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7" },
    { &EVP_sha224, &SHA224,
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 1,
      "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525" },
    { &EVP_sha224, &SHA224,
      "a", 1000000,
      "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67" },

    /* SHA-256 tests, from NIST. */
    { &EVP_sha256, &SHA256, "abc", 1,
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
    { &EVP_sha256, &SHA256,
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 1,
      "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" },

    /* SHA-384 tests, from NIST. */
    { &EVP_sha384, &SHA384, "abc", 1,
      "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
      "8086072ba1e7cc2358baeca134c825a7" },
    { &EVP_sha384, &SHA384,
      "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
      "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 1,
      "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712"
      "fcc7c71a557e2db966c3e9fa91746039" },

    /* SHA-512 tests, from NIST. */
    { &EVP_sha512, &SHA512, "abc", 1,
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
      "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" },
    { &EVP_sha512, &SHA512,
      "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
      "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", 1,
      "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
      "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909" },

    /* MD5-SHA1 tests. */
    { &EVP_md5_sha1, NULL, "abc", 1,
      "900150983cd24fb0d6963f7d28e17f72a9993e364706816aba3e25717850c26c9cd0d89d" },
};

static int compare_digest(const TEST_VECTOR *test,
                          const uint8_t *digest,
                          size_t digest_len) {
  static const char kHexTable[] = "0123456789abcdef";
  size_t i;
  char digest_hex[2*EVP_MAX_MD_SIZE + 1];

  for (i = 0; i < digest_len; i++) {
    digest_hex[2*i] = kHexTable[digest[i] >> 4];
    digest_hex[2*i + 1] = kHexTable[digest[i] & 0xf];
  }
  digest_hex[2*digest_len] = '\0';

  if (strcmp(digest_hex, test->expected_hex) != 0) {
    fprintf(stderr, "%s(\"%s\" * %d) = %s; want %s\n",
            EVP_MD_name(test->md_func()), test->input, (int)test->repeat,
            digest_hex, test->expected_hex);
    return 0;
  }

  return 1;
}

static int test_digest(const TEST_VECTOR *test) {
  int ret = 0;
  EVP_MD_CTX ctx;
  size_t i;
  uint8_t digest[EVP_MAX_MD_SIZE];
  unsigned digest_len;

  EVP_MD_CTX_init(&ctx);

  /* Test the input provided. */
  if (!EVP_DigestInit_ex(&ctx, test->md_func(), NULL)) {
    fprintf(stderr, "EVP_DigestInit_ex failed\n");
    goto done;
  }
  for (i = 0; i < test->repeat; i++) {
    if (!EVP_DigestUpdate(&ctx, test->input, strlen(test->input))) {
      fprintf(stderr, "EVP_DigestUpdate failed\n");
      goto done;
    }
  }
  if (!EVP_DigestFinal_ex(&ctx, digest, &digest_len)) {
    fprintf(stderr, "EVP_DigestFinal_ex failed\n");
    goto done;
  }
  if (!compare_digest(test, digest, digest_len)) {
    goto done;
  }

  /* Test the input one character at a time. */
  if (!EVP_DigestInit_ex(&ctx, test->md_func(), NULL)) {
    fprintf(stderr, "EVP_DigestInit_ex failed\n");
    goto done;
  }
  if (!EVP_DigestUpdate(&ctx, NULL, 0)) {
    fprintf(stderr, "EVP_DigestUpdate failed\n");
    goto done;
  }
  for (i = 0; i < test->repeat; i++) {
    const char *p;
    for (p = test->input; *p; p++) {
      if (!EVP_DigestUpdate(&ctx, p, 1)) {
        fprintf(stderr, "EVP_DigestUpdate failed\n");
        goto done;
      }
    }
  }
  if (!EVP_DigestFinal_ex(&ctx, digest, &digest_len)) {
    fprintf(stderr, "EVP_DigestFinal_ex failed\n");
    goto done;
  }
  if (digest_len != EVP_MD_size(test->md_func())) {
    fprintf(stderr, "EVP_MD_size output incorrect\n");
    goto done;
  }
  if (!compare_digest(test, digest, digest_len)) {
    goto done;
  }

  /* Test the one-shot function. */
  if (test->one_shot_func && test->repeat == 1) {
    uint8_t *out = test->one_shot_func((const uint8_t *)test->input,
                                       strlen(test->input), digest);
    if (out != digest) {
      fprintf(stderr, "one_shot_func gave incorrect return\n");
      goto done;
    }
    if (!compare_digest(test, digest, EVP_MD_size(test->md_func()))) {
      goto done;
    }

    /* Test the deprecated static buffer variant, until it's removed. */
    out = test->one_shot_func((const uint8_t *)test->input, strlen(test->input),
                              NULL);
    if (!compare_digest(test, out, EVP_MD_size(test->md_func()))) {
      goto done;
    }
  }

  ret = 1;

done:
  EVP_MD_CTX_cleanup(&ctx);
  return ret;
}

int main(void) {
  size_t i;

  CRYPTO_library_init();
  ERR_load_crypto_strings();

  for (i = 0; i < sizeof(kTestVectors) / sizeof(kTestVectors[0]); i++) {
    if (!test_digest(&kTestVectors[i])) {
      fprintf(stderr, "Test %d failed\n", (int)i);
      return 1;
    }
  }

  printf("PASS\n");
  return 0;
}
