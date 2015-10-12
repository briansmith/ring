/* ====================================================================
 * Copyright (c) 2008 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ==================================================================== */

#include <stdio.h>
#include <string.h>

#include <openssl/aes.h>
#include <openssl/crypto.h>
#include <openssl/mem.h>
#include <openssl/modes.h>

#include "internal.h"
#include "../test/test_util.h"


struct test_case {
  const char *key;
  const char *plaintext;
  const char *additional_data;
  const char *nonce;
  const char *ciphertext;
  const char *tag;
};

static const struct test_case test_cases[] = {
  {
    "00000000000000000000000000000000",
    NULL,
    NULL,
    "000000000000000000000000",
    NULL,
    "58e2fccefa7e3061367f1d57a4e7455a",
  },
  {
    "00000000000000000000000000000000",
    "00000000000000000000000000000000",
    NULL,
    "000000000000000000000000",
    "0388dace60b6a392f328c2b971b2fe78",
    "ab6e47d42cec13bdf53a67b21257bddf",
  },
  {
    "feffe9928665731c6d6a8f9467308308",
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
    NULL,
    "cafebabefacedbaddecaf888",
    "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
    "4d5c2af327cd64a62cf35abd2ba6fab4",
  },
  {
    "feffe9928665731c6d6a8f9467308308",
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
    "feedfacedeadbeeffeedfacedeadbeefabaddad2",
    "cafebabefacedbaddecaf888",
    "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
    "5bc94fbc3221a5db94fae95ae7121a47",
  },
  {
    "000000000000000000000000000000000000000000000000",
    NULL,
    NULL,
    "000000000000000000000000",
    NULL,
    "cd33b28ac773f74ba00ed1f312572435",
  },
  {
    "000000000000000000000000000000000000000000000000",
    "00000000000000000000000000000000",
    NULL,
    "000000000000000000000000",
    "98e7247c07f0fe411c267e4384b0f600",
    "2ff58d80033927ab8ef4d4587514f0fb",
  },
  {
    "feffe9928665731c6d6a8f9467308308feffe9928665731c",
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
    NULL,
    "cafebabefacedbaddecaf888",
    "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710acade256",
    "9924a7c8587336bfb118024db8674a14",
  },
  {
    "feffe9928665731c6d6a8f9467308308feffe9928665731c",
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
    "feedfacedeadbeeffeedfacedeadbeefabaddad2",
    "cafebabefacedbaddecaf888",
    "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710",
    "2519498e80f1478f37ba55bd6d27618c",
  },
  {
    "0000000000000000000000000000000000000000000000000000000000000000",
    NULL,
    NULL,
    "000000000000000000000000",
    NULL,
    "530f8afbc74536b9a963b4f1c4cb738b",
  },
  {
    "0000000000000000000000000000000000000000000000000000000000000000",
    "00000000000000000000000000000000",
    NULL,
    "000000000000000000000000",
    "cea7403d4d606b6e074ec5d3baf39d18",
    "d0d1c8a799996bf0265b98b5d48ab919",
  },
  {
    "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
    NULL,
    "cafebabefacedbaddecaf888",
    "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
    "b094dac5d93471bdec1a502270e3cc6c",
  },
  {
    "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
    "feedfacedeadbeeffeedfacedeadbeefabaddad2",
    "cafebabefacedbaddecaf888",
    "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
    "76fc6ece0f4e1768cddf8853bb2d551b",
  },
  {
    "00000000000000000000000000000000",
    NULL,
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
    "000000000000000000000000",
    NULL,
    "5fea793a2d6f974d37e68e0cb8ff9492",
  },
};

static int from_hex(uint8_t *out, char in) {
  if (in >= '0' && in <= '9') {
    *out = in - '0';
    return 1;
  }
  if (in >= 'a' && in <= 'f') {
    *out = in - 'a' + 10;
    return 1;
  }
  if (in >= 'A' && in <= 'F') {
    *out = in - 'A' + 10;
    return 1;
  }

  return 0;
}

static int decode_hex(uint8_t **out, size_t *out_len, const char *in,
                      unsigned test_num, const char *description) {
  uint8_t *buf = NULL;
  size_t i;

  if (in == NULL) {
    *out = NULL;
    *out_len = 0;
    return 1;
  }

  size_t len = strlen(in);
  if (len & 1) {
    fprintf(stderr, "%u: Odd-length %s input.\n", test_num, description);
    goto err;
  }

  buf = OPENSSL_malloc(len / 2);
  if (buf == NULL) {
    fprintf(stderr, "%u: malloc failure.\n", test_num);
    goto err;
  }

  for (i = 0; i < len; i += 2) {
    uint8_t v, v2;
    if (!from_hex(&v, in[i]) ||
        !from_hex(&v2, in[i+1])) {
      fprintf(stderr,
              "%u: invalid hex digit in %s around offset "
                  "%" OPENSSL_PR_SIZE_T ".\n", test_num, description, i);
      goto err;
    }
    buf[i/2] = (v << 4) | v2;
  }

  *out = buf;
  *out_len = len/2;
  return 1;

err:
  OPENSSL_free(buf);
  return 0;
}

static int run_test_case(unsigned test_num, const struct test_case *test) {
  size_t key_len, plaintext_len, additional_data_len, nonce_len, ciphertext_len,
      tag_len;
  uint8_t *key = NULL, *plaintext = NULL, *additional_data = NULL,
          *nonce = NULL, *ciphertext = NULL, *tag = NULL, *out = NULL;
  int ret = 0;
  AES_KEY aes_key;
  GCM128_CONTEXT_SK ctx;

  if (!decode_hex(&key, &key_len, test->key, test_num, "key") ||
      !decode_hex(&plaintext, &plaintext_len, test->plaintext, test_num,
                  "plaintext") ||
      !decode_hex(&additional_data, &additional_data_len, test->additional_data,
                  test_num, "additional_data") ||
      !decode_hex(&nonce, &nonce_len, test->nonce, test_num, "nonce") ||
      !decode_hex(&ciphertext, &ciphertext_len, test->ciphertext, test_num,
                  "ciphertext") ||
      !decode_hex(&tag, &tag_len, test->tag, test_num, "tag")) {
    goto out;
  }

  if (plaintext_len != ciphertext_len) {
    fprintf(stderr, "%u: plaintext and ciphertext have differing lengths.\n",
            test_num);
    goto out;
  }

  if (nonce_len != 12) {
    fprintf(stderr, "%u: bad nonce length.\n", test_num);
    goto out;
  }

  if (key_len != 16 && key_len != 24 && key_len != 32) {
    fprintf(stderr, "%u: bad key length.\n", test_num);
    goto out;
  }

  if (tag_len != 16) {
    fprintf(stderr, "%u: bad tag length.\n", test_num);
    goto out;
  }

  out = OPENSSL_malloc(plaintext_len);
  if (out == NULL) {
    goto out;
  }
  if (AES_set_encrypt_key(key, key_len*8, &aes_key)) {
    fprintf(stderr, "%u: AES_set_encrypt_key failed.\n", test_num);
    goto out;
  }

  CRYPTO_gcm128_init_sk(&ctx, &aes_key, (block128_f) AES_encrypt);
  CRYPTO_gcm128_set_96_bit_iv_sk(&ctx, &aes_key, nonce);
  memset(out, 0, plaintext_len);
  if (additional_data) {
    CRYPTO_gcm128_aad_sk(&ctx, additional_data, additional_data_len);
  }
  if (plaintext) {
    CRYPTO_gcm128_encrypt_sk(&ctx, &aes_key, plaintext, out, plaintext_len);
  }
  if (!CRYPTO_gcm128_finish_sk(&ctx, tag, tag_len) ||
      (ciphertext && memcmp(out, ciphertext, plaintext_len) != 0)) {
    fprintf(stderr, "%u: encrypt failed.\n", test_num);
    hexdump(stderr, "got :", out, plaintext_len);
    hexdump(stderr, "want:", ciphertext, plaintext_len);
    goto out;
  }

  CRYPTO_gcm128_set_96_bit_iv_sk(&ctx, &aes_key, nonce);
  memset(out, 0, plaintext_len);
  if (additional_data) {
    CRYPTO_gcm128_aad_sk(&ctx, additional_data, additional_data_len);
  }
  if (ciphertext) {
    CRYPTO_gcm128_decrypt_sk(&ctx, &aes_key, ciphertext, out, plaintext_len);
  }
  if (!CRYPTO_gcm128_finish_sk(&ctx, tag, tag_len)) {
    fprintf(stderr, "%u: decrypt failed.\n", test_num);
    goto out;
  }
  if (plaintext && memcmp(out, plaintext, plaintext_len)) {
    fprintf(stderr, "%u: plaintext doesn't match.\n", test_num);
    goto out;
  }

  ret = 1;

out:
  OPENSSL_free(key);
  OPENSSL_free(plaintext);
  OPENSSL_free(additional_data);
  OPENSSL_free(nonce);
  OPENSSL_free(ciphertext);
  OPENSSL_free(tag);
  OPENSSL_free(out);
  return ret;
}

int main(void) {
  int ret = 0;
  unsigned i;

  CRYPTO_library_init();

  for (i = 0; i < sizeof(test_cases) / sizeof(struct test_case); i++) {
    if (!run_test_case(i, &test_cases[i])) {
      ret = 1;
    }
  }

  if (ret == 0) {
    printf("PASS\n");
  }

  return ret;
}
