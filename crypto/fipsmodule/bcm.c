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

#include <openssl/aead.h>
#include <openssl/aes.h>
#include <openssl/base.h>
#include <openssl/crypto.h>
#include <openssl/hmac.h>

#include "../internal.h"

#include "aes/aes.c"
#include "aes/key_wrap.c"
#include "aes/mode_wrappers.c"
#include "digest/digest.c"
#include "digest/digests.c"
#include "hmac/hmac.c"
#include "md4/md4.c"
#include "md5/md5.c"
#include "sha/sha1-altivec.c"
#include "sha/sha1.c"
#include "sha/sha256.c"
#include "sha/sha512.c"


#if defined(BORINGSSL_FIPS)
static void hexdump(const uint8_t *in, size_t len) {
  for (size_t i = 0; i < len; i++) {
    printf("%02x", in[i]);
  }
}

static int check_test(const uint8_t *actual, const uint8_t *expected,
                      size_t expected_len, const char *name) {
  if (OPENSSL_memcmp(actual, expected, expected_len) != 0) {
    printf("%s failed.\nExpected: ", name);
    hexdump(actual, expected_len);
    printf("\nCalculated: ");
    hexdump(expected, expected_len);
    printf("\n");
    return 0;
  }
  return 1;
}

#if defined(__has_feature)
#if __has_feature(address_sanitizer)
/* Integrity tests cannot run under ASAN because it involves reading the full
 * .text section, which triggers the global-buffer overflow detection. */
#define OPENSSL_ASAN
#endif
#endif


#ifndef OPENSSL_ASAN
/* These functions are removed by delocate.go and references to them are
 * rewritten to point to the start and end of the module, and the location of
 * the integrity hash. */
static void BORINGSSL_bcm_text_dummy_start(void) {}
static void BORINGSSL_bcm_text_dummy_end(void) {}
static void BORINGSSL_bcm_text_dummy_hash(void) {}
#endif

static void BORINGSSL_bcm_power_on_self_test(void) __attribute__((constructor));

static void BORINGSSL_bcm_power_on_self_test(void) {
  CRYPTO_library_init();

#ifndef OPENSSL_ASAN
  const uint8_t *const start = (const uint8_t *)BORINGSSL_bcm_text_dummy_start;
  const uint8_t *const end = (const uint8_t *)BORINGSSL_bcm_text_dummy_end;

  static const uint8_t kHMACKey[32] = {0};
  uint8_t result[SHA256_DIGEST_LENGTH];

  unsigned result_len;
  if (!HMAC(EVP_sha256(), kHMACKey, sizeof(kHMACKey), start, end - start,
            result, &result_len) ||
      result_len != sizeof(result)) {
    goto err;
  }

  const uint8_t *const expected =
      (const uint8_t *)BORINGSSL_bcm_text_dummy_hash;

  if (!check_test(result, expected, sizeof(result), "FIPS integrity test")) {
    goto err;
  }
#endif

  static const uint8_t kAESKey[16] = "BoringCrypto Key";
  static const uint8_t kAESIV[16] = {0};
  static const uint8_t kPlaintext[64] =
      "BoringCryptoModule FIPS KAT Encryption and Decryption Plaintext!";
  static const uint8_t kAESCBCCiphertext[64] = {
      0x87, 0x2d, 0x98, 0xc2, 0xcc, 0x31, 0x5b, 0x41, 0xe0, 0xfa, 0x7b,
      0x0a, 0x71, 0xc0, 0x42, 0xbf, 0x4f, 0x61, 0xd0, 0x0d, 0x58, 0x8c,
      0xf7, 0x05, 0xfb, 0x94, 0x89, 0xd3, 0xbc, 0xaa, 0x1a, 0x50, 0x45,
      0x1f, 0xc3, 0x8c, 0xb8, 0x98, 0x86, 0xa3, 0xe3, 0x6c, 0xfc, 0xad,
      0x3a, 0xb5, 0x59, 0x27, 0x7d, 0x21, 0x07, 0xca, 0x4c, 0x1d, 0x55,
      0x34, 0xdd, 0x5a, 0x2d, 0xc4, 0xb4, 0xf5, 0xa8, 0x35
  };
  static const uint8_t kAESGCMCiphertext[80] = {
      0x4a, 0xd8, 0xe7, 0x7d, 0x78, 0xd7, 0x7d, 0x5e, 0xb2, 0x11, 0xb6, 0xc9,
      0xa4, 0xbc, 0xb2, 0xae, 0xbe, 0x93, 0xd1, 0xb7, 0xfe, 0x65, 0xc1, 0x82,
      0x2a, 0xb6, 0x71, 0x5f, 0x1a, 0x7c, 0xe0, 0x1b, 0x2b, 0xe2, 0x53, 0xfa,
      0xa0, 0x47, 0xfa, 0xd7, 0x8f, 0xb1, 0x4a, 0xc4, 0xdc, 0x89, 0xf9, 0xb4,
      0x14, 0x4d, 0xde, 0x95, 0xea, 0x29, 0x69, 0x76, 0x81, 0xa3, 0x5c, 0x33,
      0xd8, 0x37, 0xd8, 0xfa, 0x47, 0x19, 0x46, 0x2f, 0xf1, 0x90, 0xb7, 0x61,
      0x8f, 0x6f, 0xdd, 0x31, 0x3f, 0x6a, 0x64, 0x0d
  };
  static const uint8_t kPlaintextSHA1[20] = {
      0xc6, 0xf8, 0xc9, 0x63, 0x1c, 0x14, 0x23, 0x62, 0x9b, 0xbd,
      0x55, 0x82, 0xf4, 0xd6, 0x1d, 0xf2, 0xab, 0x7d, 0xc8, 0x28
  };
  static const uint8_t kPlaintextSHA256[32] = {
      0x37, 0xbd, 0x70, 0x53, 0x72, 0xfc, 0xd4, 0x03, 0x79, 0x70, 0xfb,
      0x06, 0x95, 0xb1, 0x2a, 0x82, 0x48, 0xe1, 0x3e, 0xf2, 0x33, 0xfb,
      0xef, 0x29, 0x81, 0x22, 0x45, 0x40, 0x43, 0x70, 0xce, 0x0f
  };
  static const uint8_t kPlaintextSHA512[64] = {
      0x08, 0x6a, 0x1c, 0x84, 0x61, 0x9d, 0x8e, 0xb3, 0xc0, 0x97, 0x4e,
      0xa1, 0x9f, 0x9c, 0xdc, 0xaf, 0x3b, 0x5c, 0x31, 0xf0, 0xf2, 0x74,
      0xc3, 0xbd, 0x6e, 0xd6, 0x1e, 0xb2, 0xbb, 0x34, 0x74, 0x72, 0x5c,
      0x51, 0x29, 0x8b, 0x87, 0x3a, 0xa3, 0xf2, 0x25, 0x23, 0xd4, 0x1c,
      0x82, 0x1b, 0xfe, 0xd3, 0xc6, 0xee, 0xb5, 0xd6, 0xaf, 0x07, 0x7b,
      0x98, 0xca, 0xa7, 0x01, 0xf3, 0x94, 0xf3, 0x68, 0x14
  };

  AES_KEY aes_key;
  uint8_t aes_iv[16];
  uint8_t output[256];

  /* AES-CBC Encryption KAT */
  memcpy(aes_iv, kAESIV, sizeof(kAESIV));
  if (AES_set_encrypt_key(kAESKey, 8 * sizeof(kAESKey), &aes_key) != 0) {
    goto err;
  }
  AES_cbc_encrypt(kPlaintext, output, sizeof(kPlaintext), &aes_key, aes_iv,
                  AES_ENCRYPT);
  if (!check_test(kAESCBCCiphertext, output, sizeof(kAESCBCCiphertext),
                  "AES-CBC Encryption KAT")) {
    goto err;
  }

  /* AES-CBC Decryption KAT */
  memcpy(aes_iv, kAESIV, sizeof(kAESIV));
  if (AES_set_decrypt_key(kAESKey, 8 * sizeof(kAESKey), &aes_key) != 0) {
    goto err;
  }
  AES_cbc_encrypt(kAESCBCCiphertext, output, sizeof(kAESCBCCiphertext),
                  &aes_key, aes_iv, AES_DECRYPT);
  if (!check_test(kPlaintext, output, sizeof(kPlaintext),
                  "AES-CBC Decryption KAT")) {
    goto err;
  }

  size_t out_len;
  uint8_t nonce[EVP_AEAD_MAX_NONCE_LENGTH];
  OPENSSL_memset(nonce, 0, sizeof(nonce));
  EVP_AEAD_CTX aead_ctx;
  if (!EVP_AEAD_CTX_init(&aead_ctx, EVP_aead_aes_128_gcm(), kAESKey,
                         sizeof(kAESKey), 0, NULL)) {
    goto err;
  }

  /* AES-GCM Encryption KAT */
  if (!EVP_AEAD_CTX_seal(&aead_ctx, output, &out_len, sizeof(output), nonce,
                         EVP_AEAD_nonce_length(EVP_aead_aes_128_gcm()),
                         kPlaintext, sizeof(kPlaintext), NULL, 0) ||
      !check_test(kAESGCMCiphertext, output, sizeof(kAESGCMCiphertext),
                  "AES-GCM Encryption KAT")) {
    goto err;
  }

  /* AES-GCM Decryption KAT */
  if (!EVP_AEAD_CTX_open(&aead_ctx, output, &out_len, sizeof(output), nonce,
                         EVP_AEAD_nonce_length(EVP_aead_aes_128_gcm()),
                         kAESGCMCiphertext, sizeof(kAESGCMCiphertext), NULL,
                         0) ||
      !check_test(kPlaintext, output, sizeof(kPlaintext),
                  "AES-GCM Decryption KAT")) {
    goto err;
  }

  EVP_AEAD_CTX_cleanup(&aead_ctx);

  // TODO(svaldez): Add 3DES Encryption KAT.
  // TODO(svaldez): Add 3DES Decryption KAT.

  /* SHA-1 KAT */
  SHA1(kPlaintext, sizeof(kPlaintext), output);
  if (!check_test(kPlaintextSHA1, output, sizeof(kPlaintextSHA1),
                  "SHA-1 KAT")) {
    goto err;
  }

  /* SHA-256 KAT */
  SHA256(kPlaintext, sizeof(kPlaintext), output);
  if (!check_test(kPlaintextSHA256, output, sizeof(kPlaintextSHA256),
                  "SHA-256 KAT")) {
    goto err;
  }

  /* SHA-512 KAT */
  SHA512(kPlaintext, sizeof(kPlaintext), output);
  if (!check_test(kPlaintextSHA512, output, sizeof(kPlaintextSHA512),
                  "SHA-512 KAT")) {
    goto err;
  }

  // TODO(svaldez): Add RSA Sign KAT.
  // TODO(svaldez): Add RSA Verify KAT.
  // TODO(svaldez): Add ECDSA Sign/Verify PWCT.
  // TODO(svaldez): Add DRBG KAT.

  return;

err:
  for (;;) {
    exit(1);
    abort();
  }
}
#endif  /* BORINGSSL_FIPS */
