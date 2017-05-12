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

/* test_fips exercises various cryptographic primitives for demonstration
 * purposes in the validation process only. */

#include <stdio.h>

#include <openssl/aead.h>
#include <openssl/aes.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/des.h>
#include <openssl/ecdsa.h>
#include <openssl/ec_key.h>
#include <openssl/hmac.h>
#include <openssl/nid.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include "../crypto/fipsmodule/rand/internal.h"
#include "../crypto/internal.h"


int main(int argc, char **argv) {
  CRYPTO_library_init();

  static const uint8_t kAESKey[16] = "BoringCrypto Key";
  static const uint8_t kPlaintext[64] =
      "BoringCryptoModule FIPS KAT Encryption and Decryption Plaintext!";
  static const DES_cblock kDESKey1 = {"BCMDESK1"};
  static const DES_cblock kDESKey2 = {"BCMDESK2"};
  static const DES_cblock kDESKey3 = {"BCMDESK3"};
  static const DES_cblock kDESIV = {"BCMDESIV"};
  static const uint8_t kPlaintextSHA256[32] = {
      0x37, 0xbd, 0x70, 0x53, 0x72, 0xfc, 0xd4, 0x03, 0x79, 0x70, 0xfb,
      0x06, 0x95, 0xb1, 0x2a, 0x82, 0x48, 0xe1, 0x3e, 0xf2, 0x33, 0xfb,
      0xef, 0x29, 0x81, 0x22, 0x45, 0x40, 0x43, 0x70, 0xce, 0x0f};
  const uint8_t kDRBGEntropy[48] =
      "DBRG Initial Entropy                            ";
  const uint8_t kDRBGPersonalization[18] = "BCMPersonalization";
  const uint8_t kDRBGAD[16] = "BCM DRBG AD     ";
  const uint8_t kDRBGEntropy2[48] =
      "DBRG Reseed Entropy                             ";

  AES_KEY aes_key;
  uint8_t aes_iv[16];
  uint8_t output[256];

  /* AES-CBC Encryption */
  memset(aes_iv, 0, sizeof(aes_iv));
  if (AES_set_encrypt_key(kAESKey, 8 * sizeof(kAESKey), &aes_key) != 0) {
    printf("AES_set_encrypt_key failed\n");
    goto err;
  }
  AES_cbc_encrypt(kPlaintext, output, sizeof(kPlaintext), &aes_key, aes_iv,
                  AES_ENCRYPT);

  /* AES-CBC Decryption */
  memset(aes_iv, 0, sizeof(aes_iv));
  if (AES_set_decrypt_key(kAESKey, 8 * sizeof(kAESKey), &aes_key) != 0) {
    printf("AES decrypt failed\n");
    goto err;
  }
  AES_cbc_encrypt(output, output, sizeof(kPlaintext), &aes_key, aes_iv,
                  AES_DECRYPT);

  size_t out_len;
  uint8_t nonce[EVP_AEAD_MAX_NONCE_LENGTH];
  OPENSSL_memset(nonce, 0, sizeof(nonce));
  EVP_AEAD_CTX aead_ctx;
  if (!EVP_AEAD_CTX_init(&aead_ctx, EVP_aead_aes_128_gcm(), kAESKey,
                         sizeof(kAESKey), 0, NULL)) {
    printf("EVP_AEAD_CTX_init failed\n");
    goto err;
  }

  /* AES-GCM Encryption */
  if (!EVP_AEAD_CTX_seal(&aead_ctx, output, &out_len, sizeof(output), nonce,
                         EVP_AEAD_nonce_length(EVP_aead_aes_128_gcm()),
                         kPlaintext, sizeof(kPlaintext), NULL, 0)) {
    printf("AES-GCM encrypt failed\n");
    goto err;
  }

  /* AES-GCM Decryption */
  if (!EVP_AEAD_CTX_open(&aead_ctx, output, &out_len, sizeof(output), nonce,
                         EVP_AEAD_nonce_length(EVP_aead_aes_128_gcm()),
                         output, out_len, NULL, 0)) {
    printf("AES-GCM decrypt failed\n");
    goto err;
  }

  EVP_AEAD_CTX_cleanup(&aead_ctx);

  DES_key_schedule des1, des2, des3;
  DES_cblock des_iv;
  DES_set_key(&kDESKey1, &des1);
  DES_set_key(&kDESKey2, &des2);
  DES_set_key(&kDESKey3, &des3);

  /* 3DES Encryption */
  memcpy(&des_iv, &kDESIV, sizeof(des_iv));
  DES_ede3_cbc_encrypt(kPlaintext, output, sizeof(kPlaintext), &des1, &des2,
                       &des3, &des_iv, DES_ENCRYPT);

  /* 3DES Decryption */
  memcpy(&des_iv, &kDESIV, sizeof(des_iv));
  DES_ede3_cbc_encrypt(output, output, sizeof(kPlaintext), &des1,
                       &des2, &des3, &des_iv, DES_DECRYPT);

  /* SHA-1 */
  SHA1(kPlaintext, sizeof(kPlaintext), output);

  /* SHA-256 */
  SHA256(kPlaintext, sizeof(kPlaintext), output);

  /* SHA-512 */
  SHA512(kPlaintext, sizeof(kPlaintext), output);

  RSA *rsa_key = RSA_new();
  if (!RSA_generate_key_fips(rsa_key, 2048, NULL)) {
    printf("RSA_generate_key_fips failed\n");
    goto err;
  }

  /* RSA Sign */
  unsigned sig_len;
  if (!RSA_sign(NID_sha256, kPlaintextSHA256, sizeof(kPlaintextSHA256), output,
                &sig_len, rsa_key)) {
    printf("RSA Sign failed\n");
    goto err;
  }

  /* RSA Verify */
  if (!RSA_verify(NID_sha256, kPlaintextSHA256, sizeof(kPlaintextSHA256),
                  output, sig_len, rsa_key)) {
    printf("RSA Verify failed.\n");
    goto err;
  }

  RSA_free(rsa_key);

  EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if (ec_key == NULL) {
    printf("invalid ECDSA key\n");
    goto err;
  }

  if (!EC_KEY_generate_key_fips(ec_key)) {
    printf("EC_KEY_generate_key_fips failed\n");
    goto err;
  }

  /* ECDSA Sign/Verify PWCT */
  ECDSA_SIG *sig =
      ECDSA_do_sign(kPlaintextSHA256, sizeof(kPlaintextSHA256), ec_key);
  if (sig == NULL ||
      !ECDSA_do_verify(kPlaintextSHA256, sizeof(kPlaintextSHA256), sig,
                       ec_key)) {
    printf("ECDSA Sign/Verify PWCT failed.\n");
    goto err;
  }

  ECDSA_SIG_free(sig);
  EC_KEY_free(ec_key);

  /* DBRG */
  CTR_DRBG_STATE drbg;
  if (!CTR_DRBG_init(&drbg, kDRBGEntropy, kDRBGPersonalization,
                     sizeof(kDRBGPersonalization)) ||
      !CTR_DRBG_generate(&drbg, output, sizeof(output), kDRBGAD,
                         sizeof(kDRBGAD)) ||
      !CTR_DRBG_reseed(&drbg, kDRBGEntropy2, kDRBGAD, sizeof(kDRBGAD)) ||
      !CTR_DRBG_generate(&drbg, output, sizeof(output), kDRBGAD,
                         sizeof(kDRBGAD))) {
    printf("DRBG failed\n");
    goto err;
  }
  CTR_DRBG_clear(&drbg);

  printf("PASS\n");
  return 0;

err:
  printf("FAIL\n");
  abort();
}
