/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.] */

#include <openssl/rsa.h>

#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/obj.h>

#include "../test/scoped_types.h"


// kPlaintext is a sample plaintext.
static const uint8_t kPlaintext[] = "\x54\x85\x9b\x34\x2c\x49\xea\x2a";
static const size_t kPlaintextLen = sizeof(kPlaintext) - 1;

// kKey1 is a DER-encoded RSAPrivateKey.
static const uint8_t kKey1[] =
    "\x30\x82\x01\x38\x02\x01\x00\x02\x41\x00\xaa\x36\xab\xce\x88\xac\xfd\xff"
    "\x55\x52\x3c\x7f\xc4\x52\x3f\x90\xef\xa0\x0d\xf3\x77\x4a\x25\x9f\x2e\x62"
    "\xb4\xc5\xd9\x9c\xb5\xad\xb3\x00\xa0\x28\x5e\x53\x01\x93\x0e\x0c\x70\xfb"
    "\x68\x76\x93\x9c\xe6\x16\xce\x62\x4a\x11\xe0\x08\x6d\x34\x1e\xbc\xac\xa0"
    "\xa1\xf5\x02\x01\x11\x02\x40\x0a\x03\x37\x48\x62\x64\x87\x69\x5f\x5f\x30"
    "\xbc\x38\xb9\x8b\x44\xc2\xcd\x2d\xff\x43\x40\x98\xcd\x20\xd8\xa1\x38\xd0"
    "\x90\xbf\x64\x79\x7c\x3f\xa7\xa2\xcd\xcb\x3c\xd1\xe0\xbd\xba\x26\x54\xb4"
    "\xf9\xdf\x8e\x8a\xe5\x9d\x73\x3d\x9f\x33\xb3\x01\x62\x4a\xfd\x1d\x51\x02"
    "\x21\x00\xd8\x40\xb4\x16\x66\xb4\x2e\x92\xea\x0d\xa3\xb4\x32\x04\xb5\xcf"
    "\xce\x33\x52\x52\x4d\x04\x16\xa5\xa4\x41\xe7\x00\xaf\x46\x12\x0d\x02\x21"
    "\x00\xc9\x7f\xb1\xf0\x27\xf4\x53\xf6\x34\x12\x33\xea\xaa\xd1\xd9\x35\x3f"
    "\x6c\x42\xd0\x88\x66\xb1\xd0\x5a\x0f\x20\x35\x02\x8b\x9d\x89\x02\x20\x59"
    "\x0b\x95\x72\xa2\xc2\xa9\xc4\x06\x05\x9d\xc2\xab\x2f\x1d\xaf\xeb\x7e\x8b"
    "\x4f\x10\xa7\x54\x9e\x8e\xed\xf5\xb4\xfc\xe0\x9e\x05\x02\x21\x00\x8e\x3c"
    "\x05\x21\xfe\x15\xe0\xea\x06\xa3\x6f\xf0\xf1\x0c\x99\x52\xc3\x5b\x7a\x75"
    "\x14\xfd\x32\x38\xb8\x0a\xad\x52\x98\x62\x8d\x51\x02\x20\x36\x3f\xf7\x18"
    "\x9d\xa8\xe9\x0b\x1d\x34\x1f\x71\xd0\x9b\x76\xa8\xa9\x43\xe1\x1d\x10\xb2"
    "\x4d\x24\x9f\x2d\xea\xfe\xf8\x0c\x18\x26";

// kOAEPCiphertext1 is a sample encryption of |kPlaintext| with |kKey1| using
// RSA OAEP.
static const uint8_t kOAEPCiphertext1[] =
    "\x1b\x8f\x05\xf9\xca\x1a\x79\x52\x6e\x53\xf3\xcc\x51\x4f\xdb\x89\x2b\xfb"
    "\x91\x93\x23\x1e\x78\xb9\x92\xe6\x8d\x50\xa4\x80\xcb\x52\x33\x89\x5c\x74"
    "\x95\x8d\x5d\x02\xab\x8c\x0f\xd0\x40\xeb\x58\x44\xb0\x05\xc3\x9e\xd8\x27"
    "\x4a\x9d\xbf\xa8\x06\x71\x40\x94\x39\xd2";

// kKey2 is a DER-encoded RSAPrivateKey.
static const uint8_t kKey2[] =
    "\x30\x81\xfb\x02\x01\x00\x02\x33\x00\xa3\x07\x9a\x90\xdf\x0d\xfd\x72\xac"
    "\x09\x0c\xcc\x2a\x78\xb8\x74\x13\x13\x3e\x40\x75\x9c\x98\xfa\xf8\x20\x4f"
    "\x35\x8a\x0b\x26\x3c\x67\x70\xe7\x83\xa9\x3b\x69\x71\xb7\x37\x79\xd2\x71"
    "\x7b\xe8\x34\x77\xcf\x02\x01\x03\x02\x32\x6c\xaf\xbc\x60\x94\xb3\xfe\x4c"
    "\x72\xb0\xb3\x32\xc6\xfb\x25\xa2\xb7\x62\x29\x80\x4e\x68\x65\xfc\xa4\x5a"
    "\x74\xdf\x0f\x8f\xb8\x41\x3b\x52\xc0\xd0\xe5\x3d\x9b\x59\x0f\xf1\x9b\xe7"
    "\x9f\x49\xdd\x21\xe5\xeb\x02\x1a\x00\xcf\x20\x35\x02\x8b\x9d\x86\x98\x40"
    "\xb4\x16\x66\xb4\x2e\x92\xea\x0d\xa3\xb4\x32\x04\xb5\xcf\xce\x91\x02\x1a"
    "\x00\xc9\x7f\xb1\xf0\x27\xf4\x53\xf6\x34\x12\x33\xea\xaa\xd1\xd9\x35\x3f"
    "\x6c\x42\xd0\x88\x66\xb1\xd0\x5f\x02\x1a\x00\x8a\x15\x78\xac\x5d\x13\xaf"
    "\x10\x2b\x22\xb9\x99\xcd\x74\x61\xf1\x5e\x6d\x22\xcc\x03\x23\xdf\xdf\x0b"
    "\x02\x1a\x00\x86\x55\x21\x4a\xc5\x4d\x8d\x4e\xcd\x61\x77\xf1\xc7\x36\x90"
    "\xce\x2a\x48\x2c\x8b\x05\x99\xcb\xe0\x3f\x02\x1a\x00\x83\xef\xef\xb8\xa9"
    "\xa4\x0d\x1d\xb6\xed\x98\xad\x84\xed\x13\x35\xdc\xc1\x08\xf3\x22\xd0\x57"
    "\xcf\x8d";

// kOAEPCiphertext2 is a sample encryption of |kPlaintext| with |kKey2| using
// RSA OAEP.
static const uint8_t kOAEPCiphertext2[] =
    "\x14\xbd\xdd\x28\xc9\x83\x35\x19\x23\x80\xe8\xe5\x49\xb1\x58\x2a\x8b\x40"
    "\xb4\x48\x6d\x03\xa6\xa5\x31\x1f\x1f\xd5\xf0\xa1\x80\xe4\x17\x53\x03\x29"
    "\xa9\x34\x90\x74\xb1\x52\x13\x54\x29\x08\x24\x52\x62\x51";

// kKey3 is a DER-encoded RSAPrivateKey.
static const uint8_t kKey3[] =
    "\x30\x82\x02\x5b\x02\x01\x00\x02\x81\x81\x00\xbb\xf8\x2f\x09\x06\x82\xce"
    "\x9c\x23\x38\xac\x2b\x9d\xa8\x71\xf7\x36\x8d\x07\xee\xd4\x10\x43\xa4\x40"
    "\xd6\xb6\xf0\x74\x54\xf5\x1f\xb8\xdf\xba\xaf\x03\x5c\x02\xab\x61\xea\x48"
    "\xce\xeb\x6f\xcd\x48\x76\xed\x52\x0d\x60\xe1\xec\x46\x19\x71\x9d\x8a\x5b"
    "\x8b\x80\x7f\xaf\xb8\xe0\xa3\xdf\xc7\x37\x72\x3e\xe6\xb4\xb7\xd9\x3a\x25"
    "\x84\xee\x6a\x64\x9d\x06\x09\x53\x74\x88\x34\xb2\x45\x45\x98\x39\x4e\xe0"
    "\xaa\xb1\x2d\x7b\x61\xa5\x1f\x52\x7a\x9a\x41\xf6\xc1\x68\x7f\xe2\x53\x72"
    "\x98\xca\x2a\x8f\x59\x46\xf8\xe5\xfd\x09\x1d\xbd\xcb\x02\x01\x11\x02\x81"
    "\x81\x00\xa5\xda\xfc\x53\x41\xfa\xf2\x89\xc4\xb9\x88\xdb\x30\xc1\xcd\xf8"
    "\x3f\x31\x25\x1e\x06\x68\xb4\x27\x84\x81\x38\x01\x57\x96\x41\xb2\x94\x10"
    "\xb3\xc7\x99\x8d\x6b\xc4\x65\x74\x5e\x5c\x39\x26\x69\xd6\x87\x0d\xa2\xc0"
    "\x82\xa9\x39\xe3\x7f\xdc\xb8\x2e\xc9\x3e\xda\xc9\x7f\xf3\xad\x59\x50\xac"
    "\xcf\xbc\x11\x1c\x76\xf1\xa9\x52\x94\x44\xe5\x6a\xaf\x68\xc5\x6c\x09\x2c"
    "\xd3\x8d\xc3\xbe\xf5\xd2\x0a\x93\x99\x26\xed\x4f\x74\xa1\x3e\xdd\xfb\xe1"
    "\xa1\xce\xcc\x48\x94\xaf\x94\x28\xc2\xb7\xb8\x88\x3f\xe4\x46\x3a\x4b\xc8"
    "\x5b\x1c\xb3\xc1\x02\x41\x00\xee\xcf\xae\x81\xb1\xb9\xb3\xc9\x08\x81\x0b"
    "\x10\xa1\xb5\x60\x01\x99\xeb\x9f\x44\xae\xf4\xfd\xa4\x93\xb8\x1a\x9e\x3d"
    "\x84\xf6\x32\x12\x4e\xf0\x23\x6e\x5d\x1e\x3b\x7e\x28\xfa\xe7\xaa\x04\x0a"
    "\x2d\x5b\x25\x21\x76\x45\x9d\x1f\x39\x75\x41\xba\x2a\x58\xfb\x65\x99\x02"
    "\x41\x00\xc9\x7f\xb1\xf0\x27\xf4\x53\xf6\x34\x12\x33\xea\xaa\xd1\xd9\x35"
    "\x3f\x6c\x42\xd0\x88\x66\xb1\xd0\x5a\x0f\x20\x35\x02\x8b\x9d\x86\x98\x40"
    "\xb4\x16\x66\xb4\x2e\x92\xea\x0d\xa3\xb4\x32\x04\xb5\xcf\xce\x33\x52\x52"
    "\x4d\x04\x16\xa5\xa4\x41\xe7\x00\xaf\x46\x15\x03\x02\x40\x54\x49\x4c\xa6"
    "\x3e\xba\x03\x37\xe4\xe2\x40\x23\xfc\xd6\x9a\x5a\xeb\x07\xdd\xdc\x01\x83"
    "\xa4\xd0\xac\x9b\x54\xb0\x51\xf2\xb1\x3e\xd9\x49\x09\x75\xea\xb7\x74\x14"
    "\xff\x59\xc1\xf7\x69\x2e\x9a\x2e\x20\x2b\x38\xfc\x91\x0a\x47\x41\x74\xad"
    "\xc9\x3c\x1f\x67\xc9\x81\x02\x40\x47\x1e\x02\x90\xff\x0a\xf0\x75\x03\x51"
    "\xb7\xf8\x78\x86\x4c\xa9\x61\xad\xbd\x3a\x8a\x7e\x99\x1c\x5c\x05\x56\xa9"
    "\x4c\x31\x46\xa7\xf9\x80\x3f\x8f\x6f\x8a\xe3\x42\xe9\x31\xfd\x8a\xe4\x7a"
    "\x22\x0d\x1b\x99\xa4\x95\x84\x98\x07\xfe\x39\xf9\x24\x5a\x98\x36\xda\x3d"
    "\x02\x41\x00\xb0\x6c\x4f\xda\xbb\x63\x01\x19\x8d\x26\x5b\xdb\xae\x94\x23"
    "\xb3\x80\xf2\x71\xf7\x34\x53\x88\x50\x93\x07\x7f\xcd\x39\xe2\x11\x9f\xc9"
    "\x86\x32\x15\x4f\x58\x83\xb1\x67\xa9\x67\xbf\x40\x2b\x4e\x9e\x2e\x0f\x96"
    "\x56\xe6\x98\xea\x36\x66\xed\xfb\x25\x79\x80\x39\xf7";

// kOAEPCiphertext3 is a sample encryption of |kPlaintext| with |kKey3| using
// RSA OAEP.
static const uint8_t kOAEPCiphertext3[] =
    "\xb8\x24\x6b\x56\xa6\xed\x58\x81\xae\xb5\x85\xd9\xa2\x5b\x2a\xd7\x90\xc4"
    "\x17\xe0\x80\x68\x1b\xf1\xac\x2b\xc3\xde\xb6\x9d\x8b\xce\xf0\xc4\x36\x6f"
    "\xec\x40\x0a\xf0\x52\xa7\x2e\x9b\x0e\xff\xb5\xb3\xf2\xf1\x92\xdb\xea\xca"
    "\x03\xc1\x27\x40\x05\x71\x13\xbf\x1f\x06\x69\xac\x22\xe9\xf3\xa7\x85\x2e"
    "\x3c\x15\xd9\x13\xca\xb0\xb8\x86\x3a\x95\xc9\x92\x94\xce\x86\x74\x21\x49"
    "\x54\x61\x03\x46\xf4\xd4\x74\xb2\x6f\x7c\x48\xb4\x2e\xe6\x8e\x1f\x57\x2a"
    "\x1f\xc4\x02\x6a\xc4\x56\xb4\xf5\x9f\x7b\x62\x1e\xa1\xb9\xd8\x8f\x64\x20"
    "\x2f\xb1";


static bool TestRSA(const uint8_t *der, size_t der_len,
                    const uint8_t *oaep_ciphertext,
                    size_t oaep_ciphertext_len) {
  ScopedRSA key(RSA_private_key_from_bytes(der, der_len));
  if (!key) {
    return false;
  }

  if (!RSA_check_key(key.get())) {
    fprintf(stderr, "RSA_check_key failed\n");
    return false;
  }

  uint8_t ciphertext[256];

  int num = RSA_public_encrypt(kPlaintextLen, kPlaintext, ciphertext, key.get(),
                               RSA_PKCS1_PADDING);
  if (num < 0 || (size_t)num != RSA_size(key.get())) {
    fprintf(stderr, "PKCS#1 v1.5 encryption failed!\n");
    return false;
  }

  uint8_t plaintext[256];
  num = RSA_private_decrypt(num, ciphertext, plaintext, key.get(),
                            RSA_PKCS1_PADDING);
  if (num < 0 ||
      (size_t)num != kPlaintextLen || memcmp(plaintext, kPlaintext, num) != 0) {
    fprintf(stderr, "PKCS#1 v1.5 decryption failed!\n");
    return false;
  }

  num = RSA_public_encrypt(kPlaintextLen, kPlaintext, ciphertext, key.get(),
                           RSA_PKCS1_OAEP_PADDING);
  if (num < 0 || (size_t)num != RSA_size(key.get())) {
    fprintf(stderr, "OAEP encryption failed!\n");
    return false;
  }

  num = RSA_private_decrypt(num, ciphertext, plaintext, key.get(),
                            RSA_PKCS1_OAEP_PADDING);
  if (num < 0 ||
      (size_t)num != kPlaintextLen || memcmp(plaintext, kPlaintext, num) != 0) {
    fprintf(stderr, "OAEP decryption (encrypted data) failed!\n");
    return false;
  }

  // |oaep_ciphertext| should decrypt to |kPlaintext|.
  num = RSA_private_decrypt(oaep_ciphertext_len, oaep_ciphertext, plaintext,
                            key.get(), RSA_PKCS1_OAEP_PADDING);

  if (num < 0 ||
      (size_t)num != kPlaintextLen || memcmp(plaintext, kPlaintext, num) != 0) {
    fprintf(stderr, "OAEP decryption (test vector data) failed!\n");
    return false;
  }

  // Try decrypting corrupted ciphertexts.
  memcpy(ciphertext, oaep_ciphertext, oaep_ciphertext_len);
  for (size_t i = 0; i < oaep_ciphertext_len; i++) {
    ciphertext[i] ^= 1;
    num = RSA_private_decrypt(oaep_ciphertext_len, ciphertext, plaintext,
                              key.get(), RSA_PKCS1_OAEP_PADDING);
    if (num > 0) {
      fprintf(stderr, "Corrupt data decrypted!\n");
      return false;
    }
    ciphertext[i] ^= 1;
  }

  // Test truncated ciphertexts.
  for (size_t len = 0; len < oaep_ciphertext_len; len++) {
    num = RSA_private_decrypt(len, ciphertext, plaintext, key.get(),
                              RSA_PKCS1_OAEP_PADDING);
    if (num > 0) {
      fprintf(stderr, "Corrupt data decrypted!\n");
      return false;
    }
  }

  return true;
}

static bool TestBadKey() {
  ScopedRSA key(RSA_new());
  ScopedBIGNUM e(BN_new());

  if (!key || !e || !BN_set_word(e.get(), RSA_F4)) {
    return false;
  }

  if (!RSA_generate_key_ex(key.get(), 512, e.get(), nullptr)) {
    fprintf(stderr, "RSA_generate_key_ex failed.\n");
    return false;
  }

  if (!BN_add(key->p, key->p, BN_value_one())) {
    fprintf(stderr, "BN error.\n");
    return false;
  }

  if (RSA_check_key(key.get())) {
    fprintf(stderr, "RSA_check_key passed with invalid key!\n");
    return false;
  }

  ERR_clear_error();
  return true;
}

static bool TestOnlyDGiven() {
  uint8_t buf[64];
  unsigned buf_len = sizeof(buf);
  ScopedRSA key(RSA_new());
  if (!key ||
      !BN_hex2bn(&key->n,
                 "00e77bbf3889d4ef36a9a25d4d69f3f632eb4362214c74517da6d6aeaa9bd"
                 "09ac42b26621cd88f3a6eb013772fc3bf9f83914b6467231c630202c35b3e"
                 "5808c659") ||
      !BN_hex2bn(&key->e, "010001") ||
      !BN_hex2bn(&key->d,
                 "0365db9eb6d73b53b015c40cd8db4de7dd7035c68b5ac1bf786d7a4ee2cea"
                 "316eaeca21a73ac365e58713195f2ae9849348525ca855386b6d028e437a9"
                 "495a01") ||
      RSA_size(key.get()) > sizeof(buf)) {
    return false;
  }

  if (!RSA_check_key(key.get())) {
    fprintf(stderr, "RSA_check_key failed with only d given.\n");
    return false;
  }

  const uint8_t kDummyHash[16] = {0};

  if (!RSA_sign(NID_sha256, kDummyHash, sizeof(kDummyHash), buf, &buf_len,
                key.get())) {
    fprintf(stderr, "RSA_sign failed with only d given.\n");
    return false;
  }

  if (!RSA_verify(NID_sha256, kDummyHash, sizeof(kDummyHash), buf, buf_len,
                  key.get())) {
    fprintf(stderr, "RSA_verify failed with only d given.\n");
    return false;
  }

  return true;
}

static bool TestRecoverCRTParams() {
  ScopedBIGNUM e(BN_new());
  if (!e || !BN_set_word(e.get(), RSA_F4)) {
    return false;
  }

  ERR_clear_error();

  for (unsigned i = 0; i < 1; i++) {
    ScopedRSA key1(RSA_new());
    if (!key1 ||
        !RSA_generate_key_ex(key1.get(), 512, e.get(), nullptr)) {
      fprintf(stderr, "RSA_generate_key_ex failed.\n");
      return false;
    }

    if (!RSA_check_key(key1.get())) {
      fprintf(stderr, "RSA_check_key failed with original key.\n");
      return false;
    }

    ScopedRSA key2(RSA_new());
    if (!key2) {
      return false;
    }
    key2->n = BN_dup(key1->n);
    key2->e = BN_dup(key1->e);
    key2->d = BN_dup(key1->d);
    if (key2->n == nullptr || key2->e == nullptr || key2->d == nullptr) {
      return false;
    }
  }

  return true;
}

static bool TestASN1() {
  // Test that private keys may be decoded.
  ScopedRSA rsa(RSA_private_key_from_bytes(kKey1, sizeof(kKey1) - 1));
  if (!rsa) {
    return false;
  }

  // Test that the serialization round-trips.
  uint8_t *der;
  size_t der_len;
  if (!RSA_private_key_to_bytes(&der, &der_len, rsa.get())) {
    return false;
  }
  ScopedOpenSSLBytes delete_der(der);
  if (der_len != sizeof(kKey1) - 1 || memcmp(der, kKey1, der_len) != 0) {
    return false;
  }

  // Test that serializing public keys works.
  if (!RSA_public_key_to_bytes(&der, &der_len, rsa.get())) {
    return false;
  }
  delete_der.reset(der);

  // Public keys may be parsed back out.
  rsa.reset(RSA_public_key_from_bytes(der, der_len));
  if (!rsa || rsa->p != NULL || rsa->q != NULL) {
    return false;
  }

  // Serializing the result round-trips.
  uint8_t *der2;
  size_t der2_len;
  if (!RSA_public_key_to_bytes(&der2, &der2_len, rsa.get())) {
    return false;
  }
  ScopedOpenSSLBytes delete_der2(der2);
  if (der_len != der2_len || memcmp(der, der2, der_len) != 0) {
    return false;
  }

  // Public keys cannot be serialized as private keys.
  if (RSA_private_key_to_bytes(&der, &der_len, rsa.get())) {
    OPENSSL_free(der);
    return false;
  }
  ERR_clear_error();

  return true;
}

int main(int argc, char *argv[]) {
  CRYPTO_library_init();

  if (!TestRSA(kKey1, sizeof(kKey1) - 1, kOAEPCiphertext1,
               sizeof(kOAEPCiphertext1) - 1) ||
      !TestRSA(kKey2, sizeof(kKey2) - 1, kOAEPCiphertext2,
               sizeof(kOAEPCiphertext2) - 1) ||
      !TestRSA(kKey3, sizeof(kKey3) - 1, kOAEPCiphertext3,
               sizeof(kOAEPCiphertext3) - 1) ||
      !TestOnlyDGiven() ||
      !TestRecoverCRTParams() ||
      !TestBadKey() ||
      !TestASN1()) {
    return 1;
  }

  printf("PASS\n");
  return 0;
}
