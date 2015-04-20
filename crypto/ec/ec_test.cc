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

#include <vector>

#include <openssl/crypto.h>
#include <openssl/ec_key.h>
#include <openssl/err.h>
#include <openssl/mem.h>

#include "../test/scoped_types.h"
#include "../test/stl_compat.h"
#include "internal.h"


static const uint8_t kECKeyWithoutPublic[] = {
  0x30, 0x31, 0x02, 0x01, 0x01, 0x04, 0x20, 0xc6, 0xc1, 0xaa, 0xda, 0x15, 0xb0,
  0x76, 0x61, 0xf8, 0x14, 0x2c, 0x6c, 0xaf, 0x0f, 0xdb, 0x24, 0x1a, 0xff, 0x2e,
  0xfe, 0x46, 0xc0, 0x93, 0x8b, 0x74, 0xf2, 0xbc, 0xc5, 0x30, 0x52, 0xb0, 0x77,
  0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
};

bool Testd2i_ECPrivateKey(void) {
  const uint8_t *inp = kECKeyWithoutPublic;
  ScopedEC_KEY key(d2i_ECPrivateKey(NULL, &inp, sizeof(kECKeyWithoutPublic)));

  if (!key || inp != kECKeyWithoutPublic + sizeof(kECKeyWithoutPublic)) {
    fprintf(stderr, "Failed to parse private key.\n");
    ERR_print_errors_fp(stderr);
    return false;
  }

  int len = i2d_ECPrivateKey(key.get(), NULL);
  std::vector<uint8_t> out(len);
  uint8_t *outp = bssl::vector_data(&out);
  if (len != i2d_ECPrivateKey(key.get(), &outp)) {
    fprintf(stderr, "Failed to serialize private key.\n");
    ERR_print_errors_fp(stderr);
    return false;
  }

  if (0 != memcmp(bssl::vector_data(&out), kECKeyWithoutPublic, len)) {
    fprintf(stderr, "Serialisation of key doesn't match original.\n");
    return false;
  }

  const EC_POINT *pub_key = EC_KEY_get0_public_key(key.get());
  if (pub_key == NULL) {
    fprintf(stderr, "Public key missing.\n");
    return false;
  }

  ScopedBIGNUM x(BN_new());
  ScopedBIGNUM y(BN_new());
  if (!x || !y) {
    return false;
  }
  if (!EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(key.get()),
                                           pub_key, x.get(), y.get(), NULL)) {
    fprintf(stderr, "Failed to get public key in affine coordinates.\n");
    return false;
  }
  ScopedOpenSSLString x_hex(BN_bn2hex(x.get()));
  ScopedOpenSSLString y_hex(BN_bn2hex(y.get()));
  if (0 != strcmp(
          x_hex.get(),
          "c81561ecf2e54edefe6617db1c7a34a70744ddb261f269b83dacfcd2ade5a681") ||
      0 != strcmp(
          y_hex.get(),
          "e0e2afa3f9b6abe4c698ef6495f1be49a3196c5056acb3763fe4507eec596e88")) {
    fprintf(stderr, "Incorrect public key: %s %s\n", x_hex.get(), y_hex.get());
    return false;
  }

  return true;
}

int main(void) {
  CRYPTO_library_init();
  ERR_load_crypto_strings();

  if (!Testd2i_ECPrivateKey()) {
    fprintf(stderr, "failed\n");
    return 1;
  }

  printf("PASS\n");
  return 0;
}
