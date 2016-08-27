/* Copyright (c) 2016, Google Inc.
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

#include <vector>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ec_key.h>
#include <openssl/ecdh.h>

#include "../test/file_test.h"
#include "../test/scoped_types.h"


static ScopedEC_GROUP GetCurve(FileTest *t, const char *key) {
  std::string curve_name;
  if (!t->GetAttribute(&curve_name, key)) {
    return nullptr;
  }

  if (curve_name == "P-224") {
    return ScopedEC_GROUP(EC_GROUP_new_by_curve_name(NID_secp224r1));
  }
  if (curve_name == "P-256") {
    return ScopedEC_GROUP(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
  }
  if (curve_name == "P-384") {
    return ScopedEC_GROUP(EC_GROUP_new_by_curve_name(NID_secp384r1));
  }
  if (curve_name == "P-521") {
    return ScopedEC_GROUP(EC_GROUP_new_by_curve_name(NID_secp521r1));
  }

  t->PrintLine("Unknown curve '%s'", curve_name.c_str());
  return nullptr;
}

static ScopedBIGNUM GetBIGNUM(FileTest *t, const char *key) {
  std::vector<uint8_t> bytes;
  if (!t->GetBytes(&bytes, key)) {
    return nullptr;
  }

  return ScopedBIGNUM(BN_bin2bn(bytes.data(), bytes.size(), nullptr));
}

static bool TestECDH(FileTest *t, void *arg) {
  ScopedEC_GROUP group = GetCurve(t, "Curve");
  ScopedBIGNUM priv_key = GetBIGNUM(t, "Private");
  ScopedBIGNUM x = GetBIGNUM(t, "X");
  ScopedBIGNUM y = GetBIGNUM(t, "Y");
  ScopedBIGNUM peer_x = GetBIGNUM(t, "PeerX");
  ScopedBIGNUM peer_y = GetBIGNUM(t, "PeerY");
  std::vector<uint8_t> z;
  if (!group || !priv_key || !x || !y || !peer_x || !peer_y ||
      !t->GetBytes(&z, "Z")) {
    return false;
  }

  ScopedEC_KEY key(EC_KEY_new());
  ScopedEC_POINT pub_key(EC_POINT_new(group.get()));
  ScopedEC_POINT peer_pub_key(EC_POINT_new(group.get()));
  if (!key || !pub_key || !peer_pub_key ||
      !EC_KEY_set_group(key.get(), group.get()) ||
      !EC_KEY_set_private_key(key.get(), priv_key.get()) ||
      !EC_POINT_set_affine_coordinates_GFp(group.get(), pub_key.get(), x.get(),
                                           y.get(), nullptr) ||
      !EC_POINT_set_affine_coordinates_GFp(group.get(), peer_pub_key.get(),
                                           peer_x.get(), peer_y.get(),
                                           nullptr) ||
      !EC_KEY_set_public_key(key.get(), pub_key.get()) ||
      !EC_KEY_check_key(key.get())) {
    return false;
  }

  std::vector<uint8_t> actual_z;
  // Make |actual_z| larger than expected to ensure |ECDH_compute_key| returns
  // the right amount of data.
  actual_z.resize(z.size() + 1);
  int ret = ECDH_compute_key(actual_z.data(), actual_z.size(),
                             peer_pub_key.get(), key.get(), nullptr);
  if (ret < 0 ||
      !t->ExpectBytesEqual(z.data(), z.size(), actual_z.data(),
                           static_cast<size_t>(ret))) {
    return false;
  }

  // Test |ECDH_compute_key| truncates.
  actual_z.resize(z.size() - 1);
  ret = ECDH_compute_key(actual_z.data(), actual_z.size(), peer_pub_key.get(),
                         key.get(), nullptr);
  if (ret < 0 ||
      !t->ExpectBytesEqual(z.data(), z.size() - 1, actual_z.data(),
                           static_cast<size_t>(ret))) {
    return false;
  }

  return true;
}

int main(int argc, char *argv[]) {
  CRYPTO_library_init();

  if (argc != 2) {
    fprintf(stderr, "%s <test file.txt>\n", argv[0]);
    return 1;
  }

  return FileTestMain(TestECDH, nullptr, argv[1]);
}
