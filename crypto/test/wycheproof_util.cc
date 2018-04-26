/* Copyright (c) 2018, Google Inc.
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

#include "./wycheproof_util.h"

#include <openssl/digest.h>
#include <openssl/ec.h>
#include <openssl/nid.h>

#include "./file_test.h"


bool GetWycheproofResult(FileTest *t, WycheproofResult *out) {
  std::string result;
  if (!t->GetAttribute(&result, "result")) {
    return false;
  }
  if (result == "valid") {
    *out = WycheproofResult::kValid;
  } else if (result == "invalid") {
    *out = WycheproofResult::kInvalid;
  } else if (result == "acceptable") {
    *out = WycheproofResult::kAcceptable;
  } else {
    t->PrintLine("Bad result string '%s'", result.c_str());
    return false;
  }
  return true;
}

const EVP_MD *GetWycheproofDigest(FileTest *t, const char *key,
                                  bool instruction) {
  std::string name;
  bool ok =
      instruction ? t->GetInstruction(&name, key) : t->GetAttribute(&name, key);
  if (!ok) {
    return nullptr;
  }
  if (name == "SHA-1") {
    return EVP_sha1();
  }
  if (name == "SHA-224") {
    return EVP_sha224();
  }
  if (name == "SHA-256") {
    return EVP_sha256();
  }
  if (name == "SHA-384") {
    return EVP_sha384();
  }
  if (name == "SHA-512") {
    return EVP_sha512();
  }
  t->PrintLine("Unknown digest '%s'", name.c_str());
  return nullptr;
}

bssl::UniquePtr<EC_GROUP> GetWycheproofCurve(FileTest *t, const char *key,
                                             bool instruction) {
  std::string name;
  bool ok =
      instruction ? t->GetInstruction(&name, key) : t->GetAttribute(&name, key);
  if (!ok) {
    return nullptr;
  }
  int nid;
  if (name == "secp224r1") {
    nid = NID_secp224r1;
  } else if (name == "secp256r1") {
    nid = NID_X9_62_prime256v1;
  } else if (name == "secp384r1") {
    nid = NID_secp384r1;
  } else if (name == "secp521r1") {
    nid = NID_secp521r1;
  } else {
    t->PrintLine("Unknown curve '%s'", name.c_str());
    return nullptr;
  }
  return bssl::UniquePtr<EC_GROUP>(EC_GROUP_new_by_curve_name(nid));
}
