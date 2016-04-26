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
#include <string.h>

#include <openssl/bytestring.h>
#include <openssl/crypto.h>
#include <openssl/obj.h>


static bool TestBasic() {
  static const int kNID = NID_sha256WithRSAEncryption;
  static const char kShortName[] = "RSA-SHA256";
  static const char kLongName[] = "sha256WithRSAEncryption";
  static const char kText[] = "1.2.840.113549.1.1.11";
  static const uint8_t kDER[] = {
      0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
  };

  CBS cbs;
  CBS_init(&cbs, kDER, sizeof(kDER));
  if (OBJ_cbs2nid(&cbs) != kNID ||
      OBJ_sn2nid(kShortName) != kNID ||
      OBJ_ln2nid(kLongName) != kNID ||
      OBJ_txt2nid(kShortName) != kNID ||
      OBJ_txt2nid(kLongName) != kNID ||
      OBJ_txt2nid(kText) != kNID) {
    return false;
  }

  if (strcmp(kShortName, OBJ_nid2sn(kNID)) != 0 ||
      strcmp(kLongName, OBJ_nid2ln(kNID)) != 0) {
    return false;
  }

  if (OBJ_sn2nid("this is not an OID") != NID_undef ||
      OBJ_ln2nid("this is not an OID") != NID_undef ||
      OBJ_txt2nid("this is not an OID") != NID_undef) {
    return false;
  }

  CBS_init(&cbs, NULL, 0);
  if (OBJ_cbs2nid(&cbs) != NID_undef) {
    return false;
  }

  // 1.2.840.113554.4.1.72585.2 (https://davidben.net/oid).
  static const uint8_t kUnknownDER[] = {
      0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x04, 0x01, 0x84, 0xb7, 0x09, 0x02,
  };
  CBS_init(&cbs, kUnknownDER, sizeof(kUnknownDER));
  if (OBJ_cbs2nid(&cbs) != NID_undef) {
    return false;
  }

  return true;
}

static bool TestSignatureAlgorithms() {
  int digest_nid, pkey_nid;
  if (!OBJ_find_sigid_algs(NID_sha256WithRSAEncryption, &digest_nid,
                           &pkey_nid) ||
      digest_nid != NID_sha256 || pkey_nid != NID_rsaEncryption) {
    return false;
  }

  if (OBJ_find_sigid_algs(NID_sha256, &digest_nid, &pkey_nid)) {
    return false;
  }

  int sign_nid;
  if (!OBJ_find_sigid_by_algs(&sign_nid, NID_sha256, NID_rsaEncryption) ||
      sign_nid != NID_sha256WithRSAEncryption) {
    return false;
  }

  if (OBJ_find_sigid_by_algs(&sign_nid, NID_dsa, NID_rsaEncryption)) {
    return false;
  }

  return true;
}

int main() {
  CRYPTO_library_init();

  if (!TestBasic() ||
      !TestSignatureAlgorithms()) {
    return 1;
  }

  printf("PASS\n");
  return 0;
}
