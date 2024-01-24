/* Copyright 2016 Brian Smith.
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

// Generate test vectors for *ring*.

#include <openssl/ec.h>

#include <assert.h>
#include <inttypes.h>
#include <vector>

#include <openssl/digest.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/nid.h>
#include <openssl/sha.h>

#include "../crypto/fipsmodule/bn/internal.h"
#include "../crypto/fipsmodule/ec/internal.h"

#include "internal.h"

enum ECDSASigFormat { Fixed, ASN1 };
enum Affinification { MakeAffineAllZero, MakeAffineToken, Unchanged };

static void digest_to_bn(BIGNUM *out, const uint8_t *digest, size_t digest_len,
                         const BIGNUM *order) {
  size_t num_bits = BN_num_bits(order);
  // Need to truncate digest if it is too long: first truncate whole bytes.
  size_t num_bytes = (num_bits + 7) / 8;
  if (digest_len > num_bytes) {
    digest_len = num_bytes;
  }

  bn_big_endian_to_words(out->d, order->width, digest, digest_len);

  // If it is still too long, truncate remaining bits with a shift.
  if (8 * digest_len > num_bits) {
    bn_rshift_words(out->d, out->d, 8 - (num_bits & 0x7), order->width);
  }

  // |out| now has the same bit width as |order|, but this only bounds by
  // 2*|order|. Subtract the order if out of range.
  //
  // Montgomery multiplication accepts the looser bounds, so this isn't strictly
  // necessary, but it is a cleaner abstraction and has no performance impact.
  BN_ULONG tmp[EC_MAX_WORDS];
  bn_reduce_once_in_place(out->d, 0 /* no carry */, order->d, tmp,
                          order->width);
}

static bool format_ecdsa_sig(uint8_t *out_sig, unsigned int *out_sig_len,
                             const ECDSA_SIG *sig, const EC_GROUP *group,
                             ECDSASigFormat fmt) {
  if (fmt == ASN1) {
    uint8_t *temp = NULL;
    size_t temp_len = 0;
    if (!ECDSA_SIG_to_bytes(&temp, &temp_len, sig)) {
      return false;
    }
    if (*out_sig_len < temp_len) {
      OPENSSL_free(temp);
      return false;
    }
    memcpy(out_sig, temp, temp_len);
    *out_sig_len = (unsigned int)temp_len;
    OPENSSL_free(temp);
    return true;
  }

  assert(fmt == Fixed);

  const BIGNUM *order = EC_GROUP_get0_order(group);
  size_t order_bits = BN_num_bits(order);
  size_t sig_len = 2 * (order_bits / 8);
  if (*out_sig_len < sig_len) {
    return false;
  }
  *out_sig_len = sig_len;
  if (!BN_bn2bin_padded(out_sig, sig_len / 2, sig->r) ||
      !BN_bn2bin_padded(out_sig + (sig_len / 2), sig_len / 2, sig->s)) {
    return false;
  }

  return true;
}

static bool ecdsa_sign(uint8_t *sig, unsigned int *sig_len, EC_KEY *key,
                       const uint8_t *digest, size_t digest_len,
                       ECDSASigFormat fmt, int i) {
  if (fmt == ASN1) {
    if (!ECDSA_sign(0, digest, digest_len, sig, sig_len, key)) {
      printf("failed\n");
      return false;
    }
  } else {
    assert(fmt == Fixed);
    bssl::UniquePtr<ECDSA_SIG> ecdsa_sig(
        ECDSA_do_sign(digest, digest_len, key));
    format_ecdsa_sig(sig, sig_len, ecdsa_sig.get(), EC_KEY_get0_group(key),
                     fmt);
  }
  return true;
}

static void print_hex(FILE *f, const uint8_t *data, size_t len) {
  for (size_t i = 0; i < len; i++) {
    fprintf(f, "%02x", data[i]);
  }
}

static void print_bn(const BIGNUM *b) {
  if (BN_is_zero(b)) {
    printf("00");
    return;
  }

  char *hex = BN_bn2hex(b);
  if (!hex) {
    abort();
  }
  printf("%s", hex);
  OPENSSL_free(hex);
}

static bool print_ecdsa_sig(const ECDSA_SIG *sig, const EC_GROUP *group,
                            ECDSASigFormat fmt) {
  uint8_t sig_bytes[1024];
  unsigned int sig_bytes_len = sizeof(sig_bytes);
  if (!format_ecdsa_sig(sig_bytes, &sig_bytes_len, sig, group, fmt)) {
    return false;
  }

  printf("Sig = ");
  print_hex(stdout, sig_bytes, sig_bytes_len);
  printf("\n");

  return true;
}

static bool GenerateTestsForRS(const EC_GROUP *group, const char *curve_name,
                               const BIGNUM *r, const BIGNUM *r_override,
                               const BIGNUM *s, ECDSASigFormat fmt, BN_CTX *ctx,
                               const char *result, const char *comment) {
  bssl::UniquePtr<EC_POINT> pub_key(EC_POINT_new(group));
  if (!pub_key ||
      !EC_POINT_set_compressed_coordinates_GFp(
          group, pub_key.get(), (r_override ? r_override : r), 0, NULL)) {
    return false;
  }

  bssl::UniquePtr<ECDSA_SIG> sig(ECDSA_SIG_new());
  if (!sig || !BN_nnmod(sig->r, r, EC_GROUP_get0_order(group), ctx)) {
    return false;
  }
  sig->s = BN_dup(s);
  if (!sig->s) {
    return false;
  }

  // Any message will do.
  uint8_t digest[EVP_MAX_MD_SIZE];

  size_t order_bits = BN_num_bits(EC_GROUP_get0_order(group));
  size_t digest_len;
  const char *digest_name;
  switch (order_bits) {
    case 384:
      digest_len = SHA384_DIGEST_LENGTH;
      digest_name = "SHA384";
      if (SHA384((const uint8_t *)"", 0, digest) == NULL) {
        return false;
      }
      break;

    case 256:
      digest_len = SHA256_DIGEST_LENGTH;
      digest_name = "SHA256";
      if (SHA256((const uint8_t *)"", 0, digest) == NULL) {
        return false;
      }
      break;
    default:
      assert(0);
      return false;
  }

  bssl::UniquePtr<BIGNUM> z_neg(BN_new());
  if (!z_neg) {
    return false;
  }
  digest_to_bn(z_neg.get(), digest, digest_len, EC_GROUP_get0_order(group));

  BN_set_negative(z_neg.get(), true);

  bssl::UniquePtr<EC_POINT> intermediate(EC_POINT_new(group));
  if (!intermediate || !EC_POINT_mul(group, intermediate.get(), z_neg.get(),
                                     pub_key.get(), sig->s, NULL)) {
    return false;
  }
  bssl::UniquePtr<BIGNUM> r_inv(BN_new());
  if (!r_inv ||
      BN_mod_inverse(r_inv.get(), r, EC_GROUP_get0_order(group), ctx) == NULL) {
    return false;
  }
  bssl::UniquePtr<EC_POINT> point(EC_POINT_new(group));
  if (!result || !EC_POINT_mul(group, point.get(), NULL, intermediate.get(),
                               r_inv.get(), NULL)) {
    return false;
  }
  uint8_t pub_key_encoded[1024];
  size_t pub_key_encoded_len =
      EC_POINT_point2oct(group, point.get(), POINT_CONVERSION_UNCOMPRESSED,
                         pub_key_encoded, sizeof(pub_key_encoded), NULL);
  if (pub_key_encoded_len == 0) {
    return false;
  }

  printf("\n");
  printf("%s\n", comment);
  printf("Curve = %s\n", curve_name);
  printf("Digest = %s\n", digest_name);
  printf("Msg = \"\"\n");
  printf("Q = ");
  print_hex(stdout, pub_key_encoded, pub_key_encoded_len);
  printf("\n");
  print_ecdsa_sig(sig.get(), group, fmt);
  printf("Result = %s\n", result);

  return true;
}

static bool GenerateMaxwellTestsForCurve(int nid, const char *curve_name,
                                         BN_ULONG r_word, BN_ULONG offset,
                                         ECDSASigFormat fmt, BN_CTX *ctx) {
  bssl::UniquePtr<EC_GROUP> group(EC_GROUP_new_by_curve_name(nid));
  bssl::UniquePtr<BIGNUM> r(BN_new());
  bssl::UniquePtr<BIGNUM> q(BN_new());
  bssl::UniquePtr<BIGNUM> q_minus_n(BN_new());
  bssl::UniquePtr<BIGNUM> q_minus_n_ish(BN_new());
  bssl::UniquePtr<BIGNUM> wrong_r(BN_new());
  bssl::UniquePtr<BIGNUM> s(BN_new());
  if (!group || !r || !q || !q_minus_n || !q_minus_n_ish || !wrong_r || !s ||
      !EC_GROUP_get_curve_GFp(group.get(), q.get(), nullptr, nullptr,
                              nullptr) ||
      !BN_sub(q_minus_n.get(), q.get(), EC_GROUP_get0_order(group.get())) ||
      !BN_copy(q_minus_n_ish.get(), q_minus_n.get()) ||
      !BN_add_word(q_minus_n_ish.get(), offset) ||
      !BN_mod_add(wrong_r.get(), q_minus_n_ish.get(),
                  EC_GROUP_get0_order(group.get()), q.get(), ctx) ||
      !BN_set_word(s.get(), 4)) {
    return false;
  }

  static const char kLessThanControlComment[] =
      "# The signature has r < q - n. This is the control case for the next\n"
      "# test case; this signature is the same but the public key is\n"
      "# different. Notice that both public keys work for the same signature!\n"
      "# This signature will validate even if the implementation doesn't\n"
      "# reduce the X coordinate of the multiplication result (mod n).";
  if (!BN_set_word(r.get(), r_word) ||
      !GenerateTestsForRS(group.get(), curve_name, r.get(), nullptr, s.get(),
                          fmt, ctx, "P (0 )", kLessThanControlComment)) {
    return false;
  }

  static const char kLessThanComment[] =
      "# The signature has r < q - n. s Since r < q - n, r + n < q. Notice\n"
      "# that this signature is the same as the signature in the preceding\n"
      "# test case, but the public key is different. That the signature\n"
      "# validates for this case too is what's special about the case where\n"
      "# r < q - n. If this test case fails it is likely that the\n"
      "# implementation doesn't reduce the X coordinate of the multiplication\n"
      "# result (mod n), or it is missing the second step of Gregory\n"
      "# Maxwell's trick.";
  if (!BN_add(r.get(), r.get(), EC_GROUP_get0_order(group.get())) ||
      !GenerateTestsForRS(group.get(), curve_name, r.get(), nullptr, s.get(),
                          fmt, ctx, "P (0 )", kLessThanComment)) {
    return false;
  }

  static const char kGreaterThanControlComment[] =
      "# The signature has r > q - n. The signature is for the public key\n"
      "# recovered from r. r + n > q since r > q - n. This is the control\n"
      "# for the next test case; this signature is the same as the signature\n"
      "# in the following test case but the public key is different.";
  if (!GenerateTestsForRS(group.get(), curve_name, q_minus_n_ish.get(), nullptr,
                          s.get(), fmt, ctx, "P (0 )",
                          kGreaterThanControlComment)) {
    return false;
  }

  static const char kGreaterThanComment[] =
      "# The signature has r > q - n. The signature is for the public key\n"
      "# recovered from r + n (mod q). r + n > q since r > q - n, and so\n"
      "# r + n (mod q) < r because r + n (mod n) != r + n (mod q). Notice\n"
      "# that this signature is the same as the signature in the preceding\n"
      "# test case but the public key is different. Also, notice that the\n"
      "# signature fails to validate in this case, unlike other related test\n"
      "# cases. If this test case fails (the signature validates), it is\n"
      "# likely that the implementation didn't guard the second case of\n"
      "# Gregory Maxwell's trick on the condition r < q - n.";
  if (!GenerateTestsForRS(group.get(), curve_name, q_minus_n_ish.get(),
                          wrong_r.get(), s.get(), fmt, ctx, "F",
                          kGreaterThanComment)) {
    return false;
  }

  return true;
}

static bool GenerateMaxwellTests(ECDSASigFormat fmt, BN_CTX *ctx) {
  printf(
      "# Test vectors for Gregory Maxwell's trick.\n"
      "#\n"
      "# In all cases, the `s` component of the signature was selected\n"
      "# arbitrarily as 4 and then the `r` component was chosen to be the\n"
      "# smallest value where the public key recovery from the signature\n"
      "# works.\n");

  // The numbers (6, 0) and (3, 2) were determined using the guess-and-check
  // method. Using smaller/different numbers causes the public key recovery
  // from the signature to fail.
  if (!GenerateMaxwellTestsForCurve(NID_X9_62_prime256v1, "P-256", 6, 0, fmt,
                                    ctx) ||
      !GenerateMaxwellTestsForCurve(NID_secp384r1, "P-384", 3, 2, fmt, ctx)) {
    return false;
  }
  return true;
}

static bool GenerateShortSTestsForCurve(int nid, const char *curve_name,
                                        ECDSASigFormat fmt, BN_CTX *ctx) {
  bssl::UniquePtr<EC_KEY> key(EC_KEY_new_by_curve_name(nid));
  if (!key || !EC_KEY_generate_key(key.get())) {
    return false;
  }
  const EC_GROUP *group = EC_KEY_get0_group(key.get());
  unsigned order_bits = BN_num_bits(EC_GROUP_get0_order(group));

  static const uint8_t MSG[1] = {};
  static const size_t MSG_LEN = 0;
  uint8_t digest[EVP_MAX_MD_SIZE];
  size_t digest_len;
  const char *digest_name;
  switch (order_bits) {
    case 256:
      SHA256(MSG, MSG_LEN, digest);
      digest_len = SHA256_DIGEST_LENGTH;
      digest_name = "SHA256";
      break;
    case 384:
      SHA384(MSG, MSG_LEN, digest);
      digest_len = SHA384_DIGEST_LENGTH;
      digest_name = "SHA384";
      break;
    default:
      abort();
  }

  uint8_t pub_key_encoded[1024];
  size_t pub_key_encoded_len = EC_POINT_point2oct(
      group, EC_KEY_get0_public_key(key.get()), POINT_CONVERSION_UNCOMPRESSED,
      pub_key_encoded, sizeof(pub_key_encoded), NULL);
  if (pub_key_encoded_len == 0) {
    return false;
  }

  uint8_t sig[1024];
  unsigned sig_len = 0;
  for (unsigned i = 0; i < 3; ++i) {
    if (!ecdsa_sign(sig, &sig_len, key.get(), digest, digest_len, fmt, i)) {
      return false;
    }

    printf("\n");
    if (i == 0) {
      printf("# S is the maximum length.\n");
    } else if (i == 1) {
      printf("# S is one byte shorter than the maximum length.\n");
    } else {
      printf("# S is %d bytes shorter than the maximum length.\n", (int)i);
    }
    printf("Curve = %s\n", curve_name);
    printf("Digest = %s\n", digest_name);
    printf("Msg = \"\"\n");
    printf("Q = ");
    print_hex(stdout, pub_key_encoded, pub_key_encoded_len);
    printf("\n");
    printf("Sig = ");
    print_hex(stdout, sig, sig_len);
    printf("\n");
    printf("Result = P (0 )\n");
  }

  return true;
}

static bool GenerateShortSTests(ECDSASigFormat fmt, BN_CTX *ctx) {
  if (!GenerateShortSTestsForCurve(NID_X9_62_prime256v1, "P-256", fmt, ctx) ||
      !GenerateShortSTestsForCurve(NID_secp384r1, "P-384", fmt, ctx)) {
    return false;
  }

  return true;
}

static bool GenerateECDSATestsForCurve(int nid, const char *curve_name,
                                       BN_ULONG r_word, ECDSASigFormat fmt,
                                       BN_CTX *ctx) {
  bssl::UniquePtr<EC_GROUP> group(EC_GROUP_new_by_curve_name(nid));
  bssl::UniquePtr<BIGNUM> r(BN_new());
  bssl::UniquePtr<BIGNUM> s(BN_new());
  if (!group || !r || !s) {
    return false;
  }
  if (!BN_set_word(r.get(), r_word)) {
    return false;
  }
  bssl::UniquePtr<BIGNUM> one(BN_new());
  if (!one || !BN_one(one.get())) {
    return false;
  }
  bssl::UniquePtr<BIGNUM> zero(BN_new());
  if (!zero) {
    return false;
  }
  BN_zero(zero.get());

  const BIGNUM *n = EC_GROUP_get0_order(group.get());
  bssl::UniquePtr<BIGNUM> n_minus_1(BN_new());
  if (!n_minus_1 || !BN_copy(n_minus_1.get(), n) ||
      !BN_sub_word(n_minus_1.get(), 1)) {
    return false;
  }

  if (!GenerateTestsForRS(group.get(), curve_name, r.get(), nullptr, zero.get(),
                          fmt, ctx, "F", "# s == 0 (out of range)") ||
      !GenerateTestsForRS(group.get(), curve_name, r.get(), nullptr, one.get(),
                          fmt, ctx, "P (0 )", "# s == 1 (minimum allowed)") ||
      !GenerateTestsForRS(group.get(), curve_name, r.get(), nullptr, n, fmt,
                          ctx, "F", "# s == n (out of range)") ||
      !GenerateTestsForRS(group.get(), curve_name, r.get(), nullptr,
                          n_minus_1.get(), fmt, ctx, "P (0 )",
                          "# s == n - 1 (maximum allowed)")) {
    return false;
  }
  return true;
}

static bool GenerateECDSATests(ECDSASigFormat fmt, BN_CTX *ctx) {
  if (!GenerateMaxwellTests(fmt, ctx)) {
    return false;
  }

  printf(
      "\n\n# Generated Test vectors edge cases of signature (r, s) values.\n");

  if (!GenerateECDSATestsForCurve(NID_X9_62_prime256v1, "P-256", 6, fmt, ctx) ||
      !GenerateECDSATestsForCurve(NID_secp384r1, "P-384", 3, fmt, ctx)) {
    return false;
  }

  return true;
}

static void GenerateECCPublicKeyTestEncoded(const char *curve_name,
                                            const uint8_t *pub_key_encoded,
                                            size_t pub_key_encoded_len,
                                            const char *result,
                                            const char *comment) {
  printf("\n");
  printf("%s\n", comment);
  printf("Curve = %s\n", curve_name);
  printf("Q = ");
  print_hex(stdout, pub_key_encoded, pub_key_encoded_len);
  printf("\n");
  printf("Result = %s\n", result);
}

static int EC_POINT_make_affine(const EC_GROUP *group, EC_POINT *point,
                                BN_CTX *ctx) {
  bssl::UniquePtr<BIGNUM> x(BN_new());
  bssl::UniquePtr<BIGNUM> y(BN_new());

  if (!EC_POINT_get_affine_coordinates(group, point, x.get(), y.get(), ctx)) {
    return false;
  }

  return EC_POINT_set_affine_coordinates(group, point, x.get(), y.get(), ctx);
}

static bool GenerateECCPublicKeyTest(const char *curve_name,
                                     const EC_GROUP *group,
                                     const EC_POINT *point, const char *result,
                                     const char *comment) {
  uint8_t pub_key_encoded[1024];
  size_t pub_key_encoded_len =
      EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED,
                         pub_key_encoded, sizeof(pub_key_encoded), NULL);
  if (pub_key_encoded_len == 0) {
    return false;
  }

  GenerateECCPublicKeyTestEncoded(curve_name, pub_key_encoded,
                                  pub_key_encoded_len, result, comment);

  return true;
}

static bool GenerateECCPublicKeyTestWithAffineDecodedCoordinates(
    const char *curve_name, const EC_GROUP *group, const BIGNUM *x,
    const BIGNUM *y, const char *result, const char *comment) {
  unsigned coord_len = (EC_GROUP_get_degree(group) + 7) / 8;

  uint8_t pub_key_encoded[1024];
  size_t pub_key_encoded_len = 1 + (2 * coord_len);
  assert(pub_key_encoded_len <= sizeof(pub_key_encoded));

  pub_key_encoded[0] = 0x04;  // Uncompressed
  if (!BN_bn2bin_padded(&pub_key_encoded[1], coord_len, x) ||
      !BN_bn2bin_padded(&pub_key_encoded[1 + coord_len], coord_len, y)) {
    return false;
  }

  GenerateECCPublicKeyTestEncoded(curve_name, pub_key_encoded,
                                  pub_key_encoded_len, result, comment);

  return true;
}

static bool GenerateECCPublicKeyTestsForCurve(int nid, const char *curve_name,
                                              BN_CTX *ctx) {
  bssl::UniquePtr<EC_GROUP> group(EC_GROUP_new_by_curve_name(nid));
  bssl::UniquePtr<BIGNUM> q(BN_new());
  if (!group || !q ||
      !EC_GROUP_get_curve_GFp(group.get(), q.get(), NULL, NULL, NULL)) {
    return false;
  }

  bssl::UniquePtr<EC_POINT> point(EC_POINT_new(group.get()));
  if (!point) {
    return false;
  }

  bssl::UniquePtr<BIGNUM> zero(BN_new());
  if (!zero) {
    return false;
  }
  BN_zero(zero.get());
  bssl::UniquePtr<BIGNUM> y(BN_new());
  if (!y) {
    return false;
  }

  static const char kXEquals0Comment[] =
      "# X == 0, decompressed with y_bit == 0. This verifies that the\n"
      "# implementation doesn't reject zero-valued field elements (they\n"
      "# aren't scalars).";

  if (!EC_POINT_set_compressed_coordinates_GFp(group.get(), point.get(),
                                               zero.get(), 0, ctx) ||
      !GenerateECCPublicKeyTest(curve_name, group.get(), point.get(), "P",
                                kXEquals0Comment)) {
    return false;
  }

  static const char kXEqualsQComment[] =
      "# X == q. This is invalid because q isn't a valid field element. Some\n"
      "# broken implementations might accept this if they reduce X mod q\n"
      "# since q mod q == 0 and the Y coordinate matches the one from the\n"
      "# x == 0 test case above.";
  if (!EC_POINT_get_affine_coordinates_GFp(group.get(), point.get(), NULL,
                                           y.get(), ctx) ||
      !GenerateECCPublicKeyTestWithAffineDecodedCoordinates(
          curve_name, group.get(), q.get(), y.get(), "F (X is out of range)",
          kXEqualsQComment)) {
    return false;
  }

  if (!EC_POINT_set_compressed_coordinates_GFp(group.get(), point.get(),
                                               zero.get(), 1, ctx) ||
      !GenerateECCPublicKeyTest(curve_name, group.get(), point.get(), "P",
                                "# X == 0, decompressed with y_bit == 1.")) {
    return false;
  }

  static const char kXEqualsCYBit1Comment[] =
      "# X == q, decompressed with y_bit == 1. See the previous X == q test\n"
      "# case.";
  if (!EC_POINT_get_affine_coordinates_GFp(group.get(), point.get(), NULL,
                                           y.get(), ctx) ||
      !GenerateECCPublicKeyTestWithAffineDecodedCoordinates(
          curve_name, group.get(), q.get(), y.get(), "F (X is out of range)",
          kXEqualsCYBit1Comment)) {
    return false;
  }

  // Find the largest valid x coordinate for the curve.
  // XXX: Assumes EC_POINT_set_compressed_coordinates_GFp won't fail for any
  // reason other than the X value not resulting in X**3 + a*x + b being a
  // perfect square.
  bssl::UniquePtr<BIGNUM> largest_x(BN_new());
  if (!BN_copy(largest_x.get(), q.get())) {
    return false;
  }
  do {
    if (!BN_sub_word(largest_x.get(), 1)) {
      return false;
    }
  } while (!EC_POINT_set_compressed_coordinates_GFp(group.get(), point.get(),
                                                    largest_x.get(), 0, ctx));

  static const char kLargestValidXCoordinateComment[] =
      "# The largest valid X coordinate, decompressed with y_bit == 0. This\n"
      "# helps ensure that the upper bound on coordinate values is not too\n"
      "# low.";
  if (!GenerateECCPublicKeyTest(curve_name, group.get(), point.get(), "P",
                                kLargestValidXCoordinateComment)) {
    return false;
  }

  return true;
}

static bool GenerateECCPublicKeyTests(BN_CTX *ctx) {
  printf(
      "# Test vectors for Public Key Point Validation.\n"
      "#\n"
      "# These test vectors were generated by applying the patch in\n"
      "# util/generate-tests.patch to BoringSSL, and then running\n"
      "# `bssl generate-tests ecc-public-key`.\n"
      "#\n");

  if (!GenerateECCPublicKeyTestsForCurve(NID_X9_62_prime256v1, "P-256", ctx) ||
      !GenerateECCPublicKeyTestsForCurve(NID_secp384r1, "P-384", ctx)) {
    return false;
  }

  return true;
}

struct InterestingPoints {
  InterestingPoints(bool *valid, int nid, const char *curve_name, BN_CTX *ctx) {
    *valid = false;
    group.reset(EC_GROUP_new_by_curve_name(nid));
    if (!group) {
      return;
    }

    g_inv.reset(EC_POINT_dup(g(), group.get()));
    if (!g_inv || !EC_POINT_invert(group.get(), g_inv.get(), ctx)) {
      return;
    }

    inf.reset(EC_POINT_new(group.get()));
    if (!inf || !EC_POINT_set_to_infinity(group.get(), inf.get())) {
      return;
    }
    inf_n_g.reset(EC_POINT_new(group.get()));
    if (!inf_n_g ||
        !EC_POINT_mul(group.get(), inf_n_g.get(),
                      EC_GROUP_get0_order(group.get()), NULL, NULL, ctx)) {
      return;
    }
    bssl::UniquePtr<BIGNUM> nm1(BN_dup(EC_GROUP_get0_order(group.get())));
    nm1_g.reset(EC_POINT_new(group.get()));
    if (!nm1 || !BN_sub_word(nm1.get(), 1) || !nm1_g ||
        !EC_POINT_mul(group.get(), nm1_g.get(), nm1.get(), NULL, NULL, ctx)) {
      return;
    }
    nm1_g_aff.reset(EC_POINT_dup(nm1_g.get(), group.get()));
    if (!nm1_g_aff ||
        !EC_POINT_make_affine(group.get(), nm1_g_aff.get(), ctx)) {
      return;
    }

    nm1_g_inv.reset(EC_POINT_dup(nm1_g.get(), group.get()));
    if (!nm1_g_inv || !EC_POINT_invert(group.get(), nm1_g_inv.get(), ctx)) {
      return;
    }
    nm1_g_inv_aff.reset(EC_POINT_dup(nm1_g_inv.get(), group.get()));
    if (!nm1_g_inv_aff ||
        !EC_POINT_make_affine(group.get(), nm1_g_inv_aff.get(), ctx)) {
      return;
    }

    // XXX: How does BoringSSL deal with failure to allocate within
    // std::string?
    this->name = curve_name;

    *valid = true;
  }

  const EC_POINT *g() const { return EC_GROUP_get0_generator(group.get()); }

  bssl::UniquePtr<EC_GROUP> group;
  std::string name;
  bssl::UniquePtr<EC_POINT> inf;
  bssl::UniquePtr<EC_POINT> g_inv;          // -G
  bssl::UniquePtr<EC_POINT> nm1_g;          // (n - 1) * G
  bssl::UniquePtr<EC_POINT> nm1_g_aff;      // (n - 1) * G (affine)
  bssl::UniquePtr<EC_POINT> nm1_g_inv;      // inverse of (n - 1) * G
  bssl::UniquePtr<EC_POINT> nm1_g_inv_aff;  // inverse of (n - 1) * G (affine)
  bssl::UniquePtr<EC_POINT> inf_n_g;        // n * (affine) G
};

static bool print_point(const EC_GROUP *group, const char *name,
                        const EC_POINT *p, Affinification aff, BN_CTX *ctx) {
  uint8_t buf[1024];
  uint8_t num_bytes = (EC_GROUP_get_degree(group) + 7) / 8;
  assert((unsigned long)num_bytes <= sizeof(buf));

  bssl::UniquePtr<EC_POINT> p_aff;
  bssl::UniquePtr<BIGNUM> t(BN_new());
  bool is_infinity = EC_POINT_is_at_infinity(group, p);
  if (aff != Unchanged && !is_infinity) {
    p_aff.reset(EC_POINT_dup(p, group));
    if (!p_aff || !EC_POINT_make_affine(group, p_aff.get(), ctx)) {
      return false;
    }
    p = p_aff.get();
  }

  printf("%s = ", name);
  if (is_infinity && aff == MakeAffineToken) {
    printf("inf");
  } else if (is_infinity && aff == MakeAffineAllZero) {
    BIGNUM zero;
    BN_init(&zero);
    BN_zero(&zero);
    if (!BN_bn2bin_padded(buf, num_bytes, &zero)) {
      return false;
    }
    print_hex(stdout, buf, num_bytes);
    printf(", ");
    print_hex(stdout, buf, num_bytes);
  } else {
    size_t bytes_out = 1024;
    ec_GFp_simple_felem_to_bytes(group, buf, &bytes_out, &p->raw.X);
    print_hex(stdout, buf, num_bytes);
    printf(", ");

    bytes_out = 1024;
    ec_GFp_simple_felem_to_bytes(group, buf, &bytes_out, &p->raw.Y);
    print_hex(stdout, buf, num_bytes);
  }
  if (aff == Unchanged) {
    size_t bytes_out = 1024;
    ec_GFp_simple_felem_to_bytes(group, buf, &bytes_out, &p->raw.Z);
    printf(", ");
    print_hex(stdout, buf, num_bytes);
  }
  printf("\n");
  return true;
}

static bool GenerateECCPointDoubleTest(const InterestingPoints &points,
                                       size_t n, const EC_POINT *a, BN_CTX *ctx,
                                       const char *comment) {
  const EC_GROUP *group = points.group.get();
  bssl::UniquePtr<EC_POINT> r(EC_POINT_dup(a, group));
  if (!r) {
    return false;
  }
  for (size_t i = 0; i < n; ++i) {
    if (!EC_POINT_dbl(group, r.get(), r.get(), ctx)) {
      return false;
    }

    if (!EC_POINT_make_affine(group, r.get(), ctx)) {
      if (ERR_GET_REASON(ERR_peek_error()) != EC_R_POINT_AT_INFINITY) {
        return false;
      }
      ERR_get_error();
    }
  }
  printf("\n");
  printf("%s\n", comment);
  if (!print_point(group, "a", a, Unchanged, ctx) ||
      !print_point(group, "r", r.get(), MakeAffineToken, ctx)) {
    return false;
  }

  return true;
}

static bool GenerateECCPointDoubleTestsForCurve(InterestingPoints &points,
                                                BN_CTX *ctx) {
  static const char kZeroComment[] =
      "# Point at infinity doubled. This uses the (0, 0, 0) representation of\n"
      "# the point at infinity instead of the classic (1, 1, 0)\n"
      "# representation.";
  static const char kNGComment[] =
      "# Point at infinity doubled. This form is the result of multiplying\n"
      "# n * G (affine), which is more interesting than the above case\n"
      "# because only the Z coordinate is zero.";
  if (!GenerateECCPointDoubleTest(points, 1, points.g(), ctx,
                                  "# G doubled once.") ||
      !GenerateECCPointDoubleTest(points, 1, points.inf.get(), ctx,
                                  kZeroComment) ||
      !GenerateECCPointDoubleTest(points, 1, points.inf_n_g.get(), ctx,
                                  kNGComment) ||
      !GenerateECCPointDoubleTest(points, 1, points.nm1_g.get(), ctx,
                                  "# (n - 1) * G doubled.")) {
  }

  return true;
}


static bool GenerateECCPointAddTest(InterestingPoints &points,
                                    const EC_POINT *a, const EC_POINT *b,
                                    Affinification b_make_aff, BN_CTX *ctx,
                                    const char *comment) {
  if (b_make_aff != Unchanged) {
    assert(b_make_aff != MakeAffineToken);
    // We never try affine addition when b is the point at infinity since we'd
    // never have an affine point that can't be represented in affine
    // coordinates, so just skip these.
    if (EC_POINT_is_at_infinity(points.group.get(), b)) {
      assert(b_make_aff == MakeAffineAllZero);
    }
  }

  const EC_GROUP *group = points.group.get();
  bssl::UniquePtr<EC_POINT> r(EC_POINT_new(group));
  if (!r) {
    return false;
  }
  if (!EC_POINT_add(group, r.get(), a, b, ctx)) {
    return false;
  }

  printf("\n");
  printf("%s\n", comment);
  if (!print_point(group, "a", a, Unchanged, ctx) ||
      !print_point(group, "b", b, b_make_aff, ctx) ||
      !print_point(group, "r", r.get(), MakeAffineToken, ctx)) {
    return false;
  }

  return true;
}

static bool GenerateECCPointAddTestsForCurve(InterestingPoints &points,
                                             Affinification b_aff,
                                             BN_CTX *ctx) {
  if (!GenerateECCPointAddTest(points, points.inf.get(), points.inf.get(),
                               b_aff, ctx, "# inf + inf == 2 * inf == inf") ||
      !GenerateECCPointAddTest(points, points.inf_n_g.get(),
                               points.inf_n_g.get(), b_aff, ctx,
                               "# inf (n*G) + inf (n*G) == 2 * inf == inf") ||
      !GenerateECCPointAddTest(points, points.inf_n_g.get(), points.inf.get(),
                               b_aff, ctx,
                               "# inf (n*G) + inf == 2 * inf == inf") ||
      !GenerateECCPointAddTest(points, points.inf.get(), points.inf_n_g.get(),
                               b_aff, ctx,
                               "# inf + inf (n*G) == 2 * inf == inf") ||
      !GenerateECCPointAddTest(points, points.g(), points.inf.get(), b_aff, ctx,
                               "# G + inf == G") ||
      !GenerateECCPointAddTest(points, points.g(), points.inf_n_g.get(), b_aff,
                               ctx, "# G + inf (n*G) == G") ||
      !GenerateECCPointAddTest(points, points.inf.get(), points.g(), b_aff, ctx,
                               "# inf + G == G") ||
      !GenerateECCPointAddTest(points, points.inf_n_g.get(), points.g(), b_aff,
                               ctx, "# inf (n*G) + G == G")) {
    return false;
  }

  if (b_aff == Affinification::Unchanged) {
    if (!GenerateECCPointAddTest(points, points.g(), points.g(), b_aff, ctx,
                                 "# G + G == 2*G") ||
        !GenerateECCPointAddTest(
            points, points.nm1_g.get(), points.g(), b_aff, ctx,
            "# (n-1)*G + G == inf; note that -G is (n-1)*G")) {
      return false;
    }
  }

  if (!GenerateECCPointAddTest(
          points, points.g(), points.nm1_g.get(), b_aff, ctx,
          "# G + (n-1)*G == inf; note that -G is (n-1)*G")) {
    return false;
  }

  if (b_aff == Affinification::Unchanged) {
    if (!GenerateECCPointAddTest(points, points.nm1_g.get(), points.nm1_g.get(),
                                 b_aff, ctx,
                                 "# (n-1)*G + (n-1)*G == 2*(n-1)*G") ||
        !GenerateECCPointAddTest(points, points.nm1_g_aff.get(),
                                 points.nm1_g.get(), b_aff, ctx,
                                 "# (n-1)*G + (n-1)*G (affine) == 2*(n-1)*G")) {
      return false;
    }
  }

  if (!GenerateECCPointAddTest(points, points.nm1_g.get(),
                               points.nm1_g_inv.get(), b_aff, ctx,
                               "# (n-1)*G + -(n-1)*G == inf") ||
      !GenerateECCPointAddTest(points, points.nm1_g_inv.get(),
                               points.nm1_g.get(), b_aff, ctx,
                               "# -(n-1)*G + (n-1)*G == inf") ||
      !GenerateECCPointAddTest(points, points.nm1_g_inv.get(),
                               points.nm1_g.get(), b_aff, ctx,
                               "# -(n-1)*G (affine) + (n-1)*G == inf") ||
      !GenerateECCPointAddTest(
          points, points.nm1_g_inv.get(), points.g_inv.get(), b_aff, ctx,
          "# -(n-1)*G + -G == inf; note that -G is (n-1)*G (affine)") ||
      !GenerateECCPointAddTest(
          points, points.g_inv.get(), points.nm1_g_inv.get(), b_aff, ctx,
          "# -G + -(n-1)*G == inf; note that -G is (n-1)*G (affine)")) {
    return false;
  }

  if (b_aff == Affinification::Unchanged) {
    if (!GenerateECCPointAddTest(
            points, points.nm1_g.get(), points.g_inv.get(), b_aff, ctx,
            "# (n-1)*G + -G; == -2*G; note that -G == (n-1)*G (affine)") ||
        !GenerateECCPointAddTest(
            points, points.g_inv.get(), points.nm1_g.get(), b_aff, ctx,
            "# -G + (n-1)*G == -2*G; note that -G is (n-1)*G (affine)") ||
        !GenerateECCPointAddTest(
            points, points.nm1_g.get(), points.g_inv.get(), b_aff, ctx,
            "# (n-1)*G + -G == -2*G; note that -G is (n-1)*G (affine)") ||
        !GenerateECCPointAddTest(
            points, points.g_inv.get(), points.nm1_g.get(), b_aff, ctx,
            "# -G + (n-1)*G == -2*G; note that -G = (n-1)*G")) {
      return false;
    }
  }

  if (!GenerateECCPointAddTest(
          points, points.g_inv.get(), points.g(), b_aff, ctx,
          "# -G + G == inf; note that -G is (n-1)*G (affine)") ||
      !GenerateECCPointAddTest(
          points, points.g(), points.g_inv.get(), b_aff, ctx,
          "# G + -G == inf; note that -G is (n-1)*G (affine)")) {
    return false;
  }

  return true;
}

static bool GeneratePointMulTest(const InterestingPoints &points,
                                 const BIGNUM *g_scalar, const BIGNUM *p_scalar,
                                 const EC_POINT *p, BN_CTX *ctx) {
  bssl::UniquePtr<EC_POINT> result(EC_POINT_new(points.group.get()));
  if (!result || !EC_POINT_mul(points.group.get(), result.get(), g_scalar, p,
                               p_scalar, ctx)) {
    return false;
  }

  if (g_scalar != NULL) {
    printf("g_scalar = ");
    print_bn(g_scalar);
    printf("\n");
  }
  if (p_scalar != NULL) {
    printf("p_scalar = ");
    print_bn(p_scalar);
    printf("\n");
    if (!print_point(points.group.get(), "p", p, MakeAffineToken, ctx)) {
      return false;
    }
  }
  if (EC_POINT_is_at_infinity(points.group.get(), result.get())) {
    printf("r = inf\n");
  } else {
    if (!print_point(points.group.get(), "r", result.get(), MakeAffineToken,
                     ctx)) {
      return false;
    }
  }

  return true;
}


static bool GeneratePointMulTwinTests(const InterestingPoints &points,
                                      bool generator, bool do_p, BN_CTX *ctx) {
  const int SHIFT = 5;
  const BN_ULONG N = (1 << SHIFT);
  const size_t NUM_SCALARS = (N + 1) + (N - 1) + N;
  bssl::UniquePtr<BIGNUM> scalars[NUM_SCALARS];
  size_t START_SMALL_HIGH = N + 1;
  size_t START_BIG = START_SMALL_HIGH + (N - 1);

  int order_bits = EC_GROUP_get_degree(points.group.get());

  {
    size_t i;
    const BIGNUM *n = EC_GROUP_get0_order(points.group.get());
    for (i = 0; i <= N; ++i) {
      scalars[i].reset(BN_new());
      if (!scalars[i] || !BN_set_word(scalars[i].get(), i)) {
        return false;
      }

      if (i != 0 && i != N) {
        scalars[START_SMALL_HIGH + i - 1].reset(BN_new());
        BIGNUM *small_high = scalars[START_SMALL_HIGH + i - 1].get();
        if (!small_high ||
            !BN_lshift(small_high, scalars[i].get(), order_bits - SHIFT)) {
          return false;
        }
      }

      if (i != N) {
        scalars[START_BIG + i].reset(BN_dup(n));
        if (!scalars[START_BIG + i] ||
            !BN_sub_word(scalars[START_BIG + i].get(), N - i)) {
          return false;
        }
      }
    }
  }

  bssl::UniquePtr<EC_POINT> p;
  if (do_p) {
    bssl::UniquePtr<BIGNUM> n_half(BN_new());
    if (!n_half ||
        !BN_rshift1(n_half.get(), EC_GROUP_get0_order(points.group.get()))) {
      return false;
    }
    p.reset(EC_POINT_new(points.group.get()));
    if (!p || !EC_POINT_mul(points.group.get(), p.get(), n_half.get(), NULL,
                            NULL, ctx)) {
      return false;
    }
  }

  for (size_t i = 0; i < NUM_SCALARS; ++i) {
    for (size_t j = 0; j < 3; ++j) {
      printf("\n");
      if (j >= START_BIG) {
        printf("# p_scalar = n - %d\n", (int)(N - (j - START_BIG)));
      }
      if (!GeneratePointMulTest(points, generator ? scalars[i].get() : NULL,
                                scalars[j].get(), p.get(), ctx)) {
        return false;
      }
    }
  }

  for (size_t i = 0; i < 3; ++i) {
    for (size_t j = 3; j < NUM_SCALARS; ++j) {
      printf("\n");
      if (j >= START_BIG) {
        printf("# p_scalar = n - %d\n", (int)(N - (j - START_BIG)));
      }
      if (!GeneratePointMulTest(points, generator ? scalars[i].get() : NULL,
                                scalars[j].get(), p.get(), ctx)) {
        return false;
      }
    }
  }

  return true;
}

static bool GenerateSumTest(const InterestingPoints &points,
                            const bssl::UniquePtr<BIGNUM> &a,
                            const bssl::UniquePtr<BIGNUM> &b,
                            const bssl::UniquePtr<BIGNUM> *r,
                            const bssl::UniquePtr<BIGNUM> &m,
                            const bssl::UniquePtr<BIGNUM> &p) {
  bssl::UniquePtr<BIGNUM> actualR(BN_new());
  if (!actualR || !BN_add(actualR.get(), a.get(), b.get())) {
    return false;
  }

  if (BN_cmp(actualR.get(), m.get()) >= 0) {
    if (!BN_sub(actualR.get(), actualR.get(), p.get())) {
      return false;
    }
  }

  if (BN_cmp(actualR.get(), m.get()) >= 0 ||
      (r && BN_cmp(r->get(), actualR.get()) != 0)) {
    printf("a: ");
    print_bn(a.get());
    printf("\n");
    printf("b: ");
    print_bn(b.get());
    printf("\n");
    printf("actual R: ");
    print_bn(actualR.get());
    printf("\n");
    printf("given R: ");
    print_bn(r->get());
    printf("\n");
    ;
    return false;
  }

  printf("\n");
  printf("a = ");
  print_bn(a.get());
  printf("\n");
  printf("b = ");
  print_bn(b.get());
  printf("\n");
  printf("r = ");
  print_bn(actualR.get());
  printf("\n");

  return 1;
}

static bool GenerateElemSumTests(const InterestingPoints &points, BN_CTX *ctx) {
  bssl::UniquePtr<BIGNUM> q(BN_new());
  bssl::UniquePtr<BIGNUM> zero(BN_new());
  bssl::UniquePtr<BIGNUM> one(BN_dup(BN_value_one()));
  bssl::UniquePtr<BIGNUM> two(BN_new());
  bssl::UniquePtr<BIGNUM> three(BN_new());
  bssl::UniquePtr<BIGNUM> p_div_2(BN_new());
  bssl::UniquePtr<BIGNUM> p_div_2_plus_1(BN_new());
  bssl::UniquePtr<BIGNUM> highest_bit_set(BN_new());
  bssl::UniquePtr<BIGNUM> max(BN_new());
  bssl::UniquePtr<BIGNUM> two_to_the_b(BN_new());
  bssl::UniquePtr<BIGNUM> two_to_the_b_minus_1(BN_new());
  bssl::UniquePtr<BIGNUM> q_plus_1(BN_new());
  bssl::UniquePtr<BIGNUM> q_plus_2(BN_new());
  bssl::UniquePtr<BIGNUM> tmp1(BN_new());
  bssl::UniquePtr<BIGNUM> tmp2(BN_new());
  if (!q ||
      !EC_GROUP_get_curve_GFp(points.group.get(), q.get(), NULL, NULL, ctx) ||
      !zero || !one || !BN_set_word(one.get(), 1) || !two ||
      !BN_set_word(two.get(), 2) || !three || !BN_set_word(three.get(), 3) ||
      !p_div_2 || !BN_div(p_div_2.get(), NULL, q.get(), two.get(), ctx) ||
      !p_div_2_plus_1 ||
      !BN_add(p_div_2_plus_1.get(), p_div_2.get(), BN_value_one()) ||
      !highest_bit_set ||
      !BN_lshift(highest_bit_set.get(), BN_value_one(),
                 BN_num_bits(q.get()) - 1) ||
      !max || !BN_sub(max.get(), q.get(), BN_value_one()) || !two_to_the_b ||
      !BN_lshift(two_to_the_b.get(), BN_value_one(), BN_num_bits(q.get())) ||
      !two_to_the_b_minus_1 ||
      !BN_sub(two_to_the_b_minus_1.get(), two_to_the_b.get(), BN_value_one()) ||
      !q_plus_1 || !BN_add(q_plus_1.get(), q.get(), one.get()) || !q_plus_1 ||
      !BN_add(q_plus_2.get(), q.get(), two.get()) || !tmp1 || !tmp2) {
    return false;
  }
  BN_zero(zero.get());

  const bssl::UniquePtr<BIGNUM> &m = q;

  printf("# Montgomery Arithmetic; values are in the range [0, q).\n");

  if (!GenerateSumTest(points, zero, zero, &zero, m, q) ||
      !GenerateSumTest(points, zero, one, &one, m, q) ||
      !GenerateSumTest(points, zero, max, &max, m, q) ||
      !GenerateSumTest(points, one, max, &zero, m, q) ||
      !GenerateSumTest(points, two, max, &one, m, q) ||
      !GenerateSumTest(points, three, max, &two, m, q) ||
      !GenerateSumTest(points, p_div_2, p_div_2_plus_1, &zero, m, q) ||
      !GenerateSumTest(points, p_div_2_plus_1, p_div_2_plus_1, &one, m, q) ||
      !GenerateSumTest(points, highest_bit_set, highest_bit_set, NULL, m, q)) {
    return false;
  }

  if (!BN_mod(tmp1.get(), two_to_the_b.get(), m.get(), ctx) ||
      !BN_sub(tmp2.get(), two_to_the_b.get(), highest_bit_set.get()) ||
      !GenerateSumTest(points, tmp2, highest_bit_set, &tmp1, m, q)) {
    return false;
  }

  if (!BN_mod(tmp1.get(), two_to_the_b.get(), m.get(), ctx) ||
      !BN_sub(tmp2.get(), two_to_the_b.get(), p_div_2.get()) ||
      !GenerateSumTest(points, tmp2, p_div_2, &tmp1, m, q)) {
    return false;
  }

  if (!BN_mod(tmp1.get(), two_to_the_b_minus_1.get(), m.get(), ctx) ||
      !BN_sub(tmp2.get(), two_to_the_b_minus_1.get(), highest_bit_set.get()) ||
      !GenerateSumTest(points, tmp2, highest_bit_set, &tmp1, m, q)) {
    return false;
  }

  if (!BN_mod(tmp1.get(), two_to_the_b_minus_1.get(), m.get(), ctx) ||
      !BN_sub(tmp2.get(), two_to_the_b_minus_1.get(), p_div_2.get()) ||
      !GenerateSumTest(points, tmp2, p_div_2, &tmp1, m, q)) {
    return false;
  }


  printf("\n# Carry Propagation.\n");

  {
    bssl::UniquePtr<BIGNUM> a(BN_new());
    if (!a || !BN_set_word(a.get(), 0xff)) {
      return false;
    }
    while (BN_cmp(a.get(), q.get()) < 0) {
      if (!GenerateSumTest(points, a, one, NULL, m, q)) {
        return false;
      }

      if (!BN_mul_word(a.get(), 2) || !BN_add_word(a.get(), 0x1)) {
        return false;
      }
    }
  }

  return true;
}

static bool GenerateMulTest(const bssl::UniquePtr<BIGNUM> &a,
                            const bssl::UniquePtr<BIGNUM> &b,
                            const bssl::UniquePtr<BIGNUM> *r, const BIGNUM *m,
                            const bssl::UniquePtr<BN_MONT_CTX> &mont,
                            BN_CTX *ctx) {
  bssl::UniquePtr<BIGNUM> actualR(BN_new());
  if (!actualR || !BN_mod_mul_montgomery(actualR.get(), a.get(), b.get(),
                                         mont.get(), ctx)) {
    return false;
  }

  if (r && BN_cmp(r->get(), actualR.get()) != 0) {
    printf("a: ");
    print_bn(a.get());
    printf("\n");
    printf("b: ");
    print_bn(b.get());
    printf("\n");
    printf("actual R: ");
    print_bn(actualR.get());
    printf("\n");
    printf("given R: ");
    print_bn(r->get());
    printf("\n");
    ;
    return false;
  }

  printf("\n");
  printf("a = ");
  print_bn(a.get());
  printf("\n");
  printf("b = ");
  print_bn(b.get());
  printf("\n");
  printf("r = ");
  print_bn(actualR.get());
  printf("\n");

  return 1;
}

static bool GenerateModMulTests(const BIGNUM *p, BN_CTX *ctx) {
  bssl::UniquePtr<BN_MONT_CTX> mont(BN_MONT_CTX_new());
  bssl::UniquePtr<BIGNUM> zero(BN_new());
  bssl::UniquePtr<BIGNUM> one(BN_dup(BN_value_one()));
  bssl::UniquePtr<BIGNUM> two(BN_new());
  bssl::UniquePtr<BIGNUM> three(BN_new());
  bssl::UniquePtr<BIGNUM> p_div_2(BN_new());
  bssl::UniquePtr<BIGNUM> p_div_2_plus_1(BN_new());
  bssl::UniquePtr<BIGNUM> p_minus_1(BN_new());
  bssl::UniquePtr<BIGNUM> highest_bit_set(BN_new());
  bssl::UniquePtr<BIGNUM> max(BN_new());
  bssl::UniquePtr<BIGNUM> two_to_the_b(BN_new());
  bssl::UniquePtr<BIGNUM> two_to_the_b_minus_1(BN_new());
  bssl::UniquePtr<BIGNUM> tmp1(BN_new());
  bssl::UniquePtr<BIGNUM> tmp2(BN_new());
  if (!mont || !BN_MONT_CTX_set(mont.get(), p, ctx) || !zero || !one ||
      !BN_set_word(one.get(), 1) || !two || !BN_set_word(two.get(), 2) ||
      !three || !BN_set_word(three.get(), 3) || !p_div_2 ||
      !BN_div(p_div_2.get(), NULL, p, two.get(), ctx) || !p_div_2_plus_1 ||
      !BN_add(p_div_2_plus_1.get(), p_div_2.get(), BN_value_one()) ||
      !highest_bit_set ||
      !BN_lshift(highest_bit_set.get(), BN_value_one(), BN_num_bits(p) - 1) ||
      !max || !BN_sub(max.get(), p, BN_value_one()) || !two_to_the_b ||
      !BN_lshift(two_to_the_b.get(), BN_value_one(), BN_num_bits(p)) ||
      !two_to_the_b_minus_1 ||
      !BN_sub(two_to_the_b_minus_1.get(), two_to_the_b.get(), BN_value_one()) ||
      !tmp1 || !tmp2) {
    return false;
  }
  BN_zero(zero.get());

  const BIGNUM *m = p;

  if (!GenerateMulTest(zero, zero, NULL, m, mont, ctx) ||
      !GenerateMulTest(zero, max, NULL, m, mont, ctx) ||
      !GenerateMulTest(one, max, NULL, m, mont, ctx) ||
      !GenerateMulTest(two, max, NULL, m, mont, ctx) ||
      !GenerateMulTest(three, max, NULL, m, mont, ctx) ||
      !GenerateMulTest(p_div_2, two, NULL, m, mont, ctx) ||
      !GenerateMulTest(p_div_2_plus_1, two, NULL, m, mont, ctx) ||
      !GenerateMulTest(highest_bit_set, two, NULL, m, mont, ctx)) {
    return false;
  }

  // TODO:  printf("\n# Carry Propagation.\n");

  return true;
}

static bool GenerateSquareTest(const bssl::UniquePtr<BIGNUM> &a,
                               const bssl::UniquePtr<BIGNUM> *r,
                               const BIGNUM *m,
                               const bssl::UniquePtr<BN_MONT_CTX> &mont,
                               BN_CTX *ctx) {
  bssl::UniquePtr<BIGNUM> actualR(BN_new());
  if (!actualR || !BN_mod_mul_montgomery(actualR.get(), a.get(), a.get(),
                                         mont.get(), ctx)) {
    return false;
  }

  if (r && BN_cmp(r->get(), actualR.get()) != 0) {
    printf("a: ");
    print_bn(a.get());
    printf("\n");
    printf("actual R: ");
    print_bn(actualR.get());
    printf("\n");
    printf("given R: ");
    print_bn(r->get());
    printf("\n");
    ;
    return false;
  }

  printf("\n");
  printf("a = ");
  print_bn(a.get());
  printf("\n");
  printf("r = ");
  print_bn(actualR.get());
  printf("\n");

  return 1;
}

static bool GenerateModSquareTests(const BIGNUM *p, BN_CTX *ctx,
                                   const char *sqrt) {
  bssl::UniquePtr<BN_MONT_CTX> mont(BN_MONT_CTX_new());
  bssl::UniquePtr<BIGNUM> zero(BN_new());
  bssl::UniquePtr<BIGNUM> one(BN_dup(BN_value_one()));
  bssl::UniquePtr<BIGNUM> two(BN_new());
  bssl::UniquePtr<BIGNUM> three(BN_new());
  bssl::UniquePtr<BIGNUM> p_sqrt(BN_new());
  bssl::UniquePtr<BIGNUM> p_sqrt_plus_1(BN_new());
  bssl::UniquePtr<BIGNUM> p_minus_1(BN_new());
  bssl::UniquePtr<BIGNUM> highest_bit_set(BN_new());
  bssl::UniquePtr<BIGNUM> max(BN_new());
  bssl::UniquePtr<BIGNUM> two_to_the_b(BN_new());
  bssl::UniquePtr<BIGNUM> two_to_the_b_minus_1(BN_new());
  bssl::UniquePtr<BIGNUM> tmp1(BN_new());
  bssl::UniquePtr<BIGNUM> tmp2(BN_new());
  if (!mont || !BN_MONT_CTX_set(mont.get(), p, ctx) || !zero || !one ||
      !BN_set_word(one.get(), 1) || !two || !BN_set_word(two.get(), 2) ||
      !three || !BN_set_word(three.get(), 3) || !p_sqrt || !p_sqrt_plus_1 ||
      !highest_bit_set ||
      !BN_lshift(highest_bit_set.get(), BN_value_one(), BN_num_bits(p) - 1) ||
      !max || !BN_sub(max.get(), p, BN_value_one()) || !two_to_the_b ||
      !BN_lshift(two_to_the_b.get(), BN_value_one(), BN_num_bits(p)) ||
      !two_to_the_b_minus_1 ||
      !BN_sub(two_to_the_b_minus_1.get(), two_to_the_b.get(), BN_value_one()) ||
      !tmp1 || !tmp2) {
    return false;
  }
  BN_zero(zero.get());

  const BIGNUM *m = p;

  BIGNUM *p_sqrt_raw = NULL;
  if (!BN_hex2bn(&p_sqrt_raw, sqrt)) {
    return false;
  }
  p_sqrt.reset(p_sqrt_raw);
  if (!BN_add(p_sqrt_plus_1.get(), p_sqrt.get(), BN_value_one())) {
    return false;
  }


  if (!GenerateSquareTest(zero, NULL, m, mont, ctx) ||
      !GenerateSquareTest(zero, NULL, m, mont, ctx) ||
      !GenerateSquareTest(one, NULL, m, mont, ctx) ||
      !GenerateSquareTest(two, NULL, m, mont, ctx) ||
      !GenerateSquareTest(max, NULL, m, mont, ctx) ||
      !GenerateSquareTest(p_sqrt, NULL, m, mont, ctx) ||
      !GenerateSquareTest(p_sqrt_plus_1, NULL, m, mont, ctx) ||
      !GenerateSquareTest(highest_bit_set, NULL, m, mont, ctx)) {
    return false;
  }

  // TODO:  printf("\n# Carry Propagation.\n");

  return true;
}

static bool GenerateElemMulTests(const InterestingPoints &points, BN_CTX *ctx) {
  bssl::UniquePtr<BIGNUM> q(BN_new());
  if (!q ||
      !EC_GROUP_get_curve_GFp(points.group.get(), q.get(), NULL, NULL, ctx)) {
    return 0;
  }
  return GenerateModMulTests(q.get(), ctx);
}

static bool GenerateScalarMulTests(const InterestingPoints &points,
                                   BN_CTX *ctx) {
  return GenerateModMulTests(EC_GROUP_get0_order(points.group.get()), ctx);
}

static bool GenerateScalarSquareTests(const InterestingPoints &points,
                                      BN_CTX *ctx, const char *sqrt) {
  return GenerateModSquareTests(EC_GROUP_get0_order(points.group.get()), ctx,
                                sqrt);
}

static bool GenerateDivBy2Test(const bssl::UniquePtr<BIGNUM> &a,
                               const bssl::UniquePtr<BIGNUM> &p, BN_CTX *ctx) {
  bssl::UniquePtr<BIGNUM> half(BN_new());
  bssl::UniquePtr<BIGNUM> r(BN_new());
  if (!half || !BN_set_word(half.get(), 2) ||
      !BN_mod_inverse(half.get(), half.get(), p.get(), ctx) || !r ||
      !BN_mod_mul(r.get(), a.get(), half.get(), p.get(), ctx)) {
    return false;
  }

  printf("\n");
  printf("a = ");
  print_bn(a.get());
  printf("\n");
  printf("r = ");
  print_bn(r.get());
  printf("\n");

  return true;
}

static bool GenerateDivBy2Tests(const InterestingPoints &points, BN_CTX *ctx) {
  bssl::UniquePtr<BN_MONT_CTX> mont(BN_MONT_CTX_new());
  bssl::UniquePtr<BIGNUM> q(BN_new());
  bssl::UniquePtr<BIGNUM> zero(BN_new());
  bssl::UniquePtr<BIGNUM> one(BN_dup(BN_value_one()));
  bssl::UniquePtr<BIGNUM> two(BN_new());
  bssl::UniquePtr<BIGNUM> three(BN_new());
  bssl::UniquePtr<BIGNUM> p_div_2(BN_new());
  bssl::UniquePtr<BIGNUM> p_div_2_plus_1(BN_new());
  bssl::UniquePtr<BIGNUM> highest_bit_set(BN_new());
  bssl::UniquePtr<BIGNUM> max(BN_new());
  bssl::UniquePtr<BIGNUM> two_to_the_b(BN_new());
  bssl::UniquePtr<BIGNUM> two_to_the_b_minus_1(BN_new());
  bssl::UniquePtr<BIGNUM> tmp1(BN_new());
  bssl::UniquePtr<BIGNUM> tmp2(BN_new());
  if (!q ||
      !EC_GROUP_get_curve_GFp(points.group.get(), q.get(), NULL, NULL, ctx) ||
      !mont || !BN_MONT_CTX_set(mont.get(), q.get(), ctx) || !zero || !one ||
      !BN_set_word(one.get(), 1) || !two || !BN_set_word(two.get(), 2) ||
      !three || !BN_set_word(three.get(), 3) || !p_div_2 ||
      !BN_div(p_div_2.get(), NULL, q.get(), two.get(), ctx) ||
      !p_div_2_plus_1 ||
      !BN_add(p_div_2_plus_1.get(), p_div_2.get(), BN_value_one()) ||
      !highest_bit_set ||
      !BN_lshift(highest_bit_set.get(), BN_value_one(),
                 BN_num_bits(q.get()) - 1) ||
      !max || !BN_sub(max.get(), q.get(), BN_value_one()) || !two_to_the_b ||
      !BN_lshift(two_to_the_b.get(), BN_value_one(), BN_num_bits(q.get())) ||
      !two_to_the_b_minus_1 ||
      !BN_sub(two_to_the_b_minus_1.get(), two_to_the_b.get(), BN_value_one()) ||
      !tmp1 || !tmp2) {
    return false;
  }
  BN_zero(zero.get());

  const bssl::UniquePtr<BIGNUM> &m = q;

  if (!GenerateDivBy2Test(zero, m, ctx) || !GenerateDivBy2Test(zero, m, ctx) ||
      !GenerateDivBy2Test(one, m, ctx) || !GenerateDivBy2Test(two, m, ctx) ||
      !GenerateDivBy2Test(three, m, ctx) || !GenerateDivBy2Test(max, m, ctx) ||
      !GenerateDivBy2Test(p_div_2, m, ctx) ||
      !GenerateDivBy2Test(p_div_2_plus_1, m, ctx) ||
      !GenerateDivBy2Test(highest_bit_set, m, ctx)) {
    return false;
  }

  return true;
}

static bool GenerateNegTest(const bssl::UniquePtr<BIGNUM> &a,
                            const bssl::UniquePtr<BIGNUM> &m, BN_CTX *ctx) {
  bssl::UniquePtr<BIGNUM> b(BN_dup(a.get()));
  if (!b) {
    return false;
  }


  if (BN_cmp(b.get(), m.get()) >= 0) {
    if (!BN_sub(b.get(), a.get(), m.get()) || BN_cmp(b.get(), m.get()) >= 0) {
      return false;
    }
  }
  if (!BN_is_zero(b.get())) {
    BN_set_negative(b.get(), 1);
  }
  if (!BN_nnmod(b.get(), b.get(), m.get(), ctx)) {
    return false;
  }

  printf("\n");
  printf("a = ");
  print_bn(a.get());
  printf("\n");
  printf("b = ");
  print_bn(b.get());
  printf("\n");

  return true;
}

static bool GenerateNegTests(const InterestingPoints &points, BN_CTX *ctx) {
  bssl::UniquePtr<BN_MONT_CTX> mont(BN_MONT_CTX_new());
  bssl::UniquePtr<BIGNUM> q(BN_new());
  bssl::UniquePtr<BIGNUM> zero(BN_new());
  bssl::UniquePtr<BIGNUM> one(BN_dup(BN_value_one()));
  bssl::UniquePtr<BIGNUM> two(BN_new());
  bssl::UniquePtr<BIGNUM> three(BN_new());
  bssl::UniquePtr<BIGNUM> p_div_2(BN_new());
  bssl::UniquePtr<BIGNUM> p_div_2_plus_1(BN_new());
  bssl::UniquePtr<BIGNUM> highest_bit_set(BN_new());
  bssl::UniquePtr<BIGNUM> max(BN_new());
  bssl::UniquePtr<BIGNUM> two_to_the_b(BN_new());
  bssl::UniquePtr<BIGNUM> two_to_the_b_minus_1(BN_new());
  bssl::UniquePtr<BIGNUM> tmp1(BN_new());
  bssl::UniquePtr<BIGNUM> tmp2(BN_new());
  bssl::UniquePtr<BIGNUM> p_plus_1(BN_new());
  if (!q ||
      !EC_GROUP_get_curve_GFp(points.group.get(), q.get(), NULL, NULL, ctx) ||
      !mont || !BN_MONT_CTX_set(mont.get(), q.get(), ctx) || !zero || !one ||
      !BN_set_word(one.get(), 1) || !two || !BN_set_word(two.get(), 2) ||
      !three || !BN_set_word(three.get(), 3) || !p_div_2 ||
      !BN_div(p_div_2.get(), NULL, q.get(), two.get(), ctx) ||
      !p_div_2_plus_1 ||
      !BN_add(p_div_2_plus_1.get(), p_div_2.get(), BN_value_one()) ||
      !highest_bit_set ||
      !BN_lshift(highest_bit_set.get(), BN_value_one(),
                 BN_num_bits(q.get()) - 1) ||
      !max || !BN_sub(max.get(), q.get(), BN_value_one()) || !two_to_the_b ||
      !BN_lshift(two_to_the_b.get(), BN_value_one(), BN_num_bits(q.get())) ||
      !two_to_the_b_minus_1 ||
      !BN_sub(two_to_the_b_minus_1.get(), two_to_the_b.get(), BN_value_one()) ||
      !p_plus_1 || !BN_add(p_plus_1.get(), q.get(), one.get())) {
    return false;
  }
  BN_zero(zero.get());

  const bssl::UniquePtr<BIGNUM> &m = q;

  if (!GenerateNegTest(zero, m, ctx) || !GenerateNegTest(one, m, ctx) ||
      !GenerateNegTest(two, m, ctx) || !GenerateNegTest(three, m, ctx) ||
      !GenerateNegTest(max, m, ctx) || !GenerateNegTest(p_div_2, m, ctx) ||
      !GenerateNegTest(p_div_2_plus_1, m, ctx) ||
      !GenerateNegTest(highest_bit_set, m, ctx)) {
    return false;
  }

  return true;
}

#define GEN_CURVE_TESTS(curve, name, gen)                    \
  {                                                          \
    std::string test_name = "ecc-" curve "-" name;           \
    if (args[0] == curve || args[0] == test_name) {          \
      if (args[0] == curve) {                                \
        std::string file_name = curve "_" name "_tests.txt"; \
        freopen(file_name.c_str(), "w", stdout);             \
      }                                                      \
      bool status = gen;                                     \
      if (!status || args[0] != curve) {                     \
        return status;                                       \
      }                                                      \
    }                                                        \
  }

bool GenerateTests(const std::vector<std::string> &args) {
  if (args.size() == 0) {
    printf("No test set specified.\n");
    return false;
  }

  bssl::UniquePtr<BN_CTX> ctx(BN_CTX_new());
  if (!ctx) {
    return false;
  }

  if (args[0] == "ecdsa-short-s-asn1") {
    return GenerateShortSTests(ASN1, ctx.get());
  }

  if (args[0] == "ecdsa-asn1") {
    return GenerateECDSATests(ASN1, ctx.get());
  }

  if (args[0] == "ecdsa-short-s-fixed") {
    return GenerateShortSTests(Fixed, ctx.get());
  }

  if (args[0] == "ecdsa-fixed") {
    return GenerateECDSATests(Fixed, ctx.get());
  }

  if (args[0] == "ecc-public-key") {
    return GenerateECCPublicKeyTests(ctx.get());
  }

  bool valid_points = false;
  InterestingPoints p256_points(&valid_points, NID_X9_62_prime256v1, "P-256",
                                ctx.get());
  if (!valid_points) {
    return false;
  }

  valid_points = false;
  InterestingPoints p384_points(&valid_points, NID_secp384r1, "P-384",
                                ctx.get());
  if (!valid_points) {
    return false;
  }

  valid_points = false;
  InterestingPoints p521_points(&valid_points, NID_secp521r1, "P-521",
                                ctx.get());
  if (!valid_points) {
    return false;
  }

  GEN_CURVE_TESTS("p256", "point_double",
                  GenerateECCPointDoubleTestsForCurve(p256_points, ctx.get()));

  GEN_CURVE_TESTS(
      "p256", "point_sum",
      GenerateECCPointAddTestsForCurve(p256_points, Unchanged, ctx.get()));

  GEN_CURVE_TESTS("p256", "point_sum_mixed",
                  GenerateECCPointAddTestsForCurve(
                      p256_points, MakeAffineAllZero, ctx.get()));

  GEN_CURVE_TESTS("p256", "elem_sum",
                  GenerateElemSumTests(p256_points, ctx.get()));

  GEN_CURVE_TESTS("p256", "elem_mul",
                  GenerateElemMulTests(p256_points, ctx.get()));

  GEN_CURVE_TESTS("p256", "scalar_mul",
                  GenerateScalarMulTests(p256_points, ctx.get()));

  GEN_CURVE_TESTS(
      "p256", "scalar_square",
      GenerateScalarSquareTests(p256_points, ctx.get(),
                                "ffffffff80000000600000002fffffff"));

  GEN_CURVE_TESTS("p256", "elem_neg", GenerateNegTests(p256_points, ctx.get()));

  if (args[0] == "ecc-p256-point-mul-twin") {
    return GeneratePointMulTwinTests(p256_points, true, true, ctx.get());
  }

  if (args[0] == "p256") {
    return true;
  }

  GEN_CURVE_TESTS("p384", "point_double",
                  GenerateECCPointDoubleTestsForCurve(p384_points, ctx.get()));

  GEN_CURVE_TESTS(
      "p384", "point_sum",
      GenerateECCPointAddTestsForCurve(p384_points, Unchanged, ctx.get()));

  GEN_CURVE_TESTS("p384", "point_sum_mixed",
                  GenerateECCPointAddTestsForCurve(
                      p384_points, MakeAffineAllZero, ctx.get()));

  GEN_CURVE_TESTS("p384", "elem_sum",
                  GenerateElemSumTests(p384_points, ctx.get()));

  GEN_CURVE_TESTS("p384", "elem_mul",
                  GenerateElemMulTests(p384_points, ctx.get()));

  GEN_CURVE_TESTS("p384", "scalar_mul",
                  GenerateScalarMulTests(p384_points, ctx.get()));

  GEN_CURVE_TESTS(
      "p384", "scalar_square",
      GenerateScalarSquareTests(p384_points, ctx.get(),
                                "ffffffff80000000600000002fffffff"));

  GEN_CURVE_TESTS("p384", "elem_neg", GenerateNegTests(p384_points, ctx.get()));

  GEN_CURVE_TESTS("p384", "elem_div_by_2",
                  GenerateDivBy2Tests(p384_points, ctx.get()));

  if (args[0] == "ecc-p384-point-mul-twin") {
    return GeneratePointMulTwinTests(p384_points, true, true, ctx.get());
  }

  if (args[0] == "p384") {
    return true;
  }

  GEN_CURVE_TESTS("p521", "point_double",
                  GenerateECCPointDoubleTestsForCurve(p521_points, ctx.get()));

  GEN_CURVE_TESTS(
      "p521", "point_sum",
      GenerateECCPointAddTestsForCurve(p521_points, Unchanged, ctx.get()));

  GEN_CURVE_TESTS("p521", "point_sum_mixed",
                  GenerateECCPointAddTestsForCurve(
                      p521_points, MakeAffineAllZero, ctx.get()));

  GEN_CURVE_TESTS("p521", "elem_sum",
                  GenerateElemSumTests(p521_points, ctx.get()));

  GEN_CURVE_TESTS("p521", "elem_mul",
                  GenerateElemMulTests(p521_points, ctx.get()));

  GEN_CURVE_TESTS("p521", "scalar_mul",
                  GenerateScalarMulTests(p521_points, ctx.get()));

  GEN_CURVE_TESTS(
      "p521", "scalar_square",
      GenerateScalarSquareTests(p521_points, ctx.get(),
                                "ffffffff80000000600000002fffffff"));

  GEN_CURVE_TESTS("p521", "elem_neg", GenerateNegTests(p521_points, ctx.get()));

  GEN_CURVE_TESTS("p521", "elem_div_by_2",
                  GenerateDivBy2Tests(p521_points, ctx.get()));

  if (args[0] == "ecc-p521-point-mul-twin") {
    return GeneratePointMulTwinTests(p521_points, true, true, ctx.get());
  }

  if (args[0] == "p521") {
    return true;
  }

  printf("Unrecognized test set.\n");
  return false;
}
