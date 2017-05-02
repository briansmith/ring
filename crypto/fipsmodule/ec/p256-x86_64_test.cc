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

#if !defined(__STDC_FORMAT_MACROS)
#define __STDC_FORMAT_MACROS
#endif

#include <openssl/base.h>

#include <stdio.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/mem.h>

#include "../bn/internal.h"
#include "../../test/file_test.h"
#include "p256-x86_64.h"


// Disable tests if BORINGSSL_SHARED_LIBRARY is defined. These tests need access
// to internal functions.
#if !defined(OPENSSL_NO_ASM) && defined(OPENSSL_X86_64) && \
    !defined(OPENSSL_SMALL) && !defined(BORINGSSL_SHARED_LIBRARY)

static bool TestSelectW5() {
  // Fill a table with some garbage input.
  P256_POINT table[16];
  for (size_t i = 0; i < 16; i++) {
    OPENSSL_memset(table[i].X, 3 * i, sizeof(table[i].X));
    OPENSSL_memset(table[i].Y, 3 * i + 1, sizeof(table[i].Y));
    OPENSSL_memset(table[i].Z, 3 * i + 2, sizeof(table[i].Z));
  }

  for (int i = 0; i <= 16; i++) {
    P256_POINT val;
    ecp_nistz256_select_w5(&val, table, i);

    P256_POINT expected;
    if (i == 0) {
      OPENSSL_memset(&expected, 0, sizeof(expected));
    } else {
      expected = table[i-1];
    }

    if (OPENSSL_memcmp(&val, &expected, sizeof(P256_POINT)) != 0) {
      fprintf(stderr, "ecp_nistz256_select_w5(%d) gave the wrong value.\n", i);
      return false;
    }
  }

  return true;
}

static bool TestSelectW7() {
  // Fill a table with some garbage input.
  P256_POINT_AFFINE table[64];
  for (size_t i = 0; i < 64; i++) {
    OPENSSL_memset(table[i].X, 2 * i, sizeof(table[i].X));
    OPENSSL_memset(table[i].Y, 2 * i + 1, sizeof(table[i].Y));
  }

  for (int i = 0; i <= 64; i++) {
    P256_POINT_AFFINE val;
    ecp_nistz256_select_w7(&val, table, i);

    P256_POINT_AFFINE expected;
    if (i == 0) {
      OPENSSL_memset(&expected, 0, sizeof(expected));
    } else {
      expected = table[i-1];
    }

    if (OPENSSL_memcmp(&val, &expected, sizeof(P256_POINT_AFFINE)) != 0) {
      fprintf(stderr, "ecp_nistz256_select_w7(%d) gave the wrong value.\n", i);
      return false;
    }
  }

  return true;
}

static bool GetFieldElement(FileTest *t, BN_ULONG out[P256_LIMBS],
                            const char *name) {
  std::vector<uint8_t> bytes;
  if (!t->GetBytes(&bytes, name)) {
    return false;
  }

  if (bytes.size() != BN_BYTES * P256_LIMBS) {
    t->PrintLine("Invalid length: %s", name);
    return false;
  }

  // |byte| contains bytes in big-endian while |out| should contain |BN_ULONG|s
  // in little-endian.
  OPENSSL_memset(out, 0, P256_LIMBS * sizeof(BN_ULONG));
  for (size_t i = 0; i < bytes.size(); i++) {
    out[P256_LIMBS - 1 - (i / BN_BYTES)] <<= 8;
    out[P256_LIMBS - 1 - (i / BN_BYTES)] |= bytes[i];
  }

  return true;
}

static std::string FieldElementToString(const BN_ULONG a[P256_LIMBS]) {
  std::string ret;
  for (size_t i = P256_LIMBS-1; i < P256_LIMBS; i--) {
    char buf[2 * BN_BYTES + 1];
    BIO_snprintf(buf, sizeof(buf), BN_HEX_FMT2, a[i]);
    ret += buf;
  }
  return ret;
}

static bool ExpectFieldElementsEqual(FileTest *t, const char *message,
                                     const BN_ULONG expected[P256_LIMBS],
                                     const BN_ULONG actual[P256_LIMBS]) {
  if (OPENSSL_memcmp(expected, actual, sizeof(BN_ULONG) * P256_LIMBS) == 0) {
    return true;
  }

  t->PrintLine("%s", message);
  t->PrintLine("Expected: %s", FieldElementToString(expected).c_str());
  t->PrintLine("Actual:   %s", FieldElementToString(actual).c_str());
  return false;
}

static bool PointToAffine(P256_POINT_AFFINE *out, const P256_POINT *in) {
  static const uint8_t kP[] = {
      0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  };

  bssl::UniquePtr<BIGNUM> x(BN_new()), y(BN_new()), z(BN_new());
  bssl::UniquePtr<BIGNUM> p(BN_bin2bn(kP, sizeof(kP), nullptr));
  if (!x || !y || !z || !p ||
      !bn_set_words(x.get(), in->X, P256_LIMBS) ||
      !bn_set_words(y.get(), in->Y, P256_LIMBS) ||
      !bn_set_words(z.get(), in->Z, P256_LIMBS)) {
    return false;
  }

  // Coordinates must be fully-reduced.
  if (BN_cmp(x.get(), p.get()) >= 0 ||
      BN_cmp(y.get(), p.get()) >= 0 ||
      BN_cmp(z.get(), p.get()) >= 0) {
    return false;
  }

  OPENSSL_memset(out, 0, sizeof(P256_POINT_AFFINE));

  if (BN_is_zero(z.get())) {
    // The point at infinity is represented as (0, 0).
    return true;
  }

  bssl::UniquePtr<BN_CTX> ctx(BN_CTX_new());
  bssl::UniquePtr<BN_MONT_CTX> mont(BN_MONT_CTX_new());
  if (!ctx || !mont ||
      !BN_MONT_CTX_set(mont.get(), p.get(), ctx.get()) ||
      // Invert Z.
      !BN_from_montgomery(z.get(), z.get(), mont.get(), ctx.get()) ||
      !BN_mod_inverse(z.get(), z.get(), p.get(), ctx.get()) ||
      !BN_to_montgomery(z.get(), z.get(), mont.get(), ctx.get()) ||
      // Convert (X, Y, Z) to (X/Z^2, Y/Z^3).
      !BN_mod_mul_montgomery(x.get(), x.get(), z.get(), mont.get(),
                             ctx.get()) ||
      !BN_mod_mul_montgomery(x.get(), x.get(), z.get(), mont.get(),
                             ctx.get()) ||
      !BN_mod_mul_montgomery(y.get(), y.get(), z.get(), mont.get(),
                             ctx.get()) ||
      !BN_mod_mul_montgomery(y.get(), y.get(), z.get(), mont.get(),
                             ctx.get()) ||
      !BN_mod_mul_montgomery(y.get(), y.get(), z.get(), mont.get(),
                             ctx.get())) {
    return false;
  }

  OPENSSL_memcpy(out->X, x->d, sizeof(BN_ULONG) * x->top);
  OPENSSL_memcpy(out->Y, y->d, sizeof(BN_ULONG) * y->top);
  return true;
}

static bool ExpectPointsEqual(FileTest *t, const char *message,
                              const P256_POINT_AFFINE *expected,
                              const P256_POINT *point) {
  // There are multiple representations of the same |P256_POINT|, so convert to
  // |P256_POINT_AFFINE| and compare.
  P256_POINT_AFFINE affine;
  if (!PointToAffine(&affine, point)) {
    t->PrintLine("%s", message);
    t->PrintLine("Could not convert to affine: (%s, %s, %s)",
                 FieldElementToString(point->X).c_str(),
                 FieldElementToString(point->Y).c_str(),
                 FieldElementToString(point->Z).c_str());
    return false;
  }

  if (OPENSSL_memcmp(expected, &affine, sizeof(P256_POINT_AFFINE)) != 0) {
    t->PrintLine("%s", message);
    t->PrintLine("Expected: (%s, %s)",
                 FieldElementToString(expected->X).c_str(),
                 FieldElementToString(expected->Y).c_str());
    t->PrintLine("Actual:   (%s, %s)", FieldElementToString(affine.X).c_str(),
                 FieldElementToString(affine.Y).c_str());
    return false;
  }

  return true;
}

static bool TestNegate(FileTest *t) {
  BN_ULONG a[P256_LIMBS], b[P256_LIMBS];
  if (!GetFieldElement(t, a, "A") ||
      !GetFieldElement(t, b, "B")) {
    return false;
  }

  // Test that -A = B.
  BN_ULONG ret[P256_LIMBS];
  ecp_nistz256_neg(ret, a);
  if (!ExpectFieldElementsEqual(t, "ecp_nistz256_neg(A) was incorrect.", b,
                                ret)) {
    return false;
  }

  OPENSSL_memcpy(ret, a, sizeof(ret));
  ecp_nistz256_neg(ret, ret);
  if (!ExpectFieldElementsEqual(
          t, "In-place ecp_nistz256_neg(A) was incorrect.", b, ret)) {
    return false;
  }

  // Test that -B = A.
  ecp_nistz256_neg(ret, b);
  if (!ExpectFieldElementsEqual(t, "ecp_nistz256_neg(B) was incorrect.", a,
                                ret)) {
    return false;
  }

  OPENSSL_memcpy(ret, b, sizeof(ret));
  ecp_nistz256_neg(ret, ret);
  if (!ExpectFieldElementsEqual(
          t, "In-place ecp_nistz256_neg(B) was incorrect.", a, ret)) {
    return false;
  }

  return true;
}

static bool TestMulMont(FileTest *t) {
  BN_ULONG a[P256_LIMBS], b[P256_LIMBS], result[P256_LIMBS];
  if (!GetFieldElement(t, a, "A") ||
      !GetFieldElement(t, b, "B") ||
      !GetFieldElement(t, result, "Result")) {
    return false;
  }

  BN_ULONG ret[P256_LIMBS];
  ecp_nistz256_mul_mont(ret, a, b);
  if (!ExpectFieldElementsEqual(t, "ecp_nistz256_mul_mont(A, B) was incorrect.",
                                result, ret)) {
    return false;
  }

  ecp_nistz256_mul_mont(ret, b, a);
  if (!ExpectFieldElementsEqual(t, "ecp_nistz256_mul_mont(B, A) was incorrect.",
                                result, ret)) {
    return false;
  }

  OPENSSL_memcpy(ret, a, sizeof(ret));
  ecp_nistz256_mul_mont(ret, ret, b);
  if (!ExpectFieldElementsEqual(
          t, "ecp_nistz256_mul_mont(ret = A, B) was incorrect.", result, ret)) {
    return false;
  }

  OPENSSL_memcpy(ret, a, sizeof(ret));
  ecp_nistz256_mul_mont(ret, b, ret);
  if (!ExpectFieldElementsEqual(
          t, "ecp_nistz256_mul_mont(B, ret = A) was incorrect.", result, ret)) {
    return false;
  }

  OPENSSL_memcpy(ret, b, sizeof(ret));
  ecp_nistz256_mul_mont(ret, a, ret);
  if (!ExpectFieldElementsEqual(
          t, "ecp_nistz256_mul_mont(A, ret = B) was incorrect.", result, ret)) {
    return false;
  }

  OPENSSL_memcpy(ret, b, sizeof(ret));
  ecp_nistz256_mul_mont(ret, ret, a);
  if (!ExpectFieldElementsEqual(
          t, "ecp_nistz256_mul_mont(ret = B, A) was incorrect.", result, ret)) {
    return false;
  }

  if (OPENSSL_memcmp(a, b, sizeof(a)) == 0) {
    ecp_nistz256_sqr_mont(ret, a);
    if (!ExpectFieldElementsEqual(t, "ecp_nistz256_sqr_mont(A) was incorrect.",
                                  result, ret)) {
      return false;
    }

    OPENSSL_memcpy(ret, a, sizeof(ret));
    ecp_nistz256_sqr_mont(ret, ret);
    if (!ExpectFieldElementsEqual(
            t, "ecp_nistz256_sqr_mont(ret = A) was incorrect.", result, ret)) {
      return false;
    }
  }

  return true;
}

static bool TestFromMont(FileTest *t) {
  BN_ULONG a[P256_LIMBS], result[P256_LIMBS];
  if (!GetFieldElement(t, a, "A") ||
      !GetFieldElement(t, result, "Result")) {
    return false;
  }

  BN_ULONG ret[P256_LIMBS];
  ecp_nistz256_from_mont(ret, a);
  if (!ExpectFieldElementsEqual(t, "ecp_nistz256_from_mont(A) was incorrect.",
                                result, ret)) {
    return false;
  }

  OPENSSL_memcpy(ret, a, sizeof(ret));
  ecp_nistz256_from_mont(ret, ret);
  if (!ExpectFieldElementsEqual(
          t, "ecp_nistz256_from_mont(ret = A) was incorrect.", result, ret)) {
    return false;
  }

  return true;
}

static bool TestPointAdd(FileTest *t) {
  P256_POINT a, b;
  P256_POINT_AFFINE result;
  if (!GetFieldElement(t, a.X, "A.X") ||
      !GetFieldElement(t, a.Y, "A.Y") ||
      !GetFieldElement(t, a.Z, "A.Z") ||
      !GetFieldElement(t, b.X, "B.X") ||
      !GetFieldElement(t, b.Y, "B.Y") ||
      !GetFieldElement(t, b.Z, "B.Z") ||
      !GetFieldElement(t, result.X, "Result.X") ||
      !GetFieldElement(t, result.Y, "Result.Y")) {
    return false;
  }

  P256_POINT ret;
  ecp_nistz256_point_add(&ret, &a, &b);
  if (!ExpectPointsEqual(t, "ecp_nistz256_point_add(A, B) was incorrect.",
                         &result, &ret)) {
    return false;
  }

  ecp_nistz256_point_add(&ret, &b, &a);
  if (!ExpectPointsEqual(t, "ecp_nistz256_point_add(B, A) was incorrect.",
                         &result, &ret)) {
    return false;
  }

  OPENSSL_memcpy(&ret, &a, sizeof(ret));
  ecp_nistz256_point_add(&ret, &ret, &b);
  if (!ExpectPointsEqual(t, "ecp_nistz256_point_add(ret = A, B) was incorrect.",
                         &result, &ret)) {
    return false;
  }

  OPENSSL_memcpy(&ret, &a, sizeof(ret));
  ecp_nistz256_point_add(&ret, &b, &ret);
  if (!ExpectPointsEqual(t, "ecp_nistz256_point_add(B, ret = A) was incorrect.",
                         &result, &ret)) {
    return false;
  }

  OPENSSL_memcpy(&ret, &b, sizeof(ret));
  ecp_nistz256_point_add(&ret, &a, &ret);
  if (!ExpectPointsEqual(t, "ecp_nistz256_point_add(ret = A, B) was incorrect.",
                         &result, &ret)) {
    return false;
  }

  OPENSSL_memcpy(&ret, &b, sizeof(ret));
  ecp_nistz256_point_add(&ret, &ret, &a);
  if (!ExpectPointsEqual(t, "ecp_nistz256_point_add(ret = B, A) was incorrect.",
                         &result, &ret)) {
    return false;
  }

  P256_POINT_AFFINE a_affine, b_affine, infinity;
  OPENSSL_memset(&infinity, 0, sizeof(infinity));
  if (!PointToAffine(&a_affine, &a) ||
      !PointToAffine(&b_affine, &b)) {
    return false;
  }

  // ecp_nistz256_point_add_affine does not work when a == b unless doubling the
  // point at infinity.
  if (OPENSSL_memcmp(&a_affine, &b_affine, sizeof(a_affine)) != 0 ||
      OPENSSL_memcmp(&a_affine, &infinity, sizeof(a_affine)) == 0) {
    ecp_nistz256_point_add_affine(&ret, &a, &b_affine);
    if (!ExpectPointsEqual(t,
                           "ecp_nistz256_point_add_affine(A, B) was incorrect.",
                           &result, &ret)) {
      return false;
    }

    OPENSSL_memcpy(&ret, &a, sizeof(ret));
    ecp_nistz256_point_add_affine(&ret, &ret, &b_affine);
    if (!ExpectPointsEqual(
            t, "ecp_nistz256_point_add_affine(ret = A, B) was incorrect.",
            &result, &ret)) {
      return false;
    }

    ecp_nistz256_point_add_affine(&ret, &b, &a_affine);
    if (!ExpectPointsEqual(t,
                           "ecp_nistz256_point_add_affine(B, A) was incorrect.",
                           &result, &ret)) {
      return false;
    }

    OPENSSL_memcpy(&ret, &b, sizeof(ret));
    ecp_nistz256_point_add_affine(&ret, &ret, &a_affine);
    if (!ExpectPointsEqual(
            t, "ecp_nistz256_point_add_affine(ret = B, A) was incorrect.",
            &result, &ret)) {
      return false;
    }
  }

  if (OPENSSL_memcmp(&a, &b, sizeof(a)) == 0) {
    ecp_nistz256_point_double(&ret, &a);
    if (!ExpectPointsEqual(t, "ecp_nistz256_point_double(A) was incorrect.",
                           &result, &ret)) {
      return false;
    }

    ret = a;
    ecp_nistz256_point_double(&ret, &ret);
    if (!ExpectPointsEqual(
            t, "In-place ecp_nistz256_point_double(A) was incorrect.", &result,
            &ret)) {
      return false;
    }
  }

  return true;
}

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "%s TEST_FILE\n", argv[0]);
    return 1;
  }

  if (!TestSelectW5() ||
      !TestSelectW7()) {
    return 1;
  }

  return FileTestMain([](FileTest *t, void *) -> bool {
    if (t->GetParameter() == "Negate") {
      return TestNegate(t);
    }
    if (t->GetParameter() == "MulMont") {
      return TestMulMont(t);
    }
    if (t->GetParameter() == "FromMont") {
      return TestFromMont(t);
    }
    if (t->GetParameter() == "PointAdd") {
      return TestPointAdd(t);
    }

    t->PrintLine("Unknown test type: %s", t->GetParameter().c_str());
    return false;
  }, nullptr, argv[1]);
}

#else

int main() {
  printf("PASS\n");
  return 0;
}

#endif
