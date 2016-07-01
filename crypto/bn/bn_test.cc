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
 * [including the GNU Public Licence.]
 */
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 *
 * Portions of the attached software ("Contribution") are developed by
 * SUN MICROSYSTEMS, INC., and are contributed to the OpenSSL project.
 *
 * The Contribution is licensed pursuant to the Eric Young open source
 * license provided above.
 *
 * The binary polynomial arithmetic software is originally written by
 * Sheueling Chang Shantz and Douglas Stebila of Sun Microsystems
 * Laboratories. */

/* For BIGNUM format macros. */
#if !defined(__STDC_FORMAT_MACROS)
#define __STDC_FORMAT_MACROS
#endif

// rustc always links with the non-debug runtime, but when _DEBUG is defined
// MSVC's C++ standard library expects to be linked to the debug runtime.
#if defined(_DEBUG)
#undef _DEBUG
#endif

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#include <utility>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/mem.h>

#include "../test/bn_test_lib.h"
#include "../crypto/test/file_test.h"
#include "../crypto/test/scoped_types.h"
#include "../test/bn_test_util.h"


extern "C" int bssl_bn_test_main(RAND *rng);


// This program tests the BIGNUM implementation. It takes an optional -bc
// argument to write a transcript compatible with the UNIX bc utility.
//
// TODO(davidben): Rather than generate random inputs and depend on bc to check
// the results, most of these tests should use known answers.

static const int num0 = 100; // number of tests
static const int num2 = 5;   // number of tests for slow functions

static int rand_neg(void);

static bool test_mont(RAND *rng, BN_CTX *ctx);
static bool test_mod_mul(RAND *rng, BN_CTX *ctx);
static bool test_mod_exp_mont(RAND *rng, BN_CTX *ctx);
static bool test_mod_exp_mont_consttime(RAND *rng, BN_CTX *ctx);
static bool test_exp(RAND *rng, BN_CTX *ctx);
static bool test_mod_exp_mont5(RAND *rng, BN_CTX *ctx);
static bool TestBN2BinPadded(RAND *rng);
static bool TestHex2BN();
static bool TestRand(RAND *rng);
static bool TestNegativeZero(BN_CTX *ctx);
static bool TestBadModulus(BN_CTX *ctx);
static bool TestExpModZero(RAND *rng);
static bool RunTest(FileTest *t, void *arg);


extern "C" int bssl_bn_test_main(RAND *rng) {
  ScopedBN_CTX ctx(BN_CTX_new());
  if (!ctx) {
    return 1;
  }


  if (!test_mod_mul(rng, ctx.get()) ||
      !test_mont(rng, ctx.get()) ||
      !test_mod_exp_mont(rng, ctx.get()) ||
      !test_mod_exp_mont_consttime(rng, ctx.get()) ||
      !test_mod_exp_mont5(rng, ctx.get()) ||
      !test_exp(rng, ctx.get()) ||
      !TestBN2BinPadded(rng) ||
      !TestHex2BN() ||
      !TestRand(rng) ||
      !TestNegativeZero(ctx.get()) ||
      !TestBadModulus(ctx.get()) ||
      !TestExpModZero(rng)) {
    return 1;
  }

  return FileTestMain(RunTest, ctx.get(), "crypto/bn/bn_tests.txt");
}

static int HexToBIGNUM(ScopedBIGNUM *out, const char *in) {
  BIGNUM *raw = NULL;
  int ret = BN_hex2bn(&raw, in);
  out->reset(raw);
  return ret;
}

static ScopedBIGNUM GetBIGNUM(FileTest *t, const char *attribute) {
  std::string hex;
  if (!t->GetAttribute(&hex, attribute)) {
    return nullptr;
  }

  ScopedBIGNUM ret;
  if (HexToBIGNUM(&ret, hex.c_str()) != static_cast<int>(hex.size())) {
    t->PrintLine("Could not decode '%s'.", hex.c_str());
    return nullptr;
  }
  return ret;
}

static bool GetInt(FileTest *t, int *out, const char *attribute) {
  ScopedBIGNUM ret = GetBIGNUM(t, attribute);
  if (!ret) {
    return false;
  }

  // This is |BN_get_word|, inlined and improved.
  switch (ret->top) {
    case 0:
      *out = 0;
      return 1;
    case 1:
      if (ret->d[0] > (BN_ULONG)INT_MAX) {
        return false;
      }
      *out = static_cast<int>(ret->d[0]);
      return true;
    default:
      return false;
  }
}

static bool ExpectBIGNUMsEqual(FileTest *t, const char *operation,
                               const BIGNUM *expected, const BIGNUM *actual) {
  if (BN_cmp(expected, actual) == 0) {
    return true;
  }
  t->PrintLine("Got wrong value for %s", operation);
  return false;
}

static bool TestSum(FileTest *t, BN_CTX *) {
  ScopedBIGNUM a = GetBIGNUM(t, "A");
  ScopedBIGNUM b = GetBIGNUM(t, "B");
  ScopedBIGNUM sum = GetBIGNUM(t, "Sum");
  if (!a || !b || !sum) {
    return false;
  }

  ScopedBIGNUM ret(BN_new());
  if (!ret ||
      !BN_add(ret.get(), a.get(), b.get()) ||
      !ExpectBIGNUMsEqual(t, "A + B", sum.get(), ret.get()) ||
      !BN_sub(ret.get(), sum.get(), a.get()) ||
      !ExpectBIGNUMsEqual(t, "Sum - A", b.get(), ret.get()) ||
      !BN_sub(ret.get(), sum.get(), b.get()) ||
      !ExpectBIGNUMsEqual(t, "Sum - B", a.get(), ret.get())) {
    return false;
  }

  return true;
}

static bool TestLShift1(FileTest *t, BN_CTX *ctx) {
  ScopedBIGNUM a = GetBIGNUM(t, "A");
  ScopedBIGNUM lshift1 = GetBIGNUM(t, "LShift1");
  ScopedBIGNUM zero(BN_new());
  if (!a || !lshift1 || !zero) {
    return false;
  }

  BN_zero(zero.get());

  ScopedBIGNUM ret(BN_new()), two(BN_new()), remainder(BN_new());
  if (!ret || !two || !remainder ||
      !BN_set_word(two.get(), 2) ||
      !BN_add(ret.get(), a.get(), a.get()) ||
      !ExpectBIGNUMsEqual(t, "A + A", lshift1.get(), ret.get()) ||
      !BN_mul(ret.get(), a.get(), two.get(), ctx) ||
      !ExpectBIGNUMsEqual(t, "A * 2", lshift1.get(), ret.get()) ||
      !BN_div(ret.get(), remainder.get(), lshift1.get(), two.get(), ctx) ||
      !ExpectBIGNUMsEqual(t, "LShift1 / 2", a.get(), ret.get()) ||
      !ExpectBIGNUMsEqual(t, "LShift1 % 2", zero.get(), remainder.get()) ||
      !BN_lshift1(ret.get(), a.get()) ||
      !ExpectBIGNUMsEqual(t, "A << 1", lshift1.get(), ret.get()) ||
      !BN_rshift1(ret.get(), lshift1.get()) ||
      !ExpectBIGNUMsEqual(t, "LShift >> 1", a.get(), ret.get()) ||
      !BN_rshift1(ret.get(), lshift1.get()) ||
      !ExpectBIGNUMsEqual(t, "LShift >> 1", a.get(), ret.get())) {
    return false;
  }

  // Set the LSB to 1 and test rshift1 again.
  if (BN_is_negative(lshift1.get())) {
    if (!BN_sub(lshift1.get(), lshift1.get(), BN_value_one())) {
      return false;
    }
  } else {
    if (!BN_add(lshift1.get(), lshift1.get(), BN_value_one())) {
      return false;
    }
  }

  if (!BN_div(ret.get(), nullptr /* rem */, lshift1.get(), two.get(), ctx) ||
      !ExpectBIGNUMsEqual(t, "(LShift1 | 1) / 2", a.get(), ret.get()) ||
      !BN_rshift1(ret.get(), lshift1.get()) ||
      !ExpectBIGNUMsEqual(t, "(LShift | 1) >> 1", a.get(), ret.get())) {
    return false;
  }

  return true;
}

static bool TestLShift(FileTest *t, BN_CTX *) {
  ScopedBIGNUM a = GetBIGNUM(t, "A");
  ScopedBIGNUM lshift = GetBIGNUM(t, "LShift");
  int n = 0;
  if (!a || !lshift || !GetInt(t, &n, "N")) {
    return false;
  }

  ScopedBIGNUM ret(BN_new());
  if (!ret ||
      !BN_lshift(ret.get(), a.get(), n) ||
      !ExpectBIGNUMsEqual(t, "A << N", lshift.get(), ret.get()) ||
      !BN_rshift(ret.get(), lshift.get(), n) ||
      !ExpectBIGNUMsEqual(t, "A >> N", a.get(), ret.get())) {
    return false;
  }

  return true;
}

static bool TestRShift(FileTest *t, BN_CTX *) {
  ScopedBIGNUM a = GetBIGNUM(t, "A");
  ScopedBIGNUM rshift = GetBIGNUM(t, "RShift");
  int n = 0;
  if (!a || !rshift || !GetInt(t, &n, "N")) {
    return false;
  }

  ScopedBIGNUM ret(BN_new());
  if (!ret ||
      !BN_rshift(ret.get(), a.get(), n) ||
      !ExpectBIGNUMsEqual(t, "A >> N", rshift.get(), ret.get())) {
    return false;
  }

  return true;
}

static bool TestSquare(FileTest *t, BN_CTX *ctx) {
  ScopedBIGNUM a = GetBIGNUM(t, "A");
  ScopedBIGNUM square = GetBIGNUM(t, "Square");
  ScopedBIGNUM zero(BN_new());
  if (!a || !square || !zero) {
    return false;
  }

  BN_zero(zero.get());

  ScopedBIGNUM ret(BN_new()), remainder(BN_new());
  if (!ret ||
      !BN_sqr(ret.get(), a.get(), ctx) ||
      !ExpectBIGNUMsEqual(t, "A^2", square.get(), ret.get()) ||
      !BN_mul(ret.get(), a.get(), a.get(), ctx) ||
      !ExpectBIGNUMsEqual(t, "A * A", square.get(), ret.get()) ||
      !BN_div(ret.get(), remainder.get(), square.get(), a.get(), ctx) ||
      !ExpectBIGNUMsEqual(t, "Square / A", a.get(), ret.get()) ||
      !ExpectBIGNUMsEqual(t, "Square % A", zero.get(), remainder.get())) {
    return false;
  }

  return true;
}

static bool TestProduct(FileTest *t, BN_CTX *ctx) {
  ScopedBIGNUM a = GetBIGNUM(t, "A");
  ScopedBIGNUM b = GetBIGNUM(t, "B");
  ScopedBIGNUM product = GetBIGNUM(t, "Product");
  ScopedBIGNUM zero(BN_new());
  if (!a || !b || !product || !zero) {
    return false;
  }

  BN_zero(zero.get());

  ScopedBIGNUM ret(BN_new()), remainder(BN_new());
  if (!ret || !remainder ||
      !BN_mul(ret.get(), a.get(), b.get(), ctx) ||
      !ExpectBIGNUMsEqual(t, "A * B", product.get(), ret.get()) ||
      !BN_div(ret.get(), remainder.get(), product.get(), a.get(), ctx) ||
      !ExpectBIGNUMsEqual(t, "Product / A", b.get(), ret.get()) ||
      !ExpectBIGNUMsEqual(t, "Product % A", zero.get(), remainder.get()) ||
      !BN_div(ret.get(), remainder.get(), product.get(), b.get(), ctx) ||
      !ExpectBIGNUMsEqual(t, "Product / B", a.get(), ret.get()) ||
      !ExpectBIGNUMsEqual(t, "Product % B", zero.get(), remainder.get())) {
    return false;
  }

  return true;
}

static bool TestQuotient(FileTest *t, BN_CTX *ctx) {
  ScopedBIGNUM a = GetBIGNUM(t, "A");
  ScopedBIGNUM b = GetBIGNUM(t, "B");
  ScopedBIGNUM quotient = GetBIGNUM(t, "Quotient");
  ScopedBIGNUM remainder = GetBIGNUM(t, "Remainder");
  if (!a || !b || !quotient || !remainder) {
    return false;
  }

  ScopedBIGNUM ret(BN_new()), ret2(BN_new());
  if (!ret || !ret2 ||
      !BN_div(ret.get(), ret2.get(), a.get(), b.get(), ctx) ||
      !ExpectBIGNUMsEqual(t, "A / B", quotient.get(), ret.get()) ||
      !ExpectBIGNUMsEqual(t, "A % B", remainder.get(), ret2.get()) ||
      !BN_mul(ret.get(), quotient.get(), b.get(), ctx) ||
      !BN_add(ret.get(), ret.get(), remainder.get()) ||
      !ExpectBIGNUMsEqual(t, "Quotient * B + Remainder", a.get(), ret.get())) {
    return false;
  }

  return true;
}

struct Test {
  const char *name;
  bool (*func)(FileTest *t, BN_CTX *ctx);
};

static const Test kTests[] = {
    {"Sum", TestSum},
    {"LShift1", TestLShift1},
    {"LShift", TestLShift},
    {"RShift", TestRShift},
    {"Square", TestSquare},
    {"Product", TestProduct},
    {"Quotient", TestQuotient},
};

static bool RunTest(FileTest *t, void *arg) {
  BN_CTX *ctx = reinterpret_cast<BN_CTX *>(arg);
  for (const Test &test : kTests) {
    if (t->GetType() != test.name) {
      continue;
    }
    return test.func(t, ctx);
  }
  t->PrintLine("Unknown test type: %s", t->GetType().c_str());
  return false;
}

static int rand_neg() {
  static unsigned int neg = 0;
  static const int sign[8] = {0, 0, 0, 1, 1, 0, 1, 1};

  return sign[(neg++) % 8];
}

static bool test_mont(RAND *rng, BN_CTX *ctx) {
  ScopedBIGNUM a(BN_new());
  ScopedBIGNUM b(BN_new());
  ScopedBIGNUM c(BN_new());
  ScopedBIGNUM d(BN_new());
  ScopedBIGNUM A(BN_new());
  ScopedBIGNUM B(BN_new());
  ScopedBIGNUM n(BN_new());
  ScopedBN_MONT_CTX mont(BN_MONT_CTX_new());
  if (!a || !b || !c || !d || !A || !B || !n || !mont) {
    return false;
  }

  if (!BN_rand(a.get(), 100, 0, 0, rng) ||
      !BN_rand(b.get(), 100, 0, 0, rng)) {
    return false;
  }

  for (int i = 0; i < num2; i++) {
    int bits = (200 * (i + 1)) / num2;

    if (bits == 0) {
      continue;
    }
    if (!BN_rand(n.get(), bits, 0, 1, rng) ||
        !BN_MONT_CTX_set(mont.get(), n.get(), ctx) ||
        !BN_nnmod(a.get(), a.get(), n.get(), ctx) ||
        !BN_nnmod(b.get(), b.get(), n.get(), ctx) ||
        !BN_to_montgomery(A.get(), a.get(), mont.get(), ctx) ||
        !BN_to_montgomery(B.get(), b.get(), mont.get(), ctx) ||
        !BN_mod_mul_montgomery(c.get(), A.get(), B.get(), mont.get(), ctx) ||
        !BN_from_montgomery(A.get(), c.get(), mont.get(), ctx)) {
      return false;
    }
    if (!BN_mod_mul(d.get(), a.get(), b.get(), n.get(), ctx) ||
        !BN_sub(d.get(), d.get(), A.get())) {
      return false;
    }
    if (!BN_is_zero(d.get())) {
      fprintf(stderr, "Montgomery multiplication test failed!\n");
      return false;
    }
  }

  return true;
}

static bool test_mod_mul(RAND *rng, BN_CTX *ctx) {
  ScopedBIGNUM a(BN_new());
  ScopedBIGNUM b(BN_new());
  ScopedBIGNUM c(BN_new());
  ScopedBIGNUM d(BN_new());
  ScopedBIGNUM e(BN_new());
  if (!a || !b || !c || !d || !e) {
    return false;
  }

  for (int j = 0; j < 3; j++) {
    if (!BN_rand(c.get(), 1024, 0, 0, rng)) {
      return false;
    }
    for (int i = 0; i < num0; i++) {
      if (!BN_rand(a.get(), 475 + i * 10, 0, 0, rng) ||
          !BN_rand(b.get(), 425 + i * 11, 0, 0, rng)) {
        return false;
      }
      a->neg = rand_neg();
      b->neg = rand_neg();
      if (!BN_mod_mul(e.get(), a.get(), b.get(), c.get(), ctx)) {
        return false;
      }
      if (!BN_mul(d.get(), a.get(), b.get(), ctx) ||
          !BN_sub(d.get(), d.get(), e.get()) ||
          !BN_div(a.get(), b.get(), d.get(), c.get(), ctx)) {
        return false;
      }
      if (!BN_is_zero(b.get())) {
        fprintf(stderr, "Modulo multiply test failed!\n");
        return false;
      }
    }
  }
  return true;
}

static bool test_mod_exp_mont(RAND *rng, BN_CTX *ctx) {
  ScopedBIGNUM a(BN_new());
  ScopedBIGNUM b(BN_new());
  ScopedBIGNUM c(BN_new());
  ScopedBIGNUM d(BN_new());
  ScopedBIGNUM e(BN_new());
  if (!a || !b || !c || !d || !e) {
    return false;
  }

  if (!BN_rand(c.get(), 30, 0, 1, rng)) {  // must be odd for montgomery
    return false;
  }
  for (int i = 0; i < num2; i++) {
    if (!BN_rand_range(a.get(), c.get(), rng) ||
        !BN_rand(b.get(), 2 + i, 0, 0, rng) ||
        !BN_mod_exp_mont(d.get(), a.get(), b.get(), c.get(), ctx, nullptr)) {
      return false;
    }

    /* TODO: add a test for the case where |a| == |m| and where |a| > |m|. */

    if (!BN_exp(e.get(), a.get(), b.get(), ctx) ||
        !BN_sub(e.get(), e.get(), d.get()) ||
        !BN_div(a.get(), b.get(), e.get(), c.get(), ctx)) {
      return false;
    }
    if (!BN_is_zero(b.get())) {
      fprintf(stderr, "Modulo exponentiation test failed!\n");
      return false;
    }
  }

   // Regression test for carry propagation bug in sqr8x_reduction.
  if (!HexToBIGNUM(&a, "050505050505") ||
      !HexToBIGNUM(&b, "02") ||
      !HexToBIGNUM(
          &c,
          "4141414141414141414141274141414141414141414141414141414141414141"
          "4141414141414141414141414141414141414141414141414141414141414141"
          "4141414141414141414141800000000000000000000000000000000000000000"
          "0000000000000000000000000000000000000000000000000000000000000000"
          "0000000000000000000000000000000000000000000000000000000000000000"
          "0000000000000000000000000000000000000000000000000000000001") ||
      !BN_mod_exp_mont(d.get(), a.get(), b.get(), c.get(), ctx, nullptr) ||
      !BN_mul(e.get(), a.get(), a.get(), ctx)) {
    return false;
  }
  if (BN_cmp(d.get(), e.get()) != 0) {
    fprintf(stderr, "BN_mod_exp_mont and BN_mul produce different results!\n");
    return false;
  }

  return true;
}

static bool test_mod_exp_mont_consttime(RAND *rng, BN_CTX *ctx) {
  ScopedBIGNUM a(BN_new());
  ScopedBIGNUM b(BN_new());
  ScopedBIGNUM c(BN_new());
  ScopedBIGNUM d(BN_new());
  ScopedBIGNUM e(BN_new());
  if (!a || !b || !c || !d || !e) {
    return false;
  }

  if (!BN_rand(c.get(), 30, 0, 1, rng)) {  // must be odd for montgomery
    return false;
  }
  for (int i = 0; i < num2; i++) {
    if (!BN_rand_range(a.get(), c.get(), rng) ||
        !BN_rand(b.get(), 2 + i, 0, 0, rng) ||
        !BN_mod_exp_mont_consttime(d.get(), a.get(), b.get(), c.get(), ctx,
                                   NULL)) {
      return false;
    }

    if (!BN_exp(e.get(), a.get(), b.get(), ctx) ||
        !BN_sub(e.get(), e.get(), d.get()) ||
        !BN_div(a.get(), b.get(), e.get(), c.get(), ctx)) {
      return false;
    }
    if (!BN_is_zero(b.get())) {
      fprintf(stderr, "Modulo exponentiation test failed!\n");
      return false;
    }
  }
  return true;
}

// Test constant-time modular exponentiation with 1024-bit inputs,
// which on x86_64 cause a different code branch to be taken.
static bool test_mod_exp_mont5(RAND *rng, BN_CTX *ctx) {
  ScopedBIGNUM a(BN_new());
  ScopedBIGNUM p(BN_new());
  ScopedBIGNUM m(BN_new());
  ScopedBIGNUM d(BN_new());
  ScopedBIGNUM e(BN_new());
  if (!a || !p || !m || !d || !e ||
      !BN_rand(m.get(), 1024, 0, 1, rng) ||  // must be odd for montgomery
      !BN_rand_range(a.get(), m.get(), rng)) {
    return false;
  }
  // Zero exponent.
  BN_zero(p.get());
  if (!BN_mod_exp_mont_consttime(d.get(), a.get(), p.get(), m.get(), ctx,
                                 NULL)) {
    return false;
  }
  if (!BN_is_one(d.get())) {
    fprintf(stderr, "Modular exponentiation test failed!\n");
    return false;
  }
  if (!BN_rand(p.get(), 1024, 0, 0, rng)) {
    return false;
  }
  // Zero input.
  BN_zero(a.get());
  if (!BN_mod_exp_mont_consttime(d.get(), a.get(), p.get(), m.get(), ctx,
                                 NULL)) {
    return false;
  }
  if (!BN_is_zero(d.get())) {
    fprintf(stderr, "Modular exponentiation test failed!\n");
    return false;
  }
  // Craft an input whose Montgomery representation is 1, i.e., shorter than the
  // modulus m, in order to test the const time precomputation
  // scattering/gathering.
  ScopedBN_MONT_CTX mont(BN_MONT_CTX_new());
  if (!mont || !BN_one(a.get()) ||
      !BN_MONT_CTX_set(mont.get(), m.get(), ctx) ||
      !BN_from_montgomery(e.get(), a.get(), mont.get(), ctx) ||
      !BN_mod_exp_mont_consttime(d.get(), e.get(), p.get(), m.get(), ctx,
                                 nullptr) ||
      !BN_mod_exp_mont(a.get(), e.get(), p.get(), m.get(), ctx, nullptr)) {
    return false;
  }
  if (BN_cmp(a.get(), d.get()) != 0) {
    fprintf(stderr, "Modular exponentiation test failed!\n");
    return false;
  }
  // Finally, some regular test vectors.
  if (!BN_rand_range(e.get(), m.get(), rng) ||
      !BN_mod_exp_mont_consttime(d.get(), e.get(), p.get(), m.get(), ctx,
                                 nullptr) ||
      !BN_mod_exp_mont(a.get(), e.get(), p.get(), m.get(), ctx, nullptr)) {
    return false;
  }
  if (BN_cmp(a.get(), d.get()) != 0) {
    fprintf(stderr, "Modular exponentiation test failed!\n");
    return false;
  }

  return true;
}

static bool test_exp(RAND *rng, BN_CTX *ctx) {
  ScopedBIGNUM a(BN_new());
  ScopedBIGNUM b(BN_new());
  ScopedBIGNUM d(BN_new());
  ScopedBIGNUM e(BN_new());
  if (!a || !b || !d || !e) {
    return false;
  }

  for (int i = 0; i < num2; i++) {
    if (!BN_rand(a.get(), 20 + i * 5, 0, 0, rng) ||
        !BN_rand(b.get(), 2 + i, 0, 0, rng) ||
        !BN_exp(d.get(), a.get(), b.get(), ctx)) {
      return false;
    }

    if (!BN_one(e.get())) {
      return false;
    }
    while (!BN_is_zero(b.get())) {
      if (!BN_mul(e.get(), e.get(), a.get(), ctx) ||
          !BN_sub(b.get(), b.get(), BN_value_one())) {
        return false;
      }
    }
    if (!BN_sub(e.get(), e.get(), d.get())) {
      return false;
    }
    if (!BN_is_zero(e.get())) {
      fprintf(stderr, "Exponentiation test failed!\n");
      return false;
    }
  }
  return true;
}

static bool TestBN2BinPadded(RAND *rng) {
  uint8_t zeros[256], out[256], reference[128];

  memset(zeros, 0, sizeof(zeros));

  // Test edge case at 0.
  ScopedBIGNUM n(BN_new());
  if (!n || !BN_bn2bin_padded(NULL, 0, n.get())) {
    fprintf(stderr,
            "BN_bn2bin_padded failed to encode 0 in an empty buffer.\n");
    return false;
  }
  memset(out, -1, sizeof(out));
  if (!BN_bn2bin_padded(out, sizeof(out), n.get())) {
    fprintf(stderr,
            "BN_bn2bin_padded failed to encode 0 in a non-empty buffer.\n");
    return false;
  }
  if (memcmp(zeros, out, sizeof(out))) {
    fprintf(stderr, "BN_bn2bin_padded did not zero buffer.\n");
    return false;
  }

  // Test a random numbers at various byte lengths.
  for (size_t bytes = 128 - 7; bytes <= 128; bytes++) {
    if (!BN_rand(n.get(), bytes * 8, 0 /* make sure top bit is 1 */,
                 0 /* don't modify bottom bit */, rng)) {
      return false;
    }
    if (BN_num_bytes(n.get()) != bytes ||
        BN_bn2bin(n.get(), reference) != bytes) {
      fprintf(stderr, "Bad result from BN_rand; bytes.\n");
      return false;
    }
    // Empty buffer should fail.
    if (BN_bn2bin_padded(NULL, 0, n.get())) {
      fprintf(stderr,
              "BN_bn2bin_padded incorrectly succeeded on empty buffer.\n");
      return false;
    }
    // One byte short should fail.
    if (BN_bn2bin_padded(out, bytes - 1, n.get())) {
      fprintf(stderr, "BN_bn2bin_padded incorrectly succeeded on short.\n");
      return false;
    }
    // Exactly right size should encode.
    if (!BN_bn2bin_padded(out, bytes, n.get()) ||
        memcmp(out, reference, bytes) != 0) {
      fprintf(stderr, "BN_bn2bin_padded gave a bad result.\n");
      return false;
    }
    // Pad up one byte extra.
    if (!BN_bn2bin_padded(out, bytes + 1, n.get()) ||
        memcmp(out + 1, reference, bytes) || memcmp(out, zeros, 1)) {
      fprintf(stderr, "BN_bn2bin_padded gave a bad result.\n");
      return false;
    }
    // Pad up to 256.
    if (!BN_bn2bin_padded(out, sizeof(out), n.get()) ||
        memcmp(out + sizeof(out) - bytes, reference, bytes) ||
        memcmp(out, zeros, sizeof(out) - bytes)) {
      fprintf(stderr, "BN_bn2bin_padded gave a bad result.\n");
      return false;
    }
  }

  return true;
}

static int BN_is_word(const BIGNUM *bn, BN_ULONG w) {
  return BN_abs_is_word(bn, w) && (w == 0 || bn->neg == 0);
}

static bool TestHex2BN() {
  ScopedBIGNUM bn;
  int ret = HexToBIGNUM(&bn, "0");
  if (ret != 1 || !BN_is_zero(bn.get()) || BN_is_negative(bn.get())) {
    fprintf(stderr, "BN_hex2bn gave a bad result.\n");
    return false;
  }

  ret = HexToBIGNUM(&bn, "256");
  if (ret != 3 || !BN_is_word(bn.get(), 0x256) || BN_is_negative(bn.get())) {
    fprintf(stderr, "BN_hex2bn gave a bad result.\n");
    return false;
  }

  ret = HexToBIGNUM(&bn, "-42");
  if (ret != 3 || !BN_abs_is_word(bn.get(), 0x42) || !BN_is_negative(bn.get())) {
    fprintf(stderr, "BN_hex2bn gave a bad result.\n");
    return false;
  }

  ret = HexToBIGNUM(&bn, "-0");
  if (ret != 2 || !BN_is_zero(bn.get()) || BN_is_negative(bn.get())) {
    fprintf(stderr, "BN_hex2bn gave a bad result.\n");
    return false;
  }

  ret = HexToBIGNUM(&bn, "abctrailing garbage is ignored");
  if (ret != 3 || !BN_is_word(bn.get(), 0xabc) || BN_is_negative(bn.get())) {
    fprintf(stderr, "BN_hex2bn gave a bad result.\n");
    return false;
  }

  return true;
}

static bool TestRand(RAND *rng) {
  ScopedBIGNUM bn(BN_new());
  if (!bn) {
    return false;
  }

  // Test BN_rand accounts for degenerate cases with |top| and |bottom|
  // parameters.
  if (!BN_rand(bn.get(), 0, 0 /* top */, 0 /* bottom */, rng) ||
      !BN_is_zero(bn.get())) {
    fprintf(stderr, "BN_rand gave a bad result.\n");
    return false;
  }
  if (!BN_rand(bn.get(), 0, 1 /* top */, 1 /* bottom */, rng) ||
      !BN_is_zero(bn.get())) {
    fprintf(stderr, "BN_rand gave a bad result.\n");
    return false;
  }

  if (!BN_rand(bn.get(), 1, 0 /* top */, 0 /* bottom */, rng) ||
      !BN_is_word(bn.get(), 1)) {
    fprintf(stderr, "BN_rand gave a bad result.\n");
    return false;
  }
  if (!BN_rand(bn.get(), 1, 1 /* top */, 0 /* bottom */, rng) ||
      !BN_is_word(bn.get(), 1)) {
    fprintf(stderr, "BN_rand gave a bad result.\n");
    return false;
  }
  if (!BN_rand(bn.get(), 1, -1 /* top */, 1 /* bottom */, rng) ||
      !BN_is_word(bn.get(), 1)) {
    fprintf(stderr, "BN_rand gave a bad result.\n");
    return false;
  }

  if (!BN_rand(bn.get(), 2, 1 /* top */, 0 /* bottom */, rng) ||
      !BN_is_word(bn.get(), 3)) {
    fprintf(stderr, "BN_rand gave a bad result.\n");
    return false;
  }

  return true;
}

static bool TestNegativeZero(BN_CTX *ctx) {
  ScopedBIGNUM a(BN_new());
  ScopedBIGNUM b(BN_new());
  ScopedBIGNUM c(BN_new());
  ScopedBIGNUM d(BN_new());
  if (!a || !b || !c || !d) {
    return false;
  }

  // Test that BN_mul never gives negative zero.
  if (!BN_set_word(a.get(), 1)) {
    return false;
  }
  BN_set_negative(a.get(), 1);
  BN_zero(b.get());
  if (!BN_mul(c.get(), a.get(), b.get(), ctx)) {
    return false;
  }
  if (!BN_is_zero(c.get()) || BN_is_negative(c.get())) {
    fprintf(stderr, "Multiplication test failed!\n");
    return false;
  }

  // Test that BN_div never gives negative zero in the quotient.
  if (!BN_set_word(a.get(), 1) ||
      !BN_set_word(b.get(), 2)) {
    return false;
  }
  BN_set_negative(a.get(), 1);
  if (!BN_div(d.get(), c.get(), a.get(), b.get(), ctx)) {
    return false;
  }
  if (!BN_is_zero(d.get()) || BN_is_negative(d.get())) {
    fprintf(stderr, "Division test failed!\n");
    return false;
  }

  // Test that BN_div never gives negative zero in the remainder.
  if (!BN_set_word(b.get(), 1)) {
    return false;
  }
  if (!BN_div(d.get(), c.get(), a.get(), b.get(), ctx)) {
    return false;
  }
  if (!BN_is_zero(c.get()) || BN_is_negative(c.get())) {
    fprintf(stderr, "Division test failed!\n");
    return false;
  }

  return true;
}

static bool TestBadModulus(BN_CTX *ctx) {
  ScopedBIGNUM a(BN_new());
  ScopedBIGNUM b(BN_new());
  ScopedBIGNUM zero(BN_new());
  ScopedBN_MONT_CTX mont(BN_MONT_CTX_new());
  if (!a || !b || !zero || !mont) {
    return false;
  }

  BN_zero(zero.get());

  if (BN_div(a.get(), b.get(), BN_value_one(), zero.get(), ctx)) {
    fprintf(stderr, "Division by zero succeeded!\n");
    return false;
  }
  ERR_clear_error();

  if (BN_mod_mul(a.get(), BN_value_one(), BN_value_one(), zero.get(), ctx)) {
    fprintf(stderr, "BN_mod_mul with zero modulus succeeded!\n");
    return false;
  }
  ERR_clear_error();

  if (BN_mod_exp_mont(a.get(), BN_value_one(), BN_value_one(), zero.get(), ctx,
                      NULL)) {
    fprintf(stderr, "BN_mod_exp_mont with zero modulus succeeded!\n");
    return 0;
  }
  ERR_clear_error();

  if (BN_mod_exp_mont_consttime(a.get(), BN_value_one(), BN_value_one(),
                                zero.get(), ctx, nullptr)) {
    fprintf(stderr, "BN_mod_exp_mont_consttime with zero modulus succeeded!\n");
    return 0;
  }
  ERR_clear_error();

  if (BN_MONT_CTX_set(mont.get(), zero.get(), ctx)) {
    fprintf(stderr, "BN_MONT_CTX_set succeeded for zero modulus!\n");
    return false;
  }
  ERR_clear_error();

  // Some operations also may not be used with an even modulus.

  if (!BN_set_word(b.get(), 16)) {
    return false;
  }

  if (BN_MONT_CTX_set(mont.get(), b.get(), ctx)) {
    fprintf(stderr, "BN_MONT_CTX_set succeeded for even modulus!\n");
    return false;
  }
  ERR_clear_error();

  if (BN_mod_exp_mont(a.get(), BN_value_one(), BN_value_one(), b.get(), ctx,
                      NULL)) {
    fprintf(stderr, "BN_mod_exp_mont with even modulus succeeded!\n");
    return 0;
  }
  ERR_clear_error();

  if (BN_mod_exp_mont_consttime(a.get(), BN_value_one(), BN_value_one(),
                                b.get(), ctx, nullptr)) {
    fprintf(stderr, "BN_mod_exp_mont_consttime with even modulus succeeded!\n");
    return 0;
  }
  ERR_clear_error();

  return true;
}

// TestExpModZero tests that 1**0 mod 1 == 0.
static bool TestExpModZero(RAND *rng) {
  ScopedBIGNUM zero(BN_new()), a(BN_new()), r(BN_new());
  if (!zero || !a || !r || !BN_rand(a.get(), 1024, 0, 0, rng)) {
    return false;
  }
  BN_zero(zero.get());

  if (!BN_mod_exp_mont(r.get(), a.get(), zero.get(), BN_value_one(), nullptr,
                       nullptr) ||
      !BN_is_zero(r.get()) ||
      !BN_mod_exp_mont_consttime(r.get(), a.get(), zero.get(), BN_value_one(),
                                 nullptr, nullptr) ||
      !BN_is_zero(r.get())) {
    return false;
  }

  return true;
}
