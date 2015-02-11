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

#include <stdio.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/mem.h>

#include "internal.h"


static const int num0 = 100; /* number of tests */
static const int num1 = 50;  /* additional tests for some functions */
static const int num2 = 5;   /* number of tests for slow functions */

int test_add(BIO *bp);
int test_sub(BIO *bp);
int test_lshift1(BIO *bp);
int test_lshift(BIO *bp, BN_CTX *ctx, BIGNUM *a_);
int test_rshift1(BIO *bp);
int test_rshift(BIO *bp, BN_CTX *ctx);
int test_sqr(BIO *bp, BN_CTX *ctx);
int test_mul(BIO *bp);
int test_div(BIO *bp, BN_CTX *ctx);
int rand_neg(void);

int test_div_word(BIO *bp);
int test_mont(BIO *bp, BN_CTX *ctx);
int test_mod(BIO *bp, BN_CTX *ctx);
int test_mod_mul(BIO *bp, BN_CTX *ctx);
int test_mod_exp(BIO *bp, BN_CTX *ctx);
int test_mod_exp_mont_consttime(BIO *bp, BN_CTX *ctx);
int test_exp(BIO *bp, BN_CTX *ctx);
int test_mod_sqrt(BIO *bp, BN_CTX *ctx);
static int test_exp_mod_zero(void);
int test_small_prime(BIO *bp,BN_CTX *ctx);
int test_mod_exp_mont5(BIO *bp, BN_CTX *ctx);
int test_sqrt(BIO *bp, BN_CTX *ctx);
int test_bn2bin_padded(BIO *bp, BN_CTX *ctx);
#if 0
int test_gf2m_add(BIO *bp);
int test_gf2m_mod(BIO *bp);
int test_gf2m_mod_mul(BIO *bp, BN_CTX *ctx);
int test_gf2m_mod_sqr(BIO *bp, BN_CTX *ctx);
int test_gf2m_mod_inv(BIO *bp, BN_CTX *ctx);
int test_gf2m_mod_div(BIO *bp, BN_CTX *ctx);
int test_gf2m_mod_exp(BIO *bp, BN_CTX *ctx);
int test_gf2m_mod_sqrt(BIO *bp, BN_CTX *ctx);
int test_gf2m_mod_solve_quad(BIO *bp, BN_CTX *ctx);
#endif
static int results = 0;

static unsigned char lst[] =
    "\xC6\x4F\x43\x04\x2A\xEA\xCA\x6E\x58\x36\x80\x5B\xE8\xC9"
    "\x9B\x04\x5D\x48\x36\xC2\xFD\x16\xC9\x64\xF0";

static void ERR_print_errors_fp(FILE *out) {
}

static void message(BIO *out, char *m) {
  BIO_puts(out, "print \"test ");
  BIO_puts(out, m);
  BIO_puts(out, "\\n\"\n");
}

int main(int argc, char *argv[]) {
  BN_CTX *ctx;
  BIO *out = NULL;
  char *outfile = NULL;

  CRYPTO_library_init();

  results = 0;

  argc--;
  argv++;
  while (argc >= 1) {
    if (strcmp(*argv, "-results") == 0) {
      results = 1;
    } else if (strcmp(*argv, "-out") == 0) {
      if (--argc < 1) {
        break;
      }
      outfile = *(++argv);
    }
    argc--;
    argv++;
  }


  ctx = BN_CTX_new();
  if (ctx == NULL) {
    return 1;
  }

  out = BIO_new(BIO_s_file());
  if (out == NULL) {
    return 1;
  }

  if (outfile == NULL) {
    BIO_set_fp(out, stdout, BIO_NOCLOSE);
  } else {
    if (!BIO_write_filename(out, outfile)) {
      perror(outfile);
      return 1;
    }
  }

  if (!results) {
    BIO_puts(out, "obase=16\nibase=16\n");
  }

  message(out, "BN_add");
  if (!test_add(out)) {
    goto err;
  }
  (void)BIO_flush(out);

  message(out, "BN_sub");
  if (!test_sub(out)) {
    goto err;
  }
  (void)BIO_flush(out);

  message(out, "BN_lshift1");
  if (!test_lshift1(out)) {
    goto err;
  }
  (void)BIO_flush(out);

  message(out, "BN_lshift (fixed)");
  if (!test_lshift(out, ctx, BN_bin2bn(lst, sizeof(lst) - 1, NULL))) {
    goto err;
  }
  (void)BIO_flush(out);

  message(out, "BN_lshift");
  if (!test_lshift(out, ctx, NULL)) {
    goto err;
  }
  (void)BIO_flush(out);

  message(out, "BN_rshift1");
  if (!test_rshift1(out)) {
    goto err;
  }
  (void)BIO_flush(out);

  message(out, "BN_rshift");
  if (!test_rshift(out, ctx)) {
    goto err;
  }
  (void)BIO_flush(out);

  message(out, "BN_sqr");
  if (!test_sqr(out, ctx)) {
    goto err;
  }
  (void)BIO_flush(out);

  message(out, "BN_mul");
  if (!test_mul(out)) {
    goto err;
  }
  (void)BIO_flush(out);

  message(out, "BN_div");
  if (!test_div(out, ctx)) {
    goto err;
  }
  (void)BIO_flush(out);

  message(out, "BN_div_word");
  if (!test_div_word(out)) {
    goto err;
  }
  (void)BIO_flush(out);

  message(out, "BN_mod");
  if (!test_mod(out, ctx)) {
    goto err;
  }
  (void)BIO_flush(out);

  message(out, "BN_mod_mul");
  if (!test_mod_mul(out, ctx)) {
    goto err;
  }
  (void)BIO_flush(out);

  message(out, "BN_mont");
  if (!test_mont(out, ctx)) {
    goto err;
  }
  (void)BIO_flush(out);

  message(out, "BN_mod_exp");
  if (!test_mod_exp(out, ctx)) {
    goto err;
  }
  (void)BIO_flush(out);

  message(out, "BN_mod_exp_mont_consttime");
  if (!test_mod_exp_mont_consttime(out, ctx) ||
      !test_mod_exp_mont5(out, ctx)) {
    goto err;
  }
  (void)BIO_flush(out);

  message(out, "BN_exp");
  if (!test_exp(out, ctx) ||
      !test_exp_mod_zero()) {
    goto err;
  }
  (void)BIO_flush(out);

  message(out, "BN_mod_sqrt");
  if (!test_mod_sqrt(out, ctx)) {
    goto err;
  }
  (void)BIO_flush(out);

  message(out, "Small prime generation");
  if (!test_small_prime(out, ctx)) {
    goto err;
  }
  (void)BIO_flush(out);

  message(out, "BN_sqrt");
  if (!test_sqrt(out, ctx)) {
    goto err;
  }
  (void)BIO_flush(out);

  message(out, "BN_bn2bin_padded");
  if (!test_bn2bin_padded(out, ctx)) {
    goto err;
  }
  (void)BIO_flush(out);

  BN_CTX_free(ctx);
  BIO_free(out);

  printf("PASS\n");
  return 0;

err:
  BIO_puts(out, "1\n"); /* make sure the Perl script fed by bc notices
                         * the failure, see test_bn in test/Makefile.ssl*/
  (void)BIO_flush(out);

  return 1;
}

int test_add(BIO *bp) {
  BIGNUM a, b, c;
  int i;

  BN_init(&a);
  BN_init(&b);
  BN_init(&c);

  BN_rand(&a, 512, 0, 0);
  for (i = 0; i < num0; i++) {
    BN_rand(&b, 450 + i, 0, 0);
    a.neg = rand_neg();
    b.neg = rand_neg();
    BN_add(&c, &a, &b);
    if (bp != NULL) {
      if (!results) {
        BN_print(bp, &a);
        BIO_puts(bp, " + ");
        BN_print(bp, &b);
        BIO_puts(bp, " - ");
      }
      BN_print(bp, &c);
      BIO_puts(bp, "\n");
    }
    a.neg = !a.neg;
    b.neg = !b.neg;
    BN_add(&c, &c, &b);
    BN_add(&c, &c, &a);
    if (!BN_is_zero(&c)) {
      fprintf(stderr, "Add test failed!\n");
      return 0;
    }
  }
  BN_free(&a);
  BN_free(&b);
  BN_free(&c);
  return (1);
}

int test_sub(BIO *bp) {
  BIGNUM a, b, c;
  int i;

  BN_init(&a);
  BN_init(&b);
  BN_init(&c);

  for (i = 0; i < num0 + num1; i++) {
    if (i < num1) {
      BN_rand(&a, 512, 0, 0);
      BN_copy(&b, &a);
      if (BN_set_bit(&a, i) == 0) {
        return (0);
      }
      BN_add_word(&b, i);
    } else {
      BN_rand(&b, 400 + i - num1, 0, 0);
      a.neg = rand_neg();
      b.neg = rand_neg();
    }
    BN_sub(&c, &a, &b);
    if (bp != NULL) {
      if (!results) {
        BN_print(bp, &a);
        BIO_puts(bp, " - ");
        BN_print(bp, &b);
        BIO_puts(bp, " - ");
      }
      BN_print(bp, &c);
      BIO_puts(bp, "\n");
    }
    BN_add(&c, &c, &b);
    BN_sub(&c, &c, &a);
    if (!BN_is_zero(&c)) {
      fprintf(stderr, "Subtract test failed!\n");
      return 0;
    }
  }
  BN_free(&a);
  BN_free(&b);
  BN_free(&c);
  return (1);
}

int test_div(BIO *bp, BN_CTX *ctx) {
  BIGNUM a, b, c, d, e;
  int i;

  BN_init(&a);
  BN_init(&b);
  BN_init(&c);
  BN_init(&d);
  BN_init(&e);

  for (i = 0; i < num0 + num1; i++) {
    if (i < num1) {
      BN_rand(&a, 400, 0, 0);
      BN_copy(&b, &a);
      BN_lshift(&a, &a, i);
      BN_add_word(&a, i);
    } else {
      BN_rand(&b, 50 + 3 * (i - num1), 0, 0);
    }
    a.neg = rand_neg();
    b.neg = rand_neg();
    BN_div(&d, &c, &a, &b, ctx);
    if (bp != NULL) {
      if (!results) {
        BN_print(bp, &a);
        BIO_puts(bp, " / ");
        BN_print(bp, &b);
        BIO_puts(bp, " - ");
      }
      BN_print(bp, &d);
      BIO_puts(bp, "\n");

      if (!results) {
        BN_print(bp, &a);
        BIO_puts(bp, " % ");
        BN_print(bp, &b);
        BIO_puts(bp, " - ");
      }
      BN_print(bp, &c);
      BIO_puts(bp, "\n");
    }
    BN_mul(&e, &d, &b, ctx);
    BN_add(&d, &e, &c);
    BN_sub(&d, &d, &a);
    if (!BN_is_zero(&d)) {
      fprintf(stderr, "Division test failed!\n");
      return 0;
    }
  }
  BN_free(&a);
  BN_free(&b);
  BN_free(&c);
  BN_free(&d);
  BN_free(&e);
  return (1);
}

int test_lshift1(BIO *bp) {
  BIGNUM *a, *b, *c;
  int i;

  a = BN_new();
  b = BN_new();
  c = BN_new();

  BN_rand(a, 200, 0, 0); /**/
  a->neg = rand_neg();
  for (i = 0; i < num0; i++) {
    BN_lshift1(b, a);
    if (bp != NULL) {
      if (!results) {
        BN_print(bp, a);
        BIO_puts(bp, " * 2");
        BIO_puts(bp, " - ");
      }
      BN_print(bp, b);
      BIO_puts(bp, "\n");
    }
    BN_add(c, a, a);
    BN_sub(a, b, c);
    if (!BN_is_zero(a)) {
      fprintf(stderr, "Left shift one test failed!\n");
      return 0;
    }

    BN_copy(a, b);
  }
  BN_free(a);
  BN_free(b);
  BN_free(c);
  return (1);
}

int test_rshift(BIO *bp, BN_CTX *ctx) {
  BIGNUM *a, *b, *c, *d, *e;
  int i;

  a = BN_new();
  b = BN_new();
  c = BN_new();
  d = BN_new();
  e = BN_new();
  BN_one(c);

  BN_rand(a, 200, 0, 0); /**/
  a->neg = rand_neg();
  for (i = 0; i < num0; i++) {
    BN_rshift(b, a, i + 1);
    BN_add(c, c, c);
    if (bp != NULL) {
      if (!results) {
        BN_print(bp, a);
        BIO_puts(bp, " / ");
        BN_print(bp, c);
        BIO_puts(bp, " - ");
      }
      BN_print(bp, b);
      BIO_puts(bp, "\n");
    }
    BN_div(d, e, a, c, ctx);
    BN_sub(d, d, b);
    if (!BN_is_zero(d)) {
      fprintf(stderr, "Right shift test failed!\n");
      return 0;
    }
  }
  BN_free(a);
  BN_free(b);
  BN_free(c);
  BN_free(d);
  BN_free(e);
  return (1);
}

int test_rshift1(BIO *bp) {
  BIGNUM *a, *b, *c;
  int i;

  a = BN_new();
  b = BN_new();
  c = BN_new();

  BN_rand(a, 200, 0, 0); /**/
  a->neg = rand_neg();
  for (i = 0; i < num0; i++) {
    BN_rshift1(b, a);
    if (bp != NULL) {
      if (!results) {
        BN_print(bp, a);
        BIO_puts(bp, " / 2");
        BIO_puts(bp, " - ");
      }
      BN_print(bp, b);
      BIO_puts(bp, "\n");
    }
    BN_sub(c, a, b);
    BN_sub(c, c, b);
    if (!BN_is_zero(c) && !BN_abs_is_word(c, 1)) {
      fprintf(stderr, "Right shift one test failed!\n");
      return 0;
    }
    BN_copy(a, b);
  }
  BN_free(a);
  BN_free(b);
  BN_free(c);
  return (1);
}

int test_lshift(BIO *bp, BN_CTX *ctx, BIGNUM *a_) {
  BIGNUM *a, *b, *c, *d;
  int i;

  b = BN_new();
  c = BN_new();
  d = BN_new();
  BN_one(c);

  if (a_) {
    a = a_;
  } else {
    a = BN_new();
    BN_rand(a, 200, 0, 0); /**/
    a->neg = rand_neg();
  }
  for (i = 0; i < num0; i++) {
    BN_lshift(b, a, i + 1);
    BN_add(c, c, c);
    if (bp != NULL) {
      if (!results) {
        BN_print(bp, a);
        BIO_puts(bp, " * ");
        BN_print(bp, c);
        BIO_puts(bp, " - ");
      }
      BN_print(bp, b);
      BIO_puts(bp, "\n");
    }
    BN_mul(d, a, c, ctx);
    BN_sub(d, d, b);
    if (!BN_is_zero(d)) {
      fprintf(stderr, "Left shift test failed!\n");
      fprintf(stderr, "a=");
      BN_print_fp(stderr, a);
      fprintf(stderr, "\nb=");
      BN_print_fp(stderr, b);
      fprintf(stderr, "\nc=");
      BN_print_fp(stderr, c);
      fprintf(stderr, "\nd=");
      BN_print_fp(stderr, d);
      fprintf(stderr, "\n");
      return 0;
    }
  }
  BN_free(a);
  BN_free(b);
  BN_free(c);
  BN_free(d);
  return (1);
}

int test_mul(BIO *bp) {
  BIGNUM a, b, c, d, e;
  int i;
  BN_CTX *ctx;

  ctx = BN_CTX_new();
  if (ctx == NULL) {
    abort();
  }

  BN_init(&a);
  BN_init(&b);
  BN_init(&c);
  BN_init(&d);
  BN_init(&e);

  for (i = 0; i < num0 + num1; i++) {
    if (i <= num1) {
      BN_rand(&a, 100, 0, 0);
      BN_rand(&b, 100, 0, 0);
    } else {
      BN_rand(&b, i - num1, 0, 0);
    }
    a.neg = rand_neg();
    b.neg = rand_neg();
    BN_mul(&c, &a, &b, ctx);
    if (bp != NULL) {
      if (!results) {
        BN_print(bp, &a);
        BIO_puts(bp, " * ");
        BN_print(bp, &b);
        BIO_puts(bp, " - ");
      }
      BN_print(bp, &c);
      BIO_puts(bp, "\n");
    }
    BN_div(&d, &e, &c, &a, ctx);
    BN_sub(&d, &d, &b);
    if (!BN_is_zero(&d) || !BN_is_zero(&e)) {
      fprintf(stderr, "Multiplication test failed!\n");
      return 0;
    }
  }
  BN_free(&a);
  BN_free(&b);
  BN_free(&c);
  BN_free(&d);
  BN_free(&e);
  BN_CTX_free(ctx);
  return (1);
}

int test_sqr(BIO *bp, BN_CTX *ctx) {
  BIGNUM *a, *c, *d, *e;
  int i, ret = 0;

  a = BN_new();
  c = BN_new();
  d = BN_new();
  e = BN_new();
  if (a == NULL || c == NULL || d == NULL || e == NULL) {
    goto err;
  }

  for (i = 0; i < num0; i++) {
    BN_rand(a, 40 + i * 10, 0, 0);
    a->neg = rand_neg();
    BN_sqr(c, a, ctx);
    if (bp != NULL) {
      if (!results) {
        BN_print(bp, a);
        BIO_puts(bp, " * ");
        BN_print(bp, a);
        BIO_puts(bp, " - ");
      }
      BN_print(bp, c);
      BIO_puts(bp, "\n");
    }
    BN_div(d, e, c, a, ctx);
    BN_sub(d, d, a);
    if (!BN_is_zero(d) || !BN_is_zero(e)) {
      fprintf(stderr, "Square test failed!\n");
      goto err;
    }
  }

  /* Regression test for a BN_sqr overflow bug. */
  BN_hex2bn(&a,
            "80000000000000008000000000000001FFFFFFFFFFFFFFFE0000000000000000");
  BN_sqr(c, a, ctx);
  if (bp != NULL) {
    if (!results) {
      BN_print(bp, a);
      BIO_puts(bp, " * ");
      BN_print(bp, a);
      BIO_puts(bp, " - ");
    }
    BN_print(bp, c);
    BIO_puts(bp, "\n");
  }
  BN_mul(d, a, a, ctx);
  if (BN_cmp(c, d)) {
    fprintf(stderr,
            "Square test failed: BN_sqr and BN_mul produce "
            "different results!\n");
    goto err;
  }

  /* Regression test for a BN_sqr overflow bug. */
  BN_hex2bn(&a,
            "80000000000000000000000080000001FFFFFFFE000000000000000000000000");
  BN_sqr(c, a, ctx);
  if (bp != NULL) {
    if (!results) {
      BN_print(bp, a);
      BIO_puts(bp, " * ");
      BN_print(bp, a);
      BIO_puts(bp, " - ");
    }
    BN_print(bp, c);
    BIO_puts(bp, "\n");
  }
  BN_mul(d, a, a, ctx);
  if (BN_cmp(c, d)) {
    fprintf(stderr,
            "Square test failed: BN_sqr and BN_mul produce "
            "different results!\n");
    goto err;
  }
  ret = 1;

err:
  if (a != NULL) {
    BN_free(a);
  }
  if (c != NULL) {
    BN_free(c);
  }
  if (d != NULL) {
    BN_free(d);
  }
  if (e != NULL) {
    BN_free(e);
  }
  return ret;
}


int rand_neg(void) {
  static unsigned int neg = 0;
  static int sign[8] = {0, 0, 0, 1, 1, 0, 1, 1};

  return (sign[(neg++) % 8]);
}

static void print_word(BIO *bp, BN_ULONG w) {
  BIO_printf(bp, BN_HEX_FMT1, w);
}

int test_div_word(BIO *bp) {
  BIGNUM a, b;
  BN_ULONG r, s;
  int i;

  BN_init(&a);
  BN_init(&b);

  for (i = 0; i < num0; i++) {
    do {
      BN_rand(&a, 512, -1, 0);
      BN_rand(&b, BN_BITS2, -1, 0);
      s = b.d[0];
    } while (!s);

    BN_copy(&b, &a);
    r = BN_div_word(&b, s);

    if (bp != NULL) {
      if (!results) {
        BN_print(bp, &a);
        BIO_puts(bp, " / ");
        print_word(bp, s);
        BIO_puts(bp, " - ");
      }
      BN_print(bp, &b);
      BIO_puts(bp, "\n");

      if (!results) {
        BN_print(bp, &a);
        BIO_puts(bp, " % ");
        print_word(bp, s);
        BIO_puts(bp, " - ");
      }
      print_word(bp, r);
      BIO_puts(bp, "\n");
    }
    BN_mul_word(&b, s);
    BN_add_word(&b, r);
    BN_sub(&b, &a, &b);
    if (!BN_is_zero(&b)) {
      fprintf(stderr, "Division (word) test failed!\n");
      return 0;
    }
  }
  BN_free(&a);
  BN_free(&b);
  return (1);
}

int test_mont(BIO *bp, BN_CTX *ctx) {
  BIGNUM a, b, c, d, A, B;
  BIGNUM n;
  int i;
  BN_MONT_CTX *mont;

  BN_init(&a);
  BN_init(&b);
  BN_init(&c);
  BN_init(&d);
  BN_init(&A);
  BN_init(&B);
  BN_init(&n);

  mont = BN_MONT_CTX_new();
  if (mont == NULL) {
    return 0;
  }

  BN_rand(&a, 100, 0, 0); /**/
  BN_rand(&b, 100, 0, 0); /**/
  for (i = 0; i < num2; i++) {
    int bits = (200 * (i + 1)) / num2;

    if (bits == 0) {
      continue;
    }
    BN_rand(&n, bits, 0, 1);
    BN_MONT_CTX_set(mont, &n, ctx);

    BN_nnmod(&a, &a, &n, ctx);
    BN_nnmod(&b, &b, &n, ctx);

    BN_to_montgomery(&A, &a, mont, ctx);
    BN_to_montgomery(&B, &b, mont, ctx);

    BN_mod_mul_montgomery(&c, &A, &B, mont, ctx); /**/
    BN_from_montgomery(&A, &c, mont, ctx);        /**/
    if (bp != NULL) {
      if (!results) {
#ifdef undef
        fprintf(stderr, "%d * %d %% %d\n", BN_num_bits(&a), BN_num_bits(&b),
                BN_num_bits(mont->N));
#endif
        BN_print(bp, &a);
        BIO_puts(bp, " * ");
        BN_print(bp, &b);
        BIO_puts(bp, " % ");
        BN_print(bp, &(mont->N));
        BIO_puts(bp, " - ");
      }
      BN_print(bp, &A);
      BIO_puts(bp, "\n");
    }
    BN_mod_mul(&d, &a, &b, &n, ctx);
    BN_sub(&d, &d, &A);
    if (!BN_is_zero(&d)) {
      fprintf(stderr, "Montgomery multiplication test failed!\n");
      return 0;
    }
  }
  BN_MONT_CTX_free(mont);
  BN_free(&a);
  BN_free(&b);
  BN_free(&c);
  BN_free(&d);
  BN_free(&A);
  BN_free(&B);
  BN_free(&n);
  return (1);
}

int test_mod(BIO *bp, BN_CTX *ctx) {
  BIGNUM *a, *b, *c, *d, *e;
  int i;

  a = BN_new();
  b = BN_new();
  c = BN_new();
  d = BN_new();
  e = BN_new();

  BN_rand(a, 1024, 0, 0); /**/
  for (i = 0; i < num0; i++) {
    BN_rand(b, 450 + i * 10, 0, 0); /**/
    a->neg = rand_neg();
    b->neg = rand_neg();
    BN_mod(c, a, b, ctx); /**/
    if (bp != NULL) {
      if (!results) {
        BN_print(bp, a);
        BIO_puts(bp, " % ");
        BN_print(bp, b);
        BIO_puts(bp, " - ");
      }
      BN_print(bp, c);
      BIO_puts(bp, "\n");
    }
    BN_div(d, e, a, b, ctx);
    BN_sub(e, e, c);
    if (!BN_is_zero(e)) {
      fprintf(stderr, "Modulo test failed!\n");
      return 0;
    }
  }
  BN_free(a);
  BN_free(b);
  BN_free(c);
  BN_free(d);
  BN_free(e);
  return (1);
}

int test_mod_mul(BIO *bp, BN_CTX *ctx) {
  BIGNUM *a, *b, *c, *d, *e;
  int i, j;

  a = BN_new();
  b = BN_new();
  c = BN_new();
  d = BN_new();
  e = BN_new();

  for (j = 0; j < 3; j++) {
    BN_rand(c, 1024, 0, 0); /**/
    for (i = 0; i < num0; i++) {
      BN_rand(a, 475 + i * 10, 0, 0); /**/
      BN_rand(b, 425 + i * 11, 0, 0); /**/
      a->neg = rand_neg();
      b->neg = rand_neg();
      if (!BN_mod_mul(e, a, b, c, ctx)) {
        unsigned long l;

        while ((l = ERR_get_error())) {
          fprintf(stderr, "ERROR:%s\n", ERR_error_string(l, NULL));
        }
        abort();
      }
      if (bp != NULL) {
        if (!results) {
          BN_print(bp, a);
          BIO_puts(bp, " * ");
          BN_print(bp, b);
          BIO_puts(bp, " % ");
          BN_print(bp, c);
          if ((a->neg ^ b->neg) && !BN_is_zero(e)) {
            /* If  (a*b) % c  is negative,  c  must be added
             * in order to obtain the normalized remainder
             * (new with OpenSSL 0.9.7, previous versions of
             * BN_mod_mul could generate negative results)
             */
            BIO_puts(bp, " + ");
            BN_print(bp, c);
          }
          BIO_puts(bp, " - ");
        }
        BN_print(bp, e);
        BIO_puts(bp, "\n");
      }
      BN_mul(d, a, b, ctx);
      BN_sub(d, d, e);
      BN_div(a, b, d, c, ctx);
      if (!BN_is_zero(b)) {
        fprintf(stderr, "Modulo multiply test failed!\n");
        ERR_print_errors_fp(stderr);
        return 0;
      }
    }
  }
  BN_free(a);
  BN_free(b);
  BN_free(c);
  BN_free(d);
  BN_free(e);
  return (1);
}

int test_mod_exp(BIO *bp, BN_CTX *ctx) {
  BIGNUM *a, *b, *c, *d, *e;
  int i;

  a = BN_new();
  b = BN_new();
  c = BN_new();
  d = BN_new();
  e = BN_new();

  BN_rand(c, 30, 0, 1); /* must be odd for montgomery */
  for (i = 0; i < num2; i++) {
    BN_rand(a, 20 + i * 5, 0, 0); /**/
    BN_rand(b, 2 + i, 0, 0);      /**/

    if (!BN_mod_exp(d, a, b, c, ctx)) {
      return (0);
    }

    if (bp != NULL) {
      if (!results) {
        BN_print(bp, a);
        BIO_puts(bp, " ^ ");
        BN_print(bp, b);
        BIO_puts(bp, " % ");
        BN_print(bp, c);
        BIO_puts(bp, " - ");
      }
      BN_print(bp, d);
      BIO_puts(bp, "\n");
    }
    BN_exp(e, a, b, ctx);
    BN_sub(e, e, d);
    BN_div(a, b, e, c, ctx);
    if (!BN_is_zero(b)) {
      fprintf(stderr, "Modulo exponentiation test failed!\n");
      return 0;
    }
  }
  BN_free(a);
  BN_free(b);
  BN_free(c);
  BN_free(d);
  BN_free(e);
  return (1);
}

int test_mod_exp_mont_consttime(BIO *bp, BN_CTX *ctx) {
  BIGNUM *a, *b, *c, *d, *e;
  int i;

  a = BN_new();
  b = BN_new();
  c = BN_new();
  d = BN_new();
  e = BN_new();

  BN_rand(c, 30, 0, 1); /* must be odd for montgomery */
  for (i = 0; i < num2; i++) {
    BN_rand(a, 20 + i * 5, 0, 0); /**/
    BN_rand(b, 2 + i, 0, 0);      /**/

    if (!BN_mod_exp_mont_consttime(d, a, b, c, ctx, NULL)) {
      return (00);
    }

    if (bp != NULL) {
      if (!results) {
        BN_print(bp, a);
        BIO_puts(bp, " ^ ");
        BN_print(bp, b);
        BIO_puts(bp, " % ");
        BN_print(bp, c);
        BIO_puts(bp, " - ");
      }
      BN_print(bp, d);
      BIO_puts(bp, "\n");
    }
    BN_exp(e, a, b, ctx);
    BN_sub(e, e, d);
    BN_div(a, b, e, c, ctx);
    if (!BN_is_zero(b)) {
      fprintf(stderr, "Modulo exponentiation test failed!\n");
      return 0;
    }
  }
  BN_free(a);
  BN_free(b);
  BN_free(c);
  BN_free(d);
  BN_free(e);
  return (1);
}

/* Test constant-time modular exponentiation with 1024-bit inputs,
 * which on x86_64 cause a different code branch to be taken. */
int test_mod_exp_mont5(BIO *bp, BN_CTX *ctx) {
  BIGNUM *a, *p, *m, *d, *e;

  BN_MONT_CTX *mont;

  a = BN_new();
  p = BN_new();
  m = BN_new();
  d = BN_new();
  e = BN_new();

  mont = BN_MONT_CTX_new();

  BN_rand(m, 1024, 0, 1); /* must be odd for montgomery */
  /* Zero exponent */
  BN_rand(a, 1024, 0, 0);
  BN_zero(p);
  if (!BN_mod_exp_mont_consttime(d, a, p, m, ctx, NULL)) {
    return 0;
  }
  if (!BN_is_one(d)) {
    fprintf(stderr, "Modular exponentiation test failed!\n");
    return 0;
  }
  /* Zero input */
  BN_rand(p, 1024, 0, 0);
  BN_zero(a);
  if (!BN_mod_exp_mont_consttime(d, a, p, m, ctx, NULL)) {
    return 0;
  }
  if (!BN_is_zero(d)) {
    fprintf(stderr, "Modular exponentiation test failed!\n");
    return 0;
  }
  /* Craft an input whose Montgomery representation is 1,
   * i.e., shorter than the modulus m, in order to test
   * the const time precomputation scattering/gathering.
   */
  BN_one(a);
  BN_MONT_CTX_set(mont, m, ctx);
  if (!BN_from_montgomery(e, a, mont, ctx) ||
      !BN_mod_exp_mont_consttime(d, e, p, m, ctx, NULL) ||
      !BN_mod_exp(a, e, p, m, ctx)) {
    return 0;
  }
  if (BN_cmp(a, d) != 0) {
    fprintf(stderr, "Modular exponentiation test failed!\n");
    return 0;
  }
  /* Finally, some regular test vectors. */
  BN_rand(e, 1024, 0, 0);
  if (!BN_mod_exp_mont_consttime(d, e, p, m, ctx, NULL) ||
      !BN_mod_exp(a, e, p, m, ctx)) {
    return 0;
  }
  if (BN_cmp(a, d) != 0) {
    fprintf(stderr, "Modular exponentiation test failed!\n");
    return 0;
  }

  BN_MONT_CTX_free(mont);
  BN_free(a);
  BN_free(p);
  BN_free(m);
  BN_free(d);
  BN_free(e);
  return 1;
}

int test_exp(BIO *bp, BN_CTX *ctx) {
  BIGNUM *a, *b, *d, *e, *one;
  int i;

  a = BN_new();
  b = BN_new();
  d = BN_new();
  e = BN_new();
  one = BN_new();
  BN_one(one);

  for (i = 0; i < num2; i++) {
    BN_rand(a, 20 + i * 5, 0, 0); /**/
    BN_rand(b, 2 + i, 0, 0);      /**/

    if (BN_exp(d, a, b, ctx) <= 0) {
      return (0);
    }

    if (bp != NULL) {
      if (!results) {
        BN_print(bp, a);
        BIO_puts(bp, " ^ ");
        BN_print(bp, b);
        BIO_puts(bp, " - ");
      }
      BN_print(bp, d);
      BIO_puts(bp, "\n");
    }
    BN_one(e);
    for (; !BN_is_zero(b); BN_sub(b, b, one)) {
      BN_mul(e, e, a, ctx);
    }
    BN_sub(e, e, d);
    if (!BN_is_zero(e)) {
      fprintf(stderr, "Exponentiation test failed!\n");
      return 0;
    }
  }
  BN_free(a);
  BN_free(b);
  BN_free(d);
  BN_free(e);
  BN_free(one);
  return 1;
}

/* test_exp_mod_zero tests that x**0 mod 1 == 0. */
static int test_exp_mod_zero(void) {
  BIGNUM a, p, m;
  BIGNUM r;
  BN_CTX *ctx = BN_CTX_new();
  int ret = 0;

  BN_init(&m);
  BN_one(&m);

  BN_init(&a);
  BN_one(&a);

  BN_init(&p);
  BN_zero(&p);

  BN_init(&r);
  BN_mod_exp(&r, &a, &p, &m, ctx);
  BN_CTX_free(ctx);

  if (BN_is_zero(&r)) {
    ret = 1;
  } else {
    printf("1**0 mod 1 = ");
    BN_print_fp(stdout, &r);
    printf(", should be 0\n");
  }

  BN_free(&r);
  BN_free(&a);
  BN_free(&p);
  BN_free(&m);

  return ret;
}

static int genprime_cb(int p, int n, BN_GENCB *arg) {
  char c = '*';

  if (p == 0) {
    c = '.';
  } else if (p == 1) {
    c = '+';
  } else if (p == 2) {
    c = '*';
  } else if (p == 3) {
    c = '\n';
  }
  putc(c, stdout);
  fflush(stdout);
  return 1;
}

int test_mod_sqrt(BIO *bp, BN_CTX *ctx) {
  BN_GENCB cb;
  BIGNUM *a, *p, *r;
  int i, j;
  int ret = 0;

  a = BN_new();
  p = BN_new();
  r = BN_new();
  if (a == NULL || p == NULL || r == NULL) {
    goto err;
  }

  BN_GENCB_set(&cb, genprime_cb, NULL);

  for (i = 0; i < 16; i++) {
    if (i < 8) {
      unsigned primes[8] = {2, 3, 5, 7, 11, 13, 17, 19};

      if (!BN_set_word(p, primes[i])) {
        goto err;
      }
    } else {
      if (!BN_set_word(a, 32) ||
          !BN_set_word(r, 2 * i + 1)) {
        goto err;
      }

      if (!BN_generate_prime_ex(p, 256, 0, a, r, &cb)) {
        goto err;
      }
      putc('\n', stdout);
    }
    p->neg = rand_neg();

    for (j = 0; j < num2; j++) {
      /* construct 'a' such that it is a square modulo p,
       * but in general not a proper square and not reduced modulo p */
      if (!BN_rand(r, 256, 0, 3) ||
          !BN_nnmod(r, r, p, ctx) ||
          !BN_mod_sqr(r, r, p, ctx) ||
          !BN_rand(a, 256, 0, 3) ||
          !BN_nnmod(a, a, p, ctx) ||
          !BN_mod_sqr(a, a, p, ctx) ||
          !BN_mul(a, a, r, ctx)) {
        goto err;
      }
      if (rand_neg() && !BN_sub(a, a, p)) {
          goto err;
      }

      if (!BN_mod_sqrt(r, a, p, ctx) ||
          !BN_mod_sqr(r, r, p, ctx) ||
          !BN_nnmod(a, a, p, ctx)) {
        goto err;
      }

      if (BN_cmp(a, r) != 0) {
        fprintf(stderr, "BN_mod_sqrt failed: a = ");
        BN_print_fp(stderr, a);
        fprintf(stderr, ", r = ");
        BN_print_fp(stderr, r);
        fprintf(stderr, ", p = ");
        BN_print_fp(stderr, p);
        fprintf(stderr, "\n");
        goto err;
      }

      putc('.', stdout);
      fflush(stdout);
    }

    putc('\n', stdout);
    fflush(stderr);
  }
  ret = 1;
err:
  if (a != NULL) {
    BN_free(a);
  }
  if (p != NULL) {
    BN_free(p);
  }
  if (r != NULL) {
    BN_free(r);
  }
  return ret;
}

int test_small_prime(BIO *bp, BN_CTX *ctx) {
  static const int bits = 10;
  int ret = 0;
  BIGNUM r;

  BN_init(&r);
  if (!BN_generate_prime_ex(&r, bits, 0, NULL, NULL, NULL)) {
    goto err;
  }
  if (BN_num_bits(&r) != bits) {
    BIO_printf(bp, "Expected %d bit prime, got %d bit number\n", bits,
               BN_num_bits(&r));
    goto err;
  }

  ret = 1;

err:
  BN_free(&r);
  return ret;
}

int test_sqrt(BIO *bp, BN_CTX *ctx) {
  BIGNUM *n = BN_new(), *nn = BN_new(), *sqrt = BN_new();
  unsigned i;

  /* Test some random squares. */
  for (i = 0; i < 100; i++) {
    if (!BN_rand(n, 1024 /* bit length */, -1 /* no modification of top bits */,
                 0 /* don't modify bottom bit */) ||
        !BN_mul(nn, n, n, ctx) ||
        !BN_sqrt(sqrt, nn, ctx)) {
      BIO_print_errors_fp(stderr);
      return 0;
    }
    if (BN_cmp(n, sqrt) != 0) {
      fprintf(stderr, "Bad result from BN_sqrt.\n");
      return 0;
    }
  }

  /* Test some non-squares */
  for (i = 0; i < 100; i++) {
    if (!BN_rand(n, 1024 /* bit length */, -1 /* no modification of top bits */,
                 0 /* don't modify bottom bit */) ||
        !BN_mul(nn, n, n, ctx) ||
        !BN_add(nn, nn, BN_value_one())) {
      BIO_print_errors_fp(stderr);
      return 0;
    }

    if (BN_sqrt(sqrt, nn, ctx)) {
      char *nn_str = BN_bn2dec(nn);
      fprintf(stderr, "BIO_sqrt didn't fail on a non-square: %s\n", nn_str);
      OPENSSL_free(nn_str);
    }
  }

  BN_free(n);
  BN_free(sqrt);
  BN_free(nn);

  return 1;
}

int test_bn2bin_padded(BIO *bp, BN_CTX *ctx) {
  BIGNUM *n = BN_new();
  uint8_t zeros[256], out[256], reference[128];
  size_t bytes;

  memset(zeros, 0, sizeof(zeros));

  /* Test edge case at 0. */
  if (!BN_bn2bin_padded(NULL, 0, n)) {
    fprintf(stderr,
            "BN_bn2bin_padded failed to encode 0 in an empty buffer.\n");
    return 0;
  }
  memset(out, -1, sizeof(out));
  if (!BN_bn2bin_padded(out, sizeof(out), n)) {
    fprintf(stderr,
            "BN_bn2bin_padded failed to encode 0 in a non-empty buffer.\n");
    return 0;
  }
  if (memcmp(zeros, out, sizeof(out))) {
    fprintf(stderr, "BN_bn2bin_padded did not zero buffer.\n");
    return 0;
  }

  /* Test a random numbers at various byte lengths. */
  for (bytes = 128 - 7; bytes <= 128; bytes++) {
    if (!BN_rand(n, bytes * 8, 0 /* make sure top bit is 1 */,
                 0 /* don't modify bottom bit */)) {
      BIO_print_errors_fp(stderr);
      return 0;
    }
    if (BN_num_bytes(n) != bytes || BN_bn2bin(n, reference) != bytes) {
      fprintf(stderr, "Bad result from BN_rand; bytes.\n");
      return 0;
    }
    /* Empty buffer should fail. */
    if (BN_bn2bin_padded(NULL, 0, n)) {
      fprintf(stderr,
              "BN_bn2bin_padded incorrectly succeeded on empty buffer.\n");
      return 0;
    }
    /* One byte short should fail. */
    if (BN_bn2bin_padded(out, bytes - 1, n)) {
      fprintf(stderr, "BN_bn2bin_padded incorrectly succeeded on short.\n");
      return 0;
    }
    /* Exactly right size should encode. */
    if (!BN_bn2bin_padded(out, bytes, n) ||
        memcmp(out, reference, bytes) != 0) {
      fprintf(stderr, "BN_bn2bin_padded gave a bad result.\n");
      return 0;
    }
    /* Pad up one byte extra. */
    if (!BN_bn2bin_padded(out, bytes + 1, n) ||
        memcmp(out + 1, reference, bytes) || memcmp(out, zeros, 1)) {
      fprintf(stderr, "BN_bn2bin_padded gave a bad result.\n");
      return 0;
    }
    /* Pad up to 256. */
    if (!BN_bn2bin_padded(out, sizeof(out), n) ||
        memcmp(out + sizeof(out) - bytes, reference, bytes) ||
        memcmp(out, zeros, sizeof(out) - bytes)) {
      fprintf(stderr, "BN_bn2bin_padded gave a bad result.\n");
      return 0;
    }
  }

  BN_free(n);

  return 1;
}
