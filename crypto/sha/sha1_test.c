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

#include <stdio.h>

#include <openssl/crypto.h>
#include <openssl/digest.h>
#include <openssl/sha.h>


static const char *const test[] = {
    "abc", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", NULL, };

static const char *const expected[] = {
    "a9993e364706816aba3e25717850c26c9cd0d89d",
    "84983e441c3bd26ebaae4aa1f95129e5e54670f1", };

static int test_incremental(void) {
  EVP_MD_CTX ctx;
  char buf[1000];
  uint8_t md[SHA_DIGEST_LENGTH];
  char md_hex[sizeof(md) * 2 + 1];
  size_t i;
  static const char expected[] = "34aa973cd4c4daa4f61eeb2bdbad27316534016f";

  memset(buf, 'a', sizeof(buf));
  EVP_MD_CTX_init(&ctx);
  EVP_DigestInit_ex(&ctx, EVP_sha1(), NULL);
  for (i = 0; i < 1000; i++) {
    EVP_DigestUpdate(&ctx, buf, sizeof(buf));
  }
  EVP_DigestFinal_ex(&ctx, md, NULL);
  EVP_MD_CTX_cleanup(&ctx);

  for (i = 0; i < sizeof(md); i++) {
    sprintf(&md_hex[i * 2], "%02x", md[i]);
  }

  if (strcmp(md_hex, expected) != 0) {
    fprintf(stderr, "test_incremental: got %s, wanted %s\n", md_hex, expected);
    return 0;
  }

  return 1;
}

int main(int argc, char **argv) {
  size_t i, j;
  uint8_t md[SHA_DIGEST_LENGTH];
  char md_hex[sizeof(md) * 2 + 1];
  int ok = 1;

  CRYPTO_library_init();

  for (i = 0; test[i] != NULL; i++) {
    EVP_Digest(test[i], strlen(test[i]), md, NULL, EVP_sha1(), NULL);
    for (j = 0; j < sizeof(md); j++) {
      sprintf(&md_hex[j * 2], "%02x", md[j]);
    }

    if (strcmp(md_hex, expected[i]) != 0) {
      fprintf(stderr, "#%u: got %s, wanted %s\n", (unsigned)i, md_hex,
              expected[i]);
      ok = 0;
    }
  }

  ok &= test_incremental();

  if (ok) {
    printf("PASS\n");
  }

  return ok ? 0 : 1;
}
