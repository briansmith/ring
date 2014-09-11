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
#include <openssl/hmac.h>


struct test_st {
  unsigned char key[16];
  unsigned key_len;
  unsigned char data[64];
  unsigned data_len;
  const char *hex_digest;
};

#define NUM_TESTS 4

static const struct test_st kTests[NUM_TESTS] = {
  {
    "", 0, "More text test vectors to stuff up EBCDIC machines :-)", 54,
    "e9139d1e6ee064ef8cf514fc7dc83e86",
  },
  {
    {
      0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
      0x0b, 0x0b, 0x0b, 0x0b,
    },
    16,
    "Hi There",
    8,
    "9294727a3638bb1c13f48ef8158bfc9d",
  },
  {
    "Jefe", 4, "what do ya want for nothing?", 28,
    "750c783e6ab0b503eaa86e310a5db738",
  },
  {
    {
      0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
      0xaa, 0xaa, 0xaa, 0xaa,
    },
    16,
    {
      0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
      0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
      0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
      0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
      0xdd, 0xdd,
    },
    50,
    "56be34521d144c88dbb8c733f0e8b3f6",
  },
};

static char *to_hex(const uint8_t *md, size_t md_len) {
  size_t i;
  static char buf[80];

  for (i = 0; i < md_len; i++) {
    sprintf(&(buf[i * 2]), "%02x", md[i]);
  }
  return buf;
}

int main(int argc, char *argv[]) {
  unsigned i;
  char *p;
  int err = 0;
  uint8_t out[EVP_MAX_MD_SIZE];
  unsigned out_len;

  CRYPTO_library_init();

  for (i = 0; i < NUM_TESTS; i++) {
    const struct test_st *test = &kTests[i];

    if (NULL == HMAC(EVP_md5(), test->key, test->key_len, test->data,
                     test->data_len, out, &out_len)) {
      printf("%u: HMAC failed.\n", i);
      err++;
      continue;
    }

    p = to_hex(out, out_len);

    if (strcmp(p, test->hex_digest) != 0) {
      printf("%u: got %s instead of %s\n", i, p, test->hex_digest);
      err++;
    }
  }

  if (err) {
    return 1;
  }

  printf("PASS\n");
  return 0;
}
