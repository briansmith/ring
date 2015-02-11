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
#include <string.h>

#include <openssl/bio.h>
#include <openssl/cipher.h>
#include <openssl/crypto.h>
#include <openssl/err.h>


static void hexdump(FILE *f, const char *title, const uint8_t *s, int l) {
  int n = 0;

  fprintf(f, "%s", title);
  for (; n < l; ++n) {
    if ((n % 16) == 0) {
      fprintf(f, "\n%04x", n);
    }
    fprintf(f, " %02x", s[n]);
  }
  fprintf(f, "\n");
}

static int convert(uint8_t *s) {
  uint8_t *d;

  for (d = s; *s; s += 2, ++d) {
    unsigned int n;

    if (!s[1]) {
      fprintf(stderr, "Odd number of hex digits!");
      exit(4);
    }
    sscanf((char *)s, "%2x", &n);
    *d = (uint8_t)n;
  }
  return s - d;
}

static char *sstrsep(char **string, const char *delim) {
  char isdelim[256];
  char *token = *string;

  if (**string == 0) {
    return NULL;
  }

  memset(isdelim, 0, 256);
  isdelim[0] = 1;

  while (*delim) {
    isdelim[(uint8_t)(*delim)] = 1;
    delim++;
  }

  while (!isdelim[(uint8_t)(**string)]) {
    (*string)++;
  }

  if (**string) {
    **string = 0;
    (*string)++;
  }

  return token;
}

static uint8_t *ustrsep(char **p, const char *sep) {
  return (uint8_t *)sstrsep(p, sep);
}

static void test1(const EVP_CIPHER *c, const uint8_t *key, int kn,
                  const uint8_t *iv, int in, const uint8_t *plaintext, int pn,
                  const uint8_t *ciphertext, int cn, const uint8_t *aad, int an,
                  const uint8_t *tag, int tn, int encdec) {
  EVP_CIPHER_CTX ctx;
  uint8_t out[4096];
  int outl, outl2, mode;

  printf("Testing cipher %s%s\n", EVP_CIPHER_name(c),
         (encdec == 1 ? "(encrypt)"
                      : (encdec == 0 ? "(decrypt)" : "(encrypt/decrypt)")));
  hexdump(stdout, "Key", key, kn);
  if (in) {
    hexdump(stdout, "IV", iv, in);
  }
  hexdump(stdout, "Plaintext", plaintext, pn);
  hexdump(stdout, "Ciphertext", ciphertext, cn);
  if (an) {
    hexdump(stdout, "AAD", aad, an);
  }
  if (tn) {
    hexdump(stdout, "Tag", tag, tn);
  }
  mode = EVP_CIPHER_mode(c);
  if (kn != EVP_CIPHER_key_length(c)) {
    fprintf(stderr, "Key length doesn't match, got %d expected %lu\n", kn,
            (unsigned long)EVP_CIPHER_key_length(c));
    exit(5);
  }
  EVP_CIPHER_CTX_init(&ctx);
  if (encdec != 0) {
    if (mode == EVP_CIPH_GCM_MODE) {
      if (!EVP_EncryptInit_ex(&ctx, c, NULL, NULL, NULL)) {
        fprintf(stderr, "EncryptInit failed\n");
        BIO_print_errors_fp(stderr);
        exit(10);
      }
      if (!EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_GCM_SET_IVLEN, in, NULL)) {
        fprintf(stderr, "IV length set failed\n");
        BIO_print_errors_fp(stderr);
        exit(11);
      }
      if (!EVP_EncryptInit_ex(&ctx, NULL, NULL, key, iv)) {
        fprintf(stderr, "Key/IV set failed\n");
        BIO_print_errors_fp(stderr);
        exit(12);
      }
      if (an && !EVP_EncryptUpdate(&ctx, NULL, &outl, aad, an)) {
        fprintf(stderr, "AAD set failed\n");
        BIO_print_errors_fp(stderr);
        exit(13);
      }
    } else if (!EVP_EncryptInit_ex(&ctx, c, NULL, key, iv)) {
      fprintf(stderr, "EncryptInit failed\n");
      BIO_print_errors_fp(stderr);
      exit(10);
    }
    EVP_CIPHER_CTX_set_padding(&ctx, 0);

    if (!EVP_EncryptUpdate(&ctx, out, &outl, plaintext, pn)) {
      fprintf(stderr, "Encrypt failed\n");
      BIO_print_errors_fp(stderr);
      exit(6);
    }
    if (!EVP_EncryptFinal_ex(&ctx, out + outl, &outl2)) {
      fprintf(stderr, "EncryptFinal failed\n");
      BIO_print_errors_fp(stderr);
      exit(7);
    }

    if (outl + outl2 != cn) {
      fprintf(stderr, "Ciphertext length mismatch got %d expected %d\n",
              outl + outl2, cn);
      exit(8);
    }

    if (memcmp(out, ciphertext, cn)) {
      fprintf(stderr, "Ciphertext mismatch\n");
      hexdump(stderr, "Got", out, cn);
      hexdump(stderr, "Expected", ciphertext, cn);
      exit(9);
    }
    if (mode == EVP_CIPH_GCM_MODE) {
      uint8_t rtag[16];
      /* Note: EVP_CTRL_CCM_GET_TAG has same value as
       * EVP_CTRL_GCM_GET_TAG
       */
      if (!EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_GCM_GET_TAG, tn, rtag)) {
        fprintf(stderr, "Get tag failed\n");
        BIO_print_errors_fp(stderr);
        exit(14);
      }
      if (memcmp(rtag, tag, tn)) {
        fprintf(stderr, "Tag mismatch\n");
        hexdump(stderr, "Got", rtag, tn);
        hexdump(stderr, "Expected", tag, tn);
        exit(9);
      }
    }
  }

  if (encdec <= 0) {
    if (mode == EVP_CIPH_GCM_MODE) {
      if (!EVP_DecryptInit_ex(&ctx, c, NULL, NULL, NULL)) {
        fprintf(stderr, "EncryptInit failed\n");
        BIO_print_errors_fp(stderr);
        exit(10);
      }
      if (!EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_GCM_SET_IVLEN, in, NULL)) {
        fprintf(stderr, "IV length set failed\n");
        BIO_print_errors_fp(stderr);
        exit(11);
      }
      if (!EVP_DecryptInit_ex(&ctx, NULL, NULL, key, iv)) {
        fprintf(stderr, "Key/IV set failed\n");
        BIO_print_errors_fp(stderr);
        exit(12);
      }
      if (!EVP_CIPHER_CTX_ctrl(&ctx, EVP_CTRL_GCM_SET_TAG, tn, (void *)tag)) {
        fprintf(stderr, "Set tag failed\n");
        BIO_print_errors_fp(stderr);
        exit(14);
      }
      if (an && !EVP_DecryptUpdate(&ctx, NULL, &outl, aad, an)) {
        fprintf(stderr, "AAD set failed\n");
        BIO_print_errors_fp(stderr);
        exit(13);
      }
    } else if (!EVP_DecryptInit_ex(&ctx, c, NULL, key, iv)) {
      fprintf(stderr, "DecryptInit failed\n");
      BIO_print_errors_fp(stderr);
      exit(11);
    }
    EVP_CIPHER_CTX_set_padding(&ctx, 0);

    if (!EVP_DecryptUpdate(&ctx, out, &outl, ciphertext, cn)) {
      fprintf(stderr, "Decrypt failed\n");
      BIO_print_errors_fp(stderr);
      exit(6);
    }
    outl2 = 0;
    if (!EVP_DecryptFinal_ex(&ctx, out + outl, &outl2)) {
      fprintf(stderr, "DecryptFinal failed\n");
      BIO_print_errors_fp(stderr);
      exit(7);
    }

    if (outl + outl2 != pn) {
      fprintf(stderr, "Plaintext length mismatch got %d expected %d\n",
              outl + outl2, pn);
      exit(8);
    }

    if (memcmp(out, plaintext, pn)) {
      fprintf(stderr, "Plaintext mismatch\n");
      hexdump(stderr, "Got", out, pn);
      hexdump(stderr, "Expected", plaintext, pn);
      exit(9);
    }
  }

  EVP_CIPHER_CTX_cleanup(&ctx);

  printf("\n");
}

static int test_cipher(const char *cipher, const uint8_t *key, int kn,
                       const uint8_t *iv, int in, const uint8_t *plaintext,
                       int pn, const uint8_t *ciphertext, int cn,
                       const uint8_t *aad, int an, const uint8_t *tag, int tn,
                       int encdec) {
  const EVP_CIPHER *c;

  if (strcmp(cipher, "DES-CBC") == 0) {
    c = EVP_des_cbc();
  } else if (strcmp(cipher, "DES-EDE3-CBC") == 0) {
    c = EVP_des_ede3_cbc();
  } else if (strcmp(cipher, "RC4") == 0) {
    c = EVP_rc4();
  } else if (strcmp(cipher, "AES-128-ECB") == 0) {
    c = EVP_aes_128_ecb();
  } else if (strcmp(cipher, "AES-256-ECB") == 0) {
    c = EVP_aes_256_ecb();
  } else if (strcmp(cipher, "AES-128-CBC") == 0) {
    c = EVP_aes_128_cbc();
  } else if (strcmp(cipher, "AES-128-GCM") == 0) {
    c = EVP_aes_128_gcm();
  } else if (strcmp(cipher, "AES-256-CBC") == 0) {
    c = EVP_aes_256_cbc();
  } else if (strcmp(cipher, "AES-128-CTR") == 0) {
    c = EVP_aes_128_ctr();
  } else if (strcmp(cipher, "AES-256-CTR") == 0) {
    c = EVP_aes_256_ctr();
  } else if (strcmp(cipher, "AES-256-GCM") == 0) {
    c = EVP_aes_256_gcm();
  } else {
    fprintf(stderr, "Unknown cipher type %s\n", cipher);
    return 0;
  }

  test1(c, key, kn, iv, in, plaintext, pn, ciphertext, cn, aad, an, tag, tn,
        encdec);

  return 1;
}

int main(int argc, char **argv) {
  const char *input_file;
  FILE *f;

  CRYPTO_library_init();

  if (argc != 2) {
    fprintf(stderr, "%s <test file>\n", argv[0]);
    return 1;
  }

  input_file = argv[1];

  f = fopen(input_file, "r");
  if (!f) {
    perror(input_file);
    return 2;
  }

  ERR_load_crypto_strings();

  for (;;) {
    char line[4096];
    char *p;
    char *cipher;
    uint8_t *iv, *key, *plaintext, *ciphertext, *aad, *tag;
    int encdec;
    int kn, in, pn, cn;
    int an = 0;
    int tn = 0;

    if (!fgets((char *)line, sizeof line, f)) {
      break;
    }
    if (line[0] == '#' || line[0] == '\n') {
      continue;
    }
    p = line;
    cipher = sstrsep(&p, ":");
    key = ustrsep(&p, ":");
    iv = ustrsep(&p, ":");
    plaintext = ustrsep(&p, ":");
    ciphertext = ustrsep(&p, ":");
    if (p[-1] == '\n') {
      encdec = -1;
      p[-1] = '\0';
      tag = aad = NULL;
      an = tn = 0;
    } else {
      aad = ustrsep(&p, ":");
      tag = ustrsep(&p, ":");
      if (tag == NULL) {
        p = (char *)aad;
        tag = aad = NULL;
        an = tn = 0;
      }
      if (p[-1] == '\n') {
        encdec = -1;
        p[-1] = '\0';
      } else {
        encdec = atoi(sstrsep(&p, "\n"));
      }
    }

    kn = convert(key);
    in = convert(iv);
    pn = convert(plaintext);
    cn = convert(ciphertext);
    if (aad) {
      an = convert(aad);
      tn = convert(tag);
    }

    if (!test_cipher(cipher, key, kn, iv, in, plaintext, pn, ciphertext, cn,
                     aad, an, tag, tn, encdec)) {
      return 3;
    }
  }
  fclose(f);

  printf("PASS\n");
  return 0;
}
