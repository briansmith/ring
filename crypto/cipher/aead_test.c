/* Copyright (c) 2014, Google Inc.
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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/aead.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

/* This program tests an AEAD against a series of test vectors from a file. The
 * test vector file consists of key-value lines where the key and value are
 * separated by a colon and optional whitespace. The keys are listed in
 * |NAMES|, below. The values are hex-encoded data.
 *
 * After a number of key-value lines, a blank line or EOF indicates the end of
 * the test case.
 *
 * For example, here's a valid test case:
 *
 *   KEY: 5a19f3173586b4c42f8412f4d5a786531b3231753e9e00998aec12fda8df10e4
 *   NONCE: 978105dfce667bf4
 *   IN: 6a4583908d
 *   AD: b654574932
 *   CT: 5294265a60
 *   TAG: 1d45758621762e061368e68868e2f929
 */

#define BUF_MAX 512

/* These are the different types of line that are found in the input file. */
enum {
  KEY = 0, /* hex encoded key. */
  NONCE,   /* hex encoded nonce. */
  IN,      /* hex encoded plaintext. */
  AD,      /* hex encoded additional data. */
  CT,      /* hex encoded ciphertext (not including the authenticator,
              which is next). */
  TAG,     /* hex encoded authenticator. */
  NO_SEAL, /* non-zero length if seal(IN) is not expected to be CT+TAG,
              however open(CT+TAG) should still be IN. */
  FAILS,   /* non-zero length if open(CT+TAG) is expected to fail. */
  NUM_TYPES,
};

static const char NAMES[8][NUM_TYPES] = {
  "KEY", "NONCE", "IN", "AD", "CT", "TAG", "NO_SEAL", "FAILS",
};

static unsigned char hex_digit(char h) {
  if (h >= '0' && h <= '9') {
    return h - '0';
  } else if (h >= 'a' && h <= 'f') {
    return h - 'a' + 10;
  } else if (h >= 'A' && h <= 'F') {
    return h - 'A' + 10;
  } else {
    return 16;
  }
}

static int run_test_case(const EVP_AEAD *aead,
                         uint8_t bufs[NUM_TYPES][BUF_MAX],
                         const unsigned int lengths[NUM_TYPES],
                         unsigned int line_no) {
  EVP_AEAD_CTX ctx;
  size_t ciphertext_len, plaintext_len;
  uint8_t out[BUF_MAX + EVP_AEAD_MAX_OVERHEAD + 1];
  /* Note: When calling |EVP_AEAD_CTX_open|, the "stateful" AEADs require
   * |max_out| be at least |in_len| despite the final output always being
   * smaller by at least tag length. */
  uint8_t out2[sizeof(out)];

  if (!EVP_AEAD_CTX_init_with_direction(&ctx, aead, bufs[KEY], lengths[KEY],
                                        lengths[TAG], evp_aead_seal)) {
    fprintf(stderr, "Failed to init AEAD on line %u\n", line_no);
    return 0;
  }

  if (!lengths[NO_SEAL]) {
    if (!EVP_AEAD_CTX_seal(&ctx, out, &ciphertext_len, sizeof(out), bufs[NONCE],
                           lengths[NONCE], bufs[IN], lengths[IN], bufs[AD],
                           lengths[AD])) {
      fprintf(stderr, "Failed to run AEAD on line %u\n", line_no);
      return 0;
    }

    if (ciphertext_len != lengths[CT] + lengths[TAG]) {
      fprintf(stderr, "Bad output length on line %u: %u vs %u\n", line_no,
              (unsigned)ciphertext_len, (unsigned)(lengths[CT] + lengths[TAG]));
      return 0;
    }

    if (memcmp(out, bufs[CT], lengths[CT]) != 0) {
      fprintf(stderr, "Bad output on line %u\n", line_no);
      return 0;
    }

    if (memcmp(out + lengths[CT], bufs[TAG], lengths[TAG]) != 0) {
      fprintf(stderr, "Bad tag on line %u\n", line_no);
      return 0;
    }
  } else {
    memcpy(out, bufs[CT], lengths[CT]);
    memcpy(out + lengths[CT], bufs[TAG], lengths[TAG]);
    ciphertext_len = lengths[CT] + lengths[TAG];
  }

  /* The "stateful" AEADs for implementing pre-AEAD cipher suites need to be
   * reset after each operation. */
  EVP_AEAD_CTX_cleanup(&ctx);
  if (!EVP_AEAD_CTX_init_with_direction(&ctx, aead, bufs[KEY], lengths[KEY],
                                        lengths[TAG], evp_aead_open)) {
    fprintf(stderr, "Failed to init AEAD on line %u\n", line_no);
    return 0;
  }

  int ret = EVP_AEAD_CTX_open(&ctx, out2, &plaintext_len, sizeof(out2),
                              bufs[NONCE], lengths[NONCE], out, ciphertext_len,
                              bufs[AD], lengths[AD]);
  if (lengths[FAILS]) {
    if (ret) {
      fprintf(stderr, "Decrypted bad data on line %u\n", line_no);
      return 0;
    }
    ERR_clear_error();
  } else {
    if (!ret) {
      fprintf(stderr, "Failed to decrypt on line %u\n", line_no);
      return 0;
    }

    if (plaintext_len != lengths[IN]) {
      fprintf(stderr, "Bad decrypt on line %u: %u\n", line_no,
              (unsigned)ciphertext_len);
      return 0;
    }

    /* The "stateful" AEADs for implementing pre-AEAD cipher suites need to be
     * reset after each operation. */
    EVP_AEAD_CTX_cleanup(&ctx);
    if (!EVP_AEAD_CTX_init_with_direction(&ctx, aead, bufs[KEY], lengths[KEY],
                                          lengths[TAG], evp_aead_open)) {
      fprintf(stderr, "Failed to init AEAD on line %u\n", line_no);
      return 0;
    }

    /* Garbage at the end isn't ignored. */
    out[ciphertext_len] = 0;
    if (EVP_AEAD_CTX_open(&ctx, out2, &plaintext_len, sizeof(out2),
                          bufs[NONCE], lengths[NONCE], out, ciphertext_len + 1,
                          bufs[AD], lengths[AD])) {
      fprintf(stderr, "Decrypted bad data on line %u\n", line_no);
      return 0;
    }
    ERR_clear_error();

    /* The "stateful" AEADs for implementing pre-AEAD cipher suites need to be
     * reset after each operation. */
    EVP_AEAD_CTX_cleanup(&ctx);
    if (!EVP_AEAD_CTX_init_with_direction(&ctx, aead, bufs[KEY], lengths[KEY],
                                          lengths[TAG], evp_aead_open)) {
      fprintf(stderr, "Failed to init AEAD on line %u\n", line_no);
      return 0;
    }

    /* Verify integrity is checked. */
    out[0] ^= 0x80;
    if (EVP_AEAD_CTX_open(&ctx, out2, &plaintext_len, sizeof(out2), bufs[NONCE],
                          lengths[NONCE], out, ciphertext_len, bufs[AD],
                          lengths[AD])) {
      fprintf(stderr, "Decrypted bad data on line %u\n", line_no);
      return 0;
    }
    ERR_clear_error();
  }

  EVP_AEAD_CTX_cleanup(&ctx);
  return 1;
}

int main(int argc, char **argv) {
  FILE *f;
  const EVP_AEAD *aead = NULL;
  unsigned int line_no = 0, num_tests = 0, j;

  unsigned char bufs[NUM_TYPES][BUF_MAX];
  unsigned int lengths[NUM_TYPES];

  CRYPTO_library_init();
  ERR_load_crypto_strings();

  if (argc != 3) {
    fprintf(stderr, "%s <aead> <test file.txt>\n", argv[0]);
    return 1;
  }

  if (strcmp(argv[1], "aes-128-gcm") == 0) {
    aead = EVP_aead_aes_128_gcm();
  } else if (strcmp(argv[1], "aes-256-gcm") == 0) {
    aead = EVP_aead_aes_256_gcm();
  } else if (strcmp(argv[1], "chacha20-poly1305") == 0) {
    aead = EVP_aead_chacha20_poly1305();
  } else if (strcmp(argv[1], "rc4-md5-tls") == 0) {
    aead = EVP_aead_rc4_md5_tls();
  } else if (strcmp(argv[1], "rc4-sha1-tls") == 0) {
    aead = EVP_aead_rc4_sha1_tls();
  } else if (strcmp(argv[1], "aes-128-cbc-sha1-tls") == 0) {
    aead = EVP_aead_aes_128_cbc_sha1_tls();
  } else if (strcmp(argv[1], "aes-128-cbc-sha1-tls-implicit-iv") == 0) {
    aead = EVP_aead_aes_128_cbc_sha1_tls_implicit_iv();
  } else if (strcmp(argv[1], "aes-128-cbc-sha256-tls") == 0) {
    aead = EVP_aead_aes_128_cbc_sha256_tls();
  } else if (strcmp(argv[1], "aes-256-cbc-sha1-tls") == 0) {
    aead = EVP_aead_aes_256_cbc_sha1_tls();
  } else if (strcmp(argv[1], "aes-256-cbc-sha1-tls-implicit-iv") == 0) {
    aead = EVP_aead_aes_256_cbc_sha1_tls_implicit_iv();
  } else if (strcmp(argv[1], "aes-256-cbc-sha256-tls") == 0) {
    aead = EVP_aead_aes_256_cbc_sha256_tls();
  } else if (strcmp(argv[1], "aes-256-cbc-sha384-tls") == 0) {
    aead = EVP_aead_aes_256_cbc_sha384_tls();
  } else if (strcmp(argv[1], "des-ede3-cbc-sha1-tls") == 0) {
    aead = EVP_aead_des_ede3_cbc_sha1_tls();
  } else if (strcmp(argv[1], "des-ede3-cbc-sha1-tls-implicit-iv") == 0) {
    aead = EVP_aead_des_ede3_cbc_sha1_tls_implicit_iv();
  } else if (strcmp(argv[1], "rc4-md5-ssl3") == 0) {
    aead = EVP_aead_rc4_md5_ssl3();
  } else if (strcmp(argv[1], "rc4-sha1-ssl3") == 0) {
    aead = EVP_aead_rc4_sha1_ssl3();
  } else if (strcmp(argv[1], "aes-128-cbc-sha1-ssl3") == 0) {
    aead = EVP_aead_aes_128_cbc_sha1_ssl3();
  } else if (strcmp(argv[1], "aes-256-cbc-sha1-ssl3") == 0) {
    aead = EVP_aead_aes_256_cbc_sha1_ssl3();
  } else if (strcmp(argv[1], "des-ede3-cbc-sha1-ssl3") == 0) {
    aead = EVP_aead_des_ede3_cbc_sha1_ssl3();
  } else if (strcmp(argv[1], "aes-128-key-wrap") == 0) {
    aead = EVP_aead_aes_128_key_wrap();
  } else if (strcmp(argv[1], "aes-256-key-wrap") == 0) {
    aead = EVP_aead_aes_256_key_wrap();
  } else {
    fprintf(stderr, "Unknown AEAD: %s\n", argv[1]);
    return 2;
  }

  f = fopen(argv[2], "r");
  if (f == NULL) {
    perror("failed to open input");
    return 1;
  }

  for (j = 0; j < NUM_TYPES; j++) {
    lengths[j] = 0;
  }

  for (;;) {
    char line[4096];
    unsigned int i, type_len = 0;

    unsigned char *buf = NULL;
    unsigned int *buf_len = NULL;

    if (!fgets(line, sizeof(line), f)) {
      line[0] = 0;
    }

    line_no++;
    if (line[0] == '#') {
      continue;
    }

    if (line[0] == '\n' || line[0] == 0) {
      /* Run a test, if possible. */
      char any_values_set = 0;
      for (j = 0; j < NUM_TYPES; j++) {
        if (lengths[j] != 0) {
          any_values_set = 1;
          break;
        }
      }

      if (any_values_set) {
        if (!run_test_case(aead, bufs, lengths, line_no)) {
          BIO_print_errors_fp(stderr);
          return 4;
        }

        for (j = 0; j < NUM_TYPES; j++) {
          lengths[j] = 0;
        }

        num_tests++;
      }

      if (line[0] == 0) {
        break;
      }
      continue;
    }

    /* Each line looks like:
     *   TYPE: 0123abc
     * Where "TYPE" is the type of the data on the line,
     * e.g. "KEY". */
    for (i = 0; line[i] != 0 && line[i] != '\n'; i++) {
      if (line[i] == ':') {
        type_len = i;
        break;
      }
    }
    i++;

    if (type_len == 0) {
      fprintf(stderr, "Parse error on line %u\n", line_no);
      return 3;
    }

    /* After the colon, there's optional whitespace. */
    for (; line[i] != 0 && line[i] != '\n'; i++) {
      if (line[i] != ' ' && line[i] != '\t') {
        break;
      }
    }

    line[type_len] = 0;
    for (j = 0; j < NUM_TYPES; j++) {
      if (strcmp(line, NAMES[j]) != 0) {
        continue;
      }
      if (lengths[j] != 0) {
        fprintf(stderr, "Duplicate value on line %u\n", line_no);
        return 3;
      }
      buf = bufs[j];
      buf_len = &lengths[j];
    }

    if (buf == NULL) {
      fprintf(stderr, "Unknown line type on line %u\n", line_no);
      return 3;
    }

    j = 0;
    for (; line[i] != 0 && line[i] != '\n'; i++) {
      unsigned char v, v2;
      v = hex_digit(line[i++]);
      if (line[i] == 0 || line[i] == '\n') {
        fprintf(stderr, "Odd-length hex data on line %u\n", line_no);
        return 3;
      }
      v2 = hex_digit(line[i]);
      if (v > 15 || v2 > 15) {
        fprintf(stderr, "Invalid hex char on line %u\n", line_no);
        return 3;
      }
      v <<= 4;
      v |= v2;

      if (j == BUF_MAX) {
        fprintf(stderr, "Too much hex data on line %u (max is %u bytes)\n",
                line_no, (unsigned)BUF_MAX);
        return 3;
      }
      buf[j++] = v;
      *buf_len = *buf_len + 1;
    }
  }

  printf("Completed %u test cases\n", num_tests);
  printf("PASS\n");
  fclose(f);

  return 0;
}
