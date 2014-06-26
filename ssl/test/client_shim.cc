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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>


SSL *setup_test() {
  if (!SSL_library_init()) {
    return NULL;
  }

  SSL_CTX *client_ctx = NULL;
  SSL *client = NULL;
  BIO *bio = NULL;

  client_ctx = SSL_CTX_new(SSLv23_client_method());
  if (client_ctx == NULL) {
    goto err;
  }

  if (!SSL_CTX_set_cipher_list(client_ctx, "ALL")) {
    goto err;
  }

  client = SSL_new(client_ctx);
  if (client == NULL) {
    goto err;
  }

  bio = BIO_new_fd(3, 1 /* take ownership */);
  if (bio == NULL) {
    goto err;
  }

  SSL_set_bio(client, bio, bio);
  SSL_CTX_free(client_ctx);

  return client;

err:
  if (bio != NULL) {
    BIO_free(bio);
  }
  if (client != NULL) {
    SSL_free(client);
  }
  if (client_ctx != NULL) {
    SSL_CTX_free(client_ctx);
  }
  return NULL;
}

int main(int argc, char **argv) {
  int i;

  SSL *client = setup_test();
  if (client == NULL) {
    BIO_print_errors_fp(stdout);
    return 1;
  }

  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-fallback-scsv") == 0) {
      SSL_enable_fallback_scsv(client);
    } else {
      fprintf(stderr, "Unknown argument: %s\n", argv[i]);
      return 1;
    }
  }

  if (SSL_connect(client) != 1) {
    SSL_free(client);
    BIO_print_errors_fp(stdout);
    return 2;
  }

  for (;;) {
    uint8_t buf[512];
    int n = SSL_read(client, buf, sizeof(buf));
    if (n < 0) {
      SSL_free(client);
      BIO_print_errors_fp(stdout);
      return 3;
    } else if (n == 0) {
      break;
    } else {
      for (int i = 0; i < n; i++) {
        buf[i] ^= 0xff;
      }
      int w = SSL_write(client, buf, n);
      if (w != n) {
        SSL_free(client);
        BIO_print_errors_fp(stdout);
        return 4;
      }
    }
  }

  SSL_free(client);
  return 0;
}
