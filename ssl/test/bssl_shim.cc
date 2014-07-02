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


SSL *setup_test(int is_server) {
  if (!SSL_library_init()) {
    return NULL;
  }

  SSL_CTX *ssl_ctx = NULL;
  SSL *ssl = NULL;
  BIO *bio = NULL;

  ssl_ctx = SSL_CTX_new(
      is_server ? SSLv23_server_method() : SSLv23_client_method());
  if (ssl_ctx == NULL) {
    goto err;
  }

  if (!SSL_CTX_set_ecdh_auto(ssl_ctx, 1)) {
    goto err;
  }

  if (!SSL_CTX_set_cipher_list(ssl_ctx, "ALL")) {
    goto err;
  }

  ssl = SSL_new(ssl_ctx);
  if (ssl == NULL) {
    goto err;
  }

  bio = BIO_new_fd(3, 1 /* take ownership */);
  if (bio == NULL) {
    goto err;
  }

  SSL_set_bio(ssl, bio, bio);
  SSL_CTX_free(ssl_ctx);

  return ssl;

err:
  if (bio != NULL) {
    BIO_free(bio);
  }
  if (ssl != NULL) {
    SSL_free(ssl);
  }
  if (ssl_ctx != NULL) {
    SSL_CTX_free(ssl_ctx);
  }
  return NULL;
}

int main(int argc, char **argv) {
  int i, is_server, ret;
  const char *expected_server_name = NULL;

  if (argc < 2) {
    fprintf(stderr, "Usage: %s (client|server) [flags...]\n", argv[0]);
    return 1;
  }
  if (strcmp(argv[1], "client") == 0) {
    is_server = 0;
  } else if (strcmp(argv[1], "server") == 0) {
    is_server = 1;
  } else {
    fprintf(stderr, "Usage: %s (client|server) [flags...]\n", argv[0]);
    return 1;
  }

  SSL *ssl = setup_test(is_server);
  if (ssl == NULL) {
    BIO_print_errors_fp(stdout);
    return 1;
  }

  for (i = 2; i < argc; i++) {
    if (strcmp(argv[i], "-fallback-scsv") == 0) {
      if (!SSL_enable_fallback_scsv(ssl)) {
        BIO_print_errors_fp(stdout);
        return 1;
      }
    } else if (strcmp(argv[i], "-key-file") == 0) {
      i++;
      if (i >= argc) {
        fprintf(stderr, "Missing parameter\n");
        return 1;
      }
      if (!SSL_use_PrivateKey_file(ssl, argv[i], SSL_FILETYPE_PEM)) {
        BIO_print_errors_fp(stdout);
        return 1;
      }
    } else if (strcmp(argv[i], "-cert-file") == 0) {
      i++;
      if (i >= argc) {
        fprintf(stderr, "Missing parameter\n");
        return 1;
      }
      if (!SSL_use_certificate_file(ssl, argv[i], SSL_FILETYPE_PEM)) {
        BIO_print_errors_fp(stdout);
        return 1;
      }
    } else if (strcmp(argv[i], "-expect-server-name") == 0) {
      i++;
      if (i >= argc) {
        fprintf(stderr, "Missing parameter\n");
        return 1;
      }
      expected_server_name = argv[i];
    } else {
      fprintf(stderr, "Unknown argument: %s\n", argv[i]);
      return 1;
    }
  }

  if (is_server) {
    ret = SSL_accept(ssl);
  } else {
    ret = SSL_connect(ssl);
  }
  if (ret != 1) {
    SSL_free(ssl);
    BIO_print_errors_fp(stdout);
    return 2;
  }

  if (expected_server_name) {
    const char *server_name =
        SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (strcmp(server_name, expected_server_name) != 0) {
      fprintf(stderr, "servername mismatch (got %s; want %s)\n",
              server_name, expected_server_name);
      return 2;
    }
  }

  for (;;) {
    uint8_t buf[512];
    int n = SSL_read(ssl, buf, sizeof(buf));
    if (n < 0) {
      SSL_free(ssl);
      BIO_print_errors_fp(stdout);
      return 3;
    } else if (n == 0) {
      break;
    } else {
      for (int i = 0; i < n; i++) {
        buf[i] ^= 0xff;
      }
      int w = SSL_write(ssl, buf, n);
      if (w != n) {
        SSL_free(ssl);
        BIO_print_errors_fp(stdout);
        return 4;
      }
    }
  }

  SSL_free(ssl);
  return 0;
}
