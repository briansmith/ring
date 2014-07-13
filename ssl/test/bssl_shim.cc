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
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/bytestring.h>

static const char *expected_server_name = NULL;
static int early_callback_called = 0;

static int select_certificate_callback(const struct ssl_early_callback_ctx *ctx) {
  early_callback_called = 1;

  if (!expected_server_name) {
    return 1;
  }

  const uint8_t *extension_data;
  size_t extension_len;
  CBS extension, server_name_list, host_name;
  uint8_t name_type;

  if (!SSL_early_callback_ctx_extension_get(ctx, TLSEXT_TYPE_server_name,
                                            &extension_data,
                                            &extension_len)) {
    fprintf(stderr, "Could not find server_name extension.\n");
    return -1;
  }

  CBS_init(&extension, extension_data, extension_len);
  if (!CBS_get_u16_length_prefixed(&extension, &server_name_list) ||
      CBS_len(&extension) != 0 ||
      !CBS_get_u8(&server_name_list, &name_type) ||
      name_type != TLSEXT_NAMETYPE_host_name ||
      !CBS_get_u16_length_prefixed(&server_name_list, &host_name) ||
      CBS_len(&server_name_list) != 0) {
    fprintf(stderr, "Could not decode server_name extension.\n");
    return -1;
  }

  if (!CBS_mem_equal(&host_name, (const uint8_t*)expected_server_name,
                     strlen(expected_server_name))) {
    fprintf(stderr, "Server name mismatch.\n");
  }

  return 1;
}

static int skip_verify(int preverify_ok, X509_STORE_CTX *store_ctx) {
  return 1;
}

static const char *advertise_npn = NULL;

static int next_protos_advertised_callback(SSL *ssl,
                                    const uint8_t **out,
                                    unsigned int *out_len,
                                    void *arg) {
  if (!advertise_npn)
    return SSL_TLSEXT_ERR_NOACK;

  // TODO(davidben): Support passing byte strings with NULs to the
  // test shim.
  *out = (const uint8_t*)advertise_npn;
  *out_len = strlen(advertise_npn);
  return SSL_TLSEXT_ERR_OK;
}

static SSL *setup_test(int is_server) {
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

  ssl_ctx->select_certificate_cb = select_certificate_callback;

  SSL_CTX_set_next_protos_advertised_cb(
      ssl_ctx, next_protos_advertised_callback, NULL);

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
  const char *expected_certificate_types = NULL;
  const char *expected_next_proto = NULL;

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
    } else if (strcmp(argv[i], "-expect-certificate-types") == 0) {
      i++;
      if (i >= argc) {
        fprintf(stderr, "Missing parameter\n");
        return 1;
      }
      // Conveniently, 00 is not a certificate type.
      expected_certificate_types = argv[i];
    } else if (strcmp(argv[i], "-require-any-client-certificate") == 0) {
      SSL_set_verify(ssl, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                     skip_verify);
    } else if (strcmp(argv[i], "-advertise-npn") == 0) {
      i++;
      if (i >= argc) {
        fprintf(stderr, "Missing parameter\n");
        return 1;
      }
      advertise_npn = argv[i];
    } else if (strcmp(argv[i], "-expect-next-proto") == 0) {
      i++;
      if (i >= argc) {
        fprintf(stderr, "Missing parameter\n");
        return 1;
      }
      expected_next_proto = argv[i];
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

    if (!early_callback_called) {
      fprintf(stderr, "early callback not called\n");
      return 2;
    }
  }

  if (expected_certificate_types) {
    uint8_t *certificate_types;
    int num_certificate_types =
      SSL_get0_certificate_types(ssl, &certificate_types);
    if (num_certificate_types != (int)strlen(expected_certificate_types) ||
        memcmp(certificate_types,
               expected_certificate_types,
               num_certificate_types) != 0) {
      fprintf(stderr, "certificate types mismatch\n");
      return 2;
    }
  }

  if (expected_next_proto) {
    const uint8_t *next_proto;
    unsigned next_proto_len;
    SSL_get0_next_proto_negotiated(ssl, &next_proto, &next_proto_len);
    if (next_proto_len != strlen(expected_next_proto) ||
        memcmp(next_proto, expected_next_proto, next_proto_len) != 0) {
      fprintf(stderr, "negotiated next proto mismatch\n");
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
