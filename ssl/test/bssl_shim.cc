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

#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/bytestring.h>
#include <openssl/ssl.h>

#include "async_bio.h"

static int usage(const char *program) {
  fprintf(stderr, "Usage: %s (client|server) (normal|resume) [flags...]\n",
          program);
  return 1;
}

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

static const char *select_next_proto = NULL;

static int next_proto_select_callback(SSL* ssl,
                                      uint8_t** out,
                                      uint8_t* outlen,
                                      const uint8_t* in,
                                      unsigned inlen,
                                      void* arg) {
  if (!select_next_proto)
    return SSL_TLSEXT_ERR_NOACK;

  *out = (uint8_t*)select_next_proto;
  *outlen = strlen(select_next_proto);
  return SSL_TLSEXT_ERR_OK;
}

static SSL_CTX *setup_ctx(int is_server) {
  if (!SSL_library_init()) {
    return NULL;
  }

  SSL_CTX *ssl_ctx = NULL;
  DH *dh = NULL;

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

  dh = DH_get_2048_256(NULL);
  if (!SSL_CTX_set_tmp_dh(ssl_ctx, dh)) {
    goto err;
  }

  SSL_CTX_set_session_cache_mode(ssl_ctx, SSL_SESS_CACHE_BOTH);

  ssl_ctx->select_certificate_cb = select_certificate_callback;

  SSL_CTX_set_next_protos_advertised_cb(
      ssl_ctx, next_protos_advertised_callback, NULL);
  SSL_CTX_set_next_proto_select_cb(
      ssl_ctx, next_proto_select_callback, NULL);

  DH_free(dh);
  return ssl_ctx;

 err:
  if (dh != NULL) {
    DH_free(dh);
  }
  if (ssl_ctx != NULL) {
    SSL_CTX_free(ssl_ctx);
  }
  return NULL;
}

static int retry_async(SSL *ssl, int ret, BIO *bio) {
  // No error; don't retry.
  if (ret >= 0) {
    return 0;
  }
  // See if we needed to read or write more. If so, allow one byte through on
  // the appropriate end to maximally stress the state machine.
  int err = SSL_get_error(ssl, ret);
  if (err == SSL_ERROR_WANT_READ) {
    async_bio_allow_read(bio, 1);
    return 1;
  } else if (err == SSL_ERROR_WANT_WRITE) {
    async_bio_allow_write(bio, 1);
    return 1;
  }
  return 0;
}

static int do_exchange(SSL_SESSION **out_session,
                       SSL_CTX *ssl_ctx,
                       int argc,
                       char **argv,
                       int is_server,
                       int is_resume,
                       int fd,
                       SSL_SESSION *session) {
  bool async = false, write_different_record_sizes = false;
  const char *expected_certificate_types = NULL;
  const char *expected_next_proto = NULL;
  expected_server_name = NULL;
  early_callback_called = 0;
  advertise_npn = NULL;

  SSL *ssl = SSL_new(ssl_ctx);
  if (ssl == NULL) {
    BIO_print_errors_fp(stdout);
    return 1;
  }

  for (int i = 0; i < argc; i++) {
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
    } else if (strcmp(argv[i], "-false-start") == 0) {
      SSL_set_mode(ssl, SSL_MODE_HANDSHAKE_CUTTHROUGH);
    } else if (strcmp(argv[i], "-select-next-proto") == 0) {
      i++;
      if (i >= argc) {
        fprintf(stderr, "Missing parameter\n");
        return 1;
      }
      select_next_proto = argv[i];
    } else if (strcmp(argv[i], "-async") == 0) {
      async = true;
    } else if (strcmp(argv[i], "-write-different-record-sizes") == 0) {
      write_different_record_sizes = true;
    } else if (strcmp(argv[i], "-cbc-record-splitting") == 0) {
      SSL_set_mode(ssl, SSL_MODE_CBC_RECORD_SPLITTING);
    } else if (strcmp(argv[i], "-partial-write") == 0) {
      SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE);
    } else if (strcmp(argv[i], "-no-tls12") == 0) {
      SSL_set_options(ssl, SSL_OP_NO_TLSv1_2);
    } else if (strcmp(argv[i], "-no-tls11") == 0) {
      SSL_set_options(ssl, SSL_OP_NO_TLSv1_1);
    } else if (strcmp(argv[i], "-no-tls1") == 0) {
      SSL_set_options(ssl, SSL_OP_NO_TLSv1);
    } else if (strcmp(argv[i], "-no-ssl3") == 0) {
      SSL_set_options(ssl, SSL_OP_NO_SSLv3);
    } else {
      fprintf(stderr, "Unknown argument: %s\n", argv[i]);
      return 1;
    }
  }

  BIO *bio = BIO_new_fd(fd, 1 /* take ownership */);
  if (bio == NULL) {
    BIO_print_errors_fp(stdout);
    return 1;
  }
  if (async) {
    BIO *async = async_bio_create();
    BIO_push(async, bio);
    bio = async;
  }
  SSL_set_bio(ssl, bio, bio);

  if (session != NULL) {
    if (SSL_set_session(ssl, session) != 1) {
      fprintf(stderr, "failed to set session\n");
      return 2;
    }
  }

  int ret;
  do {
    if (is_server) {
      ret = SSL_accept(ssl);
    } else {
      ret = SSL_connect(ssl);
    }
  } while (async && retry_async(ssl, ret, bio));
  if (ret != 1) {
    SSL_free(ssl);
    BIO_print_errors_fp(stdout);
    return 2;
  }

  if (is_resume && !SSL_session_reused(ssl)) {
    fprintf(stderr, "session was not reused\n");
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

  if (write_different_record_sizes) {
    // This mode writes a number of different record sizes in an attempt to
    // trip up the CBC record splitting code.
    uint8_t buf[32769];
    memset(buf, 0x42, sizeof(buf));
    static const size_t kRecordSizes[] = {
        0, 1, 255, 256, 257, 16383, 16384, 16385, 32767, 32768, 32769};
    for (size_t i = 0; i < sizeof(kRecordSizes) / sizeof(kRecordSizes[0]);
         i++) {
      int w;
      const size_t len = kRecordSizes[i];
      size_t off = 0;

      if (len > sizeof(buf)) {
        fprintf(stderr, "Bad kRecordSizes value.\n");
        return 5;
      }

      do {
        w = SSL_write(ssl, buf + off, len - off);
        if (w > 0) {
          off += (size_t) w;
        }
      } while ((async && retry_async(ssl, w, bio)) || (w > 0 && off < len));

      if (w < 0 || off != len) {
        SSL_free(ssl);
        BIO_print_errors_fp(stdout);
        return 4;
      }
    }
  } else {
    for (;;) {
      uint8_t buf[512];
      int n;
      do {
        n = SSL_read(ssl, buf, sizeof(buf));
      } while (async && retry_async(ssl, n, bio));
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
        int w;
        do {
          w = SSL_write(ssl, buf, n);
        } while (async && retry_async(ssl, w, bio));
        if (w != n) {
          SSL_free(ssl);
          BIO_print_errors_fp(stdout);
          return 4;
        }
      }
    }
  }

  if (out_session) {
    *out_session = SSL_get1_session(ssl);
  }

  SSL_shutdown(ssl);
  SSL_free(ssl);
  return 0;
}

int main(int argc, char **argv) {
  int is_server, resume;

  signal(SIGPIPE, SIG_IGN);

  if (argc < 3) {
    return usage(argv[0]);
  }

  if (strcmp(argv[1], "client") == 0) {
    is_server = 0;
  } else if (strcmp(argv[1], "server") == 0) {
    is_server = 1;
  } else {
    return usage(argv[0]);
  }

  if (strcmp(argv[2], "normal") == 0) {
    resume = 0;
  } else if (strcmp(argv[2], "resume") == 0) {
    resume = 1;
  } else {
    return usage(argv[0]);
  }

  SSL_CTX *ssl_ctx = setup_ctx(is_server);
  if (ssl_ctx == NULL) {
    BIO_print_errors_fp(stdout);
    return 1;
  }

  SSL_SESSION *session;
  int ret = do_exchange(&session,
                        ssl_ctx,
                        argc - 3, argv + 3,
                        is_server, 0 /* is_resume */,
                        3 /* fd */, NULL /* session */);
  if (ret != 0) {
    return ret;
  }

  if (resume) {
    int ret = do_exchange(NULL,
                          ssl_ctx, argc - 3, argv + 3,
                          is_server, 1 /* is_resume */,
                          4 /* fd */,
                          is_server ? NULL : session);
    if (ret != 0) {
      return ret;
    }
  }

  SSL_SESSION_free(session);
  SSL_CTX_free(ssl_ctx);
  return 0;
}
