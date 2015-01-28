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

#include <openssl/base.h>

#include <string>
#include <vector>

#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "internal.h"
#include "transport_common.h"


static const struct argument kArguments[] = {
    {
     "-connect", true,
     "The hostname and port of the server to connect to, e.g. foo.com:443",
    },
    {
     "-cipher", false,
     "An OpenSSL-style cipher suite string that configures the offered ciphers",
    },
    {
     "", false, "",
    },
};

bool Client(const std::vector<std::string> &args) {
  if (!InitSocketLibrary()) {
    return false;
  }

  std::map<std::string, std::string> args_map;

  if (!ParseKeyValueArguments(&args_map, args, kArguments)) {
    PrintUsage(kArguments);
    return false;
  }

  SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());

  const char *keylog_file = getenv("SSLKEYLOGFILE");
  if (keylog_file) {
    BIO *keylog_bio = BIO_new_file(keylog_file, "a");
    if (!keylog_bio) {
      ERR_print_errors_cb(PrintErrorCallback, stderr);
      return false;
    }
    SSL_CTX_set_keylog_bio(ctx, keylog_bio);
  }

  if (args_map.count("-cipher") != 0 &&
      !SSL_CTX_set_cipher_list(ctx, args_map["-cipher"].c_str())) {
    fprintf(stderr, "Failed setting cipher list\n");
    return false;
  }

  int sock = -1;
  if (!Connect(&sock, args_map["-connect"])) {
    return false;
  }

  BIO *bio = BIO_new_socket(sock, BIO_CLOSE);
  SSL *ssl = SSL_new(ctx);
  SSL_set_bio(ssl, bio, bio);

  int ret = SSL_connect(ssl);
  if (ret != 1) {
    int ssl_err = SSL_get_error(ssl, ret);
    fprintf(stderr, "Error while connecting: %d\n", ssl_err);
    ERR_print_errors_cb(PrintErrorCallback, stderr);
    return false;
  }

  fprintf(stderr, "Connected.\n");
  PrintConnectionInfo(ssl);

  bool ok = TransferData(ssl, sock);

  SSL_free(ssl);
  SSL_CTX_free(ctx);
  return ok;
}
