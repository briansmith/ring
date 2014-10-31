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

#include <string>
#include <vector>

#include <openssl/err.h>
#include <openssl/ssl.h>


#if !defined(OPENSSL_WINDOWS)
bool Client(const std::vector<std::string> &args);
#endif
bool DoPKCS12(const std::vector<std::string> &args);
bool Speed(const std::vector<std::string> &args);

static void usage(const char *name) {
  printf("Usage: %s [speed|client|pkcs12]\n", name);
}

int main(int argc, char **argv) {
  std::string tool;
  if (argc >= 2) {
    tool = argv[1];
  }

  SSL_library_init();

  std::vector<std::string> args;
  for (int i = 2; i < argc; i++) {
    args.push_back(argv[i]);
  }

  if (tool == "speed") {
    return !Speed(args);
#if !defined(OPENSSL_WINDOWS)
  } else if (tool == "s_client" || tool == "client") {
    return !Client(args);
#endif
  } else if (tool == "pkcs12") {
    return !DoPKCS12(args);
  } else {
    usage(argv[0]);
    return 1;
  }
}
