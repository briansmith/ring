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
#include <libgen.h>
#endif


#if !defined(OPENSSL_WINDOWS)
bool Client(const std::vector<std::string> &args);
bool Server(const std::vector<std::string> &args);
bool MD5Sum(const std::vector<std::string> &args);
bool SHA1Sum(const std::vector<std::string> &args);
bool SHA224Sum(const std::vector<std::string> &args);
bool SHA256Sum(const std::vector<std::string> &args);
bool SHA384Sum(const std::vector<std::string> &args);
bool SHA512Sum(const std::vector<std::string> &args);
#endif
bool DoPKCS12(const std::vector<std::string> &args);
bool Speed(const std::vector<std::string> &args);

typedef bool (*tool_func_t)(const std::vector<std::string> &args);

struct Tool {
  char name[16];
  tool_func_t func;
};

static const Tool kTools[] = {
  { "speed", Speed },
  { "pkcs12", DoPKCS12 },
#if !defined(OPENSSL_WINDOWS)
  { "client", Client },
  { "s_client", Client },
  { "server", Server },
  { "s_server", Server },
  { "md5sum", MD5Sum },
  { "sha1sum", SHA1Sum },
  { "sha224sum", SHA224Sum },
  { "sha256sum", SHA256Sum },
  { "sha384sum", SHA384Sum },
  { "sha512sum", SHA512Sum },
#endif
  { "", nullptr },
};

static void usage(const char *name) {
  printf("Usage: %s [", name);

  for (size_t i = 0;; i++) {
    const Tool &tool = kTools[i];
    if (tool.func == nullptr) {
      break;
    }
    if (i > 0) {
      printf("|");
    }
    printf("%s", tool.name);
  }
  printf("]\n");
}

tool_func_t FindTool(const std::string &name) {
  for (size_t i = 0;; i++) {
    const Tool &tool = kTools[i];
    if (tool.func == nullptr || name == tool.name) {
      return tool.func;
    }
  }
}

int main(int argc, char **argv) {
  SSL_library_init();

  int starting_arg = 1;
  tool_func_t tool = nullptr;
#if !defined(OPENSSL_WINDOWS)
  tool = FindTool(basename(argv[0]));
#endif
  if (tool == nullptr) {
    starting_arg++;
    if (argc > 1) {
      tool = FindTool(argv[1]);
    }
  }
  if (tool == nullptr) {
    usage(argv[0]);
    return 1;
  }

  std::vector<std::string> args;
  for (int i = starting_arg; i < argc; i++) {
    args.push_back(argv[i]);
  }

  return !tool(args);
}
