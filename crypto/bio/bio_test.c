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

#if !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 201410L
#endif

#include <openssl/base.h>

#if !defined(OPENSSL_WINDOWS)
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#else
#include <io.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#endif

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>


#if !defined(OPENSSL_WINDOWS)
static int closesocket(int sock) {
  return close(sock);
}

static void print_socket_error(const char *func) {
  perror(func);
}
#else
static void print_socket_error(const char *func) {
  fprintf(stderr, "%s: %d\n", func, WSAGetLastError());
}
#endif

static int test_socket_connect(void) {
  int listening_sock = socket(AF_INET, SOCK_STREAM, 0);
  int sock;
  struct sockaddr_in sin;
  socklen_t sockaddr_len = sizeof(sin);
  static const char kTestMessage[] = "test";
  char hostname[80], buf[5];
  BIO *bio;

  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  if (!inet_pton(AF_INET, "127.0.0.1", &sin.sin_addr)) {
    print_socket_error("inet_pton");
    return 0;
  }

  if (bind(listening_sock, (struct sockaddr *)&sin, sizeof(sin)) != 0) {
    print_socket_error("bind");
    return 0;
  }

  if (listen(listening_sock, 1)) {
    print_socket_error("listen");
    return 0;
  }

  if (getsockname(listening_sock, (struct sockaddr *)&sin, &sockaddr_len) ||
      sockaddr_len != sizeof(sin)) {
    print_socket_error("getsockname");
    return 0;
  }

  BIO_snprintf(hostname, sizeof(hostname), "%s:%d", "127.0.0.1",
               ntohs(sin.sin_port));
  bio = BIO_new_connect(hostname);
  if (!bio) {
    fprintf(stderr, "BIO_new_connect failed.\n");
    return 0;
  }

  if (BIO_write(bio, kTestMessage, sizeof(kTestMessage)) !=
      sizeof(kTestMessage)) {
    fprintf(stderr, "BIO_write failed.\n");
    BIO_print_errors_fp(stderr);
    return 0;
  }

  sock = accept(listening_sock, (struct sockaddr *) &sin, &sockaddr_len);
  if (sock < 0) {
    print_socket_error("accept");
    return 0;
  }

  if (recv(sock, buf, sizeof(buf), 0) != sizeof(kTestMessage)) {
    print_socket_error("read");
    return 0;
  }

  if (memcmp(buf, kTestMessage, sizeof(kTestMessage))) {
    return 0;
  }

  closesocket(sock);
  closesocket(listening_sock);
  BIO_free(bio);

  return 1;
}

static int test_printf(void) {
  /* Test a short output, a very long one, and various sizes around
   * 256 (the size of the buffer) to ensure edge cases are correct. */
  static const size_t kLengths[] = { 5, 250, 251, 252, 253, 254, 1023 };
  BIO *bio;
  char string[1024];
  int ret;
  const uint8_t *contents;
  size_t i, len;

  bio = BIO_new(BIO_s_mem());
  if (!bio) {
    fprintf(stderr, "BIO_new failed\n");
    return 0;
  }

  for (i = 0; i < sizeof(kLengths) / sizeof(kLengths[0]); i++) {
    if (kLengths[i] >= sizeof(string)) {
      fprintf(stderr, "Bad test string length\n");
      return 0;
    }
    memset(string, 'a', sizeof(string));
    string[kLengths[i]] = '\0';

    ret = BIO_printf(bio, "test %s", string);
    if (ret != 5 + kLengths[i]) {
      fprintf(stderr, "BIO_printf failed: %d\n", ret);
      return 0;
    }
    if (!BIO_mem_contents(bio, &contents, &len)) {
      fprintf(stderr, "BIO_mem_contents failed\n");
      return 0;
    }
    if (len != 5 + kLengths[i] ||
        strncmp((const char *)contents, "test ", 5) != 0 ||
        strncmp((const char *)contents + 5, string, kLengths[i]) != 0) {
      fprintf(stderr, "Contents did not match: %.*s\n", (int)len, contents);
      return 0;
    }

    if (!BIO_reset(bio)) {
      fprintf(stderr, "BIO_reset failed\n");
      return 0;
    }
  }

  BIO_free(bio);
  return 1;
}

int main(void) {
#if defined(OPENSSL_WINDOWS)
  WSADATA wsa_data;
  WORD wsa_version;
  int wsa_err;
#endif

  CRYPTO_library_init();
  ERR_load_crypto_strings();

#if defined(OPENSSL_WINDOWS)
  /* Initialize Winsock. */
  wsa_version = MAKEWORD(2, 2);
  wsa_err = WSAStartup(wsa_version, &wsa_data);
  if (wsa_err != 0) {
    fprintf(stderr, "WSAStartup failed: %d\n", wsa_err);
    return 1;
  }
  if (wsa_data.wVersion != wsa_version) {
    fprintf(stderr, "Didn't get expected version: %x\n", wsa_data.wVersion);
    return 1;
  }
#endif

  if (!test_socket_connect()) {
    return 1;
  }

  if (!test_printf()) {
    return 1;
  }

  printf("PASS\n");
  return 0;
}
