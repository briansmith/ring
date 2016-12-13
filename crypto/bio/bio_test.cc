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
OPENSSL_MSVC_PRAGMA(warning(push, 3))
#include <winsock2.h>
#include <ws2tcpip.h>
OPENSSL_MSVC_PRAGMA(warning(pop))
#endif

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/mem.h>

#include <algorithm>

#include "../internal.h"


#if !defined(OPENSSL_WINDOWS)
static int closesocket(int sock) {
  return close(sock);
}

static void PrintSocketError(const char *func) {
  perror(func);
}
#else
static void PrintSocketError(const char *func) {
  fprintf(stderr, "%s: %d\n", func, WSAGetLastError());
}
#endif

class ScopedSocket {
 public:
  explicit ScopedSocket(int sock) : sock_(sock) {}
  ~ScopedSocket() {
    closesocket(sock_);
  }

 private:
  const int sock_;
};

static bool TestSocketConnect() {
  static const char kTestMessage[] = "test";

  int listening_sock = socket(AF_INET, SOCK_STREAM, 0);
  if (listening_sock == -1) {
    PrintSocketError("socket");
    return false;
  }
  ScopedSocket listening_sock_closer(listening_sock);

  struct sockaddr_in sin;
  OPENSSL_memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  if (!inet_pton(AF_INET, "127.0.0.1", &sin.sin_addr)) {
    PrintSocketError("inet_pton");
    return false;
  }
  if (bind(listening_sock, (struct sockaddr *)&sin, sizeof(sin)) != 0) {
    PrintSocketError("bind");
    return false;
  }
  if (listen(listening_sock, 1)) {
    PrintSocketError("listen");
    return false;
  }
  socklen_t sockaddr_len = sizeof(sin);
  if (getsockname(listening_sock, (struct sockaddr *)&sin, &sockaddr_len) ||
      sockaddr_len != sizeof(sin)) {
    PrintSocketError("getsockname");
    return false;
  }

  char hostname[80];
  BIO_snprintf(hostname, sizeof(hostname), "%s:%d", "127.0.0.1",
               ntohs(sin.sin_port));
  bssl::UniquePtr<BIO> bio(BIO_new_connect(hostname));
  if (!bio) {
    fprintf(stderr, "BIO_new_connect failed.\n");
    return false;
  }

  if (BIO_write(bio.get(), kTestMessage, sizeof(kTestMessage)) !=
      sizeof(kTestMessage)) {
    fprintf(stderr, "BIO_write failed.\n");
    ERR_print_errors_fp(stderr);
    return false;
  }

  int sock = accept(listening_sock, (struct sockaddr *) &sin, &sockaddr_len);
  if (sock == -1) {
    PrintSocketError("accept");
    return false;
  }
  ScopedSocket sock_closer(sock);

  char buf[5];
  if (recv(sock, buf, sizeof(buf), 0) != sizeof(kTestMessage)) {
    PrintSocketError("read");
    return false;
  }
  if (OPENSSL_memcmp(buf, kTestMessage, sizeof(kTestMessage))) {
    return false;
  }

  return true;
}

static bool TestPrintf() {
  // Test a short output, a very long one, and various sizes around
  // 256 (the size of the buffer) to ensure edge cases are correct.
  static const size_t kLengths[] = { 5, 250, 251, 252, 253, 254, 1023 };

  bssl::UniquePtr<BIO> bio(BIO_new(BIO_s_mem()));
  if (!bio) {
    fprintf(stderr, "BIO_new failed\n");
    return false;
  }

  for (size_t i = 0; i < OPENSSL_ARRAY_SIZE(kLengths); i++) {
    char string[1024];
    if (kLengths[i] >= sizeof(string)) {
      fprintf(stderr, "Bad test string length\n");
      return false;
    }
    OPENSSL_memset(string, 'a', sizeof(string));
    string[kLengths[i]] = '\0';

    int ret = BIO_printf(bio.get(), "test %s", string);
    if (ret < 0 || static_cast<size_t>(ret) != 5 + kLengths[i]) {
      fprintf(stderr, "BIO_printf failed: %d\n", ret);
      return false;
    }
    const uint8_t *contents;
    size_t len;
    if (!BIO_mem_contents(bio.get(), &contents, &len)) {
      fprintf(stderr, "BIO_mem_contents failed\n");
      return false;
    }
    if (len != 5 + kLengths[i] ||
        strncmp((const char *)contents, "test ", 5) != 0 ||
        strncmp((const char *)contents + 5, string, kLengths[i]) != 0) {
      fprintf(stderr, "Contents did not match: %.*s\n", (int)len, contents);
      return false;
    }

    if (!BIO_reset(bio.get())) {
      fprintf(stderr, "BIO_reset failed\n");
      return false;
    }
  }

  return true;
}

static bool ReadASN1(bool should_succeed, const uint8_t *data, size_t data_len,
                     size_t expected_len, size_t max_len) {
  bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(data, data_len));

  uint8_t *out;
  size_t out_len;
  int ok = BIO_read_asn1(bio.get(), &out, &out_len, max_len);
  if (!ok) {
    out = nullptr;
  }
  bssl::UniquePtr<uint8_t> out_storage(out);

  if (should_succeed != (ok == 1)) {
    return false;
  }

  if (should_succeed && (out_len != expected_len ||
                         OPENSSL_memcmp(data, out, expected_len) != 0)) {
    return false;
  }

  return true;
}

static bool TestASN1() {
  static const uint8_t kData1[] = {0x30, 2, 1, 2, 0, 0};
  static const uint8_t kData2[] = {0x30, 3, 1, 2};  /* truncated */
  static const uint8_t kData3[] = {0x30, 0x81, 1, 1};  /* should be short len */
  static const uint8_t kData4[] = {0x30, 0x82, 0, 1, 1};  /* zero padded. */

  if (!ReadASN1(true, kData1, sizeof(kData1), 4, 100) ||
      !ReadASN1(false, kData2, sizeof(kData2), 0, 100) ||
      !ReadASN1(false, kData3, sizeof(kData3), 0, 100) ||
      !ReadASN1(false, kData4, sizeof(kData4), 0, 100)) {
    return false;
  }

  static const size_t kLargePayloadLen = 8000;
  static const uint8_t kLargePrefix[] = {0x30, 0x82, kLargePayloadLen >> 8,
                                         kLargePayloadLen & 0xff};
  bssl::UniquePtr<uint8_t> large(reinterpret_cast<uint8_t *>(
      OPENSSL_malloc(sizeof(kLargePrefix) + kLargePayloadLen)));
  if (!large) {
    return false;
  }
  OPENSSL_memset(large.get() + sizeof(kLargePrefix), 0, kLargePayloadLen);
  OPENSSL_memcpy(large.get(), kLargePrefix, sizeof(kLargePrefix));

  if (!ReadASN1(true, large.get(), sizeof(kLargePrefix) + kLargePayloadLen,
                sizeof(kLargePrefix) + kLargePayloadLen,
                kLargePayloadLen * 2)) {
    fprintf(stderr, "Large payload test failed.\n");
    return false;
  }

  if (!ReadASN1(false, large.get(), sizeof(kLargePrefix) + kLargePayloadLen,
                sizeof(kLargePrefix) + kLargePayloadLen,
                kLargePayloadLen - 1)) {
    fprintf(stderr, "max_len test failed.\n");
    return false;
  }

  static const uint8_t kIndefPrefix[] = {0x30, 0x80};
  OPENSSL_memcpy(large.get(), kIndefPrefix, sizeof(kIndefPrefix));
  if (!ReadASN1(true, large.get(), sizeof(kLargePrefix) + kLargePayloadLen,
                sizeof(kLargePrefix) + kLargePayloadLen,
                kLargePayloadLen*2)) {
    fprintf(stderr, "indefinite length test failed.\n");
    return false;
  }

  if (!ReadASN1(false, large.get(), sizeof(kLargePrefix) + kLargePayloadLen,
                sizeof(kLargePrefix) + kLargePayloadLen,
                kLargePayloadLen-1)) {
    fprintf(stderr, "indefinite length, max_len test failed.\n");
    return false;
  }

  return true;
}

static bool TestPair() {
  // Run through the tests twice, swapping |bio1| and |bio2|, for symmetry.
  for (int i = 0; i < 2; i++) {
    BIO *bio1, *bio2;
    if (!BIO_new_bio_pair(&bio1, 10, &bio2, 10)) {
      return false;
    }
    bssl::UniquePtr<BIO> free_bio1(bio1), free_bio2(bio2);

    if (i == 1) {
      std::swap(bio1, bio2);
    }

    // Check initial states.
    if (BIO_ctrl_get_write_guarantee(bio1) != 10 ||
        BIO_ctrl_get_read_request(bio1) != 0) {
      return false;
    }

    // Data written in one end may be read out the other.
    char buf[20];
    if (BIO_write(bio1, "12345", 5) != 5 ||
        BIO_ctrl_get_write_guarantee(bio1) != 5 ||
        BIO_read(bio2, buf, sizeof(buf)) != 5 ||
        OPENSSL_memcmp(buf, "12345", 5) != 0 ||
        BIO_ctrl_get_write_guarantee(bio1) != 10) {
      return false;
    }

    // Attempting to write more than 10 bytes will write partially.
    if (BIO_write(bio1, "1234567890___", 13) != 10 ||
        BIO_ctrl_get_write_guarantee(bio1) != 0 ||
        BIO_write(bio1, "z", 1) != -1 ||
        !BIO_should_write(bio1) ||
        BIO_read(bio2, buf, sizeof(buf)) != 10 ||
        OPENSSL_memcmp(buf, "1234567890", 10) != 0 ||
        BIO_ctrl_get_write_guarantee(bio1) != 10) {
      return false;
    }

    // Unsuccessful reads update the read request.
    if (BIO_read(bio2, buf, 5) != -1 ||
        !BIO_should_read(bio2) ||
        BIO_ctrl_get_read_request(bio1) != 5) {
      return false;
    }

    // The read request is clamped to the size of the buffer.
    if (BIO_read(bio2, buf, 20) != -1 ||
        !BIO_should_read(bio2) ||
        BIO_ctrl_get_read_request(bio1) != 10) {
      return false;
    }

    // Data may be written and read in chunks.
    if (BIO_write(bio1, "12345", 5) != 5 ||
        BIO_ctrl_get_write_guarantee(bio1) != 5 ||
        BIO_write(bio1, "67890___", 8) != 5 ||
        BIO_ctrl_get_write_guarantee(bio1) != 0 ||
        BIO_read(bio2, buf, 3) != 3 ||
        OPENSSL_memcmp(buf, "123", 3) != 0 ||
        BIO_ctrl_get_write_guarantee(bio1) != 3 ||
        BIO_read(bio2, buf, sizeof(buf)) != 7 ||
        OPENSSL_memcmp(buf, "4567890", 7) != 0 ||
        BIO_ctrl_get_write_guarantee(bio1) != 10) {
      return false;
    }

    // Successful reads reset the read request.
    if (BIO_ctrl_get_read_request(bio1) != 0) {
      return false;
    }

    // Test writes and reads starting in the middle of the ring buffer and
    // wrapping to front.
    if (BIO_write(bio1, "abcdefgh", 8) != 8 ||
        BIO_ctrl_get_write_guarantee(bio1) != 2 ||
        BIO_read(bio2, buf, 3) != 3 ||
        OPENSSL_memcmp(buf, "abc", 3) != 0 ||
        BIO_ctrl_get_write_guarantee(bio1) != 5 ||
        BIO_write(bio1, "ijklm___", 8) != 5 ||
        BIO_ctrl_get_write_guarantee(bio1) != 0 ||
        BIO_read(bio2, buf, sizeof(buf)) != 10 ||
        OPENSSL_memcmp(buf, "defghijklm", 10) != 0 ||
        BIO_ctrl_get_write_guarantee(bio1) != 10) {
      return false;
    }

    // Data may flow from both ends in parallel.
    if (BIO_write(bio1, "12345", 5) != 5 ||
        BIO_write(bio2, "67890", 5) != 5 ||
        BIO_read(bio2, buf, sizeof(buf)) != 5 ||
        OPENSSL_memcmp(buf, "12345", 5) != 0 ||
        BIO_read(bio1, buf, sizeof(buf)) != 5 ||
        OPENSSL_memcmp(buf, "67890", 5) != 0) {
      return false;
    }

    // Closing the write end causes an EOF on the read half, after draining.
    if (BIO_write(bio1, "12345", 5) != 5 ||
        !BIO_shutdown_wr(bio1) ||
        BIO_read(bio2, buf, sizeof(buf)) != 5 ||
        OPENSSL_memcmp(buf, "12345", 5) != 0 ||
        BIO_read(bio2, buf, sizeof(buf)) != 0) {
      return false;
    }

    // A closed write end may not be written to.
    if (BIO_ctrl_get_write_guarantee(bio1) != 0 ||
        BIO_write(bio1, "_____", 5) != -1) {
      return false;
    }

    uint32_t err = ERR_get_error();
    if (ERR_GET_LIB(err) != ERR_LIB_BIO ||
        ERR_GET_REASON(err) != BIO_R_BROKEN_PIPE) {
      return false;
    }

    // The other end is still functional.
    if (BIO_write(bio2, "12345", 5) != 5 ||
        BIO_read(bio1, buf, sizeof(buf)) != 5 ||
        OPENSSL_memcmp(buf, "12345", 5) != 0) {
      return false;
    }
  }

  return true;
}

int main() {
  CRYPTO_library_init();

#if defined(OPENSSL_WINDOWS)
  // Initialize Winsock.
  WORD wsa_version = MAKEWORD(2, 2);
  WSADATA wsa_data;
  int wsa_err = WSAStartup(wsa_version, &wsa_data);
  if (wsa_err != 0) {
    fprintf(stderr, "WSAStartup failed: %d\n", wsa_err);
    return 1;
  }
  if (wsa_data.wVersion != wsa_version) {
    fprintf(stderr, "Didn't get expected version: %x\n", wsa_data.wVersion);
    return 1;
  }
#endif

  if (!TestSocketConnect() ||
      !TestPrintf() ||
      !TestASN1() ||
      !TestPair()) {
    return 1;
  }

  printf("PASS\n");
  return 0;
}
