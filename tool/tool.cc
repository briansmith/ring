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
#include <functional>
#include <memory>
#include <vector>

#include <stdint.h>
#include <time.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/obj.h>
#include <openssl/rsa.h>

#if defined(OPENSSL_WINDOWS)
#include <Windows.h>
#endif

extern "C" {
// These values are DER encoded, RSA private keys.
extern const uint8_t kDERRSAPrivate2048[];
extern size_t kDERRSAPrivate2048Len;
extern const uint8_t kDERRSAPrivate4096[];
extern size_t kDERRSAPrivate4096Len;
}

// TimeResults represents the results of benchmarking a function.
struct TimeResults {
  // num_calls is the number of function calls done in the time period.
  unsigned num_calls;
  // us is the number of microseconds that elapsed in the time period.
  unsigned us;

  void Print(const std::string &description) {
    printf("Did %u %s operations in %uus (%.1f ops/sec)\n", num_calls,
           description.c_str(), us,
           (static_cast<double>(num_calls) / us) * 1000000);
  }
};

#if defined(OPENSSL_WINDOWS)
static uint64_t time_now() { return GetTickCount64() * 1000; }
#else
static uint64_t time_now() {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);

  uint64_t ret = ts.tv_sec;
  ret *= 1000000;
  ret += ts.tv_nsec / 1000;
  return ret;
}
#endif

static bool TimeFunction(TimeResults *results, std::function<bool()> func) {
  // kTotalMS is the total amount of time that we'll aim to measure a function
  // for.
  static const uint64_t kTotalUS = 3000000;
  uint64_t start = time_now(), now, delta;
  unsigned done = 0, iterations_between_time_checks;

  if (!func()) {
    return false;
  }
  now = time_now();
  delta = now - start;
  if (delta == 0) {
    iterations_between_time_checks = 250;
  } else {
    // Aim for about 100ms between time checks.
    iterations_between_time_checks =
        static_cast<double>(100000) / static_cast<double>(delta);
    if (iterations_between_time_checks > 1000) {
      iterations_between_time_checks = 1000;
    } else if (iterations_between_time_checks < 1) {
      iterations_between_time_checks = 1;
    }
  }

  for (;;) {
    for (unsigned i = 0; i < iterations_between_time_checks; i++) {
      if (!func()) {
        return false;
      }
      done++;
    }

    now = time_now();
    if (now - start > kTotalUS) {
      break;
    }
  }

  results->us = now - start;
  results->num_calls = done;
  return true;
}

static bool SpeedRSA(const std::string& key_name, RSA *key) {
  TimeResults results;

  std::unique_ptr<uint8_t[]> sig(new uint8_t[RSA_size(key)]);
  const uint8_t fake_sha256_hash[32] = {0};
  unsigned sig_len;

  if (!TimeFunction(&results,
                    [key, &sig, &fake_sha256_hash, &sig_len]() -> bool {
        return RSA_sign(NID_sha256, fake_sha256_hash, sizeof(fake_sha256_hash),
                        sig.get(), &sig_len, key);
      })) {
    fprintf(stderr, "RSA_sign failed.\n");
    BIO_print_errors_fp(stderr);
    return false;
  }
  results.Print(key_name + " signing");

  if (!TimeFunction(&results,
                    [key, &fake_sha256_hash, &sig, sig_len]() -> bool {
        return RSA_verify(NID_sha256, fake_sha256_hash,
                          sizeof(fake_sha256_hash), sig.get(), sig_len, key);
      })) {
    fprintf(stderr, "RSA_verify failed.\n");
    BIO_print_errors_fp(stderr);
    return false;
  }
  results.Print(key_name + " verify");

  return true;
}

static bool Speed(const std::vector<std::string> &args) {
  const uint8_t *inp;

  RSA *key = NULL;
  inp = kDERRSAPrivate2048;
  if (NULL == d2i_RSAPrivateKey(&key, &inp, kDERRSAPrivate2048Len)) {
    fprintf(stderr, "Failed to parse RSA key.\n");
    BIO_print_errors_fp(stderr);
    return false;
  }

  if (!SpeedRSA("RSA 2048", key)) {
    return false;
  }

  RSA_free(key);
  key = NULL;

  inp = kDERRSAPrivate4096;
  if (NULL == d2i_RSAPrivateKey(&key, &inp, kDERRSAPrivate4096Len)) {
    fprintf(stderr, "Failed to parse 4096-bit RSA key.\n");
    BIO_print_errors_fp(stderr);
    return 1;
  }

  if (!SpeedRSA("RSA 4096", key)) {
    return false;
  }

  RSA_free(key);

  return 0;
}

void usage(const char *name) {
  printf("Usage: %s [speed]\n", name);
}

int main(int argc, char **argv) {
  std::string tool;
  if (argc >= 2) {
    tool = argv[1];
  }

  ERR_load_crypto_strings();

  std::vector<std::string> args;
  for (int i = 2; i < argc; i++) {
    args.push_back(argv[i]);
  }

  if (tool == "speed") {
    return !Speed(args);
  } else {
    usage(argv[0]);
    return 1;
  }
}
