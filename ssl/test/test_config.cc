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

#include "test_config.h"

#include <string.h>


namespace {

typedef bool TestConfig::*BoolMember;
typedef std::string TestConfig::*StringMember;

struct BoolFlag {
  const char *flag;
  BoolMember member;
};

struct StringFlag {
  const char *flag;
  StringMember member;
};

const BoolFlag kBoolFlags[] = {
  { "-server", &TestConfig::is_server },
  { "-dtls", &TestConfig::is_dtls },
  { "-resume", &TestConfig::resume },
  { "-fallback-scsv", &TestConfig::fallback_scsv },
  { "-require-any-client-certificate",
    &TestConfig::require_any_client_certificate },
  { "-false-start", &TestConfig::false_start },
  { "-async", &TestConfig::async },
  { "-write-different-record-sizes",
    &TestConfig::write_different_record_sizes },
  { "-cbc-record-splitting", &TestConfig::cbc_record_splitting },
  { "-partial-write", &TestConfig::partial_write },
  { "-no-tls12", &TestConfig::no_tls12 },
  { "-no-tls11", &TestConfig::no_tls11 },
  { "-no-tls1", &TestConfig::no_tls1 },
  { "-no-ssl3", &TestConfig::no_ssl3 },
  { "-cookie-exchange", &TestConfig::cookie_exchange },
};

const size_t kNumBoolFlags = sizeof(kBoolFlags) / sizeof(kBoolFlags[0]);

// TODO(davidben): Some of these should be in a new kBase64Flags to allow NUL
// bytes.
const StringFlag kStringFlags[] = {
  { "-key-file", &TestConfig::key_file },
  { "-cert-file", &TestConfig::cert_file },
  { "-expect-server-name", &TestConfig::expected_server_name },
  // Conveniently, 00 is not a certificate type.
  { "-expect-certificate-types", &TestConfig::expected_certificate_types },
  { "-advertise-npn", &TestConfig::advertise_npn },
  { "-expect-next-proto", &TestConfig::expected_next_proto },
  { "-select-next-proto", &TestConfig::select_next_proto },
};

const size_t kNumStringFlags = sizeof(kStringFlags) / sizeof(kStringFlags[0]);

}  // namespace

TestConfig::TestConfig()
    : is_server(false),
      is_dtls(false),
      resume(false),
      fallback_scsv(false),
      require_any_client_certificate(false),
      false_start(false),
      async(false),
      write_different_record_sizes(false),
      cbc_record_splitting(false),
      partial_write(false),
      no_tls12(false),
      no_tls11(false),
      no_tls1(false),
      no_ssl3(false),
      cookie_exchange(false) {
}

bool ParseConfig(int argc, char **argv, TestConfig *out_config) {
  for (int i = 0; i < argc; i++) {
    size_t j;
    for (j = 0; j < kNumBoolFlags; j++) {
      if (strcmp(argv[i], kBoolFlags[j].flag) == 0) {
        break;
      }
    }
    if (j < kNumBoolFlags) {
      out_config->*(kBoolFlags[j].member) = true;
      continue;
    }

    for (j = 0; j < kNumStringFlags; j++) {
      if (strcmp(argv[i], kStringFlags[j].flag) == 0) {
        break;
      }
    }
    if (j < kNumStringFlags) {
      i++;
      if (i >= argc) {
        fprintf(stderr, "Missing parameter\n");
        return false;
      }
      out_config->*(kStringFlags[j].member) = argv[i];
      continue;
    }

    fprintf(stderr, "Unknown argument: %s\n", argv[i]);
    return false;
  }

  return true;
}
