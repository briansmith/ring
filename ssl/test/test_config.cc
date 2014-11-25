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

#include <stdio.h>
#include <string.h>

#include <memory>

#include <openssl/base64.h>

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
  { "-shim-writes-first", &TestConfig::shim_writes_first },
  { "-tls-d5-bug", &TestConfig::tls_d5_bug },
  { "-expect-session-miss", &TestConfig::expect_session_miss },
  { "-expect-extended-master-secret",
    &TestConfig::expect_extended_master_secret },
  { "-renegotiate", &TestConfig::renegotiate },
  { "-allow-unsafe-legacy-renegotiation",
    &TestConfig::allow_unsafe_legacy_renegotiation },
  { "-enable-ocsp-stapling", &TestConfig::enable_ocsp_stapling },
  { "-enable-signed-cert-timestamps",
    &TestConfig::enable_signed_cert_timestamps },
};

const size_t kNumBoolFlags = sizeof(kBoolFlags) / sizeof(kBoolFlags[0]);

const StringFlag kStringFlags[] = {
  { "-key-file", &TestConfig::key_file },
  { "-cert-file", &TestConfig::cert_file },
  { "-expect-server-name", &TestConfig::expected_server_name },
  { "-advertise-npn", &TestConfig::advertise_npn },
  { "-expect-next-proto", &TestConfig::expected_next_proto },
  { "-select-next-proto", &TestConfig::select_next_proto },
  { "-send-channel-id", &TestConfig::send_channel_id },
  { "-host-name", &TestConfig::host_name },
  { "-advertise-alpn", &TestConfig::advertise_alpn },
  { "-expect-alpn", &TestConfig::expected_alpn },
  { "-expect-advertised-alpn", &TestConfig::expected_advertised_alpn },
  { "-select-alpn", &TestConfig::select_alpn },
  { "-psk", &TestConfig::psk },
  { "-psk-identity", &TestConfig::psk_identity },
  { "-srtp-profiles", &TestConfig::srtp_profiles },
};

const size_t kNumStringFlags = sizeof(kStringFlags) / sizeof(kStringFlags[0]);

const StringFlag kBase64Flags[] = {
  { "-expect-certificate-types", &TestConfig::expected_certificate_types },
  { "-expect-channel-id", &TestConfig::expected_channel_id },
  { "-expect-ocsp-response", &TestConfig::expected_ocsp_response },
  { "-expect-signed-cert-timestamps",
    &TestConfig::expected_signed_cert_timestamps },
};

const size_t kNumBase64Flags = sizeof(kBase64Flags) / sizeof(kBase64Flags[0]);

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
      cookie_exchange(false),
      shim_writes_first(false),
      tls_d5_bug(false),
      expect_session_miss(false),
      expect_extended_master_secret(false),
      renegotiate(false),
      allow_unsafe_legacy_renegotiation(false),
      enable_ocsp_stapling(false),
      enable_signed_cert_timestamps(false) {
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

    for (j = 0; j < kNumBase64Flags; j++) {
      if (strcmp(argv[i], kBase64Flags[j].flag) == 0) {
        break;
      }
    }
    if (j < kNumBase64Flags) {
      i++;
      if (i >= argc) {
        fprintf(stderr, "Missing parameter\n");
        return false;
      }
      size_t len;
      if (!EVP_DecodedLength(&len, strlen(argv[i]))) {
        fprintf(stderr, "Invalid base64: %s\n", argv[i]);
      }
      std::unique_ptr<uint8_t[]> decoded(new uint8_t[len]);
      if (!EVP_DecodeBase64(decoded.get(), &len, len,
                            reinterpret_cast<const uint8_t *>(argv[i]),
                            strlen(argv[i]))) {
        fprintf(stderr, "Invalid base64: %s\n", argv[i]);
      }
      out_config->*(kBase64Flags[j].member) = std::string(
          reinterpret_cast<const char *>(decoded.get()), len);
      continue;
    }

    fprintf(stderr, "Unknown argument: %s\n", argv[i]);
    return false;
  }

  return true;
}
