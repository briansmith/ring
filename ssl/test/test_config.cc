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
#include <stdlib.h>
#include <string.h>

#include <memory>

#include <openssl/base64.h>

namespace {

template <typename T>
struct Flag {
  const char *flag;
  T TestConfig::*member;
};

// FindField looks for the flag in |flags| that matches |flag|. If one is found,
// it returns a pointer to the corresponding field in |config|. Otherwise, it
// returns NULL.
template<typename T, size_t N>
T *FindField(TestConfig *config, const Flag<T> (&flags)[N], const char *flag) {
  for (size_t i = 0; i < N; i++) {
    if (strcmp(flag, flags[i].flag) == 0) {
      return &(config->*(flags[i].member));
    }
  }
  return NULL;
}

const Flag<bool> kBoolFlags[] = {
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
  { "-fastradio-padding", &TestConfig::fastradio_padding },
  { "-implicit-handshake", &TestConfig::implicit_handshake },
  { "-use-early-callback", &TestConfig::use_early_callback },
  { "-fail-early-callback", &TestConfig::fail_early_callback },
};

const Flag<std::string> kStringFlags[] = {
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

const Flag<std::string> kBase64Flags[] = {
  { "-expect-certificate-types", &TestConfig::expected_certificate_types },
  { "-expect-channel-id", &TestConfig::expected_channel_id },
  { "-expect-ocsp-response", &TestConfig::expected_ocsp_response },
  { "-expect-signed-cert-timestamps",
    &TestConfig::expected_signed_cert_timestamps },
};

const Flag<int> kIntFlags[] = {
  { "-port", &TestConfig::port },
  { "-min-version", &TestConfig::min_version },
  { "-max-version", &TestConfig::max_version },
  { "-mtu", &TestConfig::mtu },
};

}  // namespace

TestConfig::TestConfig()
    : port(0),
      is_server(false),
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
      shim_writes_first(false),
      tls_d5_bug(false),
      expect_session_miss(false),
      expect_extended_master_secret(false),
      renegotiate(false),
      allow_unsafe_legacy_renegotiation(false),
      enable_ocsp_stapling(false),
      enable_signed_cert_timestamps(false),
      fastradio_padding(false),
      min_version(0),
      max_version(0),
      mtu(0),
      implicit_handshake(false),
      use_early_callback(false),
      fail_early_callback(false) {
}

bool ParseConfig(int argc, char **argv, TestConfig *out_config) {
  for (int i = 0; i < argc; i++) {
    bool *bool_field = FindField(out_config, kBoolFlags, argv[i]);
    if (bool_field != NULL) {
      *bool_field = true;
      continue;
    }

    std::string *string_field = FindField(out_config, kStringFlags, argv[i]);
    if (string_field != NULL) {
      i++;
      if (i >= argc) {
        fprintf(stderr, "Missing parameter\n");
        return false;
      }
      string_field->assign(argv[i]);
      continue;
    }

    std::string *base64_field = FindField(out_config, kBase64Flags, argv[i]);
    if (base64_field != NULL) {
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
      base64_field->assign(reinterpret_cast<const char *>(decoded.get()), len);
      continue;
    }

    int *int_field = FindField(out_config, kIntFlags, argv[i]);
    if (int_field) {
      i++;
      if (i >= argc) {
        fprintf(stderr, "Missing parameter\n");
        return false;
      }
      *int_field = atoi(argv[i]);
      continue;
    }

    fprintf(stderr, "Unknown argument: %s\n", argv[i]);
    return false;
  }

  return true;
}
