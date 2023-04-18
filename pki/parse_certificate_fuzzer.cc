// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>
#include <stdint.h>

#include "cert_errors.h"
#include "parsed_certificate.h"
#include "fillins/x509_util.h"
#include <openssl/span.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  bssl::CertErrors errors;
  std::shared_ptr<const ParsedCertificate> cert =
      ParsedCertificate::Create(
          x509_util::CreateCryptoBuffer(bssl::MakeSpan(data, size)), {},
          &errors);

  // Severe errors must be provided iff the parsing failed.
  CHECK_EQ(errors.ContainsAnyErrorWithSeverity(net::CertError::SEVERITY_HIGH),
           cert == nullptr);

  return 0;
}
