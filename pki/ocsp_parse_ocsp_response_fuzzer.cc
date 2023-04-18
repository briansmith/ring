// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>
#include <stdint.h>

#include "ocsp.h"
#include "input.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  bssl::der::Input response_der(data, size);
  net::OCSPResponse response;
  net::ParseOCSPResponse(response_der, &response);

  return 0;
}
