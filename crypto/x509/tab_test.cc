/*
 * Copyright 1999-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#if !defined(BORINGSSL_SHARED_LIBRARY)

#include <gtest/gtest.h>

#include <openssl/x509.h>

#include "../internal.h"
#include "ext_dat.h"

// Check ext_data.h is correct.
TEST(X509V3Test, TabTest) {
  EXPECT_EQ(OPENSSL_ARRAY_SIZE(standard_exts), STANDARD_EXTENSION_COUNT);
  for (size_t i = 1; i < OPENSSL_ARRAY_SIZE(standard_exts); i++) {
    SCOPED_TRACE(i);
    EXPECT_LT(standard_exts[i-1]->ext_nid, standard_exts[i]->ext_nid);
  }
}

#endif  // !BORINGSSL_SHARED_LIBRARY
