/*
 * Copyright 2001-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_HEADER_AES_H
#define OPENSSL_HEADER_AES_H

#include <ring-core/base.h>

// Raw AES functions.


// AES_MAXNR is the maximum number of AES rounds.
#define AES_MAXNR 14

// aes_key_st should be an opaque type, but EVP requires that the size be
// known.
struct aes_key_st {
  uint32_t rd_key[4 * (AES_MAXNR + 1)];
  unsigned rounds;
};
typedef struct aes_key_st AES_KEY;

#endif  // OPENSSL_HEADER_AES_H
