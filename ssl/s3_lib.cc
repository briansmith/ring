/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 *
 * Portions of the attached software ("Contribution") are developed by
 * SUN MICROSYSTEMS, INC., and are contributed to the OpenSSL project.
 *
 * The Contribution is licensed pursuant to the OpenSSL open source
 * license provided above.
 *
 * ECC cipher suite support in OpenSSL originally written by
 * Vipul Gupta and Sumit Gupta of Sun Microsystems Laboratories.
 *
 */
/* ====================================================================
 * Copyright 2005 Nokia. All rights reserved.
 *
 * The portions of the attached software ("Contribution") is developed by
 * Nokia Corporation and is licensed pursuant to the OpenSSL open source
 * license.
 *
 * The Contribution, originally written by Mika Kousa and Pasi Eronen of
 * Nokia Corporation, consists of the "PSK" (Pre-Shared Key) ciphersuites
 * support (see RFC 4279) to OpenSSL.
 *
 * No patent licenses or other rights except those expressly stated in
 * the OpenSSL open source license shall be deemed granted or received
 * expressly, by implication, estoppel, or otherwise.
 *
 * No assurances are provided by Nokia that the Contribution does not
 * infringe the patent or other intellectual property rights of any third
 * party or that the license provides you with all the necessary rights
 * to make use of the Contribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND. IN
 * ADDITION TO THE DISCLAIMERS INCLUDED IN THE LICENSE, NOKIA
 * SPECIFICALLY DISCLAIMS ANY LIABILITY FOR CLAIMS BROUGHT BY YOU OR ANY
 * OTHER ENTITY BASED ON INFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS OR
 * OTHERWISE. */

#include <openssl/ssl.h>

#include <assert.h>
#include <string.h>

#include <openssl/digest.h>
#include <openssl/err.h>
#include <openssl/md5.h>
#include <openssl/mem.h>
#include <openssl/nid.h>

#include "../crypto/internal.h"
#include "internal.h"


BSSL_NAMESPACE_BEGIN

SSL3_STATE::SSL3_STATE()
    : skip_early_data(false),
      v2_hello_done(false),
      is_v2_hello(false),
      has_message(false),
      initial_handshake_complete(false),
      session_reused(false),
      send_connection_binding(false),
      channel_id_valid(false),
      key_update_pending(false),
      early_data_accepted(false),
      alert_dispatch(false),
      renegotiate_pending(false),
      used_hello_retry_request(false),
      was_key_usage_invalid(false) {}

SSL3_STATE::~SSL3_STATE() {}

bool tls_new(SSL *ssl) {
  UniquePtr<SSL3_STATE> s3 = MakeUnique<SSL3_STATE>();
  if (!s3) {
    return false;
  }

  // TODO(crbug.com/368805255): Fields that aren't used in DTLS should not be
  // allocated at all.
  // TODO(crbug.com/371998381): Don't create these in QUIC either, once the
  // placeholder QUIC ones for subsequent epochs are removed.
  if (!SSL_is_dtls(ssl)) {
    s3->aead_read_ctx = SSLAEADContext::CreateNullCipher();
    s3->aead_write_ctx = SSLAEADContext::CreateNullCipher();
    if (!s3->aead_read_ctx || !s3->aead_write_ctx) {
      return false;
    }
  }

  s3->hs = ssl_handshake_new(ssl);
  if (!s3->hs) {
    return false;
  }

  ssl->s3 = s3.release();
  return true;
}

void tls_free(SSL *ssl) {
  if (ssl == NULL || ssl->s3 == NULL) {
    return;
  }

  Delete(ssl->s3);
  ssl->s3 = NULL;
}

BSSL_NAMESPACE_END
