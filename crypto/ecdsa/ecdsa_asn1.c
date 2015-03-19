/* ====================================================================
 * Copyright (c) 1998-2005 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com). */

#include <openssl/ecdsa.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/ec_key.h>
#include <openssl/mem.h>

#include "../ec/internal.h"


DECLARE_ASN1_FUNCTIONS_const(ECDSA_SIG);
DECLARE_ASN1_ENCODE_FUNCTIONS_const(ECDSA_SIG, ECDSA_SIG);

ASN1_SEQUENCE(ECDSA_SIG) = {
    ASN1_SIMPLE(ECDSA_SIG, r, CBIGNUM),
    ASN1_SIMPLE(ECDSA_SIG, s, CBIGNUM),
} ASN1_SEQUENCE_END(ECDSA_SIG);

IMPLEMENT_ASN1_ENCODE_FUNCTIONS_const_fname(ECDSA_SIG, ECDSA_SIG, ECDSA_SIG);

size_t ECDSA_size(const EC_KEY *key) {
  size_t ret, i, group_order_size;
  ASN1_INTEGER bs;
  BIGNUM *order = NULL;
  unsigned char buf[4];
  const EC_GROUP *group;

  if (key->ecdsa_meth && key->ecdsa_meth->group_order_size) {
    group_order_size = key->ecdsa_meth->group_order_size(key);
  } else {
    size_t num_bits;

    if (key == NULL) {
      return 0;
    }
    group = EC_KEY_get0_group(key);
    if (group == NULL) {
      return 0;
    }

    order = BN_new();
    if (order == NULL) {
      return 0;
    }
    if (!EC_GROUP_get_order(group, order, NULL)) {
      BN_clear_free(order);
      return 0;
    }

    num_bits = BN_num_bits(order);
    group_order_size = (num_bits + 7) / 8;
  }

  bs.length = group_order_size;
  bs.data = buf;
  bs.type = V_ASN1_INTEGER;
  /* If the top bit is set the ASN.1 encoding is 1 larger. */
  buf[0] = 0xff;

  i = i2d_ASN1_INTEGER(&bs, NULL);
  i += i; /* r and s */
  ret = ASN1_object_size(1, i, V_ASN1_SEQUENCE);
  BN_clear_free(order);
  return ret;
}

ECDSA_SIG *ECDSA_SIG_new(void) {
  ECDSA_SIG *sig = OPENSSL_malloc(sizeof(ECDSA_SIG));
  if (sig == NULL) {
    return NULL;
  }
  sig->r = BN_new();
  sig->s = BN_new();
  if (sig->r == NULL || sig->s == NULL) {
    ECDSA_SIG_free(sig);
    return NULL;
  }
  return sig;
}

void ECDSA_SIG_free(ECDSA_SIG *sig) {
  if (sig == NULL) {
    return;
  }

  BN_free(sig->r);
  BN_free(sig->s);
  OPENSSL_free(sig);
}
