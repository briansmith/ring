/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project 1999.
 */
/* ====================================================================
 * Copyright (c) 1999 The OpenSSL Project.  All rights reserved.
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
 *    licensing@OpenSSL.org.
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

#include <openssl/asn1t.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/obj.h>
#include <openssl/pkcs8.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include "../internal.h"
#include "internal.h"


/* PKCS#5 password based encryption structure */

ASN1_SEQUENCE(PBEPARAM) = {
	ASN1_SIMPLE(PBEPARAM, salt, ASN1_OCTET_STRING),
	ASN1_SIMPLE(PBEPARAM, iter, ASN1_INTEGER)
} ASN1_SEQUENCE_END(PBEPARAM)

IMPLEMENT_ASN1_FUNCTIONS(PBEPARAM)


X509_ALGOR *PKCS5_pbe_set(int alg, int iter, const uint8_t *salt,
                          size_t salt_len) {
  if (iter <= 0) {
    iter = PKCS5_DEFAULT_ITERATIONS;
  }

  CBB cbb;
  CBB_zero(&cbb);

  /* Generate a random salt if necessary. This will be parsed back out of the
   * serialized |X509_ALGOR|. */
  X509_ALGOR *ret = NULL;
  uint8_t *salt_buf = NULL, *der = NULL;
  size_t der_len;
  if (salt == NULL) {
    if (salt_len == 0) {
      salt_len = PKCS5_SALT_LEN;
    }

    salt_buf = OPENSSL_malloc(salt_len);
    if (salt_buf == NULL ||
        !RAND_bytes(salt_buf, salt_len)) {
      goto err;
    }

    salt = salt_buf;
  }

  /* See RFC 2898, appendix A.3. */
  CBB algorithm, param, salt_cbb;
  if (!CBB_init(&cbb, 16) ||
      !CBB_add_asn1(&cbb, &algorithm, CBS_ASN1_SEQUENCE) ||
      !OBJ_nid2cbb(&algorithm, alg) ||
      !CBB_add_asn1(&algorithm, &param, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1(&param, &salt_cbb, CBS_ASN1_OCTETSTRING) ||
      !CBB_add_bytes(&salt_cbb, salt, salt_len) ||
      !CBB_add_asn1_uint64(&param, iter) ||
      !CBB_finish(&cbb, &der, &der_len)) {
    goto err;
  }

  const uint8_t *ptr = der;
  ret = d2i_X509_ALGOR(NULL, &ptr, der_len);
  if (ret == NULL || ptr != der + der_len) {
    OPENSSL_PUT_ERROR(PKCS8, ERR_R_INTERNAL_ERROR);
    X509_ALGOR_free(ret);
    ret = NULL;
  }

err:
  OPENSSL_free(der);
  OPENSSL_free(salt_buf);
  CBB_cleanup(&cbb);
  return ret;
}
