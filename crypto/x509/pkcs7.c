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

#include <openssl/x509.h>

#include <openssl/bytestring.h>
#include <openssl/err.h>
#include <openssl/obj.h>
#include <openssl/stack.h>

#include "../bytestring/internal.h"


int PKCS7_get_certificates(STACK_OF(X509) *out_certs, CBS *cbs) {
  uint8_t *der_bytes = NULL;
  size_t der_len;
  CBS in, content_info, content_type, wrapped_signed_data, signed_data,
      certificates;
  const size_t initial_certs_len = sk_X509_num(out_certs);
  uint64_t version;
  int ret = 0;

  /* The input may be in BER format. */
  if (!CBS_asn1_ber_to_der(cbs, &der_bytes, &der_len)) {
    return 0;
  }
  if (der_bytes != NULL) {
    CBS_init(&in, der_bytes, der_len);
  } else {
    CBS_init(&in, CBS_data(cbs), CBS_len(cbs));
  }

  /* See https://tools.ietf.org/html/rfc2315#section-7 */
  if (!CBS_get_asn1(&in, &content_info, CBS_ASN1_SEQUENCE) ||
      !CBS_get_asn1(&content_info, &content_type, CBS_ASN1_OBJECT)) {
    goto err;
  }

  if (OBJ_cbs2nid(&content_type) != NID_pkcs7_signed) {
    OPENSSL_PUT_ERROR(X509, PKCS7_get_certificates,
                      X509_R_NOT_PKCS7_SIGNED_DATA);
    goto err;
  }

  /* See https://tools.ietf.org/html/rfc2315#section-9.1 */
  if (!CBS_get_asn1(&content_info, &wrapped_signed_data,
                    CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0) ||
      !CBS_get_asn1(&wrapped_signed_data, &signed_data, CBS_ASN1_SEQUENCE) ||
      !CBS_get_asn1_uint64(&signed_data, &version) ||
      !CBS_get_asn1(&signed_data, NULL /* digests */, CBS_ASN1_SET) ||
      !CBS_get_asn1(&signed_data, NULL /* content */, CBS_ASN1_SEQUENCE)) {
    goto err;
  }

  if (version < 1) {
    OPENSSL_PUT_ERROR(X509, PKCS7_get_certificates,
                      X509_R_BAD_PKCS7_VERSION);
    goto err;
  }

  if (!CBS_get_asn1(&signed_data, &certificates,
                    CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0)) {
    OPENSSL_PUT_ERROR(X509, PKCS7_get_certificates,
                      X509_R_NO_CERTIFICATES_INCLUDED);
    goto err;
  }

  while (CBS_len(&certificates) > 0) {
    CBS cert;
    X509 *x509;
    const uint8_t *inp;

    if (!CBS_get_asn1_element(&certificates, &cert, CBS_ASN1_SEQUENCE)) {
      goto err;
    }

    inp = CBS_data(&cert);
    x509 = d2i_X509(NULL, &inp, CBS_len(&cert));
    if (!x509) {
      goto err;
    }

    if (inp != CBS_data(&cert) + CBS_len(&cert)) {
      /* This suggests a disconnect between the two ASN.1 parsers. */
      goto err;
    }

    sk_X509_push(out_certs, x509);
  }

  ret = 1;

err:
  if (der_bytes) {
    OPENSSL_free(der_bytes);
  }

  if (!ret) {
    while (sk_X509_num(out_certs) != initial_certs_len) {
      X509 *x509 = sk_X509_pop(out_certs);
      X509_free(x509);
    }
  }

  return ret;
}

int PKCS7_bundle_certificates(CBB *out, const STACK_OF(X509) *certs) {
  CBB outer_seq, wrapped_seq, seq, version_bytes, digest_algos_set,
      content_info, certificates;
  size_t i;

  /* See https://tools.ietf.org/html/rfc2315#section-7 */
  if (!CBB_add_asn1(out, &outer_seq, CBS_ASN1_SEQUENCE) ||
      !OBJ_nid2cbb(&outer_seq, NID_pkcs7_signed) ||
      !CBB_add_asn1(&outer_seq, &wrapped_seq,
                    CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0) ||
      /* See https://tools.ietf.org/html/rfc2315#section-9.1 */
      !CBB_add_asn1(&wrapped_seq, &seq, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1(&seq, &version_bytes, CBS_ASN1_INTEGER) ||
      !CBB_add_u8(&version_bytes, 1) ||
      !CBB_add_asn1(&seq, &digest_algos_set, CBS_ASN1_SET) ||
      !CBB_add_asn1(&seq, &content_info, CBS_ASN1_SEQUENCE) ||
      !OBJ_nid2cbb(&content_info, NID_pkcs7_data) ||
      !CBB_add_asn1(&seq, &certificates,
                    CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0)) {
    return 0;
  }

  for (i = 0; i < sk_X509_num(certs); i++) {
    X509 *x509 = sk_X509_value(certs, i);
    uint8_t *buf;
    int len = i2d_X509(x509, NULL);

    if (len < 0 ||
        !CBB_add_space(&certificates, &buf, len) ||
        i2d_X509(x509, &buf) < 0) {
      return 0;
    }
  }

  return CBB_flush(out);
}
