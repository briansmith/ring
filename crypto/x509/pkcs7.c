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


int PKCS7_get_certificates(STACK_OF(X509) *out_certs, CBS *cbs) {
  /* See https://tools.ietf.org/html/rfc2315#section-9.1 */
  CBS content_info, content_type, wrapped_signed_data, signed_data,
      version_bytes, certificates;
  int nid;
  const size_t initial_certs_len = sk_X509_num(out_certs);

  if (!CBS_get_asn1_ber(cbs, &content_info, CBS_ASN1_SEQUENCE) ||
      !CBS_get_asn1(&content_info, &content_type, CBS_ASN1_OBJECT)) {
    return 0;
  }

  nid = OBJ_cbs2nid(&content_type);
  if (nid != NID_pkcs7_signed) {
    OPENSSL_PUT_ERROR(X509, PKCS7_get_certificates,
                      X509_R_NOT_PKCS7_SIGNED_DATA);
    return 0;
  }

  if (!CBS_get_asn1_ber(&content_info, &wrapped_signed_data,
                        CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0) ||
      !CBS_get_asn1_ber(&wrapped_signed_data, &signed_data,
                        CBS_ASN1_SEQUENCE) ||
      !CBS_get_asn1_ber(&signed_data, &version_bytes, CBS_ASN1_INTEGER) ||
      !CBS_get_asn1_ber(&signed_data, NULL /* digests */, CBS_ASN1_SET) ||
      !CBS_get_asn1_ber(&signed_data, NULL /* content */, CBS_ASN1_SEQUENCE)) {
    return 0;
  }

  if (CBS_len(&version_bytes) < 1 || CBS_data(&version_bytes)[0] == 0) {
    OPENSSL_PUT_ERROR(X509, PKCS7_get_certificates,
                      X509_R_BAD_PKCS7_VERSION);
    return 0;
  }

  if (!CBS_get_asn1_ber(&signed_data, &certificates,
                        CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 0)) {
    OPENSSL_PUT_ERROR(X509, PKCS7_get_certificates,
                      X509_R_NO_CERTIFICATES_INCLUDED);
    return 0;
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

  return 1;

err:
  while (sk_X509_num(out_certs) != initial_certs_len) {
    X509 *x509 = sk_X509_pop(out_certs);
    X509_free(x509);
  }

  return 0;
}
