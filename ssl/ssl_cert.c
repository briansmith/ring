/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */
/* ====================================================================
 * Copyright (c) 1998-2007 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
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
 * Hudson (tjh@cryptsoft.com).
 *
 */
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 * ECC cipher suite support in OpenSSL originally developed by
 * SUN MICROSYSTEMS, INC., and contributed to the OpenSSL project. */

#include <openssl/ssl.h>

#include <assert.h>
#include <limits.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/buf.h>
#include <openssl/bytestring.h>
#include <openssl/dh.h>
#include <openssl/ec_key.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "../crypto/internal.h"
#include "internal.h"


int SSL_get_ex_data_X509_STORE_CTX_idx(void) {
  /* The ex_data index to go from |X509_STORE_CTX| to |SSL| always uses the
   * reserved app_data slot. Before ex_data was introduced, app_data was used.
   * Avoid breaking any software which assumes |X509_STORE_CTX_get_app_data|
   * works. */
  return 0;
}

CERT *ssl_cert_new(void) {
  CERT *ret = OPENSSL_malloc(sizeof(CERT));
  if (ret == NULL) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
    return NULL;
  }
  OPENSSL_memset(ret, 0, sizeof(CERT));

  return ret;
}

CERT *ssl_cert_dup(CERT *cert) {
  CERT *ret = OPENSSL_malloc(sizeof(CERT));
  if (ret == NULL) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
    return NULL;
  }
  OPENSSL_memset(ret, 0, sizeof(CERT));

  if (cert->x509_leaf != NULL) {
    X509_up_ref(cert->x509_leaf);
    ret->x509_leaf = cert->x509_leaf;
  }

  if (cert->privatekey != NULL) {
    EVP_PKEY_up_ref(cert->privatekey);
    ret->privatekey = cert->privatekey;
  }

  if (cert->x509_chain) {
    ret->x509_chain = X509_chain_up_ref(cert->x509_chain);
    if (!ret->x509_chain) {
      OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
      goto err;
    }
  }

  ret->key_method = cert->key_method;

  ret->mask_k = cert->mask_k;
  ret->mask_a = cert->mask_a;

  if (cert->dh_tmp != NULL) {
    ret->dh_tmp = DHparams_dup(cert->dh_tmp);
    if (ret->dh_tmp == NULL) {
      OPENSSL_PUT_ERROR(SSL, ERR_R_DH_LIB);
      goto err;
    }
  }
  ret->dh_tmp_cb = cert->dh_tmp_cb;

  if (cert->sigalgs != NULL) {
    ret->sigalgs =
        BUF_memdup(cert->sigalgs, cert->num_sigalgs * sizeof(cert->sigalgs[0]));
    if (ret->sigalgs == NULL) {
      goto err;
    }
  }
  ret->num_sigalgs = cert->num_sigalgs;

  ret->cert_cb = cert->cert_cb;
  ret->cert_cb_arg = cert->cert_cb_arg;

  if (cert->verify_store != NULL) {
    X509_STORE_up_ref(cert->verify_store);
    ret->verify_store = cert->verify_store;
  }

  return ret;

err:
  ssl_cert_free(ret);
  return NULL;
}

/* Free up and clear all certificates and chains */
void ssl_cert_clear_certs(CERT *cert) {
  if (cert == NULL) {
    return;
  }

  X509_free(cert->x509_leaf);
  cert->x509_leaf = NULL;
  EVP_PKEY_free(cert->privatekey);
  cert->privatekey = NULL;
  sk_X509_pop_free(cert->x509_chain, X509_free);
  cert->x509_chain = NULL;
  cert->key_method = NULL;
}

void ssl_cert_free(CERT *c) {
  if (c == NULL) {
    return;
  }

  DH_free(c->dh_tmp);

  ssl_cert_clear_certs(c);
  OPENSSL_free(c->sigalgs);
  X509_STORE_free(c->verify_store);

  OPENSSL_free(c);
}

static int ssl_cert_set0_chain(CERT *cert, STACK_OF(X509) *chain) {
  sk_X509_pop_free(cert->x509_chain, X509_free);
  cert->x509_chain = chain;
  return 1;
}

static int ssl_cert_set1_chain(CERT *cert, STACK_OF(X509) *chain) {
  STACK_OF(X509) *dchain;
  if (chain == NULL) {
    return ssl_cert_set0_chain(cert, NULL);
  }

  dchain = X509_chain_up_ref(chain);
  if (dchain == NULL) {
    return 0;
  }

  if (!ssl_cert_set0_chain(cert, dchain)) {
    sk_X509_pop_free(dchain, X509_free);
    return 0;
  }

  return 1;
}

static int ssl_cert_add0_chain_cert(CERT *cert, X509 *x509) {
  if (cert->x509_chain == NULL) {
    cert->x509_chain = sk_X509_new_null();
  }
  if (cert->x509_chain == NULL || !sk_X509_push(cert->x509_chain, x509)) {
    return 0;
  }

  return 1;
}

static int ssl_cert_add1_chain_cert(CERT *cert, X509 *x509) {
  if (!ssl_cert_add0_chain_cert(cert, x509)) {
    return 0;
  }

  X509_up_ref(x509);
  return 1;
}

static void ssl_cert_set_cert_cb(CERT *c, int (*cb)(SSL *ssl, void *arg),
                                 void *arg) {
  c->cert_cb = cb;
  c->cert_cb_arg = arg;
}

int ssl_verify_cert_chain(SSL *ssl, long *out_verify_result,
                          STACK_OF(X509) *cert_chain) {
  if (cert_chain == NULL || sk_X509_num(cert_chain) == 0) {
    return 0;
  }

  X509_STORE *verify_store = ssl->ctx->cert_store;
  if (ssl->cert->verify_store != NULL) {
    verify_store = ssl->cert->verify_store;
  }

  X509 *leaf = sk_X509_value(cert_chain, 0);
  int ret = 0;
  X509_STORE_CTX ctx;
  if (!X509_STORE_CTX_init(&ctx, verify_store, leaf, cert_chain)) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_X509_LIB);
    return 0;
  }
  if (!X509_STORE_CTX_set_ex_data(&ctx, SSL_get_ex_data_X509_STORE_CTX_idx(),
                                  ssl)) {
    goto err;
  }

  /* We need to inherit the verify parameters. These can be determined by the
   * context: if its a server it will verify SSL client certificates or vice
   * versa. */
  X509_STORE_CTX_set_default(&ctx, ssl->server ? "ssl_client" : "ssl_server");

  /* Anything non-default in "param" should overwrite anything in the ctx. */
  X509_VERIFY_PARAM_set1(X509_STORE_CTX_get0_param(&ctx), ssl->param);

  if (ssl->verify_callback) {
    X509_STORE_CTX_set_verify_cb(&ctx, ssl->verify_callback);
  }

  int verify_ret;
  if (ssl->ctx->app_verify_callback != NULL) {
    verify_ret = ssl->ctx->app_verify_callback(&ctx, ssl->ctx->app_verify_arg);
  } else {
    verify_ret = X509_verify_cert(&ctx);
  }

  *out_verify_result = ctx.error;

  /* If |SSL_VERIFY_NONE|, the error is non-fatal, but we keep the result. */
  if (verify_ret <= 0 && ssl->verify_mode != SSL_VERIFY_NONE) {
    ssl3_send_alert(ssl, SSL3_AL_FATAL, ssl_verify_alarm_type(ctx.error));
    OPENSSL_PUT_ERROR(SSL, SSL_R_CERTIFICATE_VERIFY_FAILED);
    goto err;
  }

  ERR_clear_error();
  ret = 1;

err:
  X509_STORE_CTX_cleanup(&ctx);
  return ret;
}

static void set_client_CA_list(STACK_OF(X509_NAME) **ca_list,
                               STACK_OF(X509_NAME) *name_list) {
  sk_X509_NAME_pop_free(*ca_list, X509_NAME_free);
  *ca_list = name_list;
}

STACK_OF(X509_NAME) *SSL_dup_CA_list(STACK_OF(X509_NAME) *list) {
  STACK_OF(X509_NAME) *ret = sk_X509_NAME_new_null();
  if (ret == NULL) {
    return NULL;
  }

  for (size_t i = 0; i < sk_X509_NAME_num(list); i++) {
      X509_NAME *name = X509_NAME_dup(sk_X509_NAME_value(list, i));
    if (name == NULL || !sk_X509_NAME_push(ret, name)) {
      X509_NAME_free(name);
      sk_X509_NAME_pop_free(ret, X509_NAME_free);
      return NULL;
    }
  }

  return ret;
}

void SSL_set_client_CA_list(SSL *ssl, STACK_OF(X509_NAME) *name_list) {
  set_client_CA_list(&ssl->client_CA, name_list);
}

void SSL_CTX_set_client_CA_list(SSL_CTX *ctx, STACK_OF(X509_NAME) *name_list) {
  set_client_CA_list(&ctx->client_CA, name_list);
}

STACK_OF(X509_NAME) *SSL_CTX_get_client_CA_list(const SSL_CTX *ctx) {
  return ctx->client_CA;
}

STACK_OF(X509_NAME) *SSL_get_client_CA_list(const SSL *ssl) {
  /* For historical reasons, this function is used both to query configuration
   * state on a server as well as handshake state on a client. However, whether
   * |ssl| is a client or server is not known until explicitly configured with
   * |SSL_set_connect_state|. If |handshake_func| is NULL, |ssl| is in an
   * indeterminate mode and |ssl->server| is unset. */
  if (ssl->handshake_func != NULL && !ssl->server) {
    if (ssl->s3->hs != NULL) {
      return ssl->s3->hs->ca_names;
    }

    return NULL;
  }

  if (ssl->client_CA != NULL) {
    return ssl->client_CA;
  }
  return ssl->ctx->client_CA;
}

static int add_client_CA(STACK_OF(X509_NAME) **sk, X509 *x509) {
  X509_NAME *name;

  if (x509 == NULL) {
    return 0;
  }
  if (*sk == NULL) {
    *sk = sk_X509_NAME_new_null();
    if (*sk == NULL) {
      return 0;
    }
  }

  name = X509_NAME_dup(X509_get_subject_name(x509));
  if (name == NULL) {
    return 0;
  }

  if (!sk_X509_NAME_push(*sk, name)) {
    X509_NAME_free(name);
    return 0;
  }

  return 1;
}

int SSL_add_client_CA(SSL *ssl, X509 *x509) {
  return add_client_CA(&ssl->client_CA, x509);
}

int SSL_CTX_add_client_CA(SSL_CTX *ctx, X509 *x509) {
  return add_client_CA(&ctx->client_CA, x509);
}

int ssl_has_certificate(const SSL *ssl) {
  return ssl->cert->x509_leaf != NULL && ssl_has_private_key(ssl);
}

X509 *ssl_parse_x509(CBS *cbs) {
  if (CBS_len(cbs) > LONG_MAX) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    return NULL;
  }
  const uint8_t *ptr = CBS_data(cbs);
  X509 *ret = d2i_X509(NULL, &ptr, (long)CBS_len(cbs));
  if (ret == NULL) {
    return NULL;
  }
  CBS_skip(cbs, ptr - CBS_data(cbs));
  return ret;
}

STACK_OF(CRYPTO_BUFFER) *ssl_parse_cert_chain(uint8_t *out_alert,
                                              EVP_PKEY **out_pubkey,
                                              uint8_t *out_leaf_sha256,
                                              CBS *cbs,
                                              CRYPTO_BUFFER_POOL *pool) {
  *out_pubkey = NULL;

  STACK_OF(CRYPTO_BUFFER) *ret = sk_CRYPTO_BUFFER_new_null();
  if (ret == NULL) {
    *out_alert = SSL_AD_INTERNAL_ERROR;
    OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
    return NULL;
  }

  CBS certificate_list;
  if (!CBS_get_u24_length_prefixed(cbs, &certificate_list)) {
    *out_alert = SSL_AD_DECODE_ERROR;
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    goto err;
  }

  while (CBS_len(&certificate_list) > 0) {
    CBS certificate;
    if (!CBS_get_u24_length_prefixed(&certificate_list, &certificate) ||
        CBS_len(&certificate) == 0) {
      *out_alert = SSL_AD_DECODE_ERROR;
      OPENSSL_PUT_ERROR(SSL, SSL_R_CERT_LENGTH_MISMATCH);
      goto err;
    }

    if (sk_CRYPTO_BUFFER_num(ret) == 0) {
      *out_pubkey = ssl_cert_parse_pubkey(&certificate);
      if (*out_pubkey == NULL) {
        goto err;
      }

      /* Retain the hash of the leaf certificate if requested. */
      if (out_leaf_sha256 != NULL) {
        SHA256(CBS_data(&certificate), CBS_len(&certificate), out_leaf_sha256);
      }
    }

    CRYPTO_BUFFER *buf =
        CRYPTO_BUFFER_new_from_CBS(&certificate, pool);
    if (buf == NULL) {
      *out_alert = SSL_AD_DECODE_ERROR;
      goto err;
    }

    if (!sk_CRYPTO_BUFFER_push(ret, buf)) {
      *out_alert = SSL_AD_INTERNAL_ERROR;
      CRYPTO_BUFFER_free(buf);
      OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
      goto err;
    }
  }

  return ret;

err:
  EVP_PKEY_free(*out_pubkey);
  *out_pubkey = NULL;
  sk_CRYPTO_BUFFER_pop_free(ret, CRYPTO_BUFFER_free);
  return NULL;
}

int ssl_add_cert_to_cbb(CBB *cbb, X509 *x509) {
  int len = i2d_X509(x509, NULL);
  if (len < 0) {
    return 0;
  }
  uint8_t *buf;
  if (!CBB_add_space(cbb, &buf, len)) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
    return 0;
  }
  if (buf != NULL && i2d_X509(x509, &buf) < 0) {
    return 0;
  }
  return 1;
}

static int ssl_add_cert_with_length(CBB *cbb, X509 *x509) {
  CBB child;
  return CBB_add_u24_length_prefixed(cbb, &child) &&
         ssl_add_cert_to_cbb(&child, x509) &&
         CBB_flush(cbb);
}

int ssl_add_cert_chain(SSL *ssl, CBB *cbb) {
  if (!ssl_has_certificate(ssl)) {
    return CBB_add_u24(cbb, 0);
  }

  CBB child;
  if (!CBB_add_u24_length_prefixed(cbb, &child) ||
      !ssl_add_cert_with_length(&child, ssl->cert->x509_leaf)) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
    return 0;
  }

  STACK_OF(X509) *chain = ssl->cert->x509_chain;
  for (size_t i = 0; i < sk_X509_num(chain); i++) {
    if (!ssl_add_cert_with_length(&child, sk_X509_value(chain, i))) {
      return 0;
    }
  }

  return CBB_flush(cbb);
}

int ssl_auto_chain_if_needed(SSL *ssl) {
  /* Only build a chain if there are no intermediates configured and the feature
   * isn't disabled. */
  if ((ssl->mode & SSL_MODE_NO_AUTO_CHAIN) ||
      !ssl_has_certificate(ssl) ||
      ssl->cert->x509_chain != NULL) {
    return 1;
  }

  X509_STORE_CTX ctx;
  if (!X509_STORE_CTX_init(&ctx, ssl->ctx->cert_store, ssl->cert->x509_leaf,
                           NULL)) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_X509_LIB);
    return 0;
  }

  /* Attempt to build a chain, ignoring the result. */
  X509_verify_cert(&ctx);
  ERR_clear_error();

  /* Configure the intermediates from any partial chain we managed to build. */
  for (size_t i = 1; i < sk_X509_num(ctx.chain); i++) {
    if (!SSL_add1_chain_cert(ssl, sk_X509_value(ctx.chain, i))) {
      X509_STORE_CTX_cleanup(&ctx);
      return 0;
    }
  }

  X509_STORE_CTX_cleanup(&ctx);
  return 1;
}

/* ssl_cert_skip_to_spki parses a DER-encoded, X.509 certificate from |in| and
 * positions |*out_tbs_cert| to cover the TBSCertificate, starting at the
 * subjectPublicKeyInfo. */
static int ssl_cert_skip_to_spki(const CBS *in, CBS *out_tbs_cert) {
  /* From RFC 5280, section 4.1
   *    Certificate  ::=  SEQUENCE  {
   *      tbsCertificate       TBSCertificate,
   *      signatureAlgorithm   AlgorithmIdentifier,
   *      signatureValue       BIT STRING  }

   * TBSCertificate  ::=  SEQUENCE  {
   *      version         [0]  EXPLICIT Version DEFAULT v1,
   *      serialNumber         CertificateSerialNumber,
   *      signature            AlgorithmIdentifier,
   *      issuer               Name,
   *      validity             Validity,
   *      subject              Name,
   *      subjectPublicKeyInfo SubjectPublicKeyInfo,
   *      ... } */
  CBS buf = *in;

  CBS toplevel;
  if (!CBS_get_asn1(&buf, &toplevel, CBS_ASN1_SEQUENCE) ||
      CBS_len(&buf) != 0 ||
      !CBS_get_asn1(&toplevel, out_tbs_cert, CBS_ASN1_SEQUENCE) ||
      /* version */
      !CBS_get_optional_asn1(
          out_tbs_cert, NULL, NULL,
          CBS_ASN1_CONSTRUCTED | CBS_ASN1_CONTEXT_SPECIFIC | 0) ||
      /* serialNumber */
      !CBS_get_asn1(out_tbs_cert, NULL, CBS_ASN1_INTEGER) ||
      /* signature algorithm */
      !CBS_get_asn1(out_tbs_cert, NULL, CBS_ASN1_SEQUENCE) ||
      /* issuer */
      !CBS_get_asn1(out_tbs_cert, NULL, CBS_ASN1_SEQUENCE) ||
      /* validity */
      !CBS_get_asn1(out_tbs_cert, NULL, CBS_ASN1_SEQUENCE) ||
      /* subject */
      !CBS_get_asn1(out_tbs_cert, NULL, CBS_ASN1_SEQUENCE)) {
    return 0;
  }

  return 1;
}

EVP_PKEY *ssl_cert_parse_pubkey(const CBS *in) {
  CBS buf = *in, tbs_cert, spki;
  if (!ssl_cert_skip_to_spki(&buf, &tbs_cert) ||
      !CBS_get_asn1_element(&tbs_cert, &spki, CBS_ASN1_SEQUENCE)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_CANNOT_PARSE_LEAF_CERT);
    return NULL;
  }

  return EVP_parse_public_key(&spki);
}

int ssl_cert_check_digital_signature_key_usage(const CBS *in) {
  CBS buf = *in;

  CBS tbs_cert, outer_extensions;
  int has_extensions;
  if (!ssl_cert_skip_to_spki(&buf, &tbs_cert) ||
      /* subjectPublicKeyInfo */
      !CBS_get_asn1(&tbs_cert, NULL, CBS_ASN1_SEQUENCE) ||
      /* issuerUniqueID */
      !CBS_get_optional_asn1(
          &tbs_cert, NULL, NULL,
          CBS_ASN1_CONSTRUCTED | CBS_ASN1_CONTEXT_SPECIFIC | 1) ||
      /* subjectUniqueID */
      !CBS_get_optional_asn1(
          &tbs_cert, NULL, NULL,
          CBS_ASN1_CONSTRUCTED | CBS_ASN1_CONTEXT_SPECIFIC | 2) ||
      !CBS_get_optional_asn1(
          &tbs_cert, &outer_extensions, &has_extensions,
          CBS_ASN1_CONSTRUCTED | CBS_ASN1_CONTEXT_SPECIFIC | 3)) {
    goto parse_err;
  }

  if (!has_extensions) {
    return 1;
  }

  CBS extensions;
  if (!CBS_get_asn1(&outer_extensions, &extensions, CBS_ASN1_SEQUENCE)) {
    goto parse_err;
  }

  while (CBS_len(&extensions) > 0) {
    CBS extension, oid, contents;
    if (!CBS_get_asn1(&extensions, &extension, CBS_ASN1_SEQUENCE) ||
        !CBS_get_asn1(&extension, &oid, CBS_ASN1_OBJECT) ||
        (CBS_peek_asn1_tag(&extension, CBS_ASN1_BOOLEAN) &&
         !CBS_get_asn1(&extension, NULL, CBS_ASN1_BOOLEAN)) ||
        !CBS_get_asn1(&extension, &contents, CBS_ASN1_OCTETSTRING) ||
        CBS_len(&extension) != 0) {
      goto parse_err;
    }

    static const uint8_t kKeyUsageOID[3] = {0x55, 0x1d, 0x0f};
    if (CBS_len(&oid) != sizeof(kKeyUsageOID) ||
        OPENSSL_memcmp(CBS_data(&oid), kKeyUsageOID, sizeof(kKeyUsageOID)) !=
            0) {
      continue;
    }

    CBS bit_string;
    if (!CBS_get_asn1(&contents, &bit_string, CBS_ASN1_BITSTRING) ||
        CBS_len(&contents) != 0) {
      goto parse_err;
    }

    /* This is the KeyUsage extension. See
     * https://tools.ietf.org/html/rfc5280#section-4.2.1.3 */
    if (!CBS_is_valid_asn1_bitstring(&bit_string)) {
      goto parse_err;
    }

    if (!CBS_asn1_bitstring_has_bit(&bit_string, 0)) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_ECC_CERT_NOT_FOR_SIGNING);
      return 0;
    }

    return 1;
  }

  /* No KeyUsage extension found. */
  return 1;

parse_err:
  OPENSSL_PUT_ERROR(SSL, SSL_R_CANNOT_PARSE_LEAF_CERT);
  return 0;
}

static int ca_dn_cmp(const X509_NAME **a, const X509_NAME **b) {
  return X509_NAME_cmp(*a, *b);
}

STACK_OF(X509_NAME) *
    ssl_parse_client_CA_list(SSL *ssl, uint8_t *out_alert, CBS *cbs) {
  STACK_OF(X509_NAME) *ret = sk_X509_NAME_new(ca_dn_cmp);
  X509_NAME *name = NULL;
  if (ret == NULL) {
    *out_alert = SSL_AD_INTERNAL_ERROR;
    OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
    return NULL;
  }

  CBS child;
  if (!CBS_get_u16_length_prefixed(cbs, &child)) {
    *out_alert = SSL_AD_DECODE_ERROR;
    OPENSSL_PUT_ERROR(SSL, SSL_R_LENGTH_MISMATCH);
    goto err;
  }

  while (CBS_len(&child) > 0) {
    CBS distinguished_name;
    if (!CBS_get_u16_length_prefixed(&child, &distinguished_name)) {
      *out_alert = SSL_AD_DECODE_ERROR;
      OPENSSL_PUT_ERROR(SSL, SSL_R_CA_DN_TOO_LONG);
      goto err;
    }

    const uint8_t *ptr = CBS_data(&distinguished_name);
    /* A u16 length cannot overflow a long. */
    name = d2i_X509_NAME(NULL, &ptr, (long)CBS_len(&distinguished_name));
    if (name == NULL ||
        ptr != CBS_data(&distinguished_name) + CBS_len(&distinguished_name)) {
      *out_alert = SSL_AD_DECODE_ERROR;
      OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
      goto err;
    }

    if (!sk_X509_NAME_push(ret, name)) {
      *out_alert = SSL_AD_INTERNAL_ERROR;
      OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
      goto err;
    }
    name = NULL;
  }

  return ret;

err:
  X509_NAME_free(name);
  sk_X509_NAME_pop_free(ret, X509_NAME_free);
  return NULL;
}

int ssl_add_client_CA_list(SSL *ssl, CBB *cbb) {
  CBB child, name_cbb;
  if (!CBB_add_u16_length_prefixed(cbb, &child)) {
    return 0;
  }

  STACK_OF(X509_NAME) *sk = SSL_get_client_CA_list(ssl);
  if (sk == NULL) {
    return CBB_flush(cbb);
  }

  for (size_t i = 0; i < sk_X509_NAME_num(sk); i++) {
    X509_NAME *name = sk_X509_NAME_value(sk, i);
    int len = i2d_X509_NAME(name, NULL);
    if (len < 0) {
      return 0;
    }
    uint8_t *ptr;
    if (!CBB_add_u16_length_prefixed(&child, &name_cbb) ||
        !CBB_add_space(&name_cbb, &ptr, (size_t)len) ||
        (len > 0 && i2d_X509_NAME(name, &ptr) < 0)) {
      return 0;
    }
  }

  return CBB_flush(cbb);
}

static int set_cert_store(X509_STORE **store_ptr, X509_STORE *new_store, int take_ref) {
  X509_STORE_free(*store_ptr);
  *store_ptr = new_store;

  if (new_store != NULL && take_ref) {
    X509_STORE_up_ref(new_store);
  }

  return 1;
}

int SSL_CTX_set0_verify_cert_store(SSL_CTX *ctx, X509_STORE *store) {
  return set_cert_store(&ctx->cert->verify_store, store, 0);
}

int SSL_CTX_set1_verify_cert_store(SSL_CTX *ctx, X509_STORE *store) {
  return set_cert_store(&ctx->cert->verify_store, store, 1);
}

int SSL_set0_verify_cert_store(SSL *ssl, X509_STORE *store) {
  return set_cert_store(&ssl->cert->verify_store, store, 0);
}

int SSL_set1_verify_cert_store(SSL *ssl, X509_STORE *store) {
  return set_cert_store(&ssl->cert->verify_store, store, 1);
}

int SSL_CTX_set0_chain(SSL_CTX *ctx, STACK_OF(X509) *chain) {
  return ssl_cert_set0_chain(ctx->cert, chain);
}

int SSL_CTX_set1_chain(SSL_CTX *ctx, STACK_OF(X509) *chain) {
  return ssl_cert_set1_chain(ctx->cert, chain);
}

int SSL_set0_chain(SSL *ssl, STACK_OF(X509) *chain) {
  return ssl_cert_set0_chain(ssl->cert, chain);
}

int SSL_set1_chain(SSL *ssl, STACK_OF(X509) *chain) {
  return ssl_cert_set1_chain(ssl->cert, chain);
}

int SSL_CTX_add0_chain_cert(SSL_CTX *ctx, X509 *x509) {
  return ssl_cert_add0_chain_cert(ctx->cert, x509);
}

int SSL_CTX_add1_chain_cert(SSL_CTX *ctx, X509 *x509) {
  return ssl_cert_add1_chain_cert(ctx->cert, x509);
}

int SSL_CTX_add_extra_chain_cert(SSL_CTX *ctx, X509 *x509) {
  return SSL_CTX_add0_chain_cert(ctx, x509);
}

int SSL_add0_chain_cert(SSL *ssl, X509 *x509) {
  return ssl_cert_add0_chain_cert(ssl->cert, x509);
}

int SSL_add1_chain_cert(SSL *ssl, X509 *x509) {
  return ssl_cert_add1_chain_cert(ssl->cert, x509);
}

int SSL_CTX_clear_chain_certs(SSL_CTX *ctx) {
  return SSL_CTX_set0_chain(ctx, NULL);
}

int SSL_CTX_clear_extra_chain_certs(SSL_CTX *ctx) {
  return SSL_CTX_clear_chain_certs(ctx);
}

int SSL_clear_chain_certs(SSL *ssl) {
  return SSL_set0_chain(ssl, NULL);
}

void SSL_CTX_set_cert_cb(SSL_CTX *ctx, int (*cb)(SSL *ssl, void *arg),
                         void *arg) {
  ssl_cert_set_cert_cb(ctx->cert, cb, arg);
}

void SSL_set_cert_cb(SSL *ssl, int (*cb)(SSL *ssl, void *arg), void *arg) {
  ssl_cert_set_cert_cb(ssl->cert, cb, arg);
}

int SSL_CTX_get0_chain_certs(const SSL_CTX *ctx, STACK_OF(X509) **out_chain) {
  *out_chain = ctx->cert->x509_chain;
  return 1;
}

int SSL_CTX_get_extra_chain_certs(const SSL_CTX *ctx,
                                  STACK_OF(X509) **out_chain) {
  return SSL_CTX_get0_chain_certs(ctx, out_chain);
}

int SSL_get0_chain_certs(const SSL *ssl, STACK_OF(X509) **out_chain) {
  *out_chain = ssl->cert->x509_chain;
  return 1;
}

int ssl_check_leaf_certificate(SSL *ssl, EVP_PKEY *pkey,
                               const CRYPTO_BUFFER *leaf) {
  assert(ssl3_protocol_version(ssl) < TLS1_3_VERSION);

  /* Check the certificate's type matches the cipher. */
  const SSL_CIPHER *cipher = ssl->s3->tmp.new_cipher;
  int expected_type = ssl_cipher_get_key_type(cipher);
  assert(expected_type != EVP_PKEY_NONE);
  if (pkey->type != expected_type) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_WRONG_CERTIFICATE_TYPE);
    return 0;
  }

  if (cipher->algorithm_auth & SSL_aECDSA) {
    CBS leaf_cbs;
    CBS_init(&leaf_cbs, CRYPTO_BUFFER_data(leaf), CRYPTO_BUFFER_len(leaf));
    /* ECDSA and ECDH certificates use the same public key format. Instead,
     * they are distinguished by the key usage extension in the certificate. */
    if (!ssl_cert_check_digital_signature_key_usage(&leaf_cbs)) {
      return 0;
    }

    EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(pkey);
    if (ec_key == NULL) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_BAD_ECC_CERT);
      return 0;
    }

    /* Check the key's group and point format are acceptable. */
    uint16_t group_id;
    if (!ssl_nid_to_group_id(
            &group_id, EC_GROUP_get_curve_name(EC_KEY_get0_group(ec_key))) ||
        !tls1_check_group_id(ssl, group_id) ||
        EC_KEY_get_conv_form(ec_key) != POINT_CONVERSION_UNCOMPRESSED) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_BAD_ECC_CERT);
      return 0;
    }
  }

  return 1;
}

static int do_client_cert_cb(SSL *ssl, void *arg) {
  if (ssl_has_certificate(ssl) || ssl->ctx->client_cert_cb == NULL) {
    return 1;
  }

  X509 *x509 = NULL;
  EVP_PKEY *pkey = NULL;
  int ret = ssl->ctx->client_cert_cb(ssl, &x509, &pkey);
  if (ret < 0) {
    return -1;
  }

  if (ret != 0) {
    if (!SSL_use_certificate(ssl, x509) ||
        !SSL_use_PrivateKey(ssl, pkey)) {
      return 0;
    }
  }

  X509_free(x509);
  EVP_PKEY_free(pkey);
  return 1;
}

void SSL_CTX_set_client_cert_cb(SSL_CTX *ctx, int (*cb)(SSL *ssl,
                                                        X509 **out_x509,
                                                        EVP_PKEY **out_pkey)) {
  /* Emulate the old client certificate callback with the new one. */
  SSL_CTX_set_cert_cb(ctx, do_client_cert_cb, NULL);
  ctx->client_cert_cb = cb;
}
