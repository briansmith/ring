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
 * [including the GNU Public Licence.] */

#include <stdio.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/obj.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "internal.h"

static int ssl_set_cert(CERT *c, X509 *x509);
static int ssl_set_pkey(CERT *c, EVP_PKEY *pkey);

int SSL_use_certificate(SSL *ssl, X509 *x) {
  if (x == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_use_certificate, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }
  return ssl_set_cert(ssl->cert, x);
}

int SSL_use_certificate_file(SSL *ssl, const char *file, int type) {
  int reason_code;
  BIO *in;
  int ret = 0;
  X509 *x = NULL;

  in = BIO_new(BIO_s_file());
  if (in == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_use_certificate_file, ERR_R_BUF_LIB);
    goto end;
  }

  if (BIO_read_filename(in, file) <= 0) {
    OPENSSL_PUT_ERROR(SSL, SSL_use_certificate_file, ERR_R_SYS_LIB);
    goto end;
  }

  if (type == SSL_FILETYPE_ASN1) {
    reason_code = ERR_R_ASN1_LIB;
    x = d2i_X509_bio(in, NULL);
  } else if (type == SSL_FILETYPE_PEM) {
    reason_code = ERR_R_PEM_LIB;
    x = PEM_read_bio_X509(in, NULL, ssl->ctx->default_passwd_callback,
                          ssl->ctx->default_passwd_callback_userdata);
  } else {
    OPENSSL_PUT_ERROR(SSL, SSL_use_certificate_file, SSL_R_BAD_SSL_FILETYPE);
    goto end;
  }

  if (x == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_use_certificate_file, reason_code);
    goto end;
  }

  ret = SSL_use_certificate(ssl, x);

end:
  X509_free(x);
  BIO_free(in);

  return ret;
}

int SSL_use_certificate_ASN1(SSL *ssl, const uint8_t *d, int len) {
  X509 *x;
  int ret;

  x = d2i_X509(NULL, &d, (long)len);
  if (x == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_use_certificate_ASN1, ERR_R_ASN1_LIB);
    return 0;
  }

  ret = SSL_use_certificate(ssl, x);
  X509_free(x);
  return ret;
}

int SSL_use_RSAPrivateKey(SSL *ssl, RSA *rsa) {
  EVP_PKEY *pkey;
  int ret;

  if (rsa == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_use_RSAPrivateKey, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }

  pkey = EVP_PKEY_new();
  if (pkey == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_use_RSAPrivateKey, ERR_R_EVP_LIB);
    return 0;
  }

  RSA_up_ref(rsa);
  EVP_PKEY_assign_RSA(pkey, rsa);

  ret = ssl_set_pkey(ssl->cert, pkey);
  EVP_PKEY_free(pkey);

  return ret;
}

static int ssl_set_pkey(CERT *c, EVP_PKEY *pkey) {
  int i;

  i = ssl_cert_type(pkey);
  if (i < 0) {
    OPENSSL_PUT_ERROR(SSL, ssl_set_pkey, SSL_R_UNKNOWN_CERTIFICATE_TYPE);
    return 0;
  }

  if (c->pkeys[i].x509 != NULL) {
    /* Sanity-check that the private key and the certificate match, unless the
     * key is opaque (in case of, say, a smartcard). */
    if (!EVP_PKEY_is_opaque(pkey) &&
        !X509_check_private_key(c->pkeys[i].x509, pkey)) {
      X509_free(c->pkeys[i].x509);
      c->pkeys[i].x509 = NULL;
      return 0;
    }
  }

  EVP_PKEY_free(c->pkeys[i].privatekey);
  c->pkeys[i].privatekey = EVP_PKEY_up_ref(pkey);
  c->key = &(c->pkeys[i]);

  return 1;
}

int SSL_use_RSAPrivateKey_file(SSL *ssl, const char *file, int type) {
  int reason_code, ret = 0;
  BIO *in;
  RSA *rsa = NULL;

  in = BIO_new(BIO_s_file());
  if (in == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_use_RSAPrivateKey_file, ERR_R_BUF_LIB);
    goto end;
  }

  if (BIO_read_filename(in, file) <= 0) {
    OPENSSL_PUT_ERROR(SSL, SSL_use_RSAPrivateKey_file, ERR_R_SYS_LIB);
    goto end;
  }

  if (type == SSL_FILETYPE_ASN1) {
    reason_code = ERR_R_ASN1_LIB;
    rsa = d2i_RSAPrivateKey_bio(in, NULL);
  } else if (type == SSL_FILETYPE_PEM) {
    reason_code = ERR_R_PEM_LIB;
    rsa =
        PEM_read_bio_RSAPrivateKey(in, NULL, ssl->ctx->default_passwd_callback,
                                   ssl->ctx->default_passwd_callback_userdata);
  } else {
    OPENSSL_PUT_ERROR(SSL, SSL_use_RSAPrivateKey_file, SSL_R_BAD_SSL_FILETYPE);
    goto end;
  }

  if (rsa == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_use_RSAPrivateKey_file, reason_code);
    goto end;
  }
  ret = SSL_use_RSAPrivateKey(ssl, rsa);
  RSA_free(rsa);

end:
  BIO_free(in);
  return ret;
}

int SSL_use_RSAPrivateKey_ASN1(SSL *ssl, uint8_t *d, long len) {
  int ret;
  const uint8_t *p;
  RSA *rsa;

  p = d;
  rsa = d2i_RSAPrivateKey(NULL, &p, (long)len);
  if (rsa == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_use_RSAPrivateKey_ASN1, ERR_R_ASN1_LIB);
    return 0;
  }

  ret = SSL_use_RSAPrivateKey(ssl, rsa);
  RSA_free(rsa);
  return ret;
}

int SSL_use_PrivateKey(SSL *ssl, EVP_PKEY *pkey) {
  int ret;

  if (pkey == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_use_PrivateKey, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }

  ret = ssl_set_pkey(ssl->cert, pkey);
  return ret;
}

int SSL_use_PrivateKey_file(SSL *ssl, const char *file, int type) {
  int reason_code, ret = 0;
  BIO *in;
  EVP_PKEY *pkey = NULL;

  in = BIO_new(BIO_s_file());
  if (in == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_use_PrivateKey_file, ERR_R_BUF_LIB);
    goto end;
  }

  if (BIO_read_filename(in, file) <= 0) {
    OPENSSL_PUT_ERROR(SSL, SSL_use_PrivateKey_file, ERR_R_SYS_LIB);
    goto end;
  }

  if (type == SSL_FILETYPE_PEM) {
    reason_code = ERR_R_PEM_LIB;
    pkey = PEM_read_bio_PrivateKey(in, NULL, ssl->ctx->default_passwd_callback,
                                   ssl->ctx->default_passwd_callback_userdata);
  } else if (type == SSL_FILETYPE_ASN1) {
    reason_code = ERR_R_ASN1_LIB;
    pkey = d2i_PrivateKey_bio(in, NULL);
  } else {
    OPENSSL_PUT_ERROR(SSL, SSL_use_PrivateKey_file, SSL_R_BAD_SSL_FILETYPE);
    goto end;
  }

  if (pkey == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_use_PrivateKey_file, reason_code);
    goto end;
  }
  ret = SSL_use_PrivateKey(ssl, pkey);
  EVP_PKEY_free(pkey);

end:
  BIO_free(in);
  return ret;
}

int SSL_use_PrivateKey_ASN1(int type, SSL *ssl, const uint8_t *d, long len) {
  int ret;
  const uint8_t *p;
  EVP_PKEY *pkey;

  p = d;
  pkey = d2i_PrivateKey(type, NULL, &p, (long)len);
  if (pkey == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_use_PrivateKey_ASN1, ERR_R_ASN1_LIB);
    return 0;
  }

  ret = SSL_use_PrivateKey(ssl, pkey);
  EVP_PKEY_free(pkey);
  return ret;
}

int SSL_CTX_use_certificate(SSL_CTX *ctx, X509 *x) {
  if (x == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_CTX_use_certificate,
                      ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }

  return ssl_set_cert(ctx->cert, x);
}

static int ssl_set_cert(CERT *c, X509 *x) {
  EVP_PKEY *pkey;
  int i;

  pkey = X509_get_pubkey(x);
  if (pkey == NULL) {
    OPENSSL_PUT_ERROR(SSL, ssl_set_cert, SSL_R_X509_LIB);
    return 0;
  }

  i = ssl_cert_type(pkey);
  if (i < 0) {
    OPENSSL_PUT_ERROR(SSL, ssl_set_cert, SSL_R_UNKNOWN_CERTIFICATE_TYPE);
    EVP_PKEY_free(pkey);
    return 0;
  }

  if (c->pkeys[i].privatekey != NULL) {
    /* Sanity-check that the private key and the certificate match, unless the
     * key is opaque (in case of, say, a smartcard). */
    if (!EVP_PKEY_is_opaque(c->pkeys[i].privatekey) &&
        !X509_check_private_key(x, c->pkeys[i].privatekey)) {
      /* don't fail for a cert/key mismatch, just free current private key
       * (when switching to a different cert & key, first this function should
       * be used, then ssl_set_pkey */
      EVP_PKEY_free(c->pkeys[i].privatekey);
      c->pkeys[i].privatekey = NULL;
      /* clear error queue */
      ERR_clear_error();
    }
  }

  EVP_PKEY_free(pkey);

  X509_free(c->pkeys[i].x509);
  c->pkeys[i].x509 = X509_up_ref(x);
  c->key = &(c->pkeys[i]);

  return 1;
}

int SSL_CTX_use_certificate_file(SSL_CTX *ctx, const char *file, int type) {
  int reason_code;
  BIO *in;
  int ret = 0;
  X509 *x = NULL;

  in = BIO_new(BIO_s_file());
  if (in == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_CTX_use_certificate_file, ERR_R_BUF_LIB);
    goto end;
  }

  if (BIO_read_filename(in, file) <= 0) {
    OPENSSL_PUT_ERROR(SSL, SSL_CTX_use_certificate_file, ERR_R_SYS_LIB);
    goto end;
  }

  if (type == SSL_FILETYPE_ASN1) {
    reason_code = ERR_R_ASN1_LIB;
    x = d2i_X509_bio(in, NULL);
  } else if (type == SSL_FILETYPE_PEM) {
    reason_code = ERR_R_PEM_LIB;
    x = PEM_read_bio_X509(in, NULL, ctx->default_passwd_callback,
                          ctx->default_passwd_callback_userdata);
  } else {
    OPENSSL_PUT_ERROR(SSL, SSL_CTX_use_certificate_file,
                      SSL_R_BAD_SSL_FILETYPE);
    goto end;
  }

  if (x == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_CTX_use_certificate_file, reason_code);
    goto end;
  }

  ret = SSL_CTX_use_certificate(ctx, x);

end:
  X509_free(x);
  BIO_free(in);
  return ret;
}

int SSL_CTX_use_certificate_ASN1(SSL_CTX *ctx, int len, const uint8_t *d) {
  X509 *x;
  int ret;

  x = d2i_X509(NULL, &d, (long)len);
  if (x == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_CTX_use_certificate_ASN1, ERR_R_ASN1_LIB);
    return 0;
  }

  ret = SSL_CTX_use_certificate(ctx, x);
  X509_free(x);
  return ret;
}

int SSL_CTX_use_RSAPrivateKey(SSL_CTX *ctx, RSA *rsa) {
  int ret;
  EVP_PKEY *pkey;

  if (rsa == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_CTX_use_RSAPrivateKey,
                      ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }

  pkey = EVP_PKEY_new();
  if (pkey == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_CTX_use_RSAPrivateKey, ERR_R_EVP_LIB);
    return 0;
  }

  RSA_up_ref(rsa);
  EVP_PKEY_assign_RSA(pkey, rsa);

  ret = ssl_set_pkey(ctx->cert, pkey);
  EVP_PKEY_free(pkey);
  return ret;
}

int SSL_CTX_use_RSAPrivateKey_file(SSL_CTX *ctx, const char *file, int type) {
  int reason_code, ret = 0;
  BIO *in;
  RSA *rsa = NULL;

  in = BIO_new(BIO_s_file());
  if (in == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_CTX_use_RSAPrivateKey_file, ERR_R_BUF_LIB);
    goto end;
  }

  if (BIO_read_filename(in, file) <= 0) {
    OPENSSL_PUT_ERROR(SSL, SSL_CTX_use_RSAPrivateKey_file, ERR_R_SYS_LIB);
    goto end;
  }

  if (type == SSL_FILETYPE_ASN1) {
    reason_code = ERR_R_ASN1_LIB;
    rsa = d2i_RSAPrivateKey_bio(in, NULL);
  } else if (type == SSL_FILETYPE_PEM) {
    reason_code = ERR_R_PEM_LIB;
    rsa = PEM_read_bio_RSAPrivateKey(in, NULL, ctx->default_passwd_callback,
                                     ctx->default_passwd_callback_userdata);
  } else {
    OPENSSL_PUT_ERROR(SSL, SSL_CTX_use_RSAPrivateKey_file,
                      SSL_R_BAD_SSL_FILETYPE);
    goto end;
  }

  if (rsa == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_CTX_use_RSAPrivateKey_file, reason_code);
    goto end;
  }
  ret = SSL_CTX_use_RSAPrivateKey(ctx, rsa);
  RSA_free(rsa);

end:
  BIO_free(in);
  return ret;
}

int SSL_CTX_use_RSAPrivateKey_ASN1(SSL_CTX *ctx, const uint8_t *d, long len) {
  int ret;
  const uint8_t *p;
  RSA *rsa;

  p = d;
  rsa = d2i_RSAPrivateKey(NULL, &p, (long)len);
  if (rsa == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_CTX_use_RSAPrivateKey_ASN1, ERR_R_ASN1_LIB);
    return 0;
  }

  ret = SSL_CTX_use_RSAPrivateKey(ctx, rsa);
  RSA_free(rsa);
  return ret;
}

int SSL_CTX_use_PrivateKey(SSL_CTX *ctx, EVP_PKEY *pkey) {
  if (pkey == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_CTX_use_PrivateKey, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }

  return ssl_set_pkey(ctx->cert, pkey);
}

int SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type) {
  int reason_code, ret = 0;
  BIO *in;
  EVP_PKEY *pkey = NULL;

  in = BIO_new(BIO_s_file());
  if (in == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_CTX_use_PrivateKey_file, ERR_R_BUF_LIB);
    goto end;
  }

  if (BIO_read_filename(in, file) <= 0) {
    OPENSSL_PUT_ERROR(SSL, SSL_CTX_use_PrivateKey_file, ERR_R_SYS_LIB);
    goto end;
  }

  if (type == SSL_FILETYPE_PEM) {
    reason_code = ERR_R_PEM_LIB;
    pkey = PEM_read_bio_PrivateKey(in, NULL, ctx->default_passwd_callback,
                                   ctx->default_passwd_callback_userdata);
  } else if (type == SSL_FILETYPE_ASN1) {
    reason_code = ERR_R_ASN1_LIB;
    pkey = d2i_PrivateKey_bio(in, NULL);
  } else {
    OPENSSL_PUT_ERROR(SSL, SSL_CTX_use_PrivateKey_file, SSL_R_BAD_SSL_FILETYPE);
    goto end;
  }

  if (pkey == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_CTX_use_PrivateKey_file, reason_code);
    goto end;
  }
  ret = SSL_CTX_use_PrivateKey(ctx, pkey);
  EVP_PKEY_free(pkey);

end:
  BIO_free(in);
  return ret;
}

int SSL_CTX_use_PrivateKey_ASN1(int type, SSL_CTX *ctx, const uint8_t *d,
                                long len) {
  int ret;
  const uint8_t *p;
  EVP_PKEY *pkey;

  p = d;
  pkey = d2i_PrivateKey(type, NULL, &p, (long)len);
  if (pkey == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_CTX_use_PrivateKey_ASN1, ERR_R_ASN1_LIB);
    return 0;
  }

  ret = SSL_CTX_use_PrivateKey(ctx, pkey);
  EVP_PKEY_free(pkey);
  return ret;
}


/* Read a file that contains our certificate in "PEM" format, possibly followed
 * by a sequence of CA certificates that should be sent to the peer in the
 * Certificate message. */
int SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *file) {
  BIO *in;
  int ret = 0;
  X509 *x = NULL;

  ERR_clear_error(); /* clear error stack for SSL_CTX_use_certificate() */

  in = BIO_new(BIO_s_file());
  if (in == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_CTX_use_certificate_chain_file, ERR_R_BUF_LIB);
    goto end;
  }

  if (BIO_read_filename(in, file) <= 0) {
    OPENSSL_PUT_ERROR(SSL, SSL_CTX_use_certificate_chain_file, ERR_R_SYS_LIB);
    goto end;
  }

  x = PEM_read_bio_X509_AUX(in, NULL, ctx->default_passwd_callback,
                            ctx->default_passwd_callback_userdata);
  if (x == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_CTX_use_certificate_chain_file, ERR_R_PEM_LIB);
    goto end;
  }

  ret = SSL_CTX_use_certificate(ctx, x);

  if (ERR_peek_error() != 0) {
    ret = 0; /* Key/certificate mismatch doesn't imply ret==0 ... */
  }

  if (ret) {
    /* If we could set up our certificate, now proceed to the CA
     * certificates. */
    X509 *ca;
    int r;
    uint32_t err;

    SSL_CTX_clear_chain_certs(ctx);

    while ((ca = PEM_read_bio_X509(in, NULL, ctx->default_passwd_callback,
                                   ctx->default_passwd_callback_userdata)) !=
           NULL) {
      r = SSL_CTX_add0_chain_cert(ctx, ca);
      if (!r) {
        X509_free(ca);
        ret = 0;
        goto end;
      }
      /* Note that we must not free r if it was successfully added to the chain
       * (while we must free the main certificate, since its reference count is
       * increased by SSL_CTX_use_certificate). */
    }

    /* When the while loop ends, it's usually just EOF. */
    err = ERR_peek_last_error();
    if (ERR_GET_LIB(err) == ERR_LIB_PEM &&
        ERR_GET_REASON(err) == PEM_R_NO_START_LINE) {
      ERR_clear_error();
    } else {
      ret = 0; /* some real error */
    }
  }

end:
  X509_free(x);
  BIO_free(in);
  return ret;
}

void SSL_set_private_key_method(SSL *ssl,
                                const SSL_PRIVATE_KEY_METHOD *key_method) {
  ssl->cert->key_method = key_method;
}

int ssl_private_key_type(SSL *ssl, const EVP_PKEY *pkey) {
  if (ssl->cert->key_method != NULL) {
    return ssl->cert->key_method->type(ssl);
  }
  return EVP_PKEY_id(pkey);
}

int ssl_private_key_supports_digest(SSL *ssl, const EVP_PKEY *pkey,
                                    const EVP_MD *md) {
  if (ssl->cert->key_method != NULL) {
    return ssl->cert->key_method->supports_digest(ssl, md);
  }
  return EVP_PKEY_supports_digest(pkey, md);
}

size_t ssl_private_key_max_signature_len(SSL *ssl, const EVP_PKEY *pkey) {
  if (ssl->cert->key_method != NULL) {
    return ssl->cert->key_method->max_signature_len(ssl);
  }
  return EVP_PKEY_size(pkey);
}

enum ssl_private_key_result_t ssl_private_key_sign(
    SSL *ssl, EVP_PKEY *pkey, uint8_t *out, size_t *out_len, size_t max_out,
    const EVP_MD *md, const uint8_t *in, size_t in_len) {
  if (ssl->cert->key_method != NULL) {
    return ssl->cert->key_method->sign(ssl, out, out_len, max_out, md, in,
                                       in_len);
  }

  enum ssl_private_key_result_t ret = ssl_private_key_failure;
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
  if (ctx == NULL) {
    goto end;
  }

  size_t len = max_out;
  if (!EVP_PKEY_sign_init(ctx) ||
      !EVP_PKEY_CTX_set_signature_md(ctx, md) ||
      !EVP_PKEY_sign(ctx, out, &len, in, in_len)) {
    goto end;
  }
  *out_len = len;
  ret = ssl_private_key_success;

end:
  EVP_PKEY_CTX_free(ctx);
  return ret;
}

enum ssl_private_key_result_t ssl_private_key_sign_complete(
    SSL *ssl, uint8_t *out, size_t *out_len, size_t max_out) {
  /* Only custom keys may be asynchronous. */
  return ssl->cert->key_method->sign_complete(ssl, out, out_len, max_out);
}
