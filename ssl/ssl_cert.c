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

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/buf.h>
#include <openssl/ec_key.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/obj.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "../crypto/dh/internal.h"
#include "../crypto/directory.h"
#include "../crypto/internal.h"
#include "internal.h"


static CRYPTO_once_t g_x509_store_ex_data_index_once;
static int g_x509_store_ex_data_index;

static void ssl_x509_store_ex_data_index_init(void) {
  g_x509_store_ex_data_index = X509_STORE_CTX_get_ex_new_index(
      0, "SSL for verify callback", NULL, NULL, NULL);
}

int SSL_get_ex_data_X509_STORE_CTX_idx(void) {
  CRYPTO_once(&g_x509_store_ex_data_index_once,
              ssl_x509_store_ex_data_index_init);
  return g_x509_store_ex_data_index;
}

CERT *ssl_cert_new(void) {
  CERT *ret;

  ret = (CERT *)OPENSSL_malloc(sizeof(CERT));
  if (ret == NULL) {
    OPENSSL_PUT_ERROR(SSL, ssl_cert_new, ERR_R_MALLOC_FAILURE);
    return NULL;
  }
  memset(ret, 0, sizeof(CERT));

  ret->key = &ret->pkeys[SSL_PKEY_RSA];
  return ret;
}

CERT *ssl_cert_dup(CERT *cert) {
  CERT *ret;
  int i;

  ret = (CERT *)OPENSSL_malloc(sizeof(CERT));
  if (ret == NULL) {
    OPENSSL_PUT_ERROR(SSL, ssl_cert_dup, ERR_R_MALLOC_FAILURE);
    return NULL;
  }
  memset(ret, 0, sizeof(CERT));

  ret->key = &ret->pkeys[cert->key - &cert->pkeys[0]];
  /* or ret->key = ret->pkeys + (cert->key - cert->pkeys), if you find that
   * more readable */

  ret->mask_k = cert->mask_k;
  ret->mask_a = cert->mask_a;

  if (cert->dh_tmp != NULL) {
    ret->dh_tmp = DHparams_dup(cert->dh_tmp);
    if (ret->dh_tmp == NULL) {
      OPENSSL_PUT_ERROR(SSL, ssl_cert_dup, ERR_R_DH_LIB);
      goto err;
    }
    if (cert->dh_tmp->priv_key) {
      BIGNUM *b = BN_dup(cert->dh_tmp->priv_key);
      if (!b) {
        OPENSSL_PUT_ERROR(SSL, ssl_cert_dup, ERR_R_BN_LIB);
        goto err;
      }
      ret->dh_tmp->priv_key = b;
    }
    if (cert->dh_tmp->pub_key) {
      BIGNUM *b = BN_dup(cert->dh_tmp->pub_key);
      if (!b) {
        OPENSSL_PUT_ERROR(SSL, ssl_cert_dup, ERR_R_BN_LIB);
        goto err;
      }
      ret->dh_tmp->pub_key = b;
    }
  }
  ret->dh_tmp_cb = cert->dh_tmp_cb;

  ret->ecdh_nid = cert->ecdh_nid;
  ret->ecdh_tmp_cb = cert->ecdh_tmp_cb;

  for (i = 0; i < SSL_PKEY_NUM; i++) {
    CERT_PKEY *cpk = cert->pkeys + i;
    CERT_PKEY *rpk = ret->pkeys + i;
    if (cpk->x509 != NULL) {
      rpk->x509 = X509_up_ref(cpk->x509);
    }

    if (cpk->privatekey != NULL) {
      rpk->privatekey = EVP_PKEY_up_ref(cpk->privatekey);
    }

    if (cpk->chain) {
      rpk->chain = X509_chain_up_ref(cpk->chain);
      if (!rpk->chain) {
        OPENSSL_PUT_ERROR(SSL, ssl_cert_dup, ERR_R_MALLOC_FAILURE);
        goto err;
      }
    }
  }

  /* Copy over signature algorithm configuration. */
  if (cert->conf_sigalgs) {
    ret->conf_sigalgs = BUF_memdup(cert->conf_sigalgs, cert->conf_sigalgslen);
    if (!ret->conf_sigalgs) {
      goto err;
    }
    ret->conf_sigalgslen = cert->conf_sigalgslen;
  }

  if (cert->client_sigalgs) {
    ret->client_sigalgs = BUF_memdup(cert->client_sigalgs,
                                     cert->client_sigalgslen);
    if (!ret->client_sigalgs) {
      goto err;
    }
    ret->client_sigalgslen = cert->client_sigalgslen;
  }

  /* Copy any custom client certificate types */
  if (cert->client_certificate_types) {
    ret->client_certificate_types = BUF_memdup(
        cert->client_certificate_types, cert->num_client_certificate_types);
    if (!ret->client_certificate_types) {
      goto err;
    }
    ret->num_client_certificate_types = cert->num_client_certificate_types;
  }

  ret->cert_cb = cert->cert_cb;
  ret->cert_cb_arg = cert->cert_cb_arg;

  if (cert->verify_store) {
    CRYPTO_refcount_inc(&cert->verify_store->references);
    ret->verify_store = cert->verify_store;
  }

  if (cert->chain_store) {
    CRYPTO_refcount_inc(&cert->chain_store->references);
    ret->chain_store = cert->chain_store;
  }

  return ret;

err:
  ssl_cert_free(ret);
  return NULL;
}

/* Free up and clear all certificates and chains */
void ssl_cert_clear_certs(CERT *c) {
  int i;
  if (c == NULL) {
    return;
  }

  for (i = 0; i < SSL_PKEY_NUM; i++) {
    CERT_PKEY *cpk = c->pkeys + i;
    if (cpk->x509) {
      X509_free(cpk->x509);
      cpk->x509 = NULL;
    }
    if (cpk->privatekey) {
      EVP_PKEY_free(cpk->privatekey);
      cpk->privatekey = NULL;
    }
    if (cpk->chain) {
      sk_X509_pop_free(cpk->chain, X509_free);
      cpk->chain = NULL;
    }
  }
}

void ssl_cert_free(CERT *c) {
  if (c == NULL) {
    return;
  }

  DH_free(c->dh_tmp);

  ssl_cert_clear_certs(c);
  OPENSSL_free(c->peer_sigalgs);
  OPENSSL_free(c->conf_sigalgs);
  OPENSSL_free(c->client_sigalgs);
  OPENSSL_free(c->shared_sigalgs);
  OPENSSL_free(c->client_certificate_types);
  X509_STORE_free(c->verify_store);
  X509_STORE_free(c->chain_store);

  OPENSSL_free(c);
}

int ssl_cert_set0_chain(CERT *c, STACK_OF(X509) *chain) {
  CERT_PKEY *cpk = c->key;
  if (!cpk) {
    return 0;
  }
  sk_X509_pop_free(cpk->chain, X509_free);
  cpk->chain = chain;
  return 1;
}

int ssl_cert_set1_chain(CERT *c, STACK_OF(X509) *chain) {
  STACK_OF(X509) *dchain;
  if (!chain) {
    return ssl_cert_set0_chain(c, NULL);
  }

  dchain = X509_chain_up_ref(chain);
  if (!dchain) {
    return 0;
  }

  if (!ssl_cert_set0_chain(c, dchain)) {
    sk_X509_pop_free(dchain, X509_free);
    return 0;
  }

  return 1;
}

int ssl_cert_add0_chain_cert(CERT *c, X509 *x) {
  CERT_PKEY *cpk = c->key;
  if (!cpk) {
    return 0;
  }

  if (!cpk->chain) {
    cpk->chain = sk_X509_new_null();
  }
  if (!cpk->chain || !sk_X509_push(cpk->chain, x)) {
    return 0;
  }

  return 1;
}

int ssl_cert_add1_chain_cert(CERT *c, X509 *x) {
  if (!ssl_cert_add0_chain_cert(c, x)) {
    return 0;
  }

  X509_up_ref(x);
  return 1;
}

int ssl_cert_select_current(CERT *c, X509 *x) {
  int i;
  if (x == NULL) {
    return 0;
  }

  for (i = 0; i < SSL_PKEY_NUM; i++) {
    if (c->pkeys[i].x509 == x) {
      c->key = &c->pkeys[i];
      return 1;
    }
  }

  for (i = 0; i < SSL_PKEY_NUM; i++) {
    if (c->pkeys[i].x509 && !X509_cmp(c->pkeys[i].x509, x)) {
      c->key = &c->pkeys[i];
      return 1;
    }
  }

  return 0;
}

void ssl_cert_set_cert_cb(CERT *c, int (*cb)(SSL *ssl, void *arg), void *arg) {
  c->cert_cb = cb;
  c->cert_cb_arg = arg;
}

SESS_CERT *ssl_sess_cert_new(void) {
  SESS_CERT *ret;

  ret = OPENSSL_malloc(sizeof *ret);
  if (ret == NULL) {
    OPENSSL_PUT_ERROR(SSL, ssl_sess_cert_new, ERR_R_MALLOC_FAILURE);
    return NULL;
  }

  memset(ret, 0, sizeof *ret);

  return ret;
}

SESS_CERT *ssl_sess_cert_dup(const SESS_CERT *sess_cert) {
  SESS_CERT *ret = ssl_sess_cert_new();
  if (ret == NULL) {
    return NULL;
  }

  if (sess_cert->cert_chain != NULL) {
    ret->cert_chain = X509_chain_up_ref(sess_cert->cert_chain);
    if (ret->cert_chain == NULL) {
      ssl_sess_cert_free(ret);
      return NULL;
    }
  }
  if (sess_cert->peer_cert != NULL) {
    ret->peer_cert = X509_up_ref(sess_cert->peer_cert);
  }
  if (sess_cert->peer_dh_tmp != NULL) {
    ret->peer_dh_tmp = sess_cert->peer_dh_tmp;
    DH_up_ref(ret->peer_dh_tmp);
  }
  if (sess_cert->peer_ecdh_tmp != NULL) {
    ret->peer_ecdh_tmp = sess_cert->peer_ecdh_tmp;
    EC_KEY_up_ref(ret->peer_ecdh_tmp);
  }
  return ret;
}

void ssl_sess_cert_free(SESS_CERT *sess_cert) {
  if (sess_cert == NULL) {
    return;
  }

  sk_X509_pop_free(sess_cert->cert_chain, X509_free);
  X509_free(sess_cert->peer_cert);
  DH_free(sess_cert->peer_dh_tmp);
  EC_KEY_free(sess_cert->peer_ecdh_tmp);

  OPENSSL_free(sess_cert);
}

int ssl_verify_cert_chain(SSL *s, STACK_OF(X509) *sk) {
  X509 *x;
  int i;
  X509_STORE *verify_store;
  X509_STORE_CTX ctx;

  if (s->cert->verify_store) {
    verify_store = s->cert->verify_store;
  } else {
    verify_store = s->ctx->cert_store;
  }

  if (sk == NULL || sk_X509_num(sk) == 0) {
    return 0;
  }

  x = sk_X509_value(sk, 0);
  if (!X509_STORE_CTX_init(&ctx, verify_store, x, sk)) {
    OPENSSL_PUT_ERROR(SSL, ssl_verify_cert_chain, ERR_R_X509_LIB);
    return 0;
  }
  X509_STORE_CTX_set_ex_data(&ctx, SSL_get_ex_data_X509_STORE_CTX_idx(), s);

  /* We need to inherit the verify parameters. These can be determined by the
   * context: if its a server it will verify SSL client certificates or vice
   * versa. */
  X509_STORE_CTX_set_default(&ctx, s->server ? "ssl_client" : "ssl_server");

  /* Anything non-default in "param" should overwrite anything in the ctx. */
  X509_VERIFY_PARAM_set1(X509_STORE_CTX_get0_param(&ctx), s->param);

  if (s->verify_callback) {
    X509_STORE_CTX_set_verify_cb(&ctx, s->verify_callback);
  }

  if (s->ctx->app_verify_callback != NULL) {
    i = s->ctx->app_verify_callback(&ctx, s->ctx->app_verify_arg);
  } else {
    i = X509_verify_cert(&ctx);
  }

  s->verify_result = ctx.error;
  X509_STORE_CTX_cleanup(&ctx);

  return i;
}

static void set_client_CA_list(STACK_OF(X509_NAME) **ca_list,
                               STACK_OF(X509_NAME) *name_list) {
  sk_X509_NAME_pop_free(*ca_list, X509_NAME_free);
  *ca_list = name_list;
}

STACK_OF(X509_NAME) *SSL_dup_CA_list(STACK_OF(X509_NAME) *sk) {
  size_t i;
  STACK_OF(X509_NAME) *ret;
  X509_NAME *name;

  ret = sk_X509_NAME_new_null();
  for (i = 0; i < sk_X509_NAME_num(sk); i++) {
    name = X509_NAME_dup(sk_X509_NAME_value(sk, i));
    if (name == NULL || !sk_X509_NAME_push(ret, name)) {
      sk_X509_NAME_pop_free(ret, X509_NAME_free);
      return NULL;
    }
  }

  return ret;
}

void SSL_set_client_CA_list(SSL *s, STACK_OF(X509_NAME) *name_list) {
  set_client_CA_list(&(s->client_CA), name_list);
}

void SSL_CTX_set_client_CA_list(SSL_CTX *ctx, STACK_OF(X509_NAME) *name_list) {
  set_client_CA_list(&(ctx->client_CA), name_list);
}

STACK_OF(X509_NAME) *SSL_CTX_get_client_CA_list(const SSL_CTX *ctx) {
  return ctx->client_CA;
}

STACK_OF(X509_NAME) *SSL_get_client_CA_list(const SSL *s) {
  if (s->server) {
    if (s->client_CA != NULL) {
      return s->client_CA;
    } else {
      return s->ctx->client_CA;
    }
  } else {
    if ((s->version >> 8) == SSL3_VERSION_MAJOR && s->s3 != NULL) {
      return s->s3->tmp.ca_names;
    } else {
      return NULL;
    }
  }
}

static int add_client_CA(STACK_OF(X509_NAME) **sk, X509 *x) {
  X509_NAME *name;

  if (x == NULL) {
    return 0;
  }
  if (*sk == NULL) {
    *sk = sk_X509_NAME_new_null();
    if (*sk == NULL) {
      return 0;
    }
  }

  name = X509_NAME_dup(X509_get_subject_name(x));
  if (name == NULL) {
    return 0;
  }

  if (!sk_X509_NAME_push(*sk, name)) {
    X509_NAME_free(name);
    return 0;
  }

  return 1;
}

int SSL_add_client_CA(SSL *ssl, X509 *x) {
  return add_client_CA(&(ssl->client_CA), x);
}

int SSL_CTX_add_client_CA(SSL_CTX *ctx, X509 *x) {
  return add_client_CA(&(ctx->client_CA), x);
}

static int xname_cmp(const X509_NAME **a, const X509_NAME **b) {
  return X509_NAME_cmp(*a, *b);
}

/* Load CA certs from a file into a STACK. Note that it is somewhat misnamed;
 * it doesn't really have anything to do with clients (except that a common use
 * for a stack of CAs is to send it to the client). Actually, it doesn't have
 * much to do with CAs, either, since it will load any old cert.
 *
 * \param file the file containing one or more certs.
 * \return a ::STACK containing the certs. */
STACK_OF(X509_NAME) *SSL_load_client_CA_file(const char *file) {
  BIO *in;
  X509 *x = NULL;
  X509_NAME *xn = NULL;
  STACK_OF(X509_NAME) *ret = NULL, *sk;

  sk = sk_X509_NAME_new(xname_cmp);
  in = BIO_new(BIO_s_file());

  if (sk == NULL || in == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_load_client_CA_file, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  if (!BIO_read_filename(in, file)) {
    goto err;
  }

  for (;;) {
    if (PEM_read_bio_X509(in, &x, NULL, NULL) == NULL) {
      break;
    }
    if (ret == NULL) {
      ret = sk_X509_NAME_new_null();
      if (ret == NULL) {
        OPENSSL_PUT_ERROR(SSL, SSL_load_client_CA_file, ERR_R_MALLOC_FAILURE);
        goto err;
      }
    }
    xn = X509_get_subject_name(x);
    if (xn == NULL) {
      goto err;
    }

    /* check for duplicates */
    xn = X509_NAME_dup(xn);
    if (xn == NULL) {
      goto err;
    }
    if (sk_X509_NAME_find(sk, NULL, xn)) {
      X509_NAME_free(xn);
    } else {
      sk_X509_NAME_push(sk, xn);
      sk_X509_NAME_push(ret, xn);
    }
  }

  if (0) {
  err:
    sk_X509_NAME_pop_free(ret, X509_NAME_free);
    ret = NULL;
  }

  sk_X509_NAME_free(sk);
  BIO_free(in);
  X509_free(x);
  if (ret != NULL) {
    ERR_clear_error();
  }
  return ret;
}

/* Add a file of certs to a stack.
 *
 * \param stack the stack to add to.
 * \param file the file to add from. All certs in this file that are not
 *     already in the stack will be added.
 * \return 1 for success, 0 for failure. Note that in the case of failure some
 *     certs may have been added to \c stack. */
int SSL_add_file_cert_subjects_to_stack(STACK_OF(X509_NAME) *stack,
                                        const char *file) {
  BIO *in;
  X509 *x = NULL;
  X509_NAME *xn = NULL;
  int ret = 1;
  int (*oldcmp)(const X509_NAME **a, const X509_NAME **b);

  oldcmp = sk_X509_NAME_set_cmp_func(stack, xname_cmp);
  in = BIO_new(BIO_s_file());

  if (in == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_add_file_cert_subjects_to_stack,
                      ERR_R_MALLOC_FAILURE);
    goto err;
  }

  if (!BIO_read_filename(in, file)) {
    goto err;
  }

  for (;;) {
    if (PEM_read_bio_X509(in, &x, NULL, NULL) == NULL) {
      break;
    }
    xn = X509_get_subject_name(x);
    if (xn == NULL) {
      goto err;
    }
    xn = X509_NAME_dup(xn);
    if (xn == NULL) {
      goto err;
    }
    if (sk_X509_NAME_find(stack, NULL, xn)) {
      X509_NAME_free(xn);
    } else {
      sk_X509_NAME_push(stack, xn);
    }
  }

  ERR_clear_error();

  if (0) {
  err:
    ret = 0;
  }

  BIO_free(in);
  X509_free(x);

  (void) sk_X509_NAME_set_cmp_func(stack, oldcmp);

  return ret;
}

/* Add a directory of certs to a stack.
 *
 * \param stack the stack to append to.
 * \param dir the directory to append from. All files in this directory will be
 *     examined as potential certs. Any that are acceptable to
 *     SSL_add_dir_cert_subjects_to_stack() that are not already in the stack will
 *     be included.
 * \return 1 for success, 0 for failure. Note that in the case of failure some
 *     certs may have been added to \c stack. */
int SSL_add_dir_cert_subjects_to_stack(STACK_OF(X509_NAME) *stack,
                                       const char *dir) {
  OPENSSL_DIR_CTX *d = NULL;
  const char *filename;
  int ret = 0;

  /* Note that a side effect is that the CAs will be sorted by name */
  while ((filename = OPENSSL_DIR_read(&d, dir))) {
    char buf[1024];
    int r;

    if (strlen(dir) + strlen(filename) + 2 > sizeof(buf)) {
      OPENSSL_PUT_ERROR(SSL, SSL_add_dir_cert_subjects_to_stack,
                        SSL_R_PATH_TOO_LONG);
      goto err;
    }

    r = BIO_snprintf(buf, sizeof buf, "%s/%s", dir, filename);
    if (r <= 0 || r >= (int)sizeof(buf) ||
        !SSL_add_file_cert_subjects_to_stack(stack, buf)) {
      goto err;
    }
  }

  if (errno) {
    OPENSSL_PUT_ERROR(SSL, SSL_add_dir_cert_subjects_to_stack, ERR_R_SYS_LIB);
    ERR_add_error_data(3, "OPENSSL_DIR_read(&ctx, '", dir, "')");
    goto err;
  }

  ret = 1;

err:
  if (d) {
    OPENSSL_DIR_end(&d);
  }
  return ret;
}

/* Add a certificate to a BUF_MEM structure */
static int ssl_add_cert_to_buf(BUF_MEM *buf, unsigned long *l, X509 *x) {
  int n;
  uint8_t *p;

  n = i2d_X509(x, NULL);
  if (!BUF_MEM_grow_clean(buf, (int)(n + (*l) + 3))) {
    OPENSSL_PUT_ERROR(SSL, ssl_add_cert_to_buf, ERR_R_BUF_LIB);
    return 0;
  }
  p = (uint8_t *)&(buf->data[*l]);
  l2n3(n, p);
  i2d_X509(x, &p);
  *l += n + 3;

  return 1;
}

/* Add certificate chain to internal SSL BUF_MEM structure. */
int ssl_add_cert_chain(SSL *s, CERT_PKEY *cpk, unsigned long *l) {
  BUF_MEM *buf = s->init_buf;
  int no_chain = 0;
  size_t i;

  X509 *x = cpk->x509;
  STACK_OF(X509) *extra_certs;
  X509_STORE *chain_store;

  if (x == NULL) {
    OPENSSL_PUT_ERROR(SSL, ssl_add_cert_chain, SSL_R_NO_CERTIFICATE_SET);
    return 0;
  }

  if (s->cert->chain_store) {
    chain_store = s->cert->chain_store;
  } else {
    chain_store = s->ctx->cert_store;
  }

  /* If we have a certificate specific chain use it, else use parent ctx. */
  if (cpk && cpk->chain) {
    extra_certs = cpk->chain;
  } else {
    extra_certs = s->ctx->extra_certs;
  }

  if ((s->mode & SSL_MODE_NO_AUTO_CHAIN) || extra_certs) {
    no_chain = 1;
  }

  if (no_chain) {
    if (!ssl_add_cert_to_buf(buf, l, x)) {
      return 0;
    }

    for (i = 0; i < sk_X509_num(extra_certs); i++) {
      x = sk_X509_value(extra_certs, i);
      if (!ssl_add_cert_to_buf(buf, l, x)) {
        return 0;
      }
    }
  } else {
    X509_STORE_CTX xs_ctx;

    if (!X509_STORE_CTX_init(&xs_ctx, chain_store, x, NULL)) {
      OPENSSL_PUT_ERROR(SSL, ssl_add_cert_chain, ERR_R_X509_LIB);
      return 0;
    }
    X509_verify_cert(&xs_ctx);
    /* Don't leave errors in the queue */
    ERR_clear_error();
    for (i = 0; i < sk_X509_num(xs_ctx.chain); i++) {
      x = sk_X509_value(xs_ctx.chain, i);

      if (!ssl_add_cert_to_buf(buf, l, x)) {
        X509_STORE_CTX_cleanup(&xs_ctx);
        return 0;
      }
    }
    X509_STORE_CTX_cleanup(&xs_ctx);
  }

  return 1;
}

/* Build a certificate chain for current certificate */
int ssl_build_cert_chain(CERT *c, X509_STORE *chain_store, int flags) {
  CERT_PKEY *cpk = c->key;
  X509_STORE_CTX xs_ctx;
  STACK_OF(X509) *chain = NULL, *untrusted = NULL;
  X509 *x;
  int i, rv = 0;
  uint32_t error;

  if (!cpk->x509) {
    OPENSSL_PUT_ERROR(SSL, ssl_build_cert_chain, SSL_R_NO_CERTIFICATE_SET);
    goto err;
  }

  /* Rearranging and check the chain: add everything to a store */
  if (flags & SSL_BUILD_CHAIN_FLAG_CHECK) {
    size_t j;
    chain_store = X509_STORE_new();
    if (!chain_store) {
      goto err;
    }

    for (j = 0; j < sk_X509_num(cpk->chain); j++) {
      x = sk_X509_value(cpk->chain, j);
      if (!X509_STORE_add_cert(chain_store, x)) {
        error = ERR_peek_last_error();
        if (ERR_GET_LIB(error) != ERR_LIB_X509 ||
            ERR_GET_REASON(error) != X509_R_CERT_ALREADY_IN_HASH_TABLE) {
          goto err;
        }
        ERR_clear_error();
      }
    }

    /* Add EE cert too: it might be self signed */
    if (!X509_STORE_add_cert(chain_store, cpk->x509)) {
      error = ERR_peek_last_error();
      if (ERR_GET_LIB(error) != ERR_LIB_X509 ||
          ERR_GET_REASON(error) != X509_R_CERT_ALREADY_IN_HASH_TABLE) {
        goto err;
      }
      ERR_clear_error();
    }
  } else {
    if (c->chain_store) {
      chain_store = c->chain_store;
    }

    if (flags & SSL_BUILD_CHAIN_FLAG_UNTRUSTED) {
      untrusted = cpk->chain;
    }
  }

  if (!X509_STORE_CTX_init(&xs_ctx, chain_store, cpk->x509, untrusted)) {
    OPENSSL_PUT_ERROR(SSL, ssl_build_cert_chain, ERR_R_X509_LIB);
    goto err;
  }

  i = X509_verify_cert(&xs_ctx);
  if (i <= 0 && flags & SSL_BUILD_CHAIN_FLAG_IGNORE_ERROR) {
    if (flags & SSL_BUILD_CHAIN_FLAG_CLEAR_ERROR) {
      ERR_clear_error();
    }
    i = 1;
    rv = 2;
  }

  if (i > 0) {
    chain = X509_STORE_CTX_get1_chain(&xs_ctx);
  }
  if (i <= 0) {
    OPENSSL_PUT_ERROR(SSL, ssl_build_cert_chain,
                      SSL_R_CERTIFICATE_VERIFY_FAILED);
    i = X509_STORE_CTX_get_error(&xs_ctx);
    ERR_add_error_data(2, "Verify error:", X509_verify_cert_error_string(i));

    X509_STORE_CTX_cleanup(&xs_ctx);
    goto err;
  }

  X509_STORE_CTX_cleanup(&xs_ctx);
  if (cpk->chain) {
    sk_X509_pop_free(cpk->chain, X509_free);
  }

  /* Remove EE certificate from chain */
  x = sk_X509_shift(chain);
  X509_free(x);
  if (flags & SSL_BUILD_CHAIN_FLAG_NO_ROOT) {
    if (sk_X509_num(chain) > 0) {
      /* See if last cert is self signed */
      x = sk_X509_value(chain, sk_X509_num(chain) - 1);
      X509_check_purpose(x, -1, 0);
      if (x->ex_flags & EXFLAG_SS) {
        x = sk_X509_pop(chain);
        X509_free(x);
      }
    }
  }

  cpk->chain = chain;
  if (rv == 0) {
    rv = 1;
  }

err:
  if (flags & SSL_BUILD_CHAIN_FLAG_CHECK) {
    X509_STORE_free(chain_store);
  }

  return rv;
}

int ssl_cert_set_cert_store(CERT *c, X509_STORE *store, int chain, int ref) {
  X509_STORE **pstore;
  if (chain) {
    pstore = &c->chain_store;
  } else {
    pstore = &c->verify_store;
  }

  X509_STORE_free(*pstore);
  *pstore = store;

  if (ref && store) {
    CRYPTO_refcount_inc(&store->references);
  }
  return 1;
}
