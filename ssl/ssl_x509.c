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
 * SUN MICROSYSTEMS, INC., and contributed to the OpenSSL project.
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

#include <openssl/asn1.h>
#include <openssl/bytestring.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/stack.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>

#include "internal.h"


X509 *SSL_get_peer_certificate(const SSL *ssl) {
  if (ssl == NULL) {
    return NULL;
  }
  SSL_SESSION *session = SSL_get_session(ssl);
  if (session == NULL || session->x509_peer == NULL) {
    return NULL;
  }
  X509_up_ref(session->x509_peer);
  return session->x509_peer;
}

STACK_OF(X509) *SSL_get_peer_cert_chain(const SSL *ssl) {
  if (ssl == NULL) {
    return NULL;
  }
  SSL_SESSION *session = SSL_get_session(ssl);
  if (session == NULL ||
      session->x509_chain == NULL) {
    return NULL;
  }

  if (!ssl->server) {
    return session->x509_chain;
  }

  /* OpenSSL historically didn't include the leaf certificate in the returned
   * certificate chain, but only for servers. */
  if (session->x509_chain_without_leaf == NULL) {
    session->x509_chain_without_leaf = sk_X509_new_null();
    if (session->x509_chain_without_leaf == NULL) {
      return NULL;
    }

    for (size_t i = 1; i < sk_X509_num(session->x509_chain); i++) {
      X509 *cert = sk_X509_value(session->x509_chain, i);
      if (!sk_X509_push(session->x509_chain_without_leaf, cert)) {
        sk_X509_pop_free(session->x509_chain_without_leaf, X509_free);
        session->x509_chain_without_leaf = NULL;
        return NULL;
      }
      X509_up_ref(cert);
    }
  }

  return session->x509_chain_without_leaf;
}

STACK_OF(X509) *SSL_get_peer_full_cert_chain(const SSL *ssl) {
  SSL_SESSION *session = SSL_get_session(ssl);
  if (session == NULL) {
    return NULL;
  }

  return session->x509_chain;
}

int SSL_CTX_set_purpose(SSL_CTX *ctx, int purpose) {
  return X509_VERIFY_PARAM_set_purpose(ctx->param, purpose);
}

int SSL_set_purpose(SSL *ssl, int purpose) {
  return X509_VERIFY_PARAM_set_purpose(ssl->param, purpose);
}

int SSL_CTX_set_trust(SSL_CTX *ctx, int trust) {
  return X509_VERIFY_PARAM_set_trust(ctx->param, trust);
}

int SSL_set_trust(SSL *ssl, int trust) {
  return X509_VERIFY_PARAM_set_trust(ssl->param, trust);
}

int SSL_CTX_set1_param(SSL_CTX *ctx, const X509_VERIFY_PARAM *param) {
  return X509_VERIFY_PARAM_set1(ctx->param, param);
}

int SSL_set1_param(SSL *ssl, const X509_VERIFY_PARAM *param) {
  return X509_VERIFY_PARAM_set1(ssl->param, param);
}

X509_VERIFY_PARAM *SSL_CTX_get0_param(SSL_CTX *ctx) { return ctx->param; }

X509_VERIFY_PARAM *SSL_get0_param(SSL *ssl) { return ssl->param; }

int SSL_get_verify_depth(const SSL *ssl) {
  return X509_VERIFY_PARAM_get_depth(ssl->param);
}

int (*SSL_get_verify_callback(const SSL *ssl))(int, X509_STORE_CTX *) {
  return ssl->verify_callback;
}

int SSL_CTX_get_verify_mode(const SSL_CTX *ctx) { return ctx->verify_mode; }

int SSL_CTX_get_verify_depth(const SSL_CTX *ctx) {
  return X509_VERIFY_PARAM_get_depth(ctx->param);
}

int (*SSL_CTX_get_verify_callback(const SSL_CTX *ctx))(
    int ok, X509_STORE_CTX *store_ctx) {
  return ctx->default_verify_callback;
}

void SSL_set_verify(SSL *ssl, int mode,
                    int (*callback)(int ok, X509_STORE_CTX *store_ctx)) {
  ssl->verify_mode = mode;
  if (callback != NULL) {
    ssl->verify_callback = callback;
  }
}

void SSL_set_verify_depth(SSL *ssl, int depth) {
  X509_VERIFY_PARAM_set_depth(ssl->param, depth);
}

void SSL_CTX_set_cert_verify_callback(SSL_CTX *ctx,
                                      int (*cb)(X509_STORE_CTX *store_ctx,
                                                void *arg),
                                      void *arg) {
  ctx->app_verify_callback = cb;
  ctx->app_verify_arg = arg;
}

void SSL_CTX_set_verify(SSL_CTX *ctx, int mode,
                        int (*cb)(int, X509_STORE_CTX *)) {
  ctx->verify_mode = mode;
  ctx->default_verify_callback = cb;
}

void SSL_CTX_set_verify_depth(SSL_CTX *ctx, int depth) {
  X509_VERIFY_PARAM_set_depth(ctx->param, depth);
}

int SSL_CTX_set_default_verify_paths(SSL_CTX *ctx) {
  return X509_STORE_set_default_paths(ctx->cert_store);
}

int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *ca_file,
                                  const char *ca_dir) {
  return X509_STORE_load_locations(ctx->cert_store, ca_file, ca_dir);
}

void SSL_set_verify_result(SSL *ssl, long result) {
  if (result != X509_V_OK) {
    abort();
  }
}

long SSL_get_verify_result(const SSL *ssl) {
  SSL_SESSION *session = SSL_get_session(ssl);
  if (session == NULL) {
    return X509_V_ERR_INVALID_CALL;
  }
  return session->verify_result;
}

X509_STORE *SSL_CTX_get_cert_store(const SSL_CTX *ctx) {
  return ctx->cert_store;
}

void SSL_CTX_set_cert_store(SSL_CTX *ctx, X509_STORE *store) {
  X509_STORE_free(ctx->cert_store);
  ctx->cert_store = store;
}

static void ssl_crypto_x509_flush_cached_leaf(CERT *cert) {
  X509_free(cert->x509_leaf);
  cert->x509_leaf = NULL;
}

static void ssl_crypto_x509_flush_cached_chain(CERT *cert) {
  sk_X509_pop_free(cert->x509_chain, X509_free);
  cert->x509_chain = NULL;
}

static void ssl_crypto_x509_clear(CERT *cert) {
  ssl_crypto_x509_flush_cached_leaf(cert);
  ssl_crypto_x509_flush_cached_chain(cert);

  X509_free(cert->x509_stash);
  cert->x509_stash = NULL;
}

static int ssl_crypto_x509_session_cache_objects(SSL_SESSION *sess) {
  STACK_OF(X509) *chain = NULL;
  const size_t num_certs = sk_CRYPTO_BUFFER_num(sess->certs);

  if (num_certs > 0) {
    chain = sk_X509_new_null();
    if (chain == NULL) {
      OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
      goto err;
    }
  }

  X509 *leaf = NULL;
  for (size_t i = 0; i < num_certs; i++) {
    X509 *x509 = X509_parse_from_buffer(sk_CRYPTO_BUFFER_value(sess->certs, i));
    if (x509 == NULL) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
      goto err;
    }
    if (!sk_X509_push(chain, x509)) {
      OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
      X509_free(x509);
      goto err;
    }
    if (i == 0) {
      leaf = x509;
    }
  }

  sk_X509_pop_free(sess->x509_chain, X509_free);
  sess->x509_chain = chain;
  sk_X509_pop_free(sess->x509_chain_without_leaf, X509_free);
  sess->x509_chain_without_leaf = NULL;

  X509_free(sess->x509_peer);
  if (leaf != NULL) {
    X509_up_ref(leaf);
  }
  sess->x509_peer = leaf;

  return 1;

err:
  sk_X509_pop_free(chain, X509_free);
  return 0;
}

static int ssl_crypto_x509_session_dup(SSL_SESSION *new_session,
                                       const SSL_SESSION *session) {
  if (session->x509_peer != NULL) {
    X509_up_ref(session->x509_peer);
    new_session->x509_peer = session->x509_peer;
  }
  if (session->x509_chain != NULL) {
    new_session->x509_chain = X509_chain_up_ref(session->x509_chain);
    if (new_session->x509_chain == NULL) {
      return 0;
    }
  }

  return 1;
}

static void ssl_crypto_x509_session_clear(SSL_SESSION *session) {
  X509_free(session->x509_peer);
  session->x509_peer = NULL;
  sk_X509_pop_free(session->x509_chain, X509_free);
  session->x509_chain = NULL;
  sk_X509_pop_free(session->x509_chain_without_leaf, X509_free);
  session->x509_chain_without_leaf = NULL;
}

const SSL_X509_METHOD ssl_crypto_x509_method = {
  ssl_crypto_x509_clear,
  ssl_crypto_x509_flush_cached_chain,
  ssl_crypto_x509_flush_cached_leaf,
  ssl_crypto_x509_session_cache_objects,
  ssl_crypto_x509_session_dup,
  ssl_crypto_x509_session_clear,
};

/* x509_to_buffer returns a |CRYPTO_BUFFER| that contains the serialised
 * contents of |x509|. */
static CRYPTO_BUFFER *x509_to_buffer(X509 *x509) {
  uint8_t *buf = NULL;
  int cert_len = i2d_X509(x509, &buf);
  if (cert_len <= 0) {
    return 0;
  }

  CRYPTO_BUFFER *buffer = CRYPTO_BUFFER_new(buf, cert_len, NULL);
  OPENSSL_free(buf);

  return buffer;
}

static int ssl_use_certificate(CERT *cert, X509 *x) {
  if (x == NULL) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }

  CRYPTO_BUFFER *buffer = x509_to_buffer(x);
  if (buffer == NULL) {
    return 0;
  }

  const int ok = ssl_set_cert(cert, buffer);
  CRYPTO_BUFFER_free(buffer);
  return ok;
}

int SSL_use_certificate(SSL *ssl, X509 *x) {
  return ssl_use_certificate(ssl->cert, x);
}

int SSL_CTX_use_certificate(SSL_CTX *ctx, X509 *x) {
  return ssl_use_certificate(ctx->cert, x);
}

/* ssl_cert_cache_leaf_cert sets |cert->x509_leaf|, if currently NULL, from the
 * first element of |cert->chain|. */
static int ssl_cert_cache_leaf_cert(CERT *cert) {
  assert(cert->x509_method);

  if (cert->x509_leaf != NULL ||
      cert->chain == NULL) {
    return 1;
  }

  CRYPTO_BUFFER *leaf = sk_CRYPTO_BUFFER_value(cert->chain, 0);
  if (!leaf) {
    return 1;
  }

  cert->x509_leaf = X509_parse_from_buffer(leaf);
  return cert->x509_leaf != NULL;
}

static X509 *ssl_cert_get0_leaf(CERT *cert) {
  if (cert->x509_leaf == NULL &&
      !ssl_cert_cache_leaf_cert(cert)) {
    return NULL;
  }

  return cert->x509_leaf;
}

X509 *SSL_get_certificate(const SSL *ssl) {
  return ssl_cert_get0_leaf(ssl->cert);
}

X509 *SSL_CTX_get0_certificate(const SSL_CTX *ctx) {
  return ssl_cert_get0_leaf(ctx->cert);
}

/* new_leafless_chain returns a fresh stack of buffers set to {NULL}. */
static STACK_OF(CRYPTO_BUFFER) *new_leafless_chain(void) {
  STACK_OF(CRYPTO_BUFFER) *chain = sk_CRYPTO_BUFFER_new_null();
  if (chain == NULL) {
    return NULL;
  }

  if (!sk_CRYPTO_BUFFER_push(chain, NULL)) {
    sk_CRYPTO_BUFFER_free(chain);
    return NULL;
  }

  return chain;
}

/* ssl_cert_set_chain sets elements 1.. of |cert->chain| to the serialised
 * forms of elements of |chain|. It returns one on success or zero on error, in
 * which case no change to |cert->chain| is made. It preverses the existing
 * leaf from |cert->chain|, if any. */
static int ssl_cert_set_chain(CERT *cert, STACK_OF(X509) *chain) {
  STACK_OF(CRYPTO_BUFFER) *new_chain = NULL;

  if (cert->chain != NULL) {
    new_chain = sk_CRYPTO_BUFFER_new_null();
    if (new_chain == NULL) {
      return 0;
    }

    CRYPTO_BUFFER *leaf = sk_CRYPTO_BUFFER_value(cert->chain, 0);
    if (!sk_CRYPTO_BUFFER_push(new_chain, leaf)) {
      goto err;
    }
    /* |leaf| might be NULL if it's a “leafless” chain. */
    if (leaf != NULL) {
      CRYPTO_BUFFER_up_ref(leaf);
    }
  }

  for (size_t i = 0; i < sk_X509_num(chain); i++) {
    if (new_chain == NULL) {
      new_chain = new_leafless_chain();
      if (new_chain == NULL) {
        goto err;
      }
    }

    CRYPTO_BUFFER *buffer = x509_to_buffer(sk_X509_value(chain, i));
    if (buffer == NULL ||
        !sk_CRYPTO_BUFFER_push(new_chain, buffer)) {
      CRYPTO_BUFFER_free(buffer);
      goto err;
    }
  }

  sk_CRYPTO_BUFFER_pop_free(cert->chain, CRYPTO_BUFFER_free);
  cert->chain = new_chain;

  return 1;

err:
  sk_CRYPTO_BUFFER_pop_free(new_chain, CRYPTO_BUFFER_free);
  return 0;
}

static int ssl_cert_set0_chain(CERT *cert, STACK_OF(X509) *chain) {
  if (!ssl_cert_set_chain(cert, chain)) {
    return 0;
  }

  sk_X509_pop_free(chain, X509_free);
  ssl_crypto_x509_flush_cached_chain(cert);
  return 1;
}

static int ssl_cert_set1_chain(CERT *cert, STACK_OF(X509) *chain) {
  if (!ssl_cert_set_chain(cert, chain)) {
    return 0;
  }

  ssl_crypto_x509_flush_cached_chain(cert);
  return 1;
}

static int ssl_cert_append_cert(CERT *cert, X509 *x509) {
  assert(cert->x509_method);

  CRYPTO_BUFFER *buffer = x509_to_buffer(x509);
  if (buffer == NULL) {
    return 0;
  }

  if (cert->chain != NULL) {
    if (!sk_CRYPTO_BUFFER_push(cert->chain, buffer)) {
      CRYPTO_BUFFER_free(buffer);
      return 0;
    }

    return 1;
  }

  cert->chain = new_leafless_chain();
  if (cert->chain == NULL ||
      !sk_CRYPTO_BUFFER_push(cert->chain, buffer)) {
    CRYPTO_BUFFER_free(buffer);
    sk_CRYPTO_BUFFER_free(cert->chain);
    cert->chain = NULL;
    return 0;
  }

  return 1;
}

static int ssl_cert_add0_chain_cert(CERT *cert, X509 *x509) {
  if (!ssl_cert_append_cert(cert, x509)) {
    return 0;
  }

  X509_free(cert->x509_stash);
  cert->x509_stash = x509;
  ssl_crypto_x509_flush_cached_chain(cert);
  return 1;
}

static int ssl_cert_add1_chain_cert(CERT *cert, X509 *x509) {
  if (!ssl_cert_append_cert(cert, x509)) {
    return 0;
  }

  ssl_crypto_x509_flush_cached_chain(cert);
  return 1;
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

int ssl_auto_chain_if_needed(SSL *ssl) {
  /* Only build a chain if there are no intermediates configured and the feature
   * isn't disabled. */
  if ((ssl->mode & SSL_MODE_NO_AUTO_CHAIN) ||
      !ssl_has_certificate(ssl) ||
      ssl->cert->chain == NULL ||
      sk_CRYPTO_BUFFER_num(ssl->cert->chain) > 1) {
    return 1;
  }

  X509 *leaf =
      X509_parse_from_buffer(sk_CRYPTO_BUFFER_value(ssl->cert->chain, 0));
  if (!leaf) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_X509_LIB);
    return 0;
  }

  X509_STORE_CTX ctx;
  if (!X509_STORE_CTX_init(&ctx, ssl->ctx->cert_store, leaf, NULL)) {
    X509_free(leaf);
    OPENSSL_PUT_ERROR(SSL, ERR_R_X509_LIB);
    return 0;
  }

  /* Attempt to build a chain, ignoring the result. */
  X509_verify_cert(&ctx);
  X509_free(leaf);
  ERR_clear_error();

  /* Remove the leaf from the generated chain. */
  X509_free(sk_X509_shift(ctx.chain));

  const int ok = ssl_cert_set_chain(ssl->cert, ctx.chain);
  X509_STORE_CTX_cleanup(&ctx);
  if (!ok) {
    return 0;
  }

  ssl_crypto_x509_flush_cached_chain(ssl->cert);

  return 1;
}

/* ssl_cert_cache_chain_certs fills in |cert->x509_chain| from elements 1.. of
 * |cert->chain|. */
static int ssl_cert_cache_chain_certs(CERT *cert) {
  assert(cert->x509_method);

  if (cert->x509_chain != NULL ||
      cert->chain == NULL ||
      sk_CRYPTO_BUFFER_num(cert->chain) < 2) {
    return 1;
  }

  STACK_OF(X509) *chain = sk_X509_new_null();
  if (chain == NULL) {
    return 0;
  }

  for (size_t i = 1; i < sk_CRYPTO_BUFFER_num(cert->chain); i++) {
    CRYPTO_BUFFER *buffer = sk_CRYPTO_BUFFER_value(cert->chain, i);
    X509 *x509 = X509_parse_from_buffer(buffer);
    if (x509 == NULL ||
        !sk_X509_push(chain, x509)) {
      X509_free(x509);
      goto err;
    }
  }

  cert->x509_chain = chain;
  return 1;

err:
  sk_X509_pop_free(chain, X509_free);
  return 0;
}

int SSL_CTX_get0_chain_certs(const SSL_CTX *ctx, STACK_OF(X509) **out_chain) {
  if (!ssl_cert_cache_chain_certs(ctx->cert)) {
    *out_chain = NULL;
    return 0;
  }

  *out_chain = ctx->cert->x509_chain;
  return 1;
}

int SSL_CTX_get_extra_chain_certs(const SSL_CTX *ctx,
                                  STACK_OF(X509) **out_chain) {
  return SSL_CTX_get0_chain_certs(ctx, out_chain);
}

int SSL_get0_chain_certs(const SSL *ssl, STACK_OF(X509) **out_chain) {
  if (!ssl_cert_cache_chain_certs(ssl->cert)) {
    *out_chain = NULL;
    return 0;
  }

  *out_chain = ssl->cert->x509_chain;
  return 1;
}

static SSL_SESSION *ssl_session_new_with_crypto_x509(void) {
  return ssl_session_new(&ssl_crypto_x509_method);
}

SSL_SESSION *d2i_SSL_SESSION_bio(BIO *bio, SSL_SESSION **out) {
  return ASN1_d2i_bio_of(SSL_SESSION, ssl_session_new_with_crypto_x509,
                         d2i_SSL_SESSION, bio, out);
}

int i2d_SSL_SESSION_bio(BIO *bio, const SSL_SESSION *session) {
  return ASN1_i2d_bio_of(SSL_SESSION, i2d_SSL_SESSION, bio, session);
}

IMPLEMENT_PEM_rw(SSL_SESSION, SSL_SESSION, PEM_STRING_SSL_SESSION, SSL_SESSION)

SSL_SESSION *d2i_SSL_SESSION(SSL_SESSION **a, const uint8_t **pp, long length) {
  if (length < 0) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
    return NULL;
  }

  CBS cbs;
  CBS_init(&cbs, *pp, length);

  SSL_SESSION *ret = SSL_SESSION_parse(&cbs, &ssl_crypto_x509_method,
                                       NULL /* no buffer pool */);
  if (ret == NULL) {
    return NULL;
  }

  if (a) {
    SSL_SESSION_free(*a);
    *a = ret;
  }
  *pp = CBS_data(&cbs);
  return ret;
}
