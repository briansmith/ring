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
 * Copyright (c) 1998-2006 The OpenSSL Project.  All rights reserved.
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

#include <stdio.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/lhash.h>
#include <openssl/mem.h>
#include <openssl/rand.h>

#include "internal.h"
#include "../crypto/internal.h"


/* The address of this is a magic value, a pointer to which is returned by
 * SSL_magic_pending_session_ptr(). It allows a session callback to indicate
 * that it needs to asynchronously fetch session information. */
static const char g_pending_session_magic = 0;

static CRYPTO_EX_DATA_CLASS g_ex_data_class = CRYPTO_EX_DATA_CLASS_INIT;

static void SSL_SESSION_list_remove(SSL_CTX *ctx, SSL_SESSION *s);
static void SSL_SESSION_list_add(SSL_CTX *ctx, SSL_SESSION *s);
static int remove_session_lock(SSL_CTX *ctx, SSL_SESSION *c, int lck);

SSL_SESSION *SSL_magic_pending_session_ptr(void) {
  return (SSL_SESSION *)&g_pending_session_magic;
}

SSL_SESSION *SSL_get_session(const SSL *ssl)
{
  /* aka SSL_get0_session; gets 0 objects, just returns a copy of the pointer */
  return ssl->session;
}

SSL_SESSION *SSL_get1_session(SSL *ssl) {
  /* variant of SSL_get_session: caller really gets something */
  return SSL_SESSION_up_ref(ssl->session);
}

int SSL_SESSION_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
                                 CRYPTO_EX_dup *dup_func,
                                 CRYPTO_EX_free *free_func) {
  int index;
  if (!CRYPTO_get_ex_new_index(&g_ex_data_class, &index, argl, argp, new_func,
                               dup_func, free_func)) {
    return -1;
  }
  return index;
}

int SSL_SESSION_set_ex_data(SSL_SESSION *s, int idx, void *arg) {
  return CRYPTO_set_ex_data(&s->ex_data, idx, arg);
}

void *SSL_SESSION_get_ex_data(const SSL_SESSION *s, int idx) {
  return CRYPTO_get_ex_data(&s->ex_data, idx);
}

SSL_SESSION *SSL_SESSION_new(void) {
  SSL_SESSION *ss;

  ss = (SSL_SESSION *)OPENSSL_malloc(sizeof(SSL_SESSION));
  if (ss == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_SESSION_new, ERR_R_MALLOC_FAILURE);
    return 0;
  }
  memset(ss, 0, sizeof(SSL_SESSION));

  ss->verify_result = 1; /* avoid 0 (= X509_V_OK) just in case */
  ss->references = 1;
  ss->timeout = SSL_DEFAULT_SESSION_TIMEOUT;
  ss->time = (unsigned long)time(NULL);
  CRYPTO_new_ex_data(&g_ex_data_class, ss, &ss->ex_data);
  return ss;
}

const uint8_t *SSL_SESSION_get_id(const SSL_SESSION *s, unsigned int *len) {
  if (len) {
    *len = s->session_id_length;
  }
  return s->session_id;
}

/* Even with SSLv2, we have 16 bytes (128 bits) of session ID space.
 * SSLv3/TLSv1 has 32 bytes (256 bits). As such, filling the ID with random
 * gunk repeatedly until we have no conflict is going to complete in one
 * iteration pretty much "most" of the time (btw: understatement). So, if it
 * takes us 10 iterations and we still can't avoid a conflict - well that's a
 * reasonable point to call it quits. Either the RAND code is broken or someone
 * is trying to open roughly very close to 2^128 (or 2^256) SSL sessions to our
 * server. How you might store that many sessions is perhaps a more interesting
 * question ... */
static int def_generate_session_id(const SSL *ssl, uint8_t *id,
                                   unsigned int *id_len) {
  static const unsigned kMaxAttempts = 10;
  unsigned int retry = 0;
  do {
    if (!RAND_bytes(id, *id_len)) {
      return 0;
    }
  } while (SSL_has_matching_session_id(ssl, id, *id_len) &&
           (++retry < kMaxAttempts));

  if (retry < kMaxAttempts) {
    return 1;
  }

  /* else - woops a session_id match */
  /* XXX We should also check the external cache -- but the probability of a
   * collision is negligible, and we could not prevent the concurrent creation
   * of sessions with identical IDs since we currently don't have means to
   * atomically check whether a session ID already exists and make a
   * reservation for it if it does not (this problem applies to the internal
   * cache as well). */
  return 0;
}

int ssl_get_new_session(SSL *s, int session) {
  /* This gets used by clients and servers. */

  unsigned int tmp;
  SSL_SESSION *ss = NULL;
  GEN_SESSION_CB cb = def_generate_session_id;

  if (s->mode & SSL_MODE_NO_SESSION_CREATION) {
    OPENSSL_PUT_ERROR(SSL, ssl_get_new_session,
                      SSL_R_SESSION_MAY_NOT_BE_CREATED);
    return 0;
  }

  ss = SSL_SESSION_new();
  if (ss == NULL) {
    return 0;
  }

  /* If the context has a default timeout, use it over the default. */
  if (s->initial_ctx->session_timeout != 0) {
    ss->timeout = s->initial_ctx->session_timeout;
  }

  SSL_SESSION_free(s->session);
  s->session = NULL;

  if (session) {
    if (s->version == SSL3_VERSION || s->version == TLS1_VERSION ||
        s->version == TLS1_1_VERSION || s->version == TLS1_2_VERSION ||
        s->version == DTLS1_VERSION || s->version == DTLS1_2_VERSION) {
      ss->ssl_version = s->version;
      ss->session_id_length = SSL3_SSL_SESSION_ID_LENGTH;
    } else {
      OPENSSL_PUT_ERROR(SSL, ssl_get_new_session,
                        SSL_R_UNSUPPORTED_SSL_VERSION);
      SSL_SESSION_free(ss);
      return 0;
    }

    /* If RFC4507 ticket use empty session ID */
    if (s->tlsext_ticket_expected) {
      ss->session_id_length = 0;
      goto sess_id_done;
    }

    /* Choose which callback will set the session ID */
    if (s->generate_session_id) {
      cb = s->generate_session_id;
    } else if (s->initial_ctx->generate_session_id) {
      cb = s->initial_ctx->generate_session_id;
    }

    /* Choose a session ID */
    tmp = ss->session_id_length;
    if (!cb(s, ss->session_id, &tmp)) {
      /* The callback failed */
      OPENSSL_PUT_ERROR(SSL, ssl_get_new_session,
                        SSL_R_SSL_SESSION_ID_CALLBACK_FAILED);
      SSL_SESSION_free(ss);
      return 0;
    }

    /* Don't allow the callback to set the session length to zero. nor set it
     * higher than it was. */
    if (!tmp || tmp > ss->session_id_length) {
      /* The callback set an illegal length */
      OPENSSL_PUT_ERROR(SSL, ssl_get_new_session,
                        SSL_R_SSL_SESSION_ID_HAS_BAD_LENGTH);
      SSL_SESSION_free(ss);
      return 0;
    }

    ss->session_id_length = tmp;
    /* Finally, check for a conflict */
    if (SSL_has_matching_session_id(s, ss->session_id, ss->session_id_length)) {
      OPENSSL_PUT_ERROR(SSL, ssl_get_new_session,
                        SSL_R_SSL_SESSION_ID_CONFLICT);
      SSL_SESSION_free(ss);
      return 0;
    }

  sess_id_done:
    if (s->tlsext_hostname) {
      ss->tlsext_hostname = BUF_strdup(s->tlsext_hostname);
      if (ss->tlsext_hostname == NULL) {
        OPENSSL_PUT_ERROR(SSL, ssl_get_new_session, ERR_R_INTERNAL_ERROR);
        SSL_SESSION_free(ss);
        return 0;
      }
    }
  } else {
    ss->session_id_length = 0;
  }

  if (s->sid_ctx_length > sizeof(ss->sid_ctx)) {
    OPENSSL_PUT_ERROR(SSL, ssl_get_new_session, ERR_R_INTERNAL_ERROR);
    SSL_SESSION_free(ss);
    return 0;
  }

  memcpy(ss->sid_ctx, s->sid_ctx, s->sid_ctx_length);
  ss->sid_ctx_length = s->sid_ctx_length;
  s->session = ss;
  ss->ssl_version = s->version;
  ss->verify_result = X509_V_OK;

  return 1;
}

/* ssl_get_prev attempts to find an SSL_SESSION to be used to resume this
 * connection. It is only called by servers.
 *
 *   ctx: contains the early callback context, which is the result of a
 *       shallow parse of the ClientHello.
 *
 * Returns:
 *   -1: error
 *    0: a session may have been found.
 *
 * Side effects:
 *   - If a session is found then s->session is pointed at it (after freeing an
 *     existing session if need be) and s->verify_result is set from the session.
 *   - Both for new and resumed sessions, s->tlsext_ticket_expected is set to 1
 *     if the server should issue a new session ticket (to 0 otherwise). */
int ssl_get_prev_session(SSL *s, const struct ssl_early_callback_ctx *ctx) {
  /* This is used only by servers. */
  SSL_SESSION *ret = NULL;
  int fatal = 0;
  int try_session_cache = 1;
  int r;

  if (ctx->session_id_len > SSL_MAX_SSL_SESSION_ID_LENGTH) {
    goto err;
  }

  if (ctx->session_id_len == 0) {
    try_session_cache = 0;
  }

  r = tls1_process_ticket(s, ctx, &ret); /* sets s->tlsext_ticket_expected */
  switch (r) {
    case -1: /* Error during processing */
      fatal = 1;
      goto err;

    case 0:  /* No ticket found */
    case 1:  /* Zero length ticket found */
      break; /* Ok to carry on processing session id. */

    case 2:  /* Ticket found but not decrypted. */
    case 3:  /* Ticket decrypted, *ret has been set. */
      try_session_cache = 0;
      break;

    default:
      abort();
  }

  if (try_session_cache && ret == NULL &&
      !(s->initial_ctx->session_cache_mode &
        SSL_SESS_CACHE_NO_INTERNAL_LOOKUP)) {
    SSL_SESSION data;
    data.ssl_version = s->version;
    data.session_id_length = ctx->session_id_len;
    if (ctx->session_id_len == 0) {
      return 0;
    }
    memcpy(data.session_id, ctx->session_id, ctx->session_id_len);

    CRYPTO_MUTEX_lock_read(&s->initial_ctx->lock);
    ret = lh_SSL_SESSION_retrieve(s->initial_ctx->sessions, &data);
    CRYPTO_MUTEX_unlock(&s->initial_ctx->lock);

    if (ret != NULL) {
      SSL_SESSION_up_ref(ret);
    }
  }

  if (try_session_cache && ret == NULL &&
      s->initial_ctx->get_session_cb != NULL) {
    int copy = 1;

    ret = s->initial_ctx->get_session_cb(s, (uint8_t *)ctx->session_id,
                                         ctx->session_id_len, &copy);
    if (ret != NULL) {
      if (ret == SSL_magic_pending_session_ptr()) {
        /* This is a magic value which indicates that the callback needs to
         * unwind the stack and figure out the session asynchronously. */
        return PENDING_SESSION;
      }

      /* Increment reference count now if the session callback asks us to do so
       * (note that if the session structures returned by the callback are
       * shared between threads, it must handle the reference count itself
       * [i.e. copy == 0], or things won't be thread-safe). */
      if (copy) {
        SSL_SESSION_up_ref(ret);
      }

      /* Add the externally cached session to the internal cache as well if and
       * only if we are supposed to. */
      if (!(s->initial_ctx->session_cache_mode &
            SSL_SESS_CACHE_NO_INTERNAL_STORE)) {
        /* The following should not return 1, otherwise, things are very
         * strange */
        SSL_CTX_add_session(s->initial_ctx, ret);
      }
    }
  }

  if (ret == NULL) {
    goto err;
  }

  /* Now ret is non-NULL and we own one of its reference counts. */

  if (ret->sid_ctx_length != s->sid_ctx_length ||
      memcmp(ret->sid_ctx, s->sid_ctx, ret->sid_ctx_length)) {
    /* We have the session requested by the client, but we don't want to use it
     * in this context. */
    goto err; /* treat like cache miss */
  }

  if ((s->verify_mode & SSL_VERIFY_PEER) && s->sid_ctx_length == 0) {
    /* We can't be sure if this session is being used out of context, which is
     * especially important for SSL_VERIFY_PEER. The application should have
     * used SSL[_CTX]_set_session_id_context.
     *
     * For this error case, we generate an error instead of treating the event
     * like a cache miss (otherwise it would be easy for applications to
     * effectively disable the session cache by accident without anyone
     * noticing). */
    OPENSSL_PUT_ERROR(SSL, ssl_get_prev_session,
                      SSL_R_SESSION_ID_CONTEXT_UNINITIALIZED);
    fatal = 1;
    goto err;
  }

  if (ret->timeout < (long)(time(NULL) - ret->time)) {
    /* timeout */
    if (try_session_cache) {
      /* session was from the cache, so remove it */
      SSL_CTX_remove_session(s->initial_ctx, ret);
    }
    goto err;
  }

  SSL_SESSION_free(s->session);
  s->session = ret;
  s->verify_result = s->session->verify_result;
  return 1;

err:
  if (ret != NULL) {
    SSL_SESSION_free(ret);
    if (!try_session_cache) {
      /* The session was from a ticket, so we should
       * issue a ticket for the new session */
      s->tlsext_ticket_expected = 1;
    }
  }
  if (fatal) {
    return -1;
  }
  return 0;
}

int SSL_CTX_add_session(SSL_CTX *ctx, SSL_SESSION *c) {
  int ret = 0;
  SSL_SESSION *s;

  /* add just 1 reference count for the SSL_CTX's session cache even though it
   * has two ways of access: each session is in a doubly linked list and an
   * lhash */
  SSL_SESSION_up_ref(c);
  /* if session c is in already in cache, we take back the increment later */

  CRYPTO_MUTEX_lock_write(&ctx->lock);
  if (!lh_SSL_SESSION_insert(ctx->sessions, &s, c)) {
    CRYPTO_MUTEX_unlock(&ctx->lock);
    return 0;
  }

  /* s != NULL iff we already had a session with the given PID. In this case, s
   * == c should hold (then we did not really modify ctx->sessions), or we're
   * in trouble. */
  if (s != NULL && s != c) {
    /* We *are* in trouble ... */
    SSL_SESSION_list_remove(ctx, s);
    SSL_SESSION_free(s);
    /* ... so pretend the other session did not exist in cache (we cannot
     * handle two SSL_SESSION structures with identical session ID in the same
     * cache, which could happen e.g. when two threads concurrently obtain the
     * same session from an external cache) */
    s = NULL;
  }

  /* Put at the head of the queue unless it is already in the cache */
  if (s == NULL) {
    SSL_SESSION_list_add(ctx, c);
  }

  if (s != NULL) {
    /* existing cache entry -- decrement previously incremented reference count
     * because it already takes into account the cache */
    SSL_SESSION_free(s); /* s == c */
    ret = 0;
  } else {
    /* new cache entry -- remove old ones if cache has become too large */
    ret = 1;

    if (SSL_CTX_sess_get_cache_size(ctx) > 0) {
      while (SSL_CTX_sess_number(ctx) > SSL_CTX_sess_get_cache_size(ctx)) {
        if (!remove_session_lock(ctx, ctx->session_cache_tail, 0)) {
          break;
        }
      }
    }
  }

  CRYPTO_MUTEX_unlock(&ctx->lock);
  return ret;
}

int SSL_CTX_remove_session(SSL_CTX *ctx, SSL_SESSION *c) {
  return remove_session_lock(ctx, c, 1);
}

static int remove_session_lock(SSL_CTX *ctx, SSL_SESSION *c, int lock) {
  SSL_SESSION *r;
  int ret = 0;

  if (c != NULL && c->session_id_length != 0) {
    if (lock) {
      CRYPTO_MUTEX_lock_write(&ctx->lock);
    }
    r = lh_SSL_SESSION_retrieve(ctx->sessions, c);
    if (r == c) {
      ret = 1;
      r = lh_SSL_SESSION_delete(ctx->sessions, c);
      SSL_SESSION_list_remove(ctx, c);
    }

    if (lock) {
      CRYPTO_MUTEX_unlock(&ctx->lock);
    }

    if (ret) {
      r->not_resumable = 1;
      if (ctx->remove_session_cb != NULL) {
        ctx->remove_session_cb(ctx, r);
      }
      SSL_SESSION_free(r);
    }
  }

  return ret;
}

SSL_SESSION *SSL_SESSION_up_ref(SSL_SESSION *session) {
  if (session) {
    CRYPTO_refcount_inc(&session->references);
  }
  return session;
}

void SSL_SESSION_free(SSL_SESSION *session) {
  if (session == NULL ||
      !CRYPTO_refcount_dec_and_test_zero(&session->references)) {
    return;
  }

  CRYPTO_free_ex_data(&g_ex_data_class, session, &session->ex_data);

  OPENSSL_cleanse(session->master_key, sizeof(session->master_key));
  OPENSSL_cleanse(session->session_id, sizeof(session->session_id));
  ssl_sess_cert_free(session->sess_cert);
  X509_free(session->peer);
  OPENSSL_free(session->tlsext_hostname);
  OPENSSL_free(session->tlsext_tick);
  OPENSSL_free(session->tlsext_signed_cert_timestamp_list);
  OPENSSL_free(session->ocsp_response);
  OPENSSL_free(session->psk_identity);
  OPENSSL_cleanse(session, sizeof(*session));
  OPENSSL_free(session);
}

int SSL_set_session(SSL *s, SSL_SESSION *session) {
  if (s->session == session) {
    return 1;
  }

  SSL_SESSION_free(s->session);
  s->session = session;
  if (session != NULL) {
    SSL_SESSION_up_ref(session);
    s->verify_result = session->verify_result;
  }

  return 1;
}

long SSL_SESSION_set_timeout(SSL_SESSION *s, long t) {
  if (s == NULL) {
    return 0;
  }

  s->timeout = t;
  return 1;
}

long SSL_SESSION_get_timeout(const SSL_SESSION *s) {
  if (s == NULL) {
    return 0;
  }

  return s->timeout;
}

long SSL_SESSION_get_time(const SSL_SESSION *s) {
  if (s == NULL) {
    return 0;
  }

  return s->time;
}

long SSL_SESSION_set_time(SSL_SESSION *s, long t) {
  if (s == NULL) {
    return 0;
  }

  s->time = t;
  return t;
}

X509 *SSL_SESSION_get0_peer(SSL_SESSION *s) { return s->peer; }

int SSL_SESSION_set1_id_context(SSL_SESSION *s, const uint8_t *sid_ctx,
                                unsigned int sid_ctx_len) {
  if (sid_ctx_len > SSL_MAX_SID_CTX_LENGTH) {
    OPENSSL_PUT_ERROR(SSL, SSL_SESSION_set1_id_context,
                      SSL_R_SSL_SESSION_ID_CONTEXT_TOO_LONG);
    return 0;
  }

  s->sid_ctx_length = sid_ctx_len;
  memcpy(s->sid_ctx, sid_ctx, sid_ctx_len);

  return 1;
}

long SSL_CTX_set_timeout(SSL_CTX *s, long t) {
  long l;
  if (s == NULL) {
    return 0;
  }

  l = s->session_timeout;
  s->session_timeout = t;
  return l;
}

long SSL_CTX_get_timeout(const SSL_CTX *s) {
  if (s == NULL) {
    return 0;
  }

  return s->session_timeout;
}

typedef struct timeout_param_st {
  SSL_CTX *ctx;
  long time;
  LHASH_OF(SSL_SESSION) *cache;
} TIMEOUT_PARAM;

static void timeout_doall_arg(SSL_SESSION *sess, void *void_param) {
  TIMEOUT_PARAM *param = void_param;

  if (param->time == 0 ||
      param->time > (sess->time + sess->timeout)) {
    /* timeout */
    /* The reason we don't call SSL_CTX_remove_session() is to
     * save on locking overhead */
    (void) lh_SSL_SESSION_delete(param->cache, sess);
    SSL_SESSION_list_remove(param->ctx, sess);
    sess->not_resumable = 1;
    if (param->ctx->remove_session_cb != NULL) {
      param->ctx->remove_session_cb(param->ctx, sess);
    }
    SSL_SESSION_free(sess);
  }
}

void SSL_CTX_flush_sessions(SSL_CTX *ctx, long t) {
  TIMEOUT_PARAM tp;

  tp.ctx = ctx;
  tp.cache = ctx->sessions;
  if (tp.cache == NULL) {
    return;
  }
  tp.time = t;
  CRYPTO_MUTEX_lock_write(&ctx->lock);
  lh_SSL_SESSION_doall_arg(tp.cache, timeout_doall_arg, &tp);
  CRYPTO_MUTEX_unlock(&ctx->lock);
}

int ssl_clear_bad_session(SSL *s) {
  if (s->session != NULL && !(s->shutdown & SSL_SENT_SHUTDOWN) &&
      !SSL_in_init(s)) {
    SSL_CTX_remove_session(s->ctx, s->session);
    return 1;
  }

  return 0;
}

/* locked by SSL_CTX in the calling function */
static void SSL_SESSION_list_remove(SSL_CTX *ctx, SSL_SESSION *s) {
  if (s->next == NULL || s->prev == NULL) {
    return;
  }

  if (s->next == (SSL_SESSION *)&ctx->session_cache_tail) {
    /* last element in list */
    if (s->prev == (SSL_SESSION *)&ctx->session_cache_head) {
      /* only one element in list */
      ctx->session_cache_head = NULL;
      ctx->session_cache_tail = NULL;
    } else {
      ctx->session_cache_tail = s->prev;
      s->prev->next = (SSL_SESSION *)&(ctx->session_cache_tail);
    }
  } else {
    if (s->prev == (SSL_SESSION *)&ctx->session_cache_head) {
      /* first element in list */
      ctx->session_cache_head = s->next;
      s->next->prev = (SSL_SESSION *)&(ctx->session_cache_head);
    } else { /* middle of list */
      s->next->prev = s->prev;
      s->prev->next = s->next;
    }
  }
  s->prev = s->next = NULL;
}

static void SSL_SESSION_list_add(SSL_CTX *ctx, SSL_SESSION *s) {
  if (s->next != NULL && s->prev != NULL) {
    SSL_SESSION_list_remove(ctx, s);
  }

  if (ctx->session_cache_head == NULL) {
    ctx->session_cache_head = s;
    ctx->session_cache_tail = s;
    s->prev = (SSL_SESSION *)&(ctx->session_cache_head);
    s->next = (SSL_SESSION *)&(ctx->session_cache_tail);
  } else {
    s->next = ctx->session_cache_head;
    s->next->prev = s;
    s->prev = (SSL_SESSION *)&(ctx->session_cache_head);
    ctx->session_cache_head = s;
  }
}

void SSL_CTX_sess_set_new_cb(SSL_CTX *ctx,
                             int (*cb)(struct ssl_st *ssl, SSL_SESSION *sess)) {
  ctx->new_session_cb = cb;
}

int (*SSL_CTX_sess_get_new_cb(SSL_CTX *ctx))(SSL *ssl, SSL_SESSION *sess) {
  return ctx->new_session_cb;
}

void SSL_CTX_sess_set_remove_cb(SSL_CTX *ctx,
                                void (*cb)(SSL_CTX *ctx, SSL_SESSION *sess)) {
  ctx->remove_session_cb = cb;
}

void (*SSL_CTX_sess_get_remove_cb(SSL_CTX *ctx))(SSL_CTX *ctx,
                                                 SSL_SESSION *sess) {
  return ctx->remove_session_cb;
}

void SSL_CTX_sess_set_get_cb(SSL_CTX *ctx,
                             SSL_SESSION *(*cb)(struct ssl_st *ssl,
                                                uint8_t *data, int len,
                                                int *copy)) {
  ctx->get_session_cb = cb;
}

SSL_SESSION *(*SSL_CTX_sess_get_get_cb(SSL_CTX *ctx))(SSL *ssl, uint8_t *data,
                                                      int len, int *copy) {
  return ctx->get_session_cb;
}

void SSL_CTX_set_info_callback(SSL_CTX *ctx,
                               void (*cb)(const SSL *ssl, int type, int val)) {
  ctx->info_callback = cb;
}

void (*SSL_CTX_get_info_callback(SSL_CTX *ctx))(const SSL *ssl, int type,
                                                int val) {
  return ctx->info_callback;
}

void SSL_CTX_set_client_cert_cb(SSL_CTX *ctx, int (*cb)(SSL *ssl, X509 **x509,
                                                        EVP_PKEY **pkey)) {
  ctx->client_cert_cb = cb;
}

int (*SSL_CTX_get_client_cert_cb(SSL_CTX *ctx))(SSL *ssl, X509 **x509,
                                                EVP_PKEY **pkey) {
  return ctx->client_cert_cb;
}

void SSL_CTX_set_channel_id_cb(SSL_CTX *ctx,
                               void (*cb)(SSL *ssl, EVP_PKEY **pkey)) {
  ctx->channel_id_cb = cb;
}

void (*SSL_CTX_get_channel_id_cb(SSL_CTX *ctx))(SSL *ssl, EVP_PKEY **pkey) {
  return ctx->channel_id_cb;
}

IMPLEMENT_PEM_rw(SSL_SESSION, SSL_SESSION, PEM_STRING_SSL_SESSION, SSL_SESSION)
