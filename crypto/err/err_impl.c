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
 * Hudson (tjh@cryptsoft.com). */

#include <openssl/err.h>

#include <assert.h>
#include <string.h>

#include <openssl/lhash.h>
#include <openssl/mem.h>


DEFINE_LHASH_OF(ERR_STATE);

/* state_hash is a map from thread ID to ERR_STATE. It works like thread-local
 * storage. */
static LHASH_OF(ERR_STATE) *state_hash = NULL;

/* global_next_library contains the next custom library value to return. */
static int global_next_library = ERR_NUM_LIBS;

/* err_state_hash is an lhash hash function for ERR_STATE. */
static uint32_t err_state_hash(const ERR_STATE *a) {
  return CRYPTO_THREADID_hash(&a->tid);
}

/* err_state_cmp is an lhash compare function for ERR_STATE. */
static int err_state_cmp(const ERR_STATE *a, const ERR_STATE *b) {
  return CRYPTO_THREADID_cmp(&a->tid, &b->tid);
}

static ERR_STATE *err_get_state(void) {
  CRYPTO_THREADID tid;
  ERR_STATE pattern, *state, *race_state;
  int insert_result;
  static ERR_STATE fallback;

  CRYPTO_THREADID_current(&tid);
  memset(&pattern, 0, sizeof(pattern));
  CRYPTO_THREADID_cpy(&pattern.tid, &tid);

  CRYPTO_r_lock(CRYPTO_LOCK_ERR);
  if (state_hash == NULL) {
    CRYPTO_r_unlock(CRYPTO_LOCK_ERR);
    CRYPTO_w_lock(CRYPTO_LOCK_ERR);
    if (state_hash == NULL) {
      state_hash = lh_ERR_STATE_new(err_state_hash, err_state_cmp);
    }
    CRYPTO_w_unlock(CRYPTO_LOCK_ERR);
    CRYPTO_r_lock(CRYPTO_LOCK_ERR);
  }

  if (state_hash == NULL) {
    CRYPTO_r_unlock(CRYPTO_LOCK_ERR);
    return NULL;
  }

  state = lh_ERR_STATE_retrieve(state_hash, &pattern);
  CRYPTO_r_unlock(CRYPTO_LOCK_ERR);
  if (state != NULL) {
    return state;
  }

  state = OPENSSL_malloc(sizeof(ERR_STATE));
  if (state == NULL) {
    CRYPTO_r_unlock(CRYPTO_LOCK_ERR);
    /* The other error functions don't cope with a failure to get the error
     * state, so we return a dummy value. */
    return &fallback;
  }

  memset(state, 0, sizeof(ERR_STATE));
  CRYPTO_THREADID_cpy(&state->tid, &tid);

  CRYPTO_w_lock(CRYPTO_LOCK_ERR);
  insert_result = lh_ERR_STATE_insert(state_hash, &race_state, state);
  CRYPTO_w_unlock(CRYPTO_LOCK_ERR);

  if (!insert_result) {
    /* Insertion failed because of malloc failure. */
    OPENSSL_free(state);
    return &fallback;
  }

  /* We cannot have raced with another thread to insert an ERR_STATE because no
   * other thread should be inserting values for this thread. */
  assert(race_state == NULL);

  return state;
}

static ERR_STATE *err_release_state(const CRYPTO_THREADID *tid) {
  ERR_STATE pattern, *state;

  CRYPTO_THREADID_cpy(&pattern.tid, tid);

  CRYPTO_r_lock(CRYPTO_LOCK_ERR);
  if (state_hash == NULL) {
    CRYPTO_r_unlock(CRYPTO_LOCK_ERR);
    return NULL;
  }

  state = lh_ERR_STATE_delete(state_hash, &pattern);
  CRYPTO_r_unlock(CRYPTO_LOCK_ERR);

  return state;
}

static void err_shutdown(void (*err_state_free_cb)(ERR_STATE*)) {
  CRYPTO_w_lock(CRYPTO_LOCK_ERR);
  if (state_hash) {
    lh_ERR_STATE_doall(state_hash, err_state_free_cb);
    lh_ERR_STATE_free(state_hash);
    state_hash = NULL;
  }
  CRYPTO_w_unlock(CRYPTO_LOCK_ERR);
}

static int err_get_next_library(void) {
  int ret;

  CRYPTO_w_lock(CRYPTO_LOCK_ERR);
  ret = global_next_library++;
  CRYPTO_w_unlock(CRYPTO_LOCK_ERR);

  return ret;
}

const struct ERR_FNS_st openssl_err_default_impl = {
  err_shutdown,
  err_get_state,
  err_release_state,
  err_get_next_library,
};
