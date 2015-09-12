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
#include <errno.h>
#include <inttypes.h>
#include <string.h>

#if defined(OPENSSL_WINDOWS)
#pragma warning(push, 3)
#include <windows.h>
#pragma warning(pop)
#endif

#include <openssl/mem.h>
#include <openssl/thread.h>

#include "../internal.h"


/* err_clear clears the given queued error. */
static void err_clear(struct err_error_st *error) {
  memset(error, 0, sizeof(struct err_error_st));
}

/* global_next_library contains the next custom library value to return. */
static int global_next_library = ERR_NUM_LIBS;

/* global_next_library_mutex protects |global_next_library| from concurrent
 * updates. */
static struct CRYPTO_STATIC_MUTEX global_next_library_mutex =
    CRYPTO_STATIC_MUTEX_INIT;

static void err_state_free(void *statep) {
  ERR_STATE *state = statep;

  if (state == NULL) {
    return;
  }

  unsigned i;
  for (i = 0; i < ERR_NUM_ERRORS; i++) {
    err_clear(&state->errors[i]);
  }
  OPENSSL_free(state->to_free);
  OPENSSL_free(state);
}

/* err_get_state gets the ERR_STATE object for the current thread. */
static ERR_STATE *err_get_state(void) {
  ERR_STATE *state = CRYPTO_get_thread_local(OPENSSL_THREAD_LOCAL_ERR);
  if (state == NULL) {
    state = OPENSSL_malloc(sizeof(ERR_STATE));
    if (state == NULL) {
      return NULL;
    }
    memset(state, 0, sizeof(ERR_STATE));
    if (!CRYPTO_set_thread_local(OPENSSL_THREAD_LOCAL_ERR, state,
                                 err_state_free)) {
      return NULL;
    }
  }

  return state;
}

static uint32_t get_error_values(int inc, int top, const char **file, int *line,
                                 const char **data, int *flags) {
  unsigned i = 0;
  ERR_STATE *state;
  struct err_error_st *error;
  uint32_t ret;

  state = err_get_state();
  if (state == NULL || state->bottom == state->top) {
    return 0;
  }

  if (top) {
    assert(!inc);
    /* last error */
    i = state->top;
  } else {
    i = (state->bottom + 1) % ERR_NUM_ERRORS;
  }

  error = &state->errors[i];
  ret = error->packed;

  if (file != NULL && line != NULL) {
    if (error->file == NULL) {
      *file = "NA";
      *line = 0;
    } else {
      *file = error->file;
      *line = error->line;
    }
  }

  if (data != NULL) {
    *data = "";
  }

  if (flags != NULL) {
    *flags = 0;
  }

  if (inc) {
    assert(!top);
    err_clear(error);
    state->bottom = i;
  }

  return ret;
}

uint32_t ERR_get_error(void) {
  return get_error_values(1 /* inc */, 0 /* bottom */, NULL, NULL, NULL, NULL);
}

uint32_t ERR_get_error_line(const char **file, int *line) {
  return get_error_values(1 /* inc */, 0 /* bottom */, file, line, NULL, NULL);
}

uint32_t ERR_get_error_line_data(const char **file, int *line,
                                 const char **data, int *flags) {
  return get_error_values(1 /* inc */, 0 /* bottom */, file, line, data, flags);
}

uint32_t ERR_peek_error(void) {
  return get_error_values(0 /* peek */, 0 /* bottom */, NULL, NULL, NULL, NULL);
}

uint32_t ERR_peek_error_line(const char **file, int *line) {
  return get_error_values(0 /* peek */, 0 /* bottom */, file, line, NULL, NULL);
}

uint32_t ERR_peek_error_line_data(const char **file, int *line,
                                  const char **data, int *flags) {
  return get_error_values(0 /* peek */, 0 /* bottom */, file, line, data,
                          flags);
}

const char *ERR_peek_function(void) {
  ERR_STATE *state = err_get_state();
  if (state == NULL || state->bottom == state->top) {
    return NULL;
  }
  return state->errors[(state->bottom + 1) % ERR_NUM_ERRORS].function;
}

uint32_t ERR_peek_last_error(void) {
  return get_error_values(0 /* peek */, 1 /* top */, NULL, NULL, NULL, NULL);
}

uint32_t ERR_peek_last_error_line(const char **file, int *line) {
  return get_error_values(0 /* peek */, 1 /* top */, file, line, NULL, NULL);
}

uint32_t ERR_peek_last_error_line_data(const char **file, int *line,
                                       const char **data, int *flags) {
  return get_error_values(0 /* peek */, 1 /* top */, file, line, data, flags);
}

void ERR_clear_error(void) {
  ERR_STATE *const state = err_get_state();
  unsigned i;

  if (state == NULL) {
    return;
  }

  for (i = 0; i < ERR_NUM_ERRORS; i++) {
    err_clear(&state->errors[i]);
  }
  OPENSSL_free(state->to_free);
  state->to_free = NULL;

  state->top = state->bottom = 0;
}

void ERR_remove_thread_state(const CRYPTO_THREADID *tid) {
  if (tid != NULL) {
    assert(0);
    return;
  }

  ERR_clear_error();
}

int ERR_get_next_error_library(void) {
  int ret;

  CRYPTO_STATIC_MUTEX_lock_write(&global_next_library_mutex);
  ret = global_next_library++;
  CRYPTO_STATIC_MUTEX_unlock(&global_next_library_mutex);

  return ret;
}

void ERR_remove_state(unsigned long pid) {
  ERR_clear_error();
}

static const char *const kLibraryNames[ERR_NUM_LIBS] = {
    "invalid library (0)",
    "unknown library",                            /* ERR_LIB_NONE */
    "system library",                             /* ERR_LIB_SYS */
    "bignum routines",                            /* ERR_LIB_BN */
    "RSA routines",                               /* ERR_LIB_RSA */
    "Diffie-Hellman routines",                    /* ERR_LIB_DH */
    "memory buffer routines",                     /* ERR_LIB_BUF */
    "common libcrypto routines",                  /* ERR_LIB_CRYPTO */
    "elliptic curve routines",                    /* ERR_LIB_EC */
    "random number generator",                    /* ERR_LIB_RAND */
    "UI routines",                                /* ERR_LIB_UI */
    "COMP routines",                              /* ERR_LIB_COMP */
    "ECDSA routines",                             /* ERR_LIB_ECDSA */
    "ECDH routines",                              /* ERR_LIB_ECDH */
    "HMAC routines",                              /* ERR_LIB_HMAC */
    "Digest functions",                           /* ERR_LIB_DIGEST */
    "Cipher functions",                           /* ERR_LIB_CIPHER */
    "HKDF functions",                             /* ERR_LIB_HKDF */
    "User defined functions",                     /* ERR_LIB_USER */
};

const char *ERR_lib_error_string(uint32_t packed_error) {
  const uint32_t lib = ERR_GET_LIB(packed_error);

  if (lib >= ERR_NUM_LIBS) {
    return NULL;
  }
  return kLibraryNames[lib];
}

const char *ERR_func_error_string(uint32_t packed_error) {
  return "OPENSSL_internal";
}

const char *ERR_reason_error_string(uint32_t packed_error) {
  const uint32_t lib = ERR_GET_LIB(packed_error);
  const uint32_t reason = ERR_GET_REASON(packed_error);

  if (lib == ERR_LIB_SYS) {
    if (reason < 127) {
      return strerror(reason);
    }
    return NULL;
  }

  if (reason < ERR_NUM_LIBS) {
    return kLibraryNames[reason];
  }

  if (reason < 100) {
    switch (reason) {
      case ERR_R_MALLOC_FAILURE:
        return "malloc failure";
      case ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED:
        return "function should not have been called";
      case ERR_R_PASSED_NULL_PARAMETER:
        return "passed a null parameter";
      case ERR_R_INTERNAL_ERROR:
        return "internal error";
      case ERR_R_OVERFLOW:
        return "overflow";
      default:
        return NULL;
    }
  }

  /* TODO(ring): Maybe re-enable this in a way that doesn't depend on a
   * Go-based code generator. */
  return "ERR_reason_error_string not fully implemented.";
}

static int print_errors_to_file(const char* msg, size_t msg_len, void* ctx) {
  assert(msg[msg_len] == '\0');
  FILE* fp = ctx;
  int res = fputs(msg, fp);
  return res < 0 ? 0 : 1;
}

void ERR_put_error(int library, int reason, const char *function,
                   const char *file, unsigned line) {
  ERR_STATE *const state = err_get_state();
  struct err_error_st *error;

  if (state == NULL) {
    return;
  }

  if (library == ERR_LIB_SYS && reason == 0) {
#if defined(OPENSSL_WINDOWS)
    reason = GetLastError();
#else
    reason = errno;
#endif
  }

  state->top = (state->top + 1) % ERR_NUM_ERRORS;
  if (state->top == state->bottom) {
    state->bottom = (state->bottom + 1) % ERR_NUM_ERRORS;
  }

  error = &state->errors[state->top];
  err_clear(error);
  error->function = function;
  error->file = file;
  error->line = line;
  error->packed = ERR_PACK(library, reason);
}

void ERR_load_crypto_strings(void) {}

void ERR_free_strings(void) {}

void ERR_load_BIO_strings(void) {}

void ERR_load_ERR_strings(void) {}
