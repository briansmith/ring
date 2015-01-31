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

#include <openssl/thread.h>

#include <errno.h>
#include <string.h>

#if defined(OPENSSL_WINDOWS)
#pragma warning(push, 3)
#include <Windows.h>
#pragma warning(pop)
#endif

#include <openssl/mem.h>
#include <openssl/type_check.h>


/* lock_names contains the names of all the locks defined in thread.h. */
static const char *const lock_names[] = {
    "<<ERROR>>",    "err",          "ex_data",       "x509",
    "x509_info",    "x509_pkey",    "x509_crl",      "x509_req",
    "dsa",          "rsa",          "evp_pkey",      "x509_store",
    "ssl_ctx",      "ssl_cert",     "ssl_session",   "ssl_sess_cert",
    "ssl",          "ssl_method",   "rand",          "rand2",
    "debug_malloc", "BIO",          "gethostbyname", "getservbyname",
    "readdir",      "RSA_blinding", "dh",            "debug_malloc2",
    "dso",          "dynlock",      "engine",        "ui",
    "ecdsa",        "ec",           "ecdh",          "bn",
    "ec_pre_comp",  "store",        "comp",          "fips",
    "fips2",        "obj",
};

OPENSSL_COMPILE_ASSERT(CRYPTO_NUM_LOCKS ==
                           sizeof(lock_names) / sizeof(lock_names[0]),
                       CRYPTO_NUM_LOCKS_inconsistent);

static void (*locking_callback)(int mode, int lock_num, const char *file,
                                int line) = 0;
static int (*add_lock_callback)(int *pointer, int amount, int lock_num,
                                const char *file, int line) = 0;
static void (*threadid_callback)(CRYPTO_THREADID *) = 0;


int CRYPTO_num_locks(void) { return CRYPTO_NUM_LOCKS; }

void CRYPTO_set_locking_callback(void (*func)(int mode, int lock_num,
                                              const char *file, int line)) {
  locking_callback = func;
}

void CRYPTO_set_add_lock_callback(int (*func)(int *num, int mount, int lock_num,
                                              const char *file, int line)) {
  add_lock_callback = func;
}

const char *CRYPTO_get_lock_name(int lock_num) {
  if (lock_num >= 0 && lock_num < CRYPTO_NUM_LOCKS) {
    return lock_names[lock_num];
  } else {
    return "ERROR";
  }
}

int CRYPTO_THREADID_set_callback(void (*func)(CRYPTO_THREADID *)) {
  if (threadid_callback) {
    return 0;
  }
  threadid_callback = func;
  return 1;
}

void CRYPTO_THREADID_set_numeric(CRYPTO_THREADID *id, unsigned long val) {
  memset(id, 0, sizeof(*id));
  id->val = val;
}

void CRYPTO_THREADID_set_pointer(CRYPTO_THREADID *id, void *ptr) {
  memset(id, 0, sizeof(*id));
  id->ptr = ptr;
}

void (*CRYPTO_get_locking_callback(void))(int mode, int lock_num,
                                          const char *file, int line) {
  return locking_callback;
}

int (*CRYPTO_get_add_lock_callback(void))(int *num, int mount, int lock_num,
                                          const char *file, int line) {
  return add_lock_callback;
}

void CRYPTO_lock(int mode, int lock_num, const char *file, int line) {
  if (locking_callback != NULL) {
    locking_callback(mode, lock_num, file, line);
  }
}

int CRYPTO_add_lock(int *pointer, int amount, int lock_num, const char *file,
                    int line) {
  int ret = 0;

  if (add_lock_callback != NULL) {
    ret = add_lock_callback(pointer, amount, lock_num, file, line);
  } else {
    CRYPTO_lock(CRYPTO_LOCK | CRYPTO_WRITE, lock_num, file, line);
    ret = *pointer + amount;
    *pointer = ret;
    CRYPTO_lock(CRYPTO_UNLOCK | CRYPTO_WRITE, lock_num, file, line);
  }

  return ret;
}

void CRYPTO_THREADID_current(CRYPTO_THREADID *id) {
  if (threadid_callback) {
    threadid_callback(id);
    return;
  }

#if defined(OPENSSL_WINDOWS)
  CRYPTO_THREADID_set_numeric(id, (unsigned long)GetCurrentThreadId());
#else
  /* For everything else, default to using the address of 'errno' */
  CRYPTO_THREADID_set_pointer(id, (void *)&errno);
#endif
}

int CRYPTO_THREADID_cmp(const CRYPTO_THREADID *a, const CRYPTO_THREADID *b) {
  return memcmp(a, b, sizeof(*a));
}

void CRYPTO_THREADID_cpy(CRYPTO_THREADID *dest, const CRYPTO_THREADID *src) {
  memcpy(dest, src, sizeof(*src));
}

uint32_t CRYPTO_THREADID_hash(const CRYPTO_THREADID *id) {
  return OPENSSL_hash32(id, sizeof(CRYPTO_THREADID));
}

void CRYPTO_set_id_callback(unsigned long (*func)(void)) {}

void CRYPTO_set_dynlock_create_callback(struct CRYPTO_dynlock_value *(
    *dyn_create_function)(const char *file, int line)) {}

void CRYPTO_set_dynlock_lock_callback(void (*dyn_lock_function)(
    int mode, struct CRYPTO_dynlock_value *l, const char *file, int line)) {}

void CRYPTO_set_dynlock_destroy_callback(void (*dyn_destroy_function)(
    struct CRYPTO_dynlock_value *l, const char *file, int line)) {}
