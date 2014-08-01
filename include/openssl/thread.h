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

#ifndef OPENSSL_HEADER_THREAD_H
#define OPENSSL_HEADER_THREAD_H

#include <openssl/base.h>

#if defined(__cplusplus)
extern "C" {
#endif


/* Functions to support multithreading.
 *
 * OpenSSL can safely be used in multi-threaded applications provided that at
 * least two callback functions are set with |CRYPTO_set_locking_callback| and
 * |CRYPTO_THREADID_set_callback|.
 *
 * The locking callback performs mutual exclusion. Rather than using a single
 * lock for all, shared data-structures, OpenSSL requires that the locking
 * callback support a fixed (at run-time) number of different locks, given by
 * |CRYPTO_num_locks|.
 *
 * The thread ID callback is called to record the currently executing thread's
 * identifier in a |CRYPTO_THREADID| structure. If this callback is not
 * provided then the address of |errno| is used as the thread identifier. This
 * is sufficient only if the system has a thread-local |errno| value. */


/* CRYPTO_num_locks returns the number of static locks that the callback
 * function passed to |CRYPTO_set_locking_callback| must be able to handle. */
OPENSSL_EXPORT int CRYPTO_num_locks(void);

/* CRYPTO_set_locking_callback sets a callback function that implements locking
 * on behalf of OpenSSL. The callback is called whenever OpenSSL needs to lock
 * or unlock a lock, and locks are specified as a number between zero and
 * |CRYPTO_num_locks()-1|.
 *
 * The mode argument to the callback is a bitwise-OR of either CRYPTO_LOCK or
 * CRYPTO_UNLOCK, to denote the action, and CRYPTO_READ or CRYPTO_WRITE, to
 * indicate the type of lock. The |file| and |line| arguments give the location
 * in the OpenSSL source where the locking action originated. */
OPENSSL_EXPORT void CRYPTO_set_locking_callback(
    void (*func)(int mode, int lock_num, const char *file, int line));

/* CRYPTO_set_add_lock_callback sets an optional callback which is used when
 * OpenSSL needs to add a fixed amount to an integer. For example, this is used
 * when maintaining reference counts. Normally the reference counts are
 * maintained by performing the addition under a lock but, if this callback
 * has been set, the application is free to implement the operation using
 * faster methods (i.e. atomic operations).
 *
 * The callback is given a pointer to the integer to be altered (|num|), the
 * amount to add to the integer (|amount|, which may be negative), the number
 * of the lock which would have been taken to protect the operation and the
 * position in the OpenSSL code where the operation originated. */
OPENSSL_EXPORT void CRYPTO_set_add_lock_callback(int (*func)(
    int *num, int amount, int lock_num, const char *file, int line));

/* CRYPTO_get_lock_name returns the name of the lock given by |lock_num|. This
 * can be used in a locking callback for debugging purposes. */
OPENSSL_EXPORT const char *CRYPTO_get_lock_name(int lock_num);


/* CRYPTO_THREADID identifies a thread in a multithreaded program. This
 * structure should not be used directly. Rather applications should use
 * |CRYPTO_THREADID_set_numeric| and |CRYPTO_THREADID_set_pointer|. */
typedef struct crypto_threadid_st {
  void *ptr;
  unsigned long val;
} CRYPTO_THREADID;

/* CRYPTO_THREADID_set_callback sets a callback function that stores an
 * identifier of the currently executing thread into |threadid|. The
 * CRYPTO_THREADID structure should not be accessed directly. Rather one of
 * |CRYPTO_THREADID_set_numeric| or |CRYPTO_THREADID_set_pointer| should be
 * used depending on whether thread IDs are numbers or pointers on the host
 * system. */
OPENSSL_EXPORT int CRYPTO_THREADID_set_callback(
    void (*threadid_func)(CRYPTO_THREADID *threadid));

OPENSSL_EXPORT void CRYPTO_THREADID_set_numeric(CRYPTO_THREADID *id,
                                                unsigned long val);
OPENSSL_EXPORT void CRYPTO_THREADID_set_pointer(CRYPTO_THREADID *id, void *ptr);


/* Private functions: */

/* CRYPTO_get_locking_callback returns the callback, if any, that was most
 * recently set using |CRYPTO_set_locking_callback|. */
void (*CRYPTO_get_locking_callback(void))(int mode, int lock_num,
                                          const char *file, int line);

/* CRYPTO_get_add_lock_callback returns the callback, if any, that was most
 * recently set using |CRYPTO_set_add_lock_callback|. */
int (*CRYPTO_get_add_lock_callback(void))(int *num, int amount, int lock_num,
                                          const char *file, int line);

/* CRYPTO_lock locks or unlocks the lock specified by |lock_num| (one of
 * |CRYPTO_LOCK_*|). Don't call this directly, rather use one of the
 * CRYPTO_[rw]_(un)lock macros. */
OPENSSL_EXPORT void CRYPTO_lock(int mode, int lock_num, const char *file,
                                int line);

/* CRYPTO_add_lock adds |amount| to |*pointer|, protected by the lock specified
 * by |lock_num|. It returns the new value of |*pointer|. Don't call this
 * function directly, rather use the |CRYPTO_add_lock| macro.
 *
 * TODO(fork): rename to CRYPTO_add_locked. */
OPENSSL_EXPORT int CRYPTO_add_lock(int *pointer, int amount, int lock_num,
                                   const char *file, int line);


/* CRYPTO_THREADID_current stores the current thread identifier in |id|. */
OPENSSL_EXPORT void CRYPTO_THREADID_current(CRYPTO_THREADID *id);

/* CRYPTO_THREADID_cmp returns < 0, 0 or > 0 if |a| is less than, equal to or
 * greater than |b|, respectively. */
int CRYPTO_THREADID_cmp(const CRYPTO_THREADID *a, const CRYPTO_THREADID *b);

/* CRYPTO_THREADID_cpy sets |*dest| equal to |*src|. */
void CRYPTO_THREADID_cpy(CRYPTO_THREADID *dest, const CRYPTO_THREADID *src);

/* CRYPTO_THREADID_hash returns a hash of the numeric value of |id|. */
uint32_t CRYPTO_THREADID_hash(const CRYPTO_THREADID *id);

/* These are the locks used by OpenSSL. These values should match up with the
 * table in thread.c. */
#define CRYPTO_LOCK_ERR 1
#define CRYPTO_LOCK_EX_DATA 2
#define CRYPTO_LOCK_X509 3
#define CRYPTO_LOCK_X509_INFO 4
#define CRYPTO_LOCK_X509_PKEY 5
#define CRYPTO_LOCK_X509_CRL 6
#define CRYPTO_LOCK_X509_REQ 7
#define CRYPTO_LOCK_DSA 8
#define CRYPTO_LOCK_RSA 9
#define CRYPTO_LOCK_EVP_PKEY 10
#define CRYPTO_LOCK_X509_STORE 11
#define CRYPTO_LOCK_SSL_CTX 12
#define CRYPTO_LOCK_SSL_CERT 13
#define CRYPTO_LOCK_SSL_SESSION 14
#define CRYPTO_LOCK_SSL_SESS_CERT 15
#define CRYPTO_LOCK_SSL 16
#define CRYPTO_LOCK_SSL_METHOD 17
#define CRYPTO_LOCK_RAND 18
#define CRYPTO_LOCK_RAND2 19
#define CRYPTO_LOCK_MALLOC 20
#define CRYPTO_LOCK_BIO 21
#define CRYPTO_LOCK_GETHOSTBYNAME 22
#define CRYPTO_LOCK_GETSERVBYNAME 23
#define CRYPTO_LOCK_READDIR 24
#define CRYPTO_LOCK_RSA_BLINDING 25
#define CRYPTO_LOCK_DH 26
#define CRYPTO_LOCK_MALLOC2 27
#define CRYPTO_LOCK_DSO 28
#define CRYPTO_LOCK_DYNLOCK 29
#define CRYPTO_LOCK_ENGINE 30
#define CRYPTO_LOCK_UI 31
#define CRYPTO_LOCK_ECDSA 32
#define CRYPTO_LOCK_EC 33
#define CRYPTO_LOCK_ECDH 34
#define CRYPTO_LOCK_BN 35
#define CRYPTO_LOCK_EC_PRE_COMP 36
#define CRYPTO_LOCK_STORE 37
#define CRYPTO_LOCK_COMP 38
#define CRYPTO_LOCK_FIPS 39
#define CRYPTO_LOCK_FIPS2 40
#define CRYPTO_LOCK_OBJ 40
#define CRYPTO_NUM_LOCKS 42

#define CRYPTO_LOCK 1
#define CRYPTO_UNLOCK 2
#define CRYPTO_READ 4
#define CRYPTO_WRITE 8

#define CRYPTO_w_lock(lock_num) \
  CRYPTO_lock(CRYPTO_LOCK | CRYPTO_WRITE, lock_num, __FILE__, __LINE__)
#define CRYPTO_w_unlock(lock_num) \
  CRYPTO_lock(CRYPTO_UNLOCK | CRYPTO_WRITE, lock_num, __FILE__, __LINE__)
#define CRYPTO_r_lock(lock_num) \
  CRYPTO_lock(CRYPTO_LOCK | CRYPTO_READ, lock_num, __FILE__, __LINE__)
#define CRYPTO_r_unlock(lock_num) \
  CRYPTO_lock(CRYPTO_UNLOCK | CRYPTO_READ, lock_num, __FILE__, __LINE__)
#define CRYPTO_add(addr, amount, lock_num) \
  CRYPTO_add_lock(addr, amount, lock_num, __FILE__, __LINE__)


/* Private functions.
 *
 * Some old code calls these functions and so no-op implementations are
 * provided.
 *
 * TODO(fork): cleanup callers and remove. */

OPENSSL_EXPORT void CRYPTO_set_id_callback(unsigned long (*func)(void));

typedef struct {
  int references;
  struct CRYPTO_dynlock_value *data;
} CRYPTO_dynlock;

OPENSSL_EXPORT void CRYPTO_set_dynlock_create_callback(
    struct CRYPTO_dynlock_value *(*dyn_create_function)(const char *file,
                                                        int line));

OPENSSL_EXPORT void CRYPTO_set_dynlock_lock_callback(void (*dyn_lock_function)(
    int mode, struct CRYPTO_dynlock_value *l, const char *file, int line));

OPENSSL_EXPORT void CRYPTO_set_dynlock_destroy_callback(
    void (*dyn_destroy_function)(struct CRYPTO_dynlock_value *l,
                                 const char *file, int line));


#if defined(__cplusplus)
}  /* extern C */
#endif

#endif  /* OPENSSL_HEADER_THREAD_H */
