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
 * Copyright (c) 1998-2001 The OpenSSL Project.  All rights reserved.
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

#ifndef OPENSSL_HEADER_EX_DATA_H
#define OPENSSL_HEADER_EX_DATA_H

#include <openssl/base.h>

#include <openssl/stack.h>

#if defined(__cplusplus)
extern "C" {
#endif


/* ex_data is a mechanism for associating arbitrary extra data with objects.
 * The different types of objects which can have data associated with them are
 * called "classes" and there are predefined classes for all the OpenSSL
 * objects that support ex_data.
 *
 * Within a given class, different users can be assigned indexes in which to
 * store their data. Each index has callback functions that are called when a
 * new object of that type is created, freed and duplicated. */


typedef struct crypto_ex_data_st CRYPTO_EX_DATA;

/* CRYPTO_EX_new is the type of a callback function that is called whenever a
 * new object of a given class is created. For example, if this callback has
 * been passed to |CRYPTO_get_ex_new_index| with a |class| of
 * |CRYPTO_EX_INDEX_SSL| then it'll be called each time an SSL* is created.
 *
 * The callback is passed the new object (i.e. the SSL*) in |parent|. The
 * arguments |argl| and |argp| contain opaque values that were given to
 * |CRYPTO_get_ex_new_index|. The callback should return one on success, but
 * the value is ignored.
 *
 * TODO(fork): the |ptr| argument is always NULL, no? */
typedef int CRYPTO_EX_new(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                          int index, long argl, void *argp);

/* CRYPTO_EX_free is a callback function that is called when an object of the
 * class is being destroyed. See |CRYPTO_EX_new| for a discussion of the
 * arguments.
 *
 * If |CRYPTO_get_ex_new_index| was called after the creation of objects of the
 * class that this applies to then, when those those objects are destroyed,
 * this callback will be called with a NULL value for |ptr|. */
typedef void CRYPTO_EX_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                            int index, long argl, void *argp);

/* CRYPTO_EX_dup is a callback function that is called when an object of the
 * class is being copied and thus the ex_data linked to it also needs to be
 * copied. On entry, |*from_d| points to the data for this index from the
 * original object. When the callback returns, |*from_d| will be set as the
 * data for this index in |to|.
 *
 * If |CRYPTO_get_ex_new_index| was called after the creation of objects of the
 * class that this applies to then, when those those objects are copies, this
 * callback will be called with a NULL value for |*from_d|. */
typedef int CRYPTO_EX_dup(CRYPTO_EX_DATA *to, const CRYPTO_EX_DATA *from,
                          void **from_d, int index, long argl, void *argp);

/* CRYPTO_get_ex_new_index allocates a new index for ex_data linked with
 * objects of the given |class|. This should not be called directly, rather
 * each class of object should provide a wrapper function that sets
 * |class_value| correctly.
 *
 * The |class_value| argument should be one of |CRYPTO_EX_INDEX_*| or a
 * user-defined class value returned from |CRYPTO_ex_data_new_class|.
 *
 * See the descriptions of the callback typedefs for details of when they are
 * called. Any of the callback arguments may be NULL. The |argl| and |argp|
 * arguments are opaque values that are passed to the callbacks.
 *
 * It returns the new index, or a negative number on error.
 *
 * TODO(fork): this should follow the standard calling convention.
 *
 * TODO(fork): replace the class_value with a pointer to EX_CLASS_ITEM. Saves
 * having that hash table and some of the lock-bouncing. Maybe have every
 * module have a private global EX_CLASS_ITEM somewhere and any direct callers
 * of CRYPTO_{get,set}_ex_data{,_index} would have to always call the
 * wrappers. */
OPENSSL_EXPORT int CRYPTO_get_ex_new_index(int class_value, long argl,
                                           void *argp, CRYPTO_EX_new *new_func,
                                           CRYPTO_EX_dup *dup_func,
                                           CRYPTO_EX_free *free_func);

/* CRYPTO_set_ex_data sets an extra data pointer on a given object. This should
 * not be called directly, rather each class of object should provide a wrapper
 * function.
 *
 * The |index| argument should have been returned from a previous call to
 * |CRYPTO_get_ex_new_index|. */
OPENSSL_EXPORT int CRYPTO_set_ex_data(CRYPTO_EX_DATA *ad, int index, void *val);

/* CRYPTO_set_ex_data return an extra data pointer for a given object, or NULL
 * if no such index exists. This should not be called directly, rather each
 * class of object should provide a wrapper function.
 *
 * The |index| argument should have been returned from a previous call to
 * |CRYPTO_get_ex_new_index|. */
OPENSSL_EXPORT void *CRYPTO_get_ex_data(const CRYPTO_EX_DATA *ad, int index);

/* CRYPTO_EX_INDEX_* are the built-in classes of objects.
 *
 * User defined classes start at 100.
 *
 * TODO(fork): WARNING: these are called "INDEX", but they aren't! */
#define CRYPTO_EX_INDEX_BIO 0
#define CRYPTO_EX_INDEX_SSL 1
#define CRYPTO_EX_INDEX_SSL_CTX 2
#define CRYPTO_EX_INDEX_SSL_SESSION 3
#define CRYPTO_EX_INDEX_X509_STORE 4
#define CRYPTO_EX_INDEX_X509_STORE_CTX 5
#define CRYPTO_EX_INDEX_RSA 6
#define CRYPTO_EX_INDEX_DSA 7
#define CRYPTO_EX_INDEX_DH 8
#define CRYPTO_EX_INDEX_ENGINE 9
#define CRYPTO_EX_INDEX_X509 10
#define CRYPTO_EX_INDEX_UI 11
#define CRYPTO_EX_INDEX_EC_KEY 12
#define CRYPTO_EX_INDEX_EC_GROUP 13
#define CRYPTO_EX_INDEX_COMP 14
#define CRYPTO_EX_INDEX_STORE 15


/* User-defined classes of objects.
 *
 * Core OpenSSL code has predefined class values given above (the
 * |CRYPTO_EX_INDEX_*| values). It's possible to get dynamic class values
 * assigned for user-defined objects. */

/* CRYPTO_ex_data_new_class returns a fresh class value for a user-defined type
 * that wishes to use ex_data.
 *
 * TODO(fork): hopefully remove this. */
OPENSSL_EXPORT int CRYPTO_ex_data_new_class(void);


/* Embedding, allocating and freeing |CRYPTO_EX_DATA| structures for objects
 * that embed them. */

/* CRYPTO_new_ex_data initialises a newly allocated |CRYPTO_EX_DATA| which is
 * embedded inside of |obj| which is of class |class_value|. Returns one on
 * success and zero otherwise. */
OPENSSL_EXPORT int CRYPTO_new_ex_data(int class_value, void *obj,
                                      CRYPTO_EX_DATA *ad);

/* CRYPTO_dup_ex_data duplicates |from| into a freshly allocated
 * |CRYPTO_EX_DATA|, |to|. Both of which are inside objects of the given
 * class. It returns one on success and zero otherwise. */
OPENSSL_EXPORT int CRYPTO_dup_ex_data(int class_value, CRYPTO_EX_DATA *to,
                                      const CRYPTO_EX_DATA *from);

/* CRYPTO_free_ex_data frees |ad|, which is embedded inside |obj|, which is an
 * object of the given class. */
OPENSSL_EXPORT void CRYPTO_free_ex_data(int class_value, void *obj,
                                        CRYPTO_EX_DATA *ad);


/* Handling different ex_data implementations. */

/* CRYPTO_EX_DATA_IMPL is the opaque type of an implementation of ex_data. */
typedef struct st_CRYPTO_EX_DATA_IMPL CRYPTO_EX_DATA_IMPL;

/* CRYPTO_get_ex_data_implementation returns the current implementation of
 * ex_data. */
OPENSSL_EXPORT const CRYPTO_EX_DATA_IMPL *CRYPTO_get_ex_data_implementation(
    void);

/* CRYPTO_set_ex_data_implementation sets the implementation of ex_data to use,
 * unless ex_data has already been used and the default implementation
 * installed. It returns one on success and zero otherwise. */
OPENSSL_EXPORT int CRYPTO_set_ex_data_implementation(
    const CRYPTO_EX_DATA_IMPL *impl);


/* Private functions. */

/* CRYPTO_cleanup_all_ex_data cleans up all ex_data state. It assumes that no
 * other threads are executing code that might call ex_data functions. */
OPENSSL_EXPORT void CRYPTO_cleanup_all_ex_data(void);

struct crypto_ex_data_st {
  STACK_OF(void) *sk;
};


#if defined(__cplusplus)
}  /* extern C */
#endif

#endif  /* OPENSSL_HEADER_EX_DATA_H */
