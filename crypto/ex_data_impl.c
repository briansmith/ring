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

#include <openssl/ex_data.h>

#include <assert.h>

#include <openssl/err.h>
#include <openssl/lhash.h>
#include <openssl/mem.h>
#include <openssl/stack.h>
#include <openssl/thread.h>

#include "crypto_error.h"
#include "internal.h"

typedef struct crypto_ex_data_func_st {
  long argl;  /* Arbitary long */
  void *argp; /* Arbitary void pointer */
  CRYPTO_EX_new *new_func;
  CRYPTO_EX_free *free_func;
  CRYPTO_EX_dup *dup_func;
} CRYPTO_EX_DATA_FUNCS;

typedef struct st_ex_class_item {
  STACK_OF(CRYPTO_EX_DATA_FUNCS) *meth;
  int class_value;
} EX_CLASS_ITEM;

static LHASH_OF(EX_CLASS_ITEM) *global_classes = NULL;

static int global_next_class = 100;

static int new_class(void) {
  int ret;
  CRYPTO_w_lock(CRYPTO_LOCK_EX_DATA);
  ret = global_next_class++;
  CRYPTO_w_unlock(CRYPTO_LOCK_EX_DATA);

  return ret;
}

/* class_hash is a hash function used by an LHASH of |EX_CLASS_ITEM|
 * structures. */
static uint32_t class_hash(const EX_CLASS_ITEM *a) {
  return a->class_value;
}

/* class_cmp is a comparison function for an LHASH of |EX_CLASS_ITEM|
 * structures. */
static int class_cmp(const EX_CLASS_ITEM *a, const EX_CLASS_ITEM *b) {
  return a->class_value - b->class_value;
}

/* data_funcs_free is a callback function from |sk_pop_free| that frees a
 * |CRYPTO_EX_DATA_FUNCS|. */
static void data_funcs_free(CRYPTO_EX_DATA_FUNCS *funcs) {
  OPENSSL_free(funcs);
}

/* class_free is a callback function from lh_doall to free the EX_CLASS_ITEM
 * structures. */
static void class_free(EX_CLASS_ITEM *item) {
  sk_CRYPTO_EX_DATA_FUNCS_pop_free(item->meth, data_funcs_free);
  OPENSSL_free(item);
}

static LHASH_OF(EX_CLASS_ITEM) *get_classes(void) {
  LHASH_OF(EX_CLASS_ITEM) *ret;

  CRYPTO_r_lock(CRYPTO_LOCK_EX_DATA);
  ret = global_classes;
  CRYPTO_r_unlock(CRYPTO_LOCK_EX_DATA);

  if (ret != NULL) {
    return ret;
  }

  CRYPTO_w_lock(CRYPTO_LOCK_EX_DATA);
  if (global_classes == NULL) {
    global_classes = lh_EX_CLASS_ITEM_new(class_hash, class_cmp);
  }
  ret = global_classes;
  CRYPTO_w_unlock(CRYPTO_LOCK_EX_DATA);

  return ret;
}

static void cleanup(void) {
  LHASH_OF(EX_CLASS_ITEM) *classes = get_classes();

  if (classes != NULL) {
    lh_EX_CLASS_ITEM_doall(classes, class_free);
    lh_EX_CLASS_ITEM_free(classes);
  }

  global_classes = NULL;
}

static EX_CLASS_ITEM *get_class(int class_value) {
  LHASH_OF(EX_CLASS_ITEM) *const classes = get_classes();
  EX_CLASS_ITEM template, *class_item;
  int ok = 0;

  if (classes == NULL) {
    return NULL;
  }

  CRYPTO_w_lock(CRYPTO_LOCK_EX_DATA);
  template.class_value = class_value;
  class_item = lh_EX_CLASS_ITEM_retrieve(classes, &template);
  if (class_item != NULL) {
    ok = 1;
  } else {
    class_item = OPENSSL_malloc(sizeof(EX_CLASS_ITEM));
    if (class_item) {
      class_item->class_value = class_value;
      class_item->meth = sk_CRYPTO_EX_DATA_FUNCS_new_null();
      if (class_item->meth != NULL) {
        EX_CLASS_ITEM *old_data;
        ok = lh_EX_CLASS_ITEM_insert(classes, &old_data, class_item);
        assert(old_data == NULL);
      }
    }
  }
  CRYPTO_w_unlock(CRYPTO_LOCK_EX_DATA);

  if (!ok) {
    if (class_item) {
      if (class_item->meth) {
        sk_CRYPTO_EX_DATA_FUNCS_free(class_item->meth);
      }
      OPENSSL_free(class_item);
      class_item = NULL;
    }

    OPENSSL_PUT_ERROR(CRYPTO, get_class, ERR_R_MALLOC_FAILURE);
  }

  return class_item;
}

static int get_new_index(int class_value, long argl, void *argp,
                         CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func,
                         CRYPTO_EX_free *free_func) {
  EX_CLASS_ITEM *const item = get_class(class_value);
  CRYPTO_EX_DATA_FUNCS *funcs;
  int ret = -1;

  if (!item) {
    return -1;
  }

  funcs = OPENSSL_malloc(sizeof(CRYPTO_EX_DATA_FUNCS));
  if (funcs == NULL) {
    OPENSSL_PUT_ERROR(CRYPTO, get_new_index, ERR_R_MALLOC_FAILURE);
    return -1;
  }

  funcs->argl = argl;
  funcs->argp = argp;
  funcs->new_func = new_func;
  funcs->dup_func = dup_func;
  funcs->free_func = free_func;

  CRYPTO_w_lock(CRYPTO_LOCK_EX_DATA);

  if (!sk_CRYPTO_EX_DATA_FUNCS_push(item->meth, funcs)) {
    OPENSSL_PUT_ERROR(CRYPTO, get_new_index, ERR_R_MALLOC_FAILURE);
    OPENSSL_free(funcs);
    goto err;
  }

  ret = sk_CRYPTO_EX_DATA_FUNCS_num(item->meth) - 1;

err:
  CRYPTO_w_unlock(CRYPTO_LOCK_EX_DATA);
  return ret;
}

/* get_func_pointers takes a copy of the CRYPTO_EX_DATA_FUNCS pointers, if any,
 * for the given class. If there are some pointers, it sets |*out| to point to
 * a fresh stack of them. Otherwise it sets |*out| to NULL. It returns one on
 * success or zero on error. */
static int get_func_pointers(STACK_OF(CRYPTO_EX_DATA_FUNCS) **out,
                             int class_value) {
  EX_CLASS_ITEM *const item = get_class(class_value);
  size_t n;

  if (!item) {
    return 0;
  }

  *out = NULL;

  /* CRYPTO_EX_DATA_FUNCS structures are static once set, so we can take a
   * shallow copy of the list under lock and then use the structures without
   * the lock held. */
  CRYPTO_r_lock(CRYPTO_LOCK_EX_DATA);
  n = sk_CRYPTO_EX_DATA_FUNCS_num(item->meth);
  if (n > 0) {
    *out = sk_CRYPTO_EX_DATA_FUNCS_dup(item->meth);
  }
  CRYPTO_r_unlock(CRYPTO_LOCK_EX_DATA);

  if (n > 0 && *out == NULL) {
    OPENSSL_PUT_ERROR(CRYPTO, get_func_pointers, ERR_R_MALLOC_FAILURE);
    return 0;
  }

  return 1;
}

static int new_ex_data(int class_value, void *obj, CRYPTO_EX_DATA *ad) {
  STACK_OF(CRYPTO_EX_DATA_FUNCS) *func_pointers;
  size_t i;

  ad->sk = NULL;

  if (!get_func_pointers(&func_pointers, class_value)) {
    return 0;
  }

  for (i = 0; i < sk_CRYPTO_EX_DATA_FUNCS_num(func_pointers); i++) {
    CRYPTO_EX_DATA_FUNCS *func_pointer =
        sk_CRYPTO_EX_DATA_FUNCS_value(func_pointers, i);
    if (func_pointer->new_func) {
      func_pointer->new_func(obj, NULL, ad, i, func_pointer->argl,
                             func_pointer->argp);
    }
  }

  sk_CRYPTO_EX_DATA_FUNCS_free(func_pointers);

  return 1;
}

static int dup_ex_data(int class_value, CRYPTO_EX_DATA *to,
                       const CRYPTO_EX_DATA *from) {
  STACK_OF(CRYPTO_EX_DATA_FUNCS) *func_pointers;
  size_t i;

  if (!from->sk) {
    /* In this case, |from| is blank, which is also the initial state of |to|,
     * so there's nothing to do. */
    return 1;
  }

  if (!get_func_pointers(&func_pointers, class_value)) {
    return 0;
  }

  for (i = 0; i < sk_CRYPTO_EX_DATA_FUNCS_num(func_pointers); i++) {
    CRYPTO_EX_DATA_FUNCS *func_pointer =
        sk_CRYPTO_EX_DATA_FUNCS_value(func_pointers, i);
    void *ptr = CRYPTO_get_ex_data(from, i);
    if (func_pointer->dup_func) {
      func_pointer->dup_func(to, from, &ptr, i, func_pointer->argl,
                             func_pointer->argp);
    }
    CRYPTO_set_ex_data(to, i, ptr);
  }

  sk_CRYPTO_EX_DATA_FUNCS_free(func_pointers);

  return 1;
}

static void free_ex_data(int class_value, void *obj, CRYPTO_EX_DATA *ad) {
  STACK_OF(CRYPTO_EX_DATA_FUNCS) *func_pointers;
  size_t i;

  if (!get_func_pointers(&func_pointers, class_value)) {
    return;
  }

  for (i = 0; i < sk_CRYPTO_EX_DATA_FUNCS_num(func_pointers); i++) {
    CRYPTO_EX_DATA_FUNCS *func_pointer =
        sk_CRYPTO_EX_DATA_FUNCS_value(func_pointers, i);
    if (func_pointer->free_func) {
      void *ptr = CRYPTO_get_ex_data(ad, i);
      func_pointer->free_func(obj, ptr, ad, i, func_pointer->argl,
                              func_pointer->argp);
    }
  }

  sk_CRYPTO_EX_DATA_FUNCS_free(func_pointers);

  if (ad->sk) {
    sk_void_free(ad->sk);
    ad->sk = NULL;
  }
}

const CRYPTO_EX_DATA_IMPL ex_data_default_impl = {
    new_class, cleanup, get_new_index, new_ex_data, dup_ex_data, free_ex_data};
