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

#include <openssl/ssl.h>

#if !defined(OPENSSL_WINDOWS) && !defined(OPENSSL_PNACL)

#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/mem.h>


typedef struct {
  DIR *dir;
  struct dirent dirent;
} OPENSSL_DIR_CTX;

static const char *OPENSSL_DIR_read(OPENSSL_DIR_CTX **ctx,
                                    const char *directory) {
  struct dirent *dirent;

  if (ctx == NULL || directory == NULL) {
    errno = EINVAL;
    return NULL;
  }

  errno = 0;
  if (*ctx == NULL) {
    *ctx = malloc(sizeof(OPENSSL_DIR_CTX));
    if (*ctx == NULL) {
      errno = ENOMEM;
      return 0;
    }
    memset(*ctx, 0, sizeof(OPENSSL_DIR_CTX));

    (*ctx)->dir = opendir(directory);
    if ((*ctx)->dir == NULL) {
      int save_errno = errno; /* Probably not needed, but I'm paranoid */
      free(*ctx);
      *ctx = NULL;
      errno = save_errno;
      return 0;
    }
  }

  if (readdir_r((*ctx)->dir, &(*ctx)->dirent, &dirent) != 0 ||
      dirent == NULL) {
    return 0;
  }

  return (*ctx)->dirent.d_name;
}

static int OPENSSL_DIR_end(OPENSSL_DIR_CTX **ctx) {
  if (ctx != NULL && *ctx != NULL) {
    int r = closedir((*ctx)->dir);
    free(*ctx);
    *ctx = NULL;
    return r == 0;
  }

  errno = EINVAL;
  return 0;
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
      OPENSSL_PUT_ERROR(SSL, SSL_R_PATH_TOO_LONG);
      goto err;
    }

    r = BIO_snprintf(buf, sizeof buf, "%s/%s", dir, filename);
    if (r <= 0 || r >= (int)sizeof(buf) ||
        !SSL_add_file_cert_subjects_to_stack(stack, buf)) {
      goto err;
    }
  }

  if (errno) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_SYS_LIB);
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

#endif /* !WINDOWS && !PNACL */
