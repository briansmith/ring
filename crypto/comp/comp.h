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

#ifndef OPENSSL_HEADER_COMP_H
#define OPENSSL_HEADER_COMP_H

#include <openssl/base.h>

#include <openssl/ex_data.h>

#if defined(__cplusplus)
extern "C" {
#endif


/* Compression methods */

/* COMP_zlib returns a method that implements standard, zlib compression. */
COMP_METHOD *COMP_zlib(void);


/* Compression contexts */

/* COMP_CTX_new allocates a fresh |COMP_CTX| which will compress with the given
 * compression method. It returns the new |COMP_CTX| or NULL on error. */
COMP_CTX *COMP_CTX_new(COMP_METHOD *meth);

/* COMP_CTX_free frees all data owned by |ctx| and |ctx| itself. */
void COMP_CTX_free(COMP_CTX *ctx);


int COMP_compress_block(COMP_CTX *ctx, uint8_t *out, size_t out_len,
                        uint8_t *in, size_t in_len);

int COMP_expand_block(COMP_CTX *ctx, uint8_t *out, size_t out_len,
                      uint8_t *in, size_t in_len);


/* Private functions */

struct comp_ctx_st {
  COMP_METHOD *meth;
  unsigned long compress_in;
  unsigned long compress_out;
  unsigned long expand_in;
  unsigned long expand_out;

  CRYPTO_EX_DATA ex_data;
};

struct comp_method_st {
  int type;         /* NID for compression library */
  const char *name; /* A text string to identify the library */
  int (*init)(COMP_CTX *ctx);
  void (*finish)(COMP_CTX *ctx);
  int (*compress)(COMP_CTX *ctx, uint8_t *out, unsigned int olen, uint8_t *in,
                  unsigned int ilen);
  int (*expand)(COMP_CTX *ctx, uint8_t *out, unsigned int olen, uint8_t *in,
                unsigned int ilen);
  /* The following two do NOTHING, but are kept for backward compatibility */
  long (*ctrl)(void);
  long (*callback_ctrl)(void);
} /* COMP_METHOD */;


#if defined(__cplusplus)
}  /* extern C */
#endif

#endif  /* OPENSSL_HEADER_HMAC_H */
