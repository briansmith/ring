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

#ifndef OPENSSL_HEADER_BASE64_H
#define OPENSSL_HEADER_BASE64_H

#include <openssl/base.h>

#if defined(__cplusplus)
extern "C" {
#endif


/* base64 functions.
 *
 * For historical reasons, these functions have the EVP_ prefix but just do
 * base64 encoding and decoding. */


typedef struct evp_encode_ctx_st EVP_ENCODE_CTX;


/* Encoding */

/* EVP_EncodeInit initialises |*ctx|, which is typically stack allocated, for
 * an encoding operation. */
void EVP_EncodeInit(EVP_ENCODE_CTX *ctx);

/* EVP_EncodeUpdate encodes |in_len| bytes from |in| and writes an encoded
 * version of them to |out| and sets |*out_len| to the number of bytes written.
 * Some state may be contained in |ctx| so |EVP_EncodeFinal| must be used to
 * flush it before using the encoded data. */
void EVP_EncodeUpdate(EVP_ENCODE_CTX *ctx, uint8_t *out, int *out_len,
                      const uint8_t *in, size_t in_len);

/* EVP_EncodeFinal flushes any remaining output bytes from |ctx| to |out| and
 * sets |*out_len| to the number of bytes written. */
void EVP_EncodeFinal(EVP_ENCODE_CTX *ctx, uint8_t *out, int *out_len);

/* EVP_EncodeBlock encodes |src_len| bytes from |src| and writes the result to
 * |dst|. It returns the number of bytes written. */
size_t EVP_EncodeBlock(uint8_t *dst, const uint8_t *src, size_t src_len);


/* Decoding */

/* EVP_DecodeInit initialises |*ctx|, which is typically stack allocated, for
 * a decoding operation. */
void EVP_DecodeInit(EVP_ENCODE_CTX *ctx);

/* EVP_DecodeUpdate decodes |in_len| bytes from |in| and writes the decoded
 * data to |out| and sets |*out_len| to the number of bytes written. Some state
 * may be contained in |ctx| so |EVP_DecodeFinal| must be used to flush it
 * before using the encoded data.
 *
 * It returns -1 on error, one if a full line of input was processed and zero
 * if the line was short (i.e. it was the last line). */
int EVP_DecodeUpdate(EVP_ENCODE_CTX *ctx, uint8_t *out, int *out_len,
                     const uint8_t *in, size_t in_len);

/* EVP_DecodeFinal flushes any remaining output bytes from |ctx| to |out| and
 * sets |*out_len| to the number of bytes written. It returns one on success
 * and minus one on error. */
int EVP_DecodeFinal(EVP_ENCODE_CTX *ctx, uint8_t *out, int *out_len);

/* EVP_DecodeBlock encodes |src_len| bytes from |src| and writes the result to
 * |dst|. It returns the number of bytes written. */
size_t EVP_DecodeBlock(uint8_t *dst, const uint8_t *src, size_t src_len);


struct evp_encode_ctx_st {
  unsigned num;    /* number saved in a partial encode/decode */
  unsigned length; /* The length is either the output line length
               * (in input bytes) or the shortest input line
               * length that is ok.  Once decoding begins,
               * the length is adjusted up each time a longer
               * line is decoded */
  uint8_t enc_data[80]; /* data to encode */
  unsigned line_num;    /* number read on current line */
  int expect_nl;
};


#if defined(__cplusplus)
}  /* extern C */
#endif

#endif  /* OPENSSL_HEADER_BASE64_H */
