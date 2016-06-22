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

#include "bn_test_util.h"

#include <openssl/bn.h>
#include <openssl/err.h>

#include <ctype.h>
#include <limits.h>

#include "../bn/internal.h"


static int BN_mul_word(BIGNUM *bn, BN_ULONG w) {
  BN_ULONG ll;

  w &= BN_MASK2;
  if (!bn->top) {
    return 1;
  }

  if (w == 0) {
    BN_zero(bn);
    return 1;
  }

  ll = bn_mul_words(bn->d, bn->d, bn->top, w);
  if (ll) {
    if (bn_wexpand(bn, bn->top + 1) == NULL) {
      return 0;
    }
    bn->d[bn->top++] = ll;
  }

  return 1;
}

BIGNUM *bn_expand(BIGNUM *bn, size_t bits) {
  if (bits + BN_BITS2 - 1 < bits) {
    OPENSSL_PUT_ERROR(BN, BN_R_BIGNUM_TOO_LONG);
    return NULL;
  }
  return bn_wexpand(bn, (bits+BN_BITS2-1)/BN_BITS2);
}

static const char hextable[] = "0123456789abcdef";

/* decode_hex decodes |in_len| bytes of hex data from |in| and updates |bn|. */
static int decode_hex(BIGNUM *bn, const char *in, int in_len) {
  if (in_len > INT_MAX/4) {
    OPENSSL_PUT_ERROR(BN, BN_R_BIGNUM_TOO_LONG);
    return 0;
  }
  /* |in_len| is the number of hex digits. */
  if (bn_expand(bn, in_len * 4) == NULL) {
    return 0;
  }

  int i = 0;
  while (in_len > 0) {
    /* Decode one |BN_ULONG| at a time. */
    int todo = BN_BYTES * 2;
    if (todo > in_len) {
      todo = in_len;
    }

    BN_ULONG word = 0;
    int j;
    for (j = todo; j > 0; j--) {
      char c = in[in_len - j];

      BN_ULONG hex;
      if (c >= '0' && c <= '9') {
        hex = c - '0';
      } else if (c >= 'a' && c <= 'f') {
        hex = c - 'a' + 10;
      } else if (c >= 'A' && c <= 'F') {
        hex = c - 'A' + 10;
      } else {
        hex = 0;
        /* This shouldn't happen. The caller checks |isxdigit|. */
        assert(0);
      }
      word = (word << 4) | hex;
    }

    bn->d[i++] = word;
    in_len -= todo;
  }
  assert(i <= bn->dmax);
  bn->top = i;
  return 1;
}

/* decode_dec decodes |in_len| bytes of decimal data from |in| and updates |bn|. */
static int decode_dec(BIGNUM *bn, const char *in, int in_len) {
  int i, j;
  BN_ULONG l = 0;

  /* Decode |BN_DEC_NUM| digits at a time. */
  j = BN_DEC_NUM - (in_len % BN_DEC_NUM);
  if (j == BN_DEC_NUM) {
    j = 0;
  }
  l = 0;
  for (i = 0; i < in_len; i++) {
    l *= 10;
    l += in[i] - '0';
    if (++j == BN_DEC_NUM) {
      if (!BN_mul_word(bn, BN_DEC_CONV) ||
          !BN_add_word(bn, l)) {
        return 0;
      }
      l = 0;
      j = 0;
    }
  }
  return 1;
}

typedef int (*decode_func) (BIGNUM *bn, const char *in, int in_len);
typedef int (*char_test_func) (int c);

static int bn_x2bn(BIGNUM **outp, const char *in, decode_func decode, char_test_func want_char) {
  BIGNUM *ret = NULL;
  int neg = 0, i;
  int num;

  if (in == NULL || *in == 0) {
    return 0;
  }

  if (*in == '-') {
    neg = 1;
    in++;
  }

  for (i = 0; want_char((unsigned char)in[i]) && i + neg < INT_MAX; i++) {}

  num = i + neg;
  if (outp == NULL) {
    return num;
  }

  /* in is the start of the hex digits, and it is 'i' long */
  if (*outp == NULL) {
    ret = BN_new();
    if (ret == NULL) {
      return 0;
    }
  } else {
    ret = *outp;
    BN_zero(ret);
  }

  if (!decode(ret, in, i)) {
    goto err;
  }

  bn_correct_top(ret);
  if (!BN_is_zero(ret)) {
    ret->neg = neg;
  }

  *outp = ret;
  return num;

err:
  if (*outp == NULL) {
    BN_free(ret);
  }

  return 0;
}

int BN_hex2bn(BIGNUM **outp, const char *in) {
  return bn_x2bn(outp, in, decode_hex, isxdigit);
}

int BN_hex2bn_with_flags(BIGNUM **outp, const char *in, int flags) {
  if (!BN_hex2bn(outp, in)) {
    return 0;
  }
  BN_set_flags(*outp, flags);
  return 1;
}

int BN_dec2bn(BIGNUM **outp, const char *in) {
  return bn_x2bn(outp, in, decode_dec, isdigit);
}

int BN_asc2bn(BIGNUM **outp, const char *in) {
  const char *const orig_in = in;
  if (*in == '-') {
    in++;
  }

  if (in[0] == '0' && (in[1] == 'X' || in[1] == 'x')) {
    if (!BN_hex2bn(outp, in+2)) {
      return 0;
    }
  } else {
    if (!BN_dec2bn(outp, in)) {
      return 0;
    }
  }

  if (*orig_in == '-' && !BN_is_zero(*outp)) {
    (*outp)->neg = 1;
  }

  return 1;
}

int BN_print_fp(FILE *fp, const BIGNUM *a) {
  int i, j, v, z = 0;
  int ret = 0;

  if (a->neg && fputc('-', fp) != 1) {
    goto end;
  }

  if (BN_is_zero(a) && fputc('0', fp) != 1) {
    goto end;
  }

  for (i = a->top - 1; i >= 0; i--) {
    for (j = BN_BITS2 - 4; j >= 0; j -= 4) {
      /* strip leading zeros */
      v = ((int)(a->d[i] >> (long)j)) & 0x0f;
      if (z || v != 0) {
        if (fputc(hextable[v], fp) != 1) {
          goto end;
        }
        z = 1;
      }
    }
  }
  ret = 1;

end:
  return ret;
}
