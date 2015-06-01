/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project 2007.
 */
/* ====================================================================
 * Copyright (c) 2007 The OpenSSL Project.  All rights reserved.
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
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
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

#include <openssl/evp.h>

#include <string.h>

#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/mem.h>
#include <openssl/obj.h>

#include "internal.h"
#include "../digest/internal.h"


typedef struct {
  const EVP_MD *md;       /* MD for HMAC use */
  ASN1_OCTET_STRING ktmp; /* Temp storage for key */
  HMAC_CTX ctx;
} HMAC_PKEY_CTX;

static int pkey_hmac_init(EVP_PKEY_CTX *ctx) {
  HMAC_PKEY_CTX *hctx;
  hctx = OPENSSL_malloc(sizeof(HMAC_PKEY_CTX));
  if (!hctx) {
    return 0;
  }
  memset(hctx, 0, sizeof(HMAC_PKEY_CTX));
  hctx->ktmp.type = V_ASN1_OCTET_STRING;
  HMAC_CTX_init(&hctx->ctx);

  ctx->data = hctx;

  return 1;
}

static int pkey_hmac_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src) {
  HMAC_PKEY_CTX *sctx, *dctx;
  if (!pkey_hmac_init(dst)) {
    return 0;
  }
  sctx = src->data;
  dctx = dst->data;
  dctx->md = sctx->md;
  HMAC_CTX_init(&dctx->ctx);
  if (!HMAC_CTX_copy_ex(&dctx->ctx, &sctx->ctx)) {
    return 0;
  }
  if (sctx->ktmp.data) {
    if (!ASN1_OCTET_STRING_set(&dctx->ktmp, sctx->ktmp.data,
                               sctx->ktmp.length)) {
      return 0;
    }
  }
  return 1;
}

static void pkey_hmac_cleanup(EVP_PKEY_CTX *ctx) {
  HMAC_PKEY_CTX *hctx = ctx->data;

  if (hctx == NULL) {
    return;
  }

  HMAC_CTX_cleanup(&hctx->ctx);
  if (hctx->ktmp.data) {
    if (hctx->ktmp.length) {
      OPENSSL_cleanse(hctx->ktmp.data, hctx->ktmp.length);
    }
    OPENSSL_free(hctx->ktmp.data);
    hctx->ktmp.data = NULL;
  }
  OPENSSL_free(hctx);
}

static int pkey_hmac_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey) {
  ASN1_OCTET_STRING *hkey = NULL;
  HMAC_PKEY_CTX *hctx = ctx->data;

  if (!hctx->ktmp.data) {
    return 0;
  }
  hkey = ASN1_OCTET_STRING_dup(&hctx->ktmp);
  if (!hkey) {
    return 0;
  }
  EVP_PKEY_assign(pkey, EVP_PKEY_HMAC, hkey);

  return 1;
}

static void int_update(EVP_MD_CTX *ctx, const void *data, size_t count) {
  HMAC_PKEY_CTX *hctx = ctx->pctx->data;
  HMAC_Update(&hctx->ctx, data, count);
}

static int hmac_signctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx) {
  /* |mctx| gets repurposed as a hook to call |HMAC_Update|. Suppress the
   * automatic setting of |mctx->update| and the rest of its initialization. */
  EVP_MD_CTX_set_flags(mctx, EVP_MD_CTX_FLAG_NO_INIT);
  mctx->update = int_update;
  return 1;
}

static int hmac_signctx(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                        EVP_MD_CTX *mctx) {
  unsigned int hlen;
  HMAC_PKEY_CTX *hctx = ctx->data;
  size_t md_size = EVP_MD_CTX_size(mctx);

  if (!sig) {
    *siglen = md_size;
    return 1;
  } else if (*siglen < md_size) {
    OPENSSL_PUT_ERROR(EVP, hmac_signctx, EVP_R_BUFFER_TOO_SMALL);
    return 0;
  }

  if (!HMAC_Final(&hctx->ctx, sig, &hlen)) {
    return 0;
  }
  *siglen = (size_t)hlen;
  return 1;
}

static int pkey_hmac_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2) {
  HMAC_PKEY_CTX *hctx = ctx->data;
  ASN1_OCTET_STRING *key;

  switch (type) {
    case EVP_PKEY_CTRL_SET_MAC_KEY:
      if ((!p2 && p1 > 0) || (p1 < -1)) {
        return 0;
      }
      if (!ASN1_OCTET_STRING_set(&hctx->ktmp, p2, p1)) {
        return 0;
      }
      break;

    case EVP_PKEY_CTRL_MD:
      hctx->md = p2;
      break;

    case EVP_PKEY_CTRL_DIGESTINIT:
      key = (ASN1_OCTET_STRING *)ctx->pkey->pkey.ptr;
      if (!HMAC_Init_ex(&hctx->ctx, key->data, key->length, hctx->md,
                        ctx->engine)) {
        return 0;
      }
      break;

    default:
      OPENSSL_PUT_ERROR(EVP, pkey_hmac_ctrl, EVP_R_COMMAND_NOT_SUPPORTED);
      return 0;
  }
  return 1;
}

const EVP_PKEY_METHOD hmac_pkey_meth = {
    EVP_PKEY_HMAC,          0 /* flags */,        pkey_hmac_init,
    pkey_hmac_copy,         pkey_hmac_cleanup,    0 /* paramgen_init */,
    0 /* paramgen */,       0 /* keygen_init */,  pkey_hmac_keygen,
    0 /* sign_init */,      0 /* sign */,         0 /* verify_init */,
    0 /* verify */,         hmac_signctx_init,    hmac_signctx,
    0 /* verifyctx_init */, 0 /* verifyctx */,    0 /* encrypt_init */,
    0 /* encrypt */,        0 /* decrypt_init */, 0 /* decrypt */,
    0 /* derive_init */,    0 /* derive */,       pkey_hmac_ctrl,
    0,
};
