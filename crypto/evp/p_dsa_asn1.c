/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL project
 * 2006.
 */
/* ====================================================================
 * Copyright (c) 2006 The OpenSSL Project.  All rights reserved.
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

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/digest.h>
#include <openssl/bn.h>
#include <openssl/bytestring.h>
#include <openssl/dsa.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/obj.h>
#include <openssl/x509.h>

#include "internal.h"


static int dsa_pub_decode(EVP_PKEY *out, CBS *params, CBS *key) {
  /* See RFC 3279, section 2.3.2. */

  /* Parameters may or may not be present. */
  DSA *dsa;
  if (CBS_len(params) == 0) {
    dsa = DSA_new();
    if (dsa == NULL) {
      return 0;
    }
  } else {
    dsa = DSA_parse_parameters(params);
    if (dsa == NULL || CBS_len(params) != 0) {
      OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);
      goto err;
    }
  }

  dsa->pub_key = BN_new();
  if (dsa->pub_key == NULL) {
    goto err;
  }

  if (!BN_parse_asn1_unsigned(key, dsa->pub_key) ||
      CBS_len(key) != 0) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);
    goto err;
  }

  EVP_PKEY_assign_DSA(out, dsa);
  return 1;

err:
  DSA_free(dsa);
  return 0;
}

static int dsa_pub_encode(CBB *out, const EVP_PKEY *key) {
  const DSA *dsa = key->pkey.dsa;
  const int has_params = dsa->p != NULL && dsa->q != NULL && dsa->g != NULL;

  /* See RFC 5480, section 2. */
  CBB spki, algorithm, key_bitstring;
  if (!CBB_add_asn1(out, &spki, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1(&spki, &algorithm, CBS_ASN1_SEQUENCE) ||
      !OBJ_nid2cbb(&algorithm, NID_dsa) ||
      (has_params &&
       !DSA_marshal_parameters(&algorithm, dsa)) ||
      !CBB_add_asn1(&spki, &key_bitstring, CBS_ASN1_BITSTRING) ||
      !CBB_add_u8(&key_bitstring, 0 /* padding */) ||
      !BN_marshal_asn1(&key_bitstring, dsa->pub_key) ||
      !CBB_flush(out)) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_ENCODE_ERROR);
    return 0;
  }

  return 1;
}

static int dsa_priv_decode(EVP_PKEY *out, CBS *params, CBS *key) {
  /* See PKCS#11, v2.40, section 2.5. */

  /* Decode parameters. */
  BN_CTX *ctx = NULL;
  DSA *dsa = DSA_parse_parameters(params);
  if (dsa == NULL || CBS_len(params) != 0) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);
    goto err;
  }

  dsa->priv_key = BN_new();
  dsa->pub_key = BN_new();
  if (dsa->priv_key == NULL || dsa->pub_key == NULL) {
    goto err;
  }

  /* Decode the key. */
  if (!BN_parse_asn1_unsigned(key, dsa->priv_key) ||
      CBS_len(key) != 0) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);
    goto err;
  }

  /* Calculate the public key. */
  ctx = BN_CTX_new();
  if (ctx == NULL ||
      !BN_mod_exp(dsa->pub_key, dsa->g, dsa->priv_key, dsa->p, ctx)) {
    goto err;
  }

  BN_CTX_free(ctx);
  EVP_PKEY_assign_DSA(out, dsa);
  return 1;

err:
  BN_CTX_free(ctx);
  DSA_free(dsa);
  return 0;
}

static int dsa_priv_encode(CBB *out, const EVP_PKEY *key) {
  const DSA *dsa = key->pkey.dsa;
  if (dsa == NULL || dsa->priv_key == NULL) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_MISSING_PARAMETERS);
    return 0;
  }

  /* See PKCS#11, v2.40, section 2.5. */
  CBB pkcs8, algorithm, private_key;
  if (!CBB_add_asn1(out, &pkcs8, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1_uint64(&pkcs8, 0 /* version */) ||
      !CBB_add_asn1(&pkcs8, &algorithm, CBS_ASN1_SEQUENCE) ||
      !OBJ_nid2cbb(&algorithm, NID_dsa) ||
      !DSA_marshal_parameters(&algorithm, dsa) ||
      !CBB_add_asn1(&pkcs8, &private_key, CBS_ASN1_OCTETSTRING) ||
      !BN_marshal_asn1(&private_key, dsa->priv_key) ||
      !CBB_flush(out)) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_ENCODE_ERROR);
    return 0;
  }

  return 1;
}

static int int_dsa_size(const EVP_PKEY *pkey) {
  return DSA_size(pkey->pkey.dsa);
}

static int dsa_bits(const EVP_PKEY *pkey) {
  return BN_num_bits(pkey->pkey.dsa->p);
}

static int dsa_missing_parameters(const EVP_PKEY *pkey) {
  DSA *dsa;
  dsa = pkey->pkey.dsa;
  if (dsa->p == NULL || dsa->q == NULL || dsa->g == NULL) {
    return 1;
  }
  return 0;
}

static int dup_bn_into(BIGNUM **out, BIGNUM *src) {
  BIGNUM *a;

  a = BN_dup(src);
  if (a == NULL) {
    return 0;
  }
  BN_free(*out);
  *out = a;

  return 1;
}

static int dsa_copy_parameters(EVP_PKEY *to, const EVP_PKEY *from) {
  if (!dup_bn_into(&to->pkey.dsa->p, from->pkey.dsa->p) ||
      !dup_bn_into(&to->pkey.dsa->q, from->pkey.dsa->q) ||
      !dup_bn_into(&to->pkey.dsa->g, from->pkey.dsa->g)) {
    return 0;
  }

  return 1;
}

static int dsa_cmp_parameters(const EVP_PKEY *a, const EVP_PKEY *b) {
  return BN_cmp(a->pkey.dsa->p, b->pkey.dsa->p) == 0 &&
         BN_cmp(a->pkey.dsa->q, b->pkey.dsa->q) == 0 &&
         BN_cmp(a->pkey.dsa->g, b->pkey.dsa->g) == 0;
}

static int dsa_pub_cmp(const EVP_PKEY *a, const EVP_PKEY *b) {
  return BN_cmp(b->pkey.dsa->pub_key, a->pkey.dsa->pub_key) == 0;
}

static void int_dsa_free(EVP_PKEY *pkey) { DSA_free(pkey->pkey.dsa); }

static void update_buflen(const BIGNUM *b, size_t *pbuflen) {
  size_t i;

  if (!b) {
    return;
  }
  i = BN_num_bytes(b);
  if (*pbuflen < i) {
    *pbuflen = i;
  }
}

static int do_dsa_print(BIO *bp, const DSA *x, int off, int ptype) {
  uint8_t *m = NULL;
  int ret = 0;
  size_t buf_len = 0;
  const char *ktype = NULL;

  const BIGNUM *priv_key, *pub_key;

  priv_key = NULL;
  if (ptype == 2) {
    priv_key = x->priv_key;
  }

  pub_key = NULL;
  if (ptype > 0) {
    pub_key = x->pub_key;
  }

  ktype = "DSA-Parameters";
  if (ptype == 2) {
    ktype = "Private-Key";
  } else if (ptype == 1) {
    ktype = "Public-Key";
  }

  update_buflen(x->p, &buf_len);
  update_buflen(x->q, &buf_len);
  update_buflen(x->g, &buf_len);
  update_buflen(priv_key, &buf_len);
  update_buflen(pub_key, &buf_len);

  m = OPENSSL_malloc(buf_len + 10);
  if (m == NULL) {
    OPENSSL_PUT_ERROR(EVP, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  if (priv_key) {
    if (!BIO_indent(bp, off, 128) ||
        BIO_printf(bp, "%s: (%d bit)\n", ktype, BN_num_bits(x->p)) <= 0) {
      goto err;
    }
  }

  if (!ASN1_bn_print(bp, "priv:", priv_key, m, off) ||
      !ASN1_bn_print(bp, "pub: ", pub_key, m, off) ||
      !ASN1_bn_print(bp, "P:   ", x->p, m, off) ||
      !ASN1_bn_print(bp, "Q:   ", x->q, m, off) ||
      !ASN1_bn_print(bp, "G:   ", x->g, m, off)) {
    goto err;
  }
  ret = 1;

err:
  OPENSSL_free(m);
  return ret;
}

static int dsa_param_print(BIO *bp, const EVP_PKEY *pkey, int indent,
                           ASN1_PCTX *ctx) {
  return do_dsa_print(bp, pkey->pkey.dsa, indent, 0);
}

static int dsa_pub_print(BIO *bp, const EVP_PKEY *pkey, int indent,
                         ASN1_PCTX *ctx) {
  return do_dsa_print(bp, pkey->pkey.dsa, indent, 1);
}

static int dsa_priv_print(BIO *bp, const EVP_PKEY *pkey, int indent,
                          ASN1_PCTX *ctx) {
  return do_dsa_print(bp, pkey->pkey.dsa, indent, 2);
}

static int old_dsa_priv_decode(EVP_PKEY *pkey, const uint8_t **pder,
                               int derlen) {
  DSA *dsa;
  dsa = d2i_DSAPrivateKey(NULL, pder, derlen);
  if (dsa == NULL) {
    OPENSSL_PUT_ERROR(EVP, ERR_R_DSA_LIB);
    return 0;
  }
  EVP_PKEY_assign_DSA(pkey, dsa);
  return 1;
}

static int dsa_sig_print(BIO *bp, const X509_ALGOR *sigalg,
                         const ASN1_STRING *sig, int indent, ASN1_PCTX *pctx) {
  DSA_SIG *dsa_sig;
  const uint8_t *p;

  if (!sig) {
    return BIO_puts(bp, "\n") > 0;
  }

  p = sig->data;
  dsa_sig = d2i_DSA_SIG(NULL, &p, sig->length);
  if (dsa_sig == NULL) {
    return X509_signature_dump(bp, sig, indent);
  }

  int rv = 0;
  size_t buf_len = 0;
  uint8_t *m = NULL;

  update_buflen(dsa_sig->r, &buf_len);
  update_buflen(dsa_sig->s, &buf_len);
  m = OPENSSL_malloc(buf_len + 10);
  if (m == NULL) {
    OPENSSL_PUT_ERROR(EVP, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  if (BIO_write(bp, "\n", 1) != 1 ||
      !ASN1_bn_print(bp, "r:   ", dsa_sig->r, m, indent) ||
      !ASN1_bn_print(bp, "s:   ", dsa_sig->s, m, indent)) {
    goto err;
  }
  rv = 1;

err:
  OPENSSL_free(m);
  DSA_SIG_free(dsa_sig);
  return rv;
}

const EVP_PKEY_ASN1_METHOD dsa_asn1_meth = {
  EVP_PKEY_DSA,
  0,

  "DSA",

  dsa_pub_decode,
  dsa_pub_encode,
  dsa_pub_cmp,
  dsa_pub_print,

  dsa_priv_decode,
  dsa_priv_encode,
  dsa_priv_print,

  NULL /* pkey_opaque */,
  NULL /* pkey_supports_digest */,

  int_dsa_size,
  dsa_bits,

  dsa_missing_parameters,
  dsa_copy_parameters,
  dsa_cmp_parameters,
  dsa_param_print,
  dsa_sig_print,

  int_dsa_free,
  old_dsa_priv_decode,

  NULL  /* digest_verify_init_from_algorithm */,
  NULL  /* digest_sign_algorithm */,
};
