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

#include <openssl/evp.h>

#include <openssl/asn1.h>
#include <openssl/bytestring.h>
#include <openssl/err.h>
#include <openssl/obj.h>
#include <openssl/x509.h>

#include "internal.h"


EVP_PKEY *EVP_parse_public_key(CBS *cbs) {
  /* Parse the SubjectPublicKeyInfo. */
  CBS spki, algorithm, oid, key;
  uint8_t padding;
  if (!CBS_get_asn1(cbs, &spki, CBS_ASN1_SEQUENCE) ||
      !CBS_get_asn1(&spki, &algorithm, CBS_ASN1_SEQUENCE) ||
      !CBS_get_asn1(&algorithm, &oid, CBS_ASN1_OBJECT) ||
      !CBS_get_asn1(&spki, &key, CBS_ASN1_BITSTRING) ||
      CBS_len(&spki) != 0 ||
      /* Every key type defined encodes the key as a byte string with the same
       * conversion to BIT STRING. */
      !CBS_get_u8(&key, &padding) ||
      padding != 0) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);
    return NULL;
  }

  /* Set up an |EVP_PKEY| of the appropriate type. */
  EVP_PKEY *ret = EVP_PKEY_new();
  if (ret == NULL ||
      !EVP_PKEY_set_type(ret, OBJ_cbs2nid(&oid))) {
    goto err;
  }

  /* Call into the type-specific SPKI decoding function. */
  if (ret->ameth->pub_decode == NULL) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_UNSUPPORTED_ALGORITHM);
    goto err;
  }
  if (!ret->ameth->pub_decode(ret, &algorithm, &key)) {
    goto err;
  }

  return ret;

err:
  EVP_PKEY_free(ret);
  return NULL;
}

int EVP_marshal_public_key(CBB *cbb, const EVP_PKEY *key) {
  if (key->ameth->pub_encode == NULL) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_UNSUPPORTED_ALGORITHM);
    return 0;
  }

  return key->ameth->pub_encode(cbb, key);
}

EVP_PKEY *EVP_parse_private_key(CBS *cbs) {
  /* Parse the PrivateKeyInfo. */
  CBS pkcs8, algorithm, oid, key;
  uint64_t version;
  if (!CBS_get_asn1(cbs, &pkcs8, CBS_ASN1_SEQUENCE) ||
      !CBS_get_asn1_uint64(&pkcs8, &version) ||
      version != 0 ||
      !CBS_get_asn1(&pkcs8, &algorithm, CBS_ASN1_SEQUENCE) ||
      !CBS_get_asn1(&algorithm, &oid, CBS_ASN1_OBJECT) ||
      !CBS_get_asn1(&pkcs8, &key, CBS_ASN1_OCTETSTRING)) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);
    return NULL;
  }

  /* A PrivateKeyInfo ends with a SET of Attributes which we ignore. */

  /* Set up an |EVP_PKEY| of the appropriate type. */
  EVP_PKEY *ret = EVP_PKEY_new();
  if (ret == NULL ||
      !EVP_PKEY_set_type(ret, OBJ_cbs2nid(&oid))) {
    goto err;
  }

  /* Call into the type-specific PrivateKeyInfo decoding function. */
  if (ret->ameth->priv_decode == NULL) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_UNSUPPORTED_ALGORITHM);
    goto err;
  }
  if (!ret->ameth->priv_decode(ret, &algorithm, &key)) {
    goto err;
  }

  return ret;

err:
  EVP_PKEY_free(ret);
  return NULL;
}

int EVP_marshal_private_key(CBB *cbb, const EVP_PKEY *key) {
  if (key->ameth->priv_encode == NULL) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_UNSUPPORTED_ALGORITHM);
    return 0;
  }

  return key->ameth->priv_encode(cbb, key);
}

EVP_PKEY *d2i_PrivateKey(int type, EVP_PKEY **out, const uint8_t **inp,
                         long len) {
  EVP_PKEY *ret;

  if (out == NULL || *out == NULL) {
    ret = EVP_PKEY_new();
    if (ret == NULL) {
      OPENSSL_PUT_ERROR(EVP, ERR_R_EVP_LIB);
      return NULL;
    }
  } else {
    ret = *out;
  }

  if (!EVP_PKEY_set_type(ret, type)) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_UNKNOWN_PUBLIC_KEY_TYPE);
    goto err;
  }

  const uint8_t *in = *inp;
  /* If trying to remove |old_priv_decode|, note that some code depends on this
   * function writing into |*out| and the |priv_decode| path doesn't support
   * that. */
  if (!ret->ameth->old_priv_decode ||
      !ret->ameth->old_priv_decode(ret, &in, len)) {
    if (ret->ameth->priv_decode) {
      /* Reset |in| in case |old_priv_decode| advanced it on error. */
      in = *inp;
      PKCS8_PRIV_KEY_INFO *p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &in, len);
      if (!p8) {
        goto err;
      }
      EVP_PKEY_free(ret);
      ret = EVP_PKCS82PKEY(p8);
      PKCS8_PRIV_KEY_INFO_free(p8);
      if (ret == NULL) {
        goto err;
      }
    } else {
      OPENSSL_PUT_ERROR(EVP, ERR_R_ASN1_LIB);
      goto err;
    }
  }

  if (out != NULL) {
    *out = ret;
  }
  *inp = in;
  return ret;

err:
  if (out == NULL || *out != ret) {
    EVP_PKEY_free(ret);
  }
  return NULL;
}

EVP_PKEY *d2i_AutoPrivateKey(EVP_PKEY **out, const uint8_t **inp, long len) {
  STACK_OF(ASN1_TYPE) *inkey;
  const uint8_t *p;
  int keytype;
  p = *inp;

  /* Dirty trick: read in the ASN1 data into out STACK_OF(ASN1_TYPE):
   * by analyzing it we can determine the passed structure: this
   * assumes the input is surrounded by an ASN1 SEQUENCE. */
  inkey = d2i_ASN1_SEQUENCE_ANY(NULL, &p, len);
  /* Since we only need to discern "traditional format" RSA and DSA
   * keys we can just count the elements. */
  if (sk_ASN1_TYPE_num(inkey) == 6) {
    keytype = EVP_PKEY_DSA;
  } else if (sk_ASN1_TYPE_num(inkey) == 4) {
    keytype = EVP_PKEY_EC;
  } else if (sk_ASN1_TYPE_num(inkey) == 3) {
    /* This seems to be PKCS8, not traditional format */
    p = *inp;
    PKCS8_PRIV_KEY_INFO *p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, len);
    EVP_PKEY *ret;

    sk_ASN1_TYPE_pop_free(inkey, ASN1_TYPE_free);
    if (!p8) {
      OPENSSL_PUT_ERROR(EVP, EVP_R_UNSUPPORTED_PUBLIC_KEY_TYPE);
      return NULL;
    }
    ret = EVP_PKCS82PKEY(p8);
    PKCS8_PRIV_KEY_INFO_free(p8);
    if (ret == NULL) {
      return NULL;
    }

    *inp = p;
    if (out) {
      *out = ret;
    }
    return ret;
  } else {
    keytype = EVP_PKEY_RSA;
  }

  sk_ASN1_TYPE_pop_free(inkey, ASN1_TYPE_free);
  return d2i_PrivateKey(keytype, out, inp, len);
}

int i2d_PublicKey(EVP_PKEY *key, uint8_t **outp) {
  switch (key->type) {
    case EVP_PKEY_RSA:
      return i2d_RSAPublicKey(key->pkey.rsa, outp);
    case EVP_PKEY_DSA:
      return i2d_DSAPublicKey(key->pkey.dsa, outp);
    case EVP_PKEY_EC:
      return i2o_ECPublicKey(key->pkey.ec, outp);
    default:
      OPENSSL_PUT_ERROR(EVP, EVP_R_UNSUPPORTED_PUBLIC_KEY_TYPE);
      return -1;
  }
}
