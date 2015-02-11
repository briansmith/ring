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

#include <openssl/rsa.h>

#include <string.h>

#include <openssl/bn.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/ex_data.h>
#include <openssl/mem.h>
#include <openssl/obj.h>

#include "internal.h"


extern const RSA_METHOD RSA_default_method;

RSA *RSA_new(void) { return RSA_new_method(NULL); }

RSA *RSA_new_method(const ENGINE *engine) {
  RSA *rsa = (RSA *)OPENSSL_malloc(sizeof(RSA));
  if (rsa == NULL) {
    OPENSSL_PUT_ERROR(RSA, RSA_new_method, ERR_R_MALLOC_FAILURE);
    return NULL;
  }

  memset(rsa, 0, sizeof(RSA));

  if (engine) {
    rsa->meth = ENGINE_get_RSA_method(engine);
  }

  if (rsa->meth == NULL) {
    rsa->meth = (RSA_METHOD*) &RSA_default_method;
  }
  METHOD_ref(rsa->meth);

  rsa->references = 1;
  rsa->flags = rsa->meth->flags;

  if (!CRYPTO_new_ex_data(CRYPTO_EX_INDEX_RSA, rsa, &rsa->ex_data)) {
    METHOD_unref(rsa->meth);
    OPENSSL_free(rsa);
    return NULL;
  }

  if (rsa->meth->init && !rsa->meth->init(rsa)) {
    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_RSA, rsa, &rsa->ex_data);
    METHOD_unref(rsa->meth);
    OPENSSL_free(rsa);
    return NULL;
  }

  return rsa;
}

void RSA_free(RSA *rsa) {
  unsigned u;

  if (rsa == NULL) {
    return;
  }

  if (CRYPTO_add(&rsa->references, -1, CRYPTO_LOCK_RSA) > 0) {
    return;
  }

  if (rsa->meth->finish) {
    rsa->meth->finish(rsa);
  }
  METHOD_unref(rsa->meth);

  CRYPTO_free_ex_data(CRYPTO_EX_INDEX_DSA, rsa, &rsa->ex_data);

  if (rsa->n != NULL) {
    BN_clear_free(rsa->n);
  }
  if (rsa->e != NULL) {
    BN_clear_free(rsa->e);
  }
  if (rsa->d != NULL) {
    BN_clear_free(rsa->d);
  }
  if (rsa->p != NULL) {
    BN_clear_free(rsa->p);
  }
  if (rsa->q != NULL) {
    BN_clear_free(rsa->q);
  }
  if (rsa->dmp1 != NULL) {
    BN_clear_free(rsa->dmp1);
  }
  if (rsa->dmq1 != NULL) {
    BN_clear_free(rsa->dmq1);
  }
  if (rsa->iqmp != NULL) {
    BN_clear_free(rsa->iqmp);
  }
  for (u = 0; u < rsa->num_blindings; u++) {
    BN_BLINDING_free(rsa->blindings[u]);
  }
  if (rsa->blindings != NULL) {
    OPENSSL_free(rsa->blindings);
  }
  if (rsa->blindings_inuse != NULL) {
    OPENSSL_free(rsa->blindings_inuse);
  }
  OPENSSL_free(rsa);
}

int RSA_up_ref(RSA *rsa) {
  CRYPTO_add(&rsa->references, 1, CRYPTO_LOCK_RSA);
  return 1;
}

int RSA_generate_key_ex(RSA *rsa, int bits, BIGNUM *e_value, BN_GENCB *cb) {
  if (rsa->meth->keygen) {
    return rsa->meth->keygen(rsa, bits, e_value, cb);
  }

  return RSA_default_method.keygen(rsa, bits, e_value, cb);
}

int RSA_encrypt(RSA *rsa, size_t *out_len, uint8_t *out, size_t max_out,
                const uint8_t *in, size_t in_len, int padding) {
  if (rsa->meth->encrypt) {
    return rsa->meth->encrypt(rsa, out_len, out, max_out, in, in_len, padding);
  }

  return RSA_default_method.encrypt(rsa, out_len, out, max_out, in, in_len,
                                    padding);
}

int RSA_public_encrypt(int flen, const uint8_t *from, uint8_t *to, RSA *rsa,
                       int padding) {
  size_t out_len;

  if (!RSA_encrypt(rsa, &out_len, to, RSA_size(rsa), from, flen, padding)) {
    return -1;
  }

  return out_len;
}

int RSA_sign_raw(RSA *rsa, size_t *out_len, uint8_t *out, size_t max_out,
                 const uint8_t *in, size_t in_len, int padding) {
  if (rsa->meth->sign_raw) {
    return rsa->meth->sign_raw(rsa, out_len, out, max_out, in, in_len, padding);
  }

  return RSA_default_method.sign_raw(rsa, out_len, out, max_out, in, in_len,
                                     padding);
}

int RSA_private_encrypt(int flen, const uint8_t *from, uint8_t *to, RSA *rsa,
                        int padding) {
  size_t out_len;

  if (!RSA_sign_raw(rsa, &out_len, to, RSA_size(rsa), from, flen, padding)) {
    return -1;
  }

  return out_len;
}

int RSA_decrypt(RSA *rsa, size_t *out_len, uint8_t *out, size_t max_out,
                const uint8_t *in, size_t in_len, int padding) {
  if (rsa->meth->decrypt) {
    return rsa->meth->decrypt(rsa, out_len, out, max_out, in, in_len, padding);
  }

  return RSA_default_method.decrypt(rsa, out_len, out, max_out, in, in_len,
                                    padding);
}

int RSA_private_decrypt(int flen, const uint8_t *from, uint8_t *to, RSA *rsa,
                        int padding) {
  size_t out_len;

  if (!RSA_decrypt(rsa, &out_len, to, RSA_size(rsa), from, flen, padding)) {
    return -1;
  }

  return out_len;
}

int RSA_verify_raw(RSA *rsa, size_t *out_len, uint8_t *out, size_t max_out,
                   const uint8_t *in, size_t in_len, int padding) {
  if (rsa->meth->verify_raw) {
    return rsa->meth->verify_raw(rsa, out_len, out, max_out, in, in_len, padding);
  }

  return RSA_default_method.verify_raw(rsa, out_len, out, max_out, in, in_len,
                                       padding);
}

int RSA_public_decrypt(int flen, const uint8_t *from, uint8_t *to, RSA *rsa,
                       int padding) {
  size_t out_len;

  if (!RSA_verify_raw(rsa, &out_len, to, RSA_size(rsa), from, flen, padding)) {
    return -1;
  }

  return out_len;
}

unsigned RSA_size(const RSA *rsa) {
  if (rsa->meth->size) {
    return rsa->meth->size(rsa);
  }

  return RSA_default_method.size(rsa);
}

int RSA_is_opaque(const RSA *rsa) {
  return rsa->meth && (rsa->meth->flags & RSA_FLAG_OPAQUE);
}

int RSA_supports_digest(const RSA *rsa, const EVP_MD *md) {
  if (rsa->meth && rsa->meth->supports_digest) {
    return rsa->meth->supports_digest(rsa, md);
  }
  return 1;
}

int RSA_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func,
                         CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func) {
  return CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_RSA, argl, argp, new_func,
                                 dup_func, free_func);
}

int RSA_set_ex_data(RSA *d, int idx, void *arg) {
  return CRYPTO_set_ex_data(&d->ex_data, idx, arg);
}

void *RSA_get_ex_data(const RSA *d, int idx) {
  return CRYPTO_get_ex_data(&d->ex_data, idx);
}

/* SSL_SIG_LENGTH is the size of an SSL/TLS (prior to TLS 1.2) signature: it's
 * the length of an MD5 and SHA1 hash. */
static const unsigned SSL_SIG_LENGTH = 36;

/* pkcs1_sig_prefix contains the ASN.1, DER encoded prefix for a hash that is
 * to be signed with PKCS#1. */
struct pkcs1_sig_prefix {
  /* nid identifies the hash function. */
  int nid;
  /* len is the number of bytes of |bytes| which are valid. */
  uint8_t len;
  /* bytes contains the DER bytes. */
  uint8_t bytes[19];
};

/* kPKCS1SigPrefixes contains the ASN.1 prefixes for PKCS#1 signatures with
 * different hash functions. */
static const struct pkcs1_sig_prefix kPKCS1SigPrefixes[] = {
    {
     NID_md5,
     18,
     {0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
      0x02, 0x05, 0x05, 0x00, 0x04, 0x10},
    },
    {
     NID_sha1,
     15,
     {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05,
      0x00, 0x04, 0x14},
    },
    {
     NID_sha224,
     19,
     {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
      0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},
    },
    {
     NID_sha256,
     19,
     {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
      0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
    },
    {
     NID_sha384,
     19,
     {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
      0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
    },
    {
     NID_sha512,
     19,
     {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
      0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
    },
    {
     NID_ripemd160,
     14,
     {0x30, 0x20, 0x30, 0x08, 0x06, 0x06, 0x28, 0xcf, 0x06, 0x03, 0x00, 0x31,
      0x04, 0x14},
    },
    {
     NID_undef, 0, {0},
    },
};

/* TODO(fork): mostly new code, needs careful review. */

/* pkcs1_prefixed_msg builds a PKCS#1, prefixed version of |msg| for the given
 * hash function and sets |out_msg| to point to it. On successful return,
 * |*out_msg| may be allocated memory and, if so, |*is_alloced| will be 1. */
static int pkcs1_prefixed_msg(uint8_t **out_msg, size_t *out_msg_len,
                              int *is_alloced, int hash_nid, const uint8_t *msg,
                              size_t msg_len) {
  unsigned i;
  const uint8_t* prefix = NULL;
  unsigned prefix_len;
  uint8_t *signed_msg;
  unsigned signed_msg_len;

  if (hash_nid == NID_md5_sha1) {
    /* Special case: SSL signature, just check the length. */
    if (msg_len != SSL_SIG_LENGTH) {
      OPENSSL_PUT_ERROR(RSA, RSA_sign, RSA_R_INVALID_MESSAGE_LENGTH);
      return 0;
    }

    *out_msg = (uint8_t*) msg;
    *out_msg_len = SSL_SIG_LENGTH;
    *is_alloced = 0;
    return 1;
  }

  for (i = 0; kPKCS1SigPrefixes[i].nid != NID_undef; i++) {
    const struct pkcs1_sig_prefix *sig_prefix = &kPKCS1SigPrefixes[i];
    if (sig_prefix->nid == hash_nid) {
      prefix = sig_prefix->bytes;
      prefix_len = sig_prefix->len;
      break;
    }
  }

  if (prefix == NULL) {
    OPENSSL_PUT_ERROR(RSA, RSA_sign, RSA_R_UNKNOWN_ALGORITHM_TYPE);
    return 0;
  }

  signed_msg_len = prefix_len + msg_len;
  if (signed_msg_len < prefix_len) {
    OPENSSL_PUT_ERROR(RSA, RSA_sign, RSA_R_TOO_LONG);
    return 0;
  }

  signed_msg = OPENSSL_malloc(signed_msg_len);
  if (!signed_msg) {
    OPENSSL_PUT_ERROR(RSA, RSA_sign, ERR_R_MALLOC_FAILURE);
    return 0;
  }

  memcpy(signed_msg, prefix, prefix_len);
  memcpy(signed_msg + prefix_len, msg, msg_len);

  *out_msg = signed_msg;
  *out_msg_len = signed_msg_len;
  *is_alloced = 1;

  return 1;
}

int RSA_sign(int hash_nid, const uint8_t *in, unsigned in_len, uint8_t *out,
             unsigned *out_len, RSA *rsa) {
  const unsigned rsa_size = RSA_size(rsa);
  int ret = 0;
  uint8_t *signed_msg;
  size_t signed_msg_len;
  int signed_msg_is_alloced = 0;
  size_t size_t_out_len;

  if (rsa->meth->sign) {
    return rsa->meth->sign(hash_nid, in, in_len, out, out_len, rsa);
  }

  if (!pkcs1_prefixed_msg(&signed_msg, &signed_msg_len, &signed_msg_is_alloced,
                          hash_nid, in, in_len)) {
    return 0;
  }

  if (rsa_size < RSA_PKCS1_PADDING_SIZE ||
      signed_msg_len > rsa_size - RSA_PKCS1_PADDING_SIZE) {
    OPENSSL_PUT_ERROR(RSA, RSA_sign, RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY);
    goto finish;
  }

  if (RSA_sign_raw(rsa, &size_t_out_len, out, rsa_size, signed_msg,
                   signed_msg_len, RSA_PKCS1_PADDING)) {
    *out_len = size_t_out_len;
    ret = 1;
  }

finish:
  if (signed_msg_is_alloced) {
    OPENSSL_free(signed_msg);
  }
  return ret;
}

int RSA_verify(int hash_nid, const uint8_t *msg, size_t msg_len,
               const uint8_t *sig, size_t sig_len, RSA *rsa) {
  const size_t rsa_size = RSA_size(rsa);
  uint8_t *buf = NULL;
  int ret = 0;
  uint8_t *signed_msg = NULL;
  size_t signed_msg_len, len;
  int signed_msg_is_alloced = 0;

  if (rsa->meth->verify) {
    return rsa->meth->verify(hash_nid, msg, msg_len, sig, sig_len, rsa);
  }

  if (sig_len != rsa_size) {
    OPENSSL_PUT_ERROR(RSA, RSA_verify, RSA_R_WRONG_SIGNATURE_LENGTH);
    return 0;
  }

  if (hash_nid == NID_md5_sha1 && msg_len != SSL_SIG_LENGTH) {
    OPENSSL_PUT_ERROR(RSA, RSA_verify, RSA_R_INVALID_MESSAGE_LENGTH);
    return 0;
  }

  buf = OPENSSL_malloc(rsa_size);
  if (!buf) {
    OPENSSL_PUT_ERROR(RSA, RSA_verify, ERR_R_MALLOC_FAILURE);
    return 0;
  }

  if (!RSA_verify_raw(rsa, &len, buf, rsa_size, sig, sig_len,
                      RSA_PKCS1_PADDING)) {
    goto out;
  }

  if (!pkcs1_prefixed_msg(&signed_msg, &signed_msg_len, &signed_msg_is_alloced,
                          hash_nid, msg, msg_len)) {
    goto out;
  }

  if (len != signed_msg_len || CRYPTO_memcmp(buf, signed_msg, len) != 0) {
    OPENSSL_PUT_ERROR(RSA, RSA_verify, RSA_R_BAD_SIGNATURE);
    goto out;
  }

  ret = 1;

out:
  if (buf != NULL) {
    OPENSSL_free(buf);
  }
  if (signed_msg_is_alloced) {
    OPENSSL_free(signed_msg);
  }
  return ret;
}

static void bn_free_and_null(BIGNUM **bn) {
  if (*bn == NULL) {
    return;
  }

  BN_free(*bn);
  *bn = NULL;
}

int RSA_check_key(const RSA *key) {
  BIGNUM n, pm1, qm1, lcm, gcd, de, dmp1, dmq1, iqmp;
  BN_CTX *ctx;
  int ok = 0, has_crt_values;

  if (RSA_is_opaque(key)) {
    /* Opaque keys can't be checked. */
    return 1;
  }

  if ((key->p != NULL) != (key->q != NULL)) {
    OPENSSL_PUT_ERROR(RSA, RSA_check_key, RSA_R_ONLY_ONE_OF_P_Q_GIVEN);
    return 0;
  }

  if (!key->n || !key->e) {
    OPENSSL_PUT_ERROR(RSA, RSA_check_key, RSA_R_VALUE_MISSING);
    return 0;
  }

  if (!key->d || !key->p) {
    /* For a public key, or without p and q, there's nothing that can be
     * checked. */
    return 1;
  }

  ctx = BN_CTX_new();
  if (ctx == NULL) {
    OPENSSL_PUT_ERROR(RSA, RSA_check_key, ERR_R_MALLOC_FAILURE);
    return 0;
  }

  BN_init(&n);
  BN_init(&pm1);
  BN_init(&qm1);
  BN_init(&lcm);
  BN_init(&gcd);
  BN_init(&de);
  BN_init(&dmp1);
  BN_init(&dmq1);
  BN_init(&iqmp);

  if (/* n = pq */
      !BN_mul(&n, key->p, key->q, ctx) ||
      /* lcm = lcm(p-1, q-1) */
      !BN_sub(&pm1, key->p, BN_value_one()) ||
      !BN_sub(&qm1, key->q, BN_value_one()) ||
      !BN_mul(&lcm, &pm1, &qm1, ctx) ||
      !BN_gcd(&gcd, &pm1, &qm1, ctx) ||
      !BN_div(&lcm, NULL, &lcm, &gcd, ctx) ||
      /* de = d*e mod lcm(p-1, q-1) */
      !BN_mod_mul(&de, key->d, key->e, &lcm, ctx)) {
    OPENSSL_PUT_ERROR(RSA, RSA_check_key, ERR_LIB_BN);
    goto out;
  }

  if (BN_cmp(&n, key->n) != 0) {
    OPENSSL_PUT_ERROR(RSA, RSA_check_key, RSA_R_N_NOT_EQUAL_P_Q);
    goto out;
  }

  if (!BN_is_one(&de)) {
    OPENSSL_PUT_ERROR(RSA, RSA_check_key, RSA_R_D_E_NOT_CONGRUENT_TO_1);
    goto out;
  }

  has_crt_values = key->dmp1 != NULL;
  if (has_crt_values != (key->dmq1 != NULL) ||
      has_crt_values != (key->iqmp != NULL)) {
    OPENSSL_PUT_ERROR(RSA, RSA_check_key, RSA_R_INCONSISTENT_SET_OF_CRT_VALUES);
    goto out;
  }

  if (has_crt_values) {
    if (/* dmp1 = d mod (p-1) */
        !BN_mod(&dmp1, key->d, &pm1, ctx) ||
        /* dmq1 = d mod (q-1) */
        !BN_mod(&dmq1, key->d, &qm1, ctx) ||
        /* iqmp = q^-1 mod p */
        !BN_mod_inverse(&iqmp, key->q, key->p, ctx)) {
      OPENSSL_PUT_ERROR(RSA, RSA_check_key, ERR_LIB_BN);
      goto out;
    }

    if (BN_cmp(&dmp1, key->dmp1) != 0 ||
        BN_cmp(&dmq1, key->dmq1) != 0 ||
        BN_cmp(&iqmp, key->iqmp) != 0) {
      OPENSSL_PUT_ERROR(RSA, RSA_check_key, RSA_R_CRT_VALUES_INCORRECT);
      goto out;
    }
  }

  ok = 1;

out:
  BN_free(&n);
  BN_free(&pm1);
  BN_free(&qm1);
  BN_free(&lcm);
  BN_free(&gcd);
  BN_free(&de);
  BN_free(&dmp1);
  BN_free(&dmq1);
  BN_free(&iqmp);
  BN_CTX_free(ctx);

  return ok;
}

int RSA_recover_crt_params(RSA *rsa) {
  BN_CTX *ctx;
  BIGNUM *totient, *rem, *multiple, *p_plus_q, *p_minus_q;
  int ok = 0;

  if (rsa->n == NULL || rsa->e == NULL || rsa->d == NULL) {
    OPENSSL_PUT_ERROR(RSA, RSA_recover_crt_params, RSA_R_EMPTY_PUBLIC_KEY);
    return 0;
  }

  if (rsa->p || rsa->q || rsa->dmp1 || rsa->dmq1 || rsa->iqmp) {
    OPENSSL_PUT_ERROR(RSA, RSA_recover_crt_params,
                      RSA_R_CRT_PARAMS_ALREADY_GIVEN);
    return 0;
  }

  /* This uses the algorithm from section 9B of the RSA paper:
   * http://people.csail.mit.edu/rivest/Rsapaper.pdf */

  ctx = BN_CTX_new();
  if (ctx == NULL) {
    OPENSSL_PUT_ERROR(RSA, RSA_recover_crt_params, ERR_R_MALLOC_FAILURE);
    return 0;
  }

  BN_CTX_start(ctx);
  totient = BN_CTX_get(ctx);
  rem = BN_CTX_get(ctx);
  multiple = BN_CTX_get(ctx);
  p_plus_q = BN_CTX_get(ctx);
  p_minus_q = BN_CTX_get(ctx);

  if (totient == NULL || rem == NULL || multiple == NULL || p_plus_q == NULL ||
      p_minus_q == NULL) {
    OPENSSL_PUT_ERROR(RSA, RSA_recover_crt_params, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  /* ed-1 is a small multiple of φ(n). */
  if (!BN_mul(totient, rsa->e, rsa->d, ctx) ||
      !BN_sub_word(totient, 1) ||
      /* φ(n) =
       * pq - p - q + 1 =
       * n - (p + q) + 1
       *
       * Thus n is a reasonable estimate for φ(n). So, (ed-1)/n will be very
       * close. But, when we calculate the quotient, we'll be truncating it
       * because we discard the remainder. Thus (ed-1)/multiple will be >= n,
       * which the totient cannot be. So we add one to the estimate.
       *
       * Consider ed-1 as:
       *
       * multiple * (n - (p+q) + 1) =
       * multiple*n - multiple*(p+q) + multiple
       *
       * When we divide by n, the first term becomes multiple and, since
       * multiple and p+q is tiny compared to n, the second and third terms can
       * be ignored. Thus I claim that subtracting one from the estimate is
       * sufficient. */
      !BN_div(multiple, NULL, totient, rsa->n, ctx) ||
      !BN_add_word(multiple, 1) ||
      !BN_div(totient, rem, totient, multiple, ctx)) {
    OPENSSL_PUT_ERROR(RSA, RSA_recover_crt_params, ERR_R_BN_LIB);
    goto err;
  }

  if (!BN_is_zero(rem)) {
    OPENSSL_PUT_ERROR(RSA, RSA_recover_crt_params, RSA_R_BAD_RSA_PARAMETERS);
    goto err;
  }

  rsa->p = BN_new();
  rsa->q = BN_new();
  rsa->dmp1 = BN_new();
  rsa->dmq1 = BN_new();
  rsa->iqmp = BN_new();
  if (rsa->p == NULL || rsa->q == NULL || rsa->dmp1 == NULL || rsa->dmq1 ==
      NULL || rsa->iqmp == NULL) {
    OPENSSL_PUT_ERROR(RSA, RSA_recover_crt_params, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  /* φ(n) = n - (p + q) + 1 =>
   * n - totient + 1 = p + q */
  if (!BN_sub(p_plus_q, rsa->n, totient) ||
      !BN_add_word(p_plus_q, 1) ||
      /* p - q = sqrt((p+q)^2 - 4n) */
      !BN_sqr(rem, p_plus_q, ctx) ||
      !BN_lshift(multiple, rsa->n, 2) ||
      !BN_sub(rem, rem, multiple) ||
      !BN_sqrt(p_minus_q, rem, ctx) ||
      /* q is 1/2 (p+q)-(p-q) */
      !BN_sub(rsa->q, p_plus_q, p_minus_q) ||
      !BN_rshift1(rsa->q, rsa->q) ||
      !BN_div(rsa->p, NULL, rsa->n, rsa->q, ctx) ||
      !BN_mul(multiple, rsa->p, rsa->q, ctx)) {
    OPENSSL_PUT_ERROR(RSA, RSA_recover_crt_params, ERR_R_BN_LIB);
    goto err;
  }

  if (BN_cmp(multiple, rsa->n) != 0) {
    OPENSSL_PUT_ERROR(RSA, RSA_recover_crt_params, RSA_R_INTERNAL_ERROR);
    goto err;
  }

  if (!BN_sub(rem, rsa->p, BN_value_one()) ||
      !BN_mod(rsa->dmp1, rsa->d, rem, ctx) ||
      !BN_sub(rem, rsa->q, BN_value_one()) ||
      !BN_mod(rsa->dmq1, rsa->d, rem, ctx) ||
      !BN_mod_inverse(rsa->iqmp, rsa->q, rsa->p, ctx)) {
    OPENSSL_PUT_ERROR(RSA, RSA_recover_crt_params, ERR_R_BN_LIB);
    goto err;
  }

  ok = 1;

err:
  BN_CTX_end(ctx);
  BN_CTX_free(ctx);
  if (!ok) {
    bn_free_and_null(&rsa->p);
    bn_free_and_null(&rsa->q);
    bn_free_and_null(&rsa->dmp1);
    bn_free_and_null(&rsa->dmq1);
    bn_free_and_null(&rsa->iqmp);
  }
  return ok;
}

int RSA_private_transform(RSA *rsa, uint8_t *out, const uint8_t *in,
                          size_t len) {
  if (rsa->meth->private_transform) {
    return rsa->meth->private_transform(rsa, out, in, len);
  }

  return RSA_default_method.private_transform(rsa, out, in, len);
}
