/* ====================================================================
 * Copyright (c) 1998-2005 The OpenSSL Project.  All rights reserved.
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
 *    openssl-core@OpenSSL.org.
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

#include <openssl/ecdsa.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/obj.h>
#include <openssl/rand.h>


int test_builtin(BIO *out) {
  size_t n = 0;
  EC_KEY *eckey = NULL, *wrong_eckey = NULL;
  EC_GROUP *group;
  BIGNUM *order = NULL;
  ECDSA_SIG *ecdsa_sig = NULL;
  unsigned char digest[20], wrong_digest[20];
  unsigned char *signature = NULL;
  const unsigned char *sig_ptr;
  unsigned char *sig_ptr2;
  unsigned char *raw_buf = NULL;
  unsigned int sig_len, r_len, s_len, bn_len, buf_len;
  int nid, ret = 0;

  /* fill digest values with some random data */
  if (!RAND_bytes(digest, 20) || !RAND_bytes(wrong_digest, 20)) {
    BIO_printf(out, "ERROR: unable to get random data\n");
    goto builtin_err;
  }

  order = BN_new();
  if (order == NULL) {
    goto builtin_err;
  }

  /* create and verify a ecdsa signature with every availble curve
   * (with ) */
  BIO_printf(out,
             "\ntesting ECDSA_sign() and ECDSA_verify() "
             "with some internal curves:\n");

  static const int kCurveNIDs[] = {NID_secp224r1, NID_X9_62_prime256v1,
                                   NID_secp384r1, NID_secp521r1, NID_undef};

  /* now create and verify a signature for every curve */
  for (n = 0; kCurveNIDs[n] != NID_undef; n++) {
    unsigned char dirt, offset;

    nid = kCurveNIDs[n];
    /* create new ecdsa key (== EC_KEY) */
    eckey = EC_KEY_new();
    if (eckey == NULL) {
      goto builtin_err;
    }
    group = EC_GROUP_new_by_curve_name(nid);
    if (group == NULL) {
      goto builtin_err;
    }
    if (!EC_KEY_set_group(eckey, group)) {
      goto builtin_err;
    }
    EC_GROUP_free(group);
    if (!EC_GROUP_get_order(EC_KEY_get0_group(eckey), order, NULL)) {
      goto builtin_err;
    }
    if (BN_num_bits(order) < 160) {
      /* Too small to test. */
      EC_KEY_free(eckey);
      eckey = NULL;
      continue;
    }

    BIO_printf(out, "%s: ", OBJ_nid2sn(nid));
    /* create key */
    if (!EC_KEY_generate_key(eckey)) {
      BIO_printf(out, " failed\n");
      goto builtin_err;
    }
    /* create second key */
    wrong_eckey = EC_KEY_new();
    if (wrong_eckey == NULL) {
      goto builtin_err;
    }
    group = EC_GROUP_new_by_curve_name(nid);
    if (group == NULL) {
      goto builtin_err;
    }
    if (EC_KEY_set_group(wrong_eckey, group) == 0) {
      goto builtin_err;
    }
    EC_GROUP_free(group);
    if (!EC_KEY_generate_key(wrong_eckey)) {
      BIO_printf(out, " failed\n");
      goto builtin_err;
    }

    BIO_printf(out, ".");
    (void)BIO_flush(out);
    /* check key */
    if (!EC_KEY_check_key(eckey)) {
      BIO_printf(out, " failed\n");
      goto builtin_err;
    }
    BIO_printf(out, ".");
    (void)BIO_flush(out);
    /* create signature */
    sig_len = ECDSA_size(eckey);
    signature = OPENSSL_malloc(sig_len);
    if (signature == NULL) {
      goto builtin_err;
    }
    if (!ECDSA_sign(0, digest, 20, signature, &sig_len, eckey)) {
      BIO_printf(out, " failed\n");
      goto builtin_err;
    }
    BIO_printf(out, ".");
    (void)BIO_flush(out);
    /* verify signature */
    if (ECDSA_verify(0, digest, 20, signature, sig_len, eckey) != 1) {
      BIO_printf(out, " failed\n");
      goto builtin_err;
    }
    BIO_printf(out, ".");
    (void)BIO_flush(out);
    /* verify signature with the wrong key */
    if (ECDSA_verify(0, digest, 20, signature, sig_len, wrong_eckey) == 1) {
      BIO_printf(out, " failed\n");
      goto builtin_err;
    }
    BIO_printf(out, ".");
    (void)BIO_flush(out);
    /* wrong digest */
    if (ECDSA_verify(0, wrong_digest, 20, signature, sig_len, eckey) == 1) {
      BIO_printf(out, " failed\n");
      goto builtin_err;
    }
    BIO_printf(out, ".");
    (void)BIO_flush(out);
    /* wrong length */
    if (ECDSA_verify(0, digest, 20, signature, sig_len - 1, eckey) == 1) {
      BIO_printf(out, " failed\n");
      goto builtin_err;
    }
    BIO_printf(out, ".");
    (void)BIO_flush(out);

    /* Modify a single byte of the signature: to ensure we don't
     * garble the ASN1 structure, we read the raw signature and
     * modify a byte in one of the bignums directly. */
    sig_ptr = signature;
    ecdsa_sig = d2i_ECDSA_SIG(NULL, &sig_ptr, sig_len);
    if (ecdsa_sig == NULL) {
      BIO_printf(out, " failed\n");
      goto builtin_err;
    }

    /* Store the two BIGNUMs in raw_buf. */
    r_len = BN_num_bytes(ecdsa_sig->r);
    s_len = BN_num_bytes(ecdsa_sig->s);
    bn_len = BN_num_bytes(order);
    if (r_len > bn_len || s_len > bn_len) {
      BIO_printf(out, " failed\n");
      goto builtin_err;
    }
    buf_len = 2 * bn_len;
    raw_buf = OPENSSL_malloc(2 * bn_len);
    if (raw_buf == NULL) {
      goto builtin_err;
    }
    /* Pad the bignums with leading zeroes. */
    if (!BN_bn2bin_padded(raw_buf, bn_len, ecdsa_sig->r) ||
        !BN_bn2bin_padded(raw_buf + bn_len, bn_len, ecdsa_sig->s)) {
      goto builtin_err;
    }

    /* Modify a single byte in the buffer. */
    offset = raw_buf[10] % buf_len;
    dirt = raw_buf[11] ? raw_buf[11] : 1;
    raw_buf[offset] ^= dirt;
    /* Now read the BIGNUMs back in from raw_buf. */
    if (BN_bin2bn(raw_buf, bn_len, ecdsa_sig->r) == NULL ||
        BN_bin2bn(raw_buf + bn_len, bn_len, ecdsa_sig->s) == NULL) {
      goto builtin_err;
    }

    sig_ptr2 = signature;
    sig_len = i2d_ECDSA_SIG(ecdsa_sig, &sig_ptr2);
    if (ECDSA_verify(0, digest, 20, signature, sig_len, eckey) == 1) {
      BIO_printf(out, " failed\n");
      goto builtin_err;
    }
    /* Sanity check: undo the modification and verify signature. */
    raw_buf[offset] ^= dirt;
    if (BN_bin2bn(raw_buf, bn_len, ecdsa_sig->r) == NULL ||
        BN_bin2bn(raw_buf + bn_len, bn_len, ecdsa_sig->s) == NULL) {
      goto builtin_err;
    }

    sig_ptr2 = signature;
    sig_len = i2d_ECDSA_SIG(ecdsa_sig, &sig_ptr2);
    if (ECDSA_verify(0, digest, 20, signature, sig_len, eckey) != 1) {
      BIO_printf(out, " failed\n");
      goto builtin_err;
    }
    BIO_printf(out, ".");
    (void)BIO_flush(out);

    BIO_printf(out, " ok\n");
    /* cleanup */
    /* clean bogus errors */
    ERR_clear_error();
    OPENSSL_free(signature);
    signature = NULL;
    EC_KEY_free(eckey);
    eckey = NULL;
    EC_KEY_free(wrong_eckey);
    wrong_eckey = NULL;
    ECDSA_SIG_free(ecdsa_sig);
    ecdsa_sig = NULL;
    OPENSSL_free(raw_buf);
    raw_buf = NULL;
  }

  ret = 1;
builtin_err:
  if (eckey) {
    EC_KEY_free(eckey);
  }
  if (order) {
    BN_free(order);
  }
  if (wrong_eckey) {
    EC_KEY_free(wrong_eckey);
  }
  if (ecdsa_sig) {
    ECDSA_SIG_free(ecdsa_sig);
  }
  if (signature) {
    OPENSSL_free(signature);
  }
  if (raw_buf) {
    OPENSSL_free(raw_buf);
  }

  return ret;
}

int main(void) {
  int ret = 1;
  BIO *out;

  CRYPTO_library_init();
  ERR_load_crypto_strings();

  out = BIO_new_fp(stdout, BIO_NOCLOSE);

  if (!test_builtin(out)) {
    goto err;
  }

  ret = 0;

err:
  if (ret) {
    BIO_printf(out, "\nECDSA test failed\n");
  } else {
    BIO_printf(out, "\nPASS\n");
  }
  if (ret) {
    BIO_print_errors(out);
  }

  if (out != NULL) {
    BIO_free(out);
  }

  return ret;
}
