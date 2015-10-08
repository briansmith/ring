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

#include <vector>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/obj.h>
#include <openssl/rand.h>

#include "../test/scoped_types.h"
#include "../test/stl_compat.h"

enum Api {
  kEncodedApi,
  kRawApi,
};

static bool point2oct(ScopedOpenSSLBytes *out, size_t *out_len,
                      const EC_GROUP *group, const EC_POINT *point) {
  size_t der_len = EC_POINT_point2oct(group, point,
                                      POINT_CONVERSION_UNCOMPRESSED, NULL, 0,
                                      NULL);
  if (der_len <= 0) {
    return false;
  }
  out->reset((uint8_t *)OPENSSL_malloc(der_len));
  if (!out) {
    return false;
  }
  der_len = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED,
                               out->get(), der_len, NULL);
  if (der_len <= 0) {
    return false;
  }
  *out_len = der_len;
  return true;
}

// VerifyECDSASig returns true on success, false on failure.
static bool VerifyECDSASig(Api api, int digest_nid, const uint8_t *digest,
                           size_t digest_len, const ECDSA_SIG *ecdsa_sig,
                           EC_GROUP_new_fn ec_group_new, const EC_GROUP *group,
                           const EC_POINT *pub_key,
                           int expected_result) {
  int actual_result;

  switch (api) {
    case kEncodedApi: {
      uint8_t *sig_der;
      size_t sig_der_len;
      if (!ECDSA_SIG_to_bytes(&sig_der, &sig_der_len, ecdsa_sig)) {
        return false;
      }
      ScopedOpenSSLBytes delete_sig_der(sig_der);
      ScopedOpenSSLBytes key_der(nullptr);
      size_t key_der_len;
      if (!point2oct(&key_der, &key_der_len, group, pub_key)) {
        return false;
      }
      actual_result = ECDSA_verify_signed_digest(digest_nid, digest, digest_len,
                                                 sig_der, sig_der_len,
                                                 ec_group_new, key_der.get(),
                                                 key_der_len);
      break;
    }

    case kRawApi:
      actual_result = ECDSA_do_verify_point(digest, digest_len, ecdsa_sig,
                                            group, pub_key);
      break;

    default:
      return false;
  }
  return expected_result == actual_result;
}

// TestTamperedSig verifies that signature verification fails when a valid
// signature is tampered with. |ecdsa_sig| must be a valid signature, which will
// be modified. TestTamperedSig returns true on success, false on failure.
static bool TestTamperedSig(FILE *out, Api api, int digest_nid,
                            const uint8_t *digest, size_t digest_len,
                            ECDSA_SIG *ecdsa_sig, EC_GROUP_new_fn ec_group_new,
                            const EC_GROUP *group, const EC_POINT *pub_key,
                            const BIGNUM *order) {
  // Modify a single byte of the signature: to ensure we don't
  // garble the ASN1 structure, we read the raw signature and
  // modify a byte in one of the bignums directly.

  // Store the two BIGNUMs in raw_buf.
  size_t r_len = BN_num_bytes(ecdsa_sig->r);
  size_t s_len = BN_num_bytes(ecdsa_sig->s);
  size_t bn_len = BN_num_bytes(order);
  if (r_len > bn_len || s_len > bn_len) {
    return false;
  }
  size_t buf_len = 2 * bn_len;
  std::vector<uint8_t> raw_buf(buf_len);
  // Pad the bignums with leading zeroes.
  if (!BN_bn2bin_padded(bssl::vector_data(&raw_buf), bn_len, ecdsa_sig->r) ||
      !BN_bn2bin_padded(bssl::vector_data(&raw_buf) + bn_len, bn_len,
                        ecdsa_sig->s)) {
    return false;
  }

  // Modify a single byte in the buffer.
  size_t offset = raw_buf[10] % buf_len;
  uint8_t dirt = raw_buf[11] ? raw_buf[11] : 1;
  raw_buf[offset] ^= dirt;
  // Now read the BIGNUMs back in from raw_buf.
  if (BN_bin2bn(bssl::vector_data(&raw_buf), bn_len, ecdsa_sig->r) == NULL ||
      BN_bin2bn(bssl::vector_data(&raw_buf) + bn_len, bn_len,
                ecdsa_sig->s) == NULL ||
      !VerifyECDSASig(api, digest_nid, digest, digest_len, ecdsa_sig,
                      ec_group_new, group, pub_key, 0)) {
    return false;
  }

  // Sanity check: Undo the modification and verify signature.
  raw_buf[offset] ^= dirt;
  if (BN_bin2bn(bssl::vector_data(&raw_buf), bn_len, ecdsa_sig->r) == NULL ||
      BN_bin2bn(bssl::vector_data(&raw_buf) + bn_len, bn_len,
                ecdsa_sig->s) == NULL ||
      !VerifyECDSASig(api, digest_nid, digest, digest_len, ecdsa_sig,
                      ec_group_new, group, pub_key, 1)) {
    return false;
  }

  return true;
}

static bool TestBuiltin(FILE *out) {
  // Fill digest values with some random data.
  uint8_t digest[20], wrong_digest[20];
  if (!RAND_bytes(digest, 20) || !RAND_bytes(wrong_digest, 20)) {
    fprintf(out, "ERROR: unable to get random data\n");
    return false;
  }

  static const struct {
    EC_GROUP_new_fn ec_group_new;
    const char *name;
  } kCurves[] = {
      { EC_GROUP_new_p224, "secp224r1" },
      { EC_GROUP_new_p256, "secp256r1" },
      { EC_GROUP_new_p384, "secp384r1" },
      { EC_GROUP_new_p521, "secp521r1" },
      { NID_undef, NULL }
  };

  // Create and verify ECDSA signatures with every available curve.
  fputs("\ntesting ECDSA_sign(), ECDSA_verify(), ECDSA_do_sign(), and "
        "ECDSA_do_verify() with some internal curves:\n", out);

  for (size_t n = 0; kCurves[n].ec_group_new != NULL; n++) {
    fprintf(out, "%s: ", kCurves[n].name);

    // Create a new ECDSA key.
    ScopedEC_KEY eckey(EC_KEY_generate_key_ex(kCurves[n].ec_group_new));
    if (!eckey) {
      fprintf(out, " failed\n");
      return false;
    }

    const EC_GROUP *group = EC_KEY_get0_group(eckey.get());
    if (!group) {
      fprintf(out, " failed\n");
      return false;
    }

    ScopedBIGNUM order(BN_new());
    if (!order || !EC_GROUP_get_order(group, order.get(), NULL)) {
      fprintf(out, " failed\n");
      return false;
    }

    // Create a second key.
    ScopedEC_KEY wrong_eckey(EC_KEY_generate_key_ex(kCurves[n].ec_group_new));
    if (!wrong_eckey) {
      fprintf(out, " failed\n");
      return false;
    }

    fprintf(out, ".");
    fflush(out);

    // Check the key.
    if (!EC_KEY_check_key(eckey.get())) {
      fprintf(out, " failed\n");
      return false;
    }
    fprintf(out, ".");
    fflush(out);

    ScopedOpenSSLBytes eckey_der(nullptr);
    size_t eckey_der_len;
    if (!point2oct(&eckey_der, &eckey_der_len, group,
                   EC_KEY_get0_public_key(eckey.get()))) {
      fprintf(out, " failed\n");
      return false;
    }

    ScopedOpenSSLBytes wrong_eckey_der(nullptr);
    size_t wrong_eckey_der_len;
    if (!point2oct(&wrong_eckey_der, &wrong_eckey_der_len, group,
                   EC_KEY_get0_public_key(wrong_eckey.get()))) {
      fprintf(out, " failed\n");
      return false;
    }


    // Test ASN.1-encoded signatures.
    // Create a signature.
    unsigned sig_len = ECDSA_size(eckey.get());
    std::vector<uint8_t> signature(sig_len);
    if (!ECDSA_sign(0, digest, 20, bssl::vector_data(&signature), &sig_len,
                    eckey.get())) {
      fprintf(out, " failed\n");
      return false;
    }
    signature.resize(sig_len);
    fprintf(out, ".");
    fflush(out);
    // Verify the signature.
    if (!ECDSA_verify_signed_digest(NID_sha1, digest, 20,
                                    bssl::vector_data(&signature),
                                    signature.size(), kCurves[n].ec_group_new,
                                    eckey_der.get(), eckey_der_len)) {
      fprintf(out, " failed\n");
      return false;
    }
    fprintf(out, ".");
    fflush(out);
    // Verify the signature with the wrong key.
    if (ECDSA_verify_signed_digest(NID_sha1, digest, 20,
                                   bssl::vector_data(&signature),
                                   signature.size(), kCurves[n].ec_group_new,
                                   wrong_eckey_der.get(), wrong_eckey_der_len)) {
      fprintf(out, " failed\n");
      return false;
    }
    fprintf(out, ".");
    fflush(out);
    // Verify the signature using the wrong digest.
    if (ECDSA_verify_signed_digest(NID_sha1, wrong_digest, 20,
                                   bssl::vector_data(&signature),
                                   signature.size(), kCurves[n].ec_group_new,
                                   eckey_der.get(), eckey_der_len)) {
      fprintf(out, " failed\n");
      return false;
    }
    fprintf(out, ".");
    fflush(out);
    // Verify a truncated signature.
    if (ECDSA_verify_signed_digest(NID_sha1, digest, 20,
                                   bssl::vector_data(&signature),
                                   signature.size() - 1,
                                   kCurves[n].ec_group_new, eckey_der.get(),
                                   eckey_der_len)) {
      fprintf(out, " failed\n");
      return false;
    }
    fprintf(out, ".");
    fflush(out);
    // Verify a tampered signature.
    ScopedECDSA_SIG ecdsa_sig(ECDSA_SIG_from_bytes(
        bssl::vector_data(&signature), signature.size()));
    if (!ecdsa_sig ||
        !TestTamperedSig(out, kEncodedApi, NID_sha1, digest, 20, ecdsa_sig.get(),
                         kCurves[n].ec_group_new, group,
                         EC_KEY_get0_public_key(eckey.get()), order.get())) {
      fprintf(out, " failed\n");
      return false;
    }
    fprintf(out, ".");
    fflush(out);

    // Test ECDSA_SIG signing and verification.
    // Create a signature.
    ecdsa_sig.reset(ECDSA_do_sign(digest, 20, eckey.get()));
    if (!ecdsa_sig) {
      fprintf(out, " failed\n");
      return false;
    }
    fprintf(out, ".");
    fflush(out);
    // Verify the signature using the correct key.
    if (!ECDSA_do_verify_point(digest, 20, ecdsa_sig.get(), group,
                               EC_KEY_get0_public_key(eckey.get()))) {
      fprintf(out, " failed\n");
      return false;
    }
    fprintf(out, ".");
    fflush(out);
    // Verify the signature with the wrong key.
    if (ECDSA_do_verify_point(digest, 20, ecdsa_sig.get(), group,
                              EC_KEY_get0_public_key(wrong_eckey.get()))) {
      fprintf(out, " failed\n");
      return false;
    }
    fprintf(out, ".");
    fflush(out);
    // Verify the signature using the wrong digest.
    if (ECDSA_do_verify_point(wrong_digest, 20, ecdsa_sig.get(),  group,
                              EC_KEY_get0_public_key(eckey.get()))) {
      fprintf(out, " failed\n");
      return false;
    }
    fprintf(out, ".");
    fflush(out);
    // Verify a tampered signature.
    if (!TestTamperedSig(out, kRawApi, NID_sha1, digest, 20, ecdsa_sig.get(),
                         kCurves[n].ec_group_new, group,
                         EC_KEY_get0_public_key(eckey.get()), order.get())) {
      fprintf(out, " failed\n");
      return false;
    }
    fprintf(out, ".");
    fflush(out);

    fprintf(out, " ok\n");
    // Clear bogus errors.
    ERR_clear_error();
  }

  return true;
}

static bool TestECDSA_SIG_max_len(size_t order_len) {
  /* Create the largest possible |ECDSA_SIG| of the given constraints. */
  ScopedECDSA_SIG sig(ECDSA_SIG_new());
  if (!sig) {
    return false;
  }
  std::vector<uint8_t> bytes(order_len, 0xff);
  if (!BN_bin2bn(bssl::vector_data(&bytes), bytes.size(), sig->r) ||
      !BN_bin2bn(bssl::vector_data(&bytes), bytes.size(), sig->s)) {
    return false;
  }
  /* Serialize it. */
  uint8_t *der;
  size_t der_len;
  if (!ECDSA_SIG_to_bytes(&der, &der_len, sig.get())) {
    return false;
  }
  ScopedOpenSSLBytes delete_der(der);

  size_t max_len = ECDSA_SIG_max_len(order_len);
  if (max_len != der_len) {
    fprintf(stderr, "ECDSA_SIG_max_len(%u) returned %u, wanted %u\n",
            static_cast<unsigned>(order_len), static_cast<unsigned>(max_len),
            static_cast<unsigned>(der_len));
    return false;
  }
  return true;
}

int main(void) {
  CRYPTO_library_init();

  if (!TestBuiltin(stdout) ||
      !TestECDSA_SIG_max_len(224/8) ||
      !TestECDSA_SIG_max_len(256/8) ||
      !TestECDSA_SIG_max_len(384/8) ||
      !TestECDSA_SIG_max_len(512/8) ||
      !TestECDSA_SIG_max_len(10000)) {
    printf("\nECDSA test failed\n");
    return 1;
  }

  printf("\nPASS\n");
  return 0;
}
