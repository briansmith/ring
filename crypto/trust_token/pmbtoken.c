/* Copyright (c) 2020, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include <openssl/bn.h>
#include <openssl/bytestring.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/nid.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/trust_token.h>

#include "../ec_extra/internal.h"
#include "../fipsmodule/bn/internal.h"
#include "../fipsmodule/ec/internal.h"

#include "internal.h"


// get_h returns the generator H for PMBTokens.
//
// x: 66591746412783875033873351891229753622964683369847172829242944646280287810
//    81195403447871073952234683395256591180452378091073292247502091640572714366
//    588045092
// y: 12347430519393087872533727997980072129796839266949808299436682045034861065
//    18810630511924722292325611253427311923464047364545304196431830383014967865
//    162306253
//
// This point was generated with the following Python code.

/*
import hashlib

SEED_H = 'PrivacyPass H'

A = -3
B = 0x051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00
P = 2**521 - 1

def get_y(x):
  y2 = (x**3 + A*x + B) % P
  y = pow(y2, (P+1)/4, P)
  if (y*y) % P != y2:
    raise ValueError("point not on curve")
  return y

def bit(h,i):
  return (ord(h[i/8]) >> (i%8)) & 1

b = 521
def decode_point(so):
  s = hashlib.sha256(so + '0').digest() + hashlib.sha256(so + '1').digest() + \
      hashlib.sha256(so + '2').digest()

  x = 0
  for i in range(0,b):
    x = x + (long(bit(s,i))<<i)
  if x >= P:
    raise ValueError("x out of range")
  y = get_y(x)
  if y & 1 != bit(s,b-1): y = P-y
  return (x, y)


def gen_point(seed):
  v = hashlib.sha256(seed).digest()
  it = 1
  while True:
    try:
      x,y = decode_point(v)
    except Exception, e:
      print e
      it += 1
      v = hashlib.sha256(v).digest()
      continue
    print "Found in %d iterations:" % it
    print "  x = %d" % x
    print "  y = %d" % y
    print " Encoded (hex): (%x, %x)" % (x, y)
    return (x, y)

if __name__ == "__main__":
  gen_point(SEED_H)
*/

static const uint8_t kDefaultAdditionalData[32] = {0};

// TODO(svaldez): Update to use hash2curve to generate H.
static int get_h(EC_RAW_POINT *out_h) {
  EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp521r1);
  if (group == NULL) {
    return 0;
  }

  static const uint8_t kH[] = {
      0x04, 0x01, 0xf0, 0xa9, 0xf7, 0x9e, 0xbc, 0x12, 0x6c, 0xef, 0xd1, 0xab,
      0x29, 0x10, 0x03, 0x6f, 0x4e, 0xf5, 0xbd, 0xeb, 0x0f, 0x6b, 0xc0, 0x5c,
      0x0e, 0xce, 0xfe, 0x59, 0x45, 0xd1, 0x3e, 0x25, 0x33, 0x7e, 0x4c, 0xda,
      0x64, 0x53, 0x54, 0x4e, 0xf9, 0x76, 0x0d, 0x6d, 0xc5, 0x39, 0x2a, 0xd4,
      0xce, 0x84, 0x6e, 0x31, 0xc2, 0x86, 0x21, 0xf9, 0x5c, 0x98, 0xb9, 0x3d,
      0x01, 0x74, 0x9f, 0xc5, 0x1e, 0x47, 0x24, 0x00, 0x5c, 0x17, 0x62, 0x51,
      0x7d, 0x32, 0x5e, 0x29, 0xac, 0x52, 0x14, 0x75, 0x6f, 0x36, 0xd9, 0xc7,
      0xfa, 0xbb, 0xa9, 0x3b, 0x9d, 0x70, 0x49, 0x1e, 0xb4, 0x53, 0xbc, 0x55,
      0xea, 0xad, 0x8f, 0x26, 0x1d, 0xe0, 0xbc, 0xf3, 0x50, 0x5c, 0x7e, 0x66,
      0x41, 0xb5, 0x61, 0x70, 0x12, 0x72, 0xac, 0x6a, 0xb0, 0x6e, 0x78, 0x3d,
      0x17, 0x08, 0xe3, 0xdf, 0x3c, 0xff, 0xa6, 0xa0, 0xea, 0x96, 0x67, 0x92,
      0xcd,
  };

  return ec_point_from_uncompressed(group, out_h, kH, sizeof(kH));
}

static int mul_g_and_p(const EC_GROUP *group, EC_RAW_POINT *out,
                       const EC_RAW_POINT *g, const EC_SCALAR *g_scalar,
                       const EC_RAW_POINT *p, const EC_SCALAR *p_scalar) {
  EC_RAW_POINT tmp1, tmp2;
  if (!ec_point_mul_scalar(group, &tmp1, g, g_scalar) ||
      !ec_point_mul_scalar(group, &tmp2, p, p_scalar)) {
    return 0;
  }

  group->meth->add(group, out, &tmp1, &tmp2);
  return 1;
}

// generate_keypair generates a keypair for the PMBTokens construction.
// |out_x| and |out_y| are set to the secret half of the keypair, while
// |*out_pub| is set to the public half of the keypair. It returns one on
// success and zero on failure.
static int generate_keypair(EC_SCALAR *out_x, EC_SCALAR *out_y,
                            EC_RAW_POINT *out_pub, const EC_GROUP *group) {
  EC_RAW_POINT h, tmp1, tmp2;
  if (!get_h(&h) ||
      !ec_random_nonzero_scalar(group, out_x, kDefaultAdditionalData) ||
      !ec_random_nonzero_scalar(group, out_y, kDefaultAdditionalData) ||
      !ec_point_mul_scalar_base(group, &tmp1, out_x) ||
      !ec_point_mul_scalar(group, &tmp2, &h, out_y)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    return 0;
  }
  group->meth->add(group, out_pub, &tmp1, &tmp2);
  return 1;
}

static int point_to_cbb(CBB *out, const EC_GROUP *group,
                        const EC_RAW_POINT *point) {
  size_t len =
      ec_point_to_bytes(group, point, POINT_CONVERSION_UNCOMPRESSED, NULL, 0);
  if (len == 0) {
    return 0;
  }
  uint8_t *p;
  return CBB_add_space(out, &p, len) &&
         ec_point_to_bytes(group, point, POINT_CONVERSION_UNCOMPRESSED, p,
                           len) == len;
}

int TRUST_TOKEN_generate_key(uint8_t *out_priv_key, size_t *out_priv_key_len,
                             size_t max_priv_key_len, uint8_t *out_pub_key,
                             size_t *out_pub_key_len, size_t max_pub_key_len,
                             uint32_t id) {
  EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp521r1);
  if (group == NULL) {
    return 0;
  }

  EC_RAW_POINT pub0, pub1, pubs;
  EC_SCALAR x0, y0, x1, y1, xs, ys;
  if (!generate_keypair(&x0, &y0, &pub0, group) ||
      !generate_keypair(&x1, &y1, &pub1, group) ||
      !generate_keypair(&xs, &ys, &pubs, group)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_KEYGEN_FAILURE);
    return 0;
  }

  int ret = 0;
  CBB cbb;
  CBB_zero(&cbb);
  size_t scalar_len = BN_num_bytes(&group->order);
  if (!CBB_init_fixed(&cbb, out_priv_key, max_priv_key_len) ||
      !CBB_add_u32(&cbb, id)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_BUFFER_TOO_SMALL);
    goto err;
  }

  const EC_SCALAR *scalars[] = {&x0, &y0, &x1, &y1, &xs, &ys};
  for (size_t i = 0; i < OPENSSL_ARRAY_SIZE(scalars); i++) {
    uint8_t *buf;
    if (!CBB_add_space(&cbb, &buf, scalar_len)) {
      OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_BUFFER_TOO_SMALL);
      goto err;
    }
    ec_scalar_to_bytes(group, buf, &scalar_len, scalars[i]);
  }

  if (!CBB_finish(&cbb, NULL, out_priv_key_len)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_BUFFER_TOO_SMALL);
    goto err;
  }

  CBB pub_cbb;
  if (!CBB_init_fixed(&cbb, out_pub_key, max_pub_key_len) ||
      !CBB_add_u32(&cbb, id) ||
      !CBB_add_u16_length_prefixed(&cbb, &pub_cbb) ||
      !point_to_cbb(&pub_cbb, group, &pub0) ||
      !CBB_add_u16_length_prefixed(&cbb, &pub_cbb) ||
      !point_to_cbb(&pub_cbb, group, &pub1) ||
      !CBB_add_u16_length_prefixed(&cbb, &pub_cbb) ||
      !point_to_cbb(&pub_cbb, group, &pubs) ||
      !CBB_finish(&cbb, NULL, out_pub_key_len)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_BUFFER_TOO_SMALL);
    goto err;
  }

  ret = 1;

err:
  CBB_cleanup(&cbb);
  return ret;
}

void PMBTOKEN_PRETOKEN_free(PMBTOKEN_PRETOKEN *pretoken) {
  OPENSSL_free(pretoken);
}

void PMBTOKEN_TOKEN_free(PMBTOKEN_TOKEN *token) {
  OPENSSL_free(token);
}

// hash_t implements the H_t operation in PMBTokens. It returns on on success
// and zero on error.
static int hash_t(EC_GROUP *group, EC_RAW_POINT *out,
                  const uint8_t t[PMBTOKEN_NONCE_SIZE]) {
  const uint8_t kHashTLabel[] = "PMBTokensV0 HashT";
  return ec_hash_to_curve_p521_xmd_sha512_sswu(
      group, out, kHashTLabel, sizeof(kHashTLabel), t, PMBTOKEN_NONCE_SIZE);
}

// hash_s implements the H_s operation in PMBTokens. It returns on on success
// and zero on error.
static int hash_s(EC_GROUP *group, EC_RAW_POINT *out, const EC_RAW_POINT *t,
                  const uint8_t s[PMBTOKEN_NONCE_SIZE]) {
  const uint8_t kHashSLabel[] = "PMBTokensV0 HashS";
  int ret = 0;
  CBB cbb;
  uint8_t *buf = NULL;
  size_t len;
  if (!CBB_init(&cbb, 0) ||
      !point_to_cbb(&cbb, group, t) ||
      !CBB_add_bytes(&cbb, s, PMBTOKEN_NONCE_SIZE) ||
      !CBB_finish(&cbb, &buf, &len) ||
      !ec_hash_to_curve_p521_xmd_sha512_sswu(group, out, kHashSLabel,
                                             sizeof(kHashSLabel), buf, len)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  ret = 1;

err:
  OPENSSL_free(buf);
  CBB_cleanup(&cbb);
  return ret;
}

PMBTOKEN_PRETOKEN *pmbtoken_blind(void) {
  EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp521r1);
  if (group == NULL) {
    return NULL;
  }

  PMBTOKEN_PRETOKEN *pretoken = OPENSSL_malloc(sizeof(PMBTOKEN_PRETOKEN));
  if (pretoken == NULL) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  RAND_bytes(pretoken->t, sizeof(pretoken->t));

  // We sample |pretoken->r| in Montgomery form to simplify inverting.
  if (!ec_random_nonzero_scalar(group, &pretoken->r,
                                kDefaultAdditionalData)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  EC_SCALAR rinv;
  ec_scalar_inv0_montgomery(group, &rinv, &pretoken->r);
  // Convert both out of Montgomery form.
  ec_scalar_from_montgomery(group, &pretoken->r, &pretoken->r);
  ec_scalar_from_montgomery(group, &rinv, &rinv);

  if (!hash_t(group, &pretoken->T, pretoken->t) ||
      !ec_point_mul_scalar(group, &pretoken->Tp, &pretoken->T, &rinv)) {
    goto err;
  }

  return pretoken;

err:
  OPENSSL_free(pretoken);
  return NULL;
}

int pmbtoken_sign(const TRUST_TOKEN_ISSUER *ctx,
                  uint8_t out_s[PMBTOKEN_NONCE_SIZE], EC_RAW_POINT *out_Wp,
                  EC_RAW_POINT *out_Wsp, const EC_RAW_POINT *Tp,
                  uint32_t key_id, uint8_t private_metadata) {
  EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp521r1);
  if (group == NULL) {
    return 0;
  }

  if (ctx->num_keys == 0) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_NO_KEYS_CONFIGURED);
    return 0;
  }
  const struct trust_token_issuer_key_st *key = NULL;
  for (size_t i = 0; i < ctx->num_keys; i++) {
    if (ctx->keys[i].id == key_id) {
      key = &ctx->keys[i];
      break;
    }
  }

  if (key == NULL) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_INVALID_KEY_ID);
    return 0;
  }

  EC_SCALAR xb, yb;
  BN_ULONG mask = ((BN_ULONG)0) - (private_metadata&1);
  ec_scalar_select(group, &xb, mask, &key->x1, &key->x0);
  ec_scalar_select(group, &yb, mask, &key->y1, &key->y0);

  RAND_bytes(out_s, PMBTOKEN_NONCE_SIZE);

  EC_RAW_POINT Sp;
  if (!hash_s(group, &Sp, Tp, out_s)) {
    return 0;
  }

  if (!mul_g_and_p(group, out_Wp, Tp, &xb, &Sp, &yb) ||
      !mul_g_and_p(group, out_Wsp, Tp, &key->xs, &Sp, &key->ys)) {
    return 0;
  }

  // TODO: DLEQ Proofs
  return 1;
}

int pmbtoken_unblind(PMBTOKEN_TOKEN *out_token,
                     const uint8_t s[PMBTOKEN_NONCE_SIZE],
                     const EC_RAW_POINT *Wp, const EC_RAW_POINT *Wsp,
                     const PMBTOKEN_PRETOKEN *pretoken) {
  EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp521r1);
  if (group == NULL) {
    return 0;
  }

  // TODO: Check DLEQ Proofs

  EC_RAW_POINT Sp;
  if (!hash_s(group, &Sp, &pretoken->Tp, s)) {
    return 0;
  }

  OPENSSL_memcpy(out_token->t, pretoken->t, PMBTOKEN_NONCE_SIZE);
  if (!ec_point_mul_scalar(group, &out_token->S, &Sp, &pretoken->r) ||
      !ec_point_mul_scalar(group, &out_token->W, Wp, &pretoken->r) ||
      !ec_point_mul_scalar(group, &out_token->Ws, Wsp, &pretoken->r)) {
    return 0;
  }

  return 1;
}

int pmbtoken_read(const TRUST_TOKEN_ISSUER *ctx, uint8_t *out_private_metadata,
                  const PMBTOKEN_TOKEN *token, uint32_t key_id) {
  EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp521r1);
  if (group == NULL) {
    return 0;
  }

  if (ctx->num_keys == 0) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_NO_KEYS_CONFIGURED);
    return 0;
  }
  const struct trust_token_issuer_key_st *key = NULL;
  for (size_t i = 0; i < ctx->num_keys; i++) {
    if (ctx->keys[i].id == key_id) {
      key = &ctx->keys[i];
      break;
    }
  }

  if (key == NULL) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_INVALID_KEY_ID);
    return 0;
  }

  EC_RAW_POINT T;
  if (!hash_t(group, &T, token->t)) {
    return 0;
  }

  EC_RAW_POINT calculated;
  // Check the validity of the token.
  if (!mul_g_and_p(group, &calculated, &T, &key->xs, &token->S, &key->ys) ||
      !ec_GFp_simple_points_equal(group, &calculated, &token->Ws)) {
    OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_BAD_VALIDITY_CHECK);
    return 0;
  }

  EC_RAW_POINT W0, W1;
  if (!mul_g_and_p(group, &W0, &T, &key->x0, &token->S, &key->y0) ||
      !mul_g_and_p(group, &W1, &T, &key->x1, &token->S, &key->y1)) {
    return 0;
  }

  const int is_W0 = ec_GFp_simple_points_equal(group, &W0, &token->W);
  const int is_W1 = ec_GFp_simple_points_equal(group, &W1, &token->W);
  const int is_valid = is_W0 ^ is_W1;
  if (!is_valid) {
    // Invalid tokens will fail the validity check above.
    OPENSSL_PUT_ERROR(TRUST_TOKEN, ERR_R_INTERNAL_ERROR);
    return 0;
  }

  *out_private_metadata = is_W1;
  return 1;
}
