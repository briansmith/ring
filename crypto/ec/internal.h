/* Originally written by Bodo Moeller for the OpenSSL project.
 * ====================================================================
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
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
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
 * Hudson (tjh@cryptsoft.com).
 *
 */
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 *
 * Portions of the attached software ("Contribution") are developed by
 * SUN MICROSYSTEMS, INC., and are contributed to the OpenSSL project.
 *
 * The Contribution is licensed pursuant to the OpenSSL open source
 * license provided above.
 *
 * The elliptic curve binary polynomial software is originally written by
 * Sheueling Chang Shantz and Douglas Stebila of Sun Microsystems
 * Laboratories. */

#ifndef OPENSSL_HEADER_EC_INTERNAL_H
#define OPENSSL_HEADER_EC_INTERNAL_H

#include <openssl/ec.h>

#include <openssl/bn.h>

#if defined(__cplusplus)
extern "C" {
#endif


typedef struct ec_method_st {
  int (*point_get_affine_coordinates)(const EC_GROUP *, const EC_POINT *,
                                      BIGNUM *x, BIGNUM *y, BN_CTX *);

  /* Point multiplication for the case where any secret scalars are involved.
   *
   * Computes |r = g_scalar*generator + p_scalar*p| if |g_scalar| and |p_scalar|
   * are both non-null. Computes |r = g_scalar*generator| if |p_scalar| is null.
   * Computes |r = p_scalar*p| if g_scalar is null. At least one of |g_scalar|
   * and |p_scalar| must be non-null, and |p| must be non-null if |p_scalar| is
   * non-null. The scalars must be in the range [0, group->order-1]. */
  int (*mul_private)(const EC_GROUP *group, EC_POINT *r, const BIGNUM *g_scalar,
                     const EC_POINT *p, const BIGNUM *p_scalar, BN_CTX *ctx);

  /* Point multiplication for the case where no private scalars are involved.
   *
   * Computes |r = g_scalar*generator + p_scalar*p| if |g_scalar| and |p_scalar|
   * are both non-null. Computes |r = g_scalar*generator| if |p_scalar| is null.
   * Computes |r = p_scalar*p| if g_scalar is null. At least one of |g_scalar|
   * and |p_scalar| must be non-null, and |p| must be non-null if |p_scalar| is
   * non-null. The scalars must be in the range [0, group->order-1]. */
  int (*mul_public)(const EC_GROUP *group, EC_POINT *r, const BIGNUM *g_scalar,
                    const EC_POINT *p, const BIGNUM *p_scalar, BN_CTX *ctx);

  /* 'field_mul' and 'field_sqr' can be used by 'add' and 'dbl' so that the
   * same implementations of point operations can be used with different
   * optimized implementations of expensive field operations: */
  int (*field_mul)(const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                   const BIGNUM *b, BN_CTX *);
  int (*field_sqr)(const EC_GROUP *, BIGNUM *r, const BIGNUM *a, BN_CTX *);

  int (*field_encode)(const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                      BN_CTX *); /* e.g. to Montgomery */
  int (*field_decode)(const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                      BN_CTX *); /* e.g. from Montgomery */
} EC_METHOD;

extern const EC_METHOD EC_GFp_mont_method;

struct ec_point_st {
  const EC_METHOD *meth;

  BIGNUM X;
  BIGNUM Y;
  BIGNUM Z; /* Jacobian projective coordinates:
             * (X, Y, Z)  represents  (X/Z^2, Y/Z^3)  if  Z != 0 */
} /* EC_POINT */;

struct ec_group_st {
  const EC_METHOD *meth;

  const EC_POINT generator;
  const BIGNUM order;
  const BN_MONT_CTX order_mont;
  const BIGNUM order_minus_2;

  int curve_name; /* optional NID for named curve */

  /* The following members are handled by the method functions,
   * even if they appear generic */

  BIGNUM field; /* For curves over GF(p), this is the modulus. */

  BIGNUM a, b; /* Curve coefficients. */

  BN_MONT_CTX mont; /* Montgomery structure. */
  BIGNUM one; /* The value one */
} /* EC_GROUP */;

EC_GROUP *ec_group_new(const EC_METHOD *meth);

int ec_wNAF_mul_private(const EC_GROUP *group, EC_POINT *r,
                        const BIGNUM *g_scalar, const EC_POINT *p,
                        const BIGNUM *p_scalar, BN_CTX *ctx);
int ec_wNAF_mul_public(const EC_GROUP *group, EC_POINT *r,
                       const BIGNUM *g_scalar, const EC_POINT *p,
                       const BIGNUM *p_scalar, BN_CTX *ctx);

/* method functions in simple.c */
unsigned ec_GFp_simple_group_get_degree(const EC_GROUP *);
int ec_GFp_simple_point_init(EC_POINT *);
void ec_GFp_simple_point_finish(EC_POINT *);
int ec_GFp_simple_point_copy(EC_POINT *, const EC_POINT *);
int ec_GFp_simple_point_set_to_infinity(EC_POINT *);
int ec_GFp_simple_set_Jprojective_coordinates_GFp(const EC_GROUP *, EC_POINT *,
                                                  const BIGNUM *x,
                                                  const BIGNUM *y,
                                                  const BIGNUM *z, BN_CTX *);
int ec_GFp_simple_point_set_affine_coordinates(const EC_GROUP *, EC_POINT *,
                                               const BIGNUM *x, const BIGNUM *y,
                                               BN_CTX *);
int ec_GFp_simple_add(const EC_GROUP *, EC_POINT *r, const EC_POINT *a,
                      const EC_POINT *b, BN_CTX *);
int ec_GFp_simple_dbl(const EC_GROUP *, EC_POINT *r, const EC_POINT *a,
                      BN_CTX *);
int ec_GFp_simple_invert(const EC_GROUP *, EC_POINT *);
int ec_GFp_simple_is_at_infinity(const EC_POINT *);
int ec_GFp_simple_is_on_curve(const EC_GROUP *, const EC_POINT *, BN_CTX *);

/* method functions in montgomery.c */
int ec_GFp_mont_field_mul(const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                          const BIGNUM *b, BN_CTX *);
int ec_GFp_mont_field_sqr(const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                          BN_CTX *);
int ec_GFp_mont_field_encode(const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                             BN_CTX *);
int ec_GFp_mont_field_decode(const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                             BN_CTX *);

int ec_point_set_Jprojective_coordinates_GFp(const EC_GROUP *group,
                                             EC_POINT *point, const BIGNUM *x,
                                             const BIGNUM *y, const BIGNUM *z,
                                             BN_CTX *ctx);

void ec_GFp_nistp_recode_scalar_bits(uint8_t *sign, uint8_t *digit, uint8_t in);

extern const EC_METHOD EC_GFp_nistp256_method;
extern const EC_METHOD EC_GFp_nistz256_method;

struct ec_key_st {
  const EC_GROUP *group;

  EC_POINT *pub_key;
  BIGNUM *priv_key;
} /* EC_KEY */;


#if defined(__cplusplus)
}  /* extern C */
#endif

#endif  /* OPENSSL_HEADER_EC_INTERNAL_H */
