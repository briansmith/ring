/******************************************************************************
 *                                                                            *
 * Copyright 2014 Intel Corporation                                           *
 *                                                                            *
 * Licensed under the Apache License, Version 2.0 (the "License");            *
 * you may not use this file except in compliance with the License.           *
 * You may obtain a copy of the License at                                    *
 *                                                                            *
 *    http://www.apache.org/licenses/LICENSE-2.0                              *
 *                                                                            *
 * Unless required by applicable law or agreed to in writing, software        *
 * distributed under the License is distributed on an "AS IS" BASIS,          *
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.   *
 * See the License for the specific language governing permissions and        *
 * limitations under the License.                                             *
 *                                                                            *
 ******************************************************************************
 *                                                                            *
 * Developers and authors:                                                    *
 * Shay Gueron (1, 2), and Vlad Krasnov (1)                                   *
 * (1) Intel Corporation, Israel Development Center                           *
 * (2) University of Haifa                                                    *
 * Reference:                                                                 *
 * S.Gueron and V.Krasnov, "Fast Prime Field Elliptic Curve Cryptography with *
 *                          256 Bit Primes"                                   *
 *                                                                            *
 ******************************************************************************/

/* Point double: r = 2*a */
static void ecp_nistz256_point_double(P256_POINT * r, const P256_POINT * a)
{
    BN_ULONG S[P256_LIMBS];
    BN_ULONG M[P256_LIMBS];
    BN_ULONG Zsqr[P256_LIMBS];
    BN_ULONG tmp0[P256_LIMBS];

    const BN_ULONG *in_x = a->X;
    const BN_ULONG *in_y = a->Y;
    const BN_ULONG *in_z = a->Z;

    BN_ULONG *res_x = r->X;
    BN_ULONG *res_y = r->Y;
    BN_ULONG *res_z = r->Z;

    ecp_nistz256_mul_by_2(S, in_y);

    ecp_nistz256_sqr_mont(Zsqr, in_z);

    ecp_nistz256_sqr_mont(S, S);

    ecp_nistz256_mul_mont(res_z, in_z, in_y);
    ecp_nistz256_mul_by_2(res_z, res_z);

    ecp_nistz256_add(M, in_x, Zsqr);
    ecp_nistz256_sub(Zsqr, in_x, Zsqr);

    ecp_nistz256_sqr_mont(res_y, S);
    ecp_nistz256_div_by_2(res_y, res_y);

    ecp_nistz256_mul_mont(M, M, Zsqr);
    ecp_nistz256_mul_by_3(M, M);

    ecp_nistz256_mul_mont(S, S, in_x);
    ecp_nistz256_mul_by_2(tmp0, S);

    ecp_nistz256_sqr_mont(res_x, M);

    ecp_nistz256_sub(res_x, res_x, tmp0);
    ecp_nistz256_sub(S, S, res_x);

    ecp_nistz256_mul_mont(S, S, M);
    ecp_nistz256_sub(res_y, S, res_y);
}

/* Point addition: r = a+b */
static void ecp_nistz256_point_add(P256_POINT * r,
                                   const P256_POINT * a, const P256_POINT * b)
{
    BN_ULONG U2[P256_LIMBS], S2[P256_LIMBS];
    BN_ULONG U1[P256_LIMBS], S1[P256_LIMBS];
    BN_ULONG Z1sqr[P256_LIMBS];
    BN_ULONG Z2sqr[P256_LIMBS];
    BN_ULONG H[P256_LIMBS], R[P256_LIMBS];
    BN_ULONG Hsqr[P256_LIMBS];
    BN_ULONG Rsqr[P256_LIMBS];
    BN_ULONG Hcub[P256_LIMBS];

    BN_ULONG res_x[P256_LIMBS];
    BN_ULONG res_y[P256_LIMBS];
    BN_ULONG res_z[P256_LIMBS];

    BN_ULONG in1infty, in2infty;

    const BN_ULONG *in1_x = a->X;
    const BN_ULONG *in1_y = a->Y;
    const BN_ULONG *in1_z = a->Z;

    const BN_ULONG *in2_x = b->X;
    const BN_ULONG *in2_y = b->Y;
    const BN_ULONG *in2_z = b->Z;

    /* We encode infinity as (0,0), which is not on the curve,
     * so it is OK. */
    in1infty = in1_x[0] | in1_x[1] | in1_x[2] | in1_x[3] |
               in1_y[0] | in1_y[1] | in1_y[2] | in1_y[3];
    if (P256_LIMBS == 8)
        in1infty |= in1_x[4] | in1_x[5] | in1_x[6] | in1_x[7] |
                    in1_y[4] | in1_y[5] | in1_y[6] | in1_y[7];

    in2infty = in2_x[0] | in2_x[1] | in2_x[2] | in2_x[3] |
               in2_y[0] | in2_y[1] | in2_y[2] | in2_y[3];
    if (P256_LIMBS == 8)
        in2infty |= in2_x[4] | in2_x[5] | in2_x[6] | in2_x[7] |
                    in2_y[4] | in2_y[5] | in2_y[6] | in2_y[7];

    in1infty = is_zero(in1infty);
    in2infty = is_zero(in2infty);

    ecp_nistz256_sqr_mont(Z2sqr, in2_z);        /* Z2^2 */
    ecp_nistz256_sqr_mont(Z1sqr, in1_z);        /* Z1^2 */

    ecp_nistz256_mul_mont(S1, Z2sqr, in2_z);    /* S1 = Z2^3 */
    ecp_nistz256_mul_mont(S2, Z1sqr, in1_z);    /* S2 = Z1^3 */

    ecp_nistz256_mul_mont(S1, S1, in1_y);       /* S1 = Y1*Z2^3 */
    ecp_nistz256_mul_mont(S2, S2, in2_y);       /* S2 = Y2*Z1^3 */
    ecp_nistz256_sub(R, S2, S1);                /* R = S2 - S1 */

    ecp_nistz256_mul_mont(U1, in1_x, Z2sqr);    /* U1 = X1*Z2^2 */
    ecp_nistz256_mul_mont(U2, in2_x, Z1sqr);    /* U2 = X2*Z1^2 */
    ecp_nistz256_sub(H, U2, U1);                /* H = U2 - U1 */

    /* This should not happen during sign/ecdh,
     * so no constant time violation */
    if (is_equal(U1, U2) && !in1infty && !in2infty) {
        if (is_equal(S1, S2)) {
            ecp_nistz256_point_double(r, a);
            return;
        } else {
            memset(r, 0, sizeof(*r));
            return;
        }
    }

    ecp_nistz256_sqr_mont(Rsqr, R);             /* R^2 */
    ecp_nistz256_mul_mont(res_z, H, in1_z);     /* Z3 = H*Z1*Z2 */
    ecp_nistz256_sqr_mont(Hsqr, H);             /* H^2 */
    ecp_nistz256_mul_mont(res_z, res_z, in2_z); /* Z3 = H*Z1*Z2 */
    ecp_nistz256_mul_mont(Hcub, Hsqr, H);       /* H^3 */

    ecp_nistz256_mul_mont(U2, U1, Hsqr);        /* U1*H^2 */
    ecp_nistz256_mul_by_2(Hsqr, U2);            /* 2*U1*H^2 */

    ecp_nistz256_sub(res_x, Rsqr, Hsqr);
    ecp_nistz256_sub(res_x, res_x, Hcub);

    ecp_nistz256_sub(res_y, U2, res_x);

    ecp_nistz256_mul_mont(S2, S1, Hcub);
    ecp_nistz256_mul_mont(res_y, R, res_y);
    ecp_nistz256_sub(res_y, res_y, S2);

    copy_conditional(res_x, in2_x, in1infty);
    copy_conditional(res_y, in2_y, in1infty);
    copy_conditional(res_z, in2_z, in1infty);

    copy_conditional(res_x, in1_x, in2infty);
    copy_conditional(res_y, in1_y, in2infty);
    copy_conditional(res_z, in1_z, in2infty);

    memcpy(r->X, res_x, sizeof(res_x));
    memcpy(r->Y, res_y, sizeof(res_y));
    memcpy(r->Z, res_z, sizeof(res_z));
}

/* Point addition when b is known to be affine: r = a+b */
static void ecp_nistz256_point_add_affine(P256_POINT * r,
                                          const P256_POINT * a,
                                          const P256_POINT_AFFINE * b)
{
    BN_ULONG U2[P256_LIMBS], S2[P256_LIMBS];
    BN_ULONG Z1sqr[P256_LIMBS];
    BN_ULONG H[P256_LIMBS], R[P256_LIMBS];
    BN_ULONG Hsqr[P256_LIMBS];
    BN_ULONG Rsqr[P256_LIMBS];
    BN_ULONG Hcub[P256_LIMBS];

    BN_ULONG res_x[P256_LIMBS];
    BN_ULONG res_y[P256_LIMBS];
    BN_ULONG res_z[P256_LIMBS];

    BN_ULONG in1infty, in2infty;

    const BN_ULONG *in1_x = a->X;
    const BN_ULONG *in1_y = a->Y;
    const BN_ULONG *in1_z = a->Z;

    const BN_ULONG *in2_x = b->X;
    const BN_ULONG *in2_y = b->Y;

    /* In affine representation we encode infty as (0,0),
     * which is not on the curve, so it is OK */
    in1infty = in1_x[0] | in1_x[1] | in1_x[2] | in1_x[3] |
               in1_y[0] | in1_y[1] | in1_y[2] | in1_y[3];
    if (P256_LIMBS == 8)
        in1infty |= in1_x[4] | in1_x[5] | in1_x[6] | in1_x[7] |
                    in1_y[4] | in1_y[5] | in1_y[6] | in1_y[7];

    in2infty = in2_x[0] | in2_x[1] | in2_x[2] | in2_x[3] |
               in2_y[0] | in2_y[1] | in2_y[2] | in2_y[3];
    if (P256_LIMBS == 8)
        in2infty |= in2_x[4] | in2_x[5] | in2_x[6] | in2_x[7] |
                    in2_y[4] | in2_y[5] | in2_y[6] | in2_y[7];

    in1infty = is_zero(in1infty);
    in2infty = is_zero(in2infty);

    ecp_nistz256_sqr_mont(Z1sqr, in1_z);        /* Z1^2 */

    ecp_nistz256_mul_mont(U2, in2_x, Z1sqr);    /* U2 = X2*Z1^2 */
    ecp_nistz256_sub(H, U2, in1_x);             /* H = U2 - U1 */

    ecp_nistz256_mul_mont(S2, Z1sqr, in1_z);    /* S2 = Z1^3 */

    ecp_nistz256_mul_mont(res_z, H, in1_z);     /* Z3 = H*Z1*Z2 */

    ecp_nistz256_mul_mont(S2, S2, in2_y);       /* S2 = Y2*Z1^3 */
    ecp_nistz256_sub(R, S2, in1_y);             /* R = S2 - S1 */

    ecp_nistz256_sqr_mont(Hsqr, H);             /* H^2 */
    ecp_nistz256_sqr_mont(Rsqr, R);             /* R^2 */
    ecp_nistz256_mul_mont(Hcub, Hsqr, H);       /* H^3 */

    ecp_nistz256_mul_mont(U2, in1_x, Hsqr);     /* U1*H^2 */
    ecp_nistz256_mul_by_2(Hsqr, U2);            /* 2*U1*H^2 */

    ecp_nistz256_sub(res_x, Rsqr, Hsqr);
    ecp_nistz256_sub(res_x, res_x, Hcub);
    ecp_nistz256_sub(H, U2, res_x);

    ecp_nistz256_mul_mont(S2, in1_y, Hcub);
    ecp_nistz256_mul_mont(H, H, R);
    ecp_nistz256_sub(res_y, H, S2);

    copy_conditional(res_x, in2_x, in1infty);
    copy_conditional(res_x, in1_x, in2infty);

    copy_conditional(res_y, in2_y, in1infty);
    copy_conditional(res_y, in1_y, in2infty);

    copy_conditional(res_z, ONE, in1infty);
    copy_conditional(res_z, in1_z, in2infty);

    memcpy(r->X, res_x, sizeof(res_x));
    memcpy(r->Y, res_y, sizeof(res_y));
    memcpy(r->Z, res_z, sizeof(res_z));
}
