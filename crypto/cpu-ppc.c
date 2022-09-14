/*
 * Copyright 2009-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
/* This file is derived from ppccap.c in OpenSSL */

#include <ring-core/cpu.h>
#include "internal.h"

int bn_mul_mont_int(unsigned long *rp, const unsigned long *ap, const unsigned long *bp,
                    const unsigned long *np, const unsigned long *n0, int num);
int bn_mul4x_mont_int(unsigned long *rp, const unsigned long *ap, const unsigned long *bp,
                      const unsigned long *np, const unsigned long *n0, int num);
int bn_mul_mont(unsigned long *rp, const unsigned long *ap, const unsigned long *bp,
                const unsigned long *np, const unsigned long *n0, int num)
{
    if (num < 4)
        return 0;

    if ((num & 3) == 0)
        return bn_mul4x_mont_int(rp, ap, bp, np, n0, num);

    /*
     * There used to be [optional] call to bn_mul_mont_fpu64 here,
     * but above subroutine is faster on contemporary processors.
     * Formulation means that there might be old processors where
     * FPU code path would be faster, POWER6 perhaps, but there was
     * no opportunity to figure it out...
     */

    return bn_mul_mont_int(rp, ap, bp, np, n0, num);
}


