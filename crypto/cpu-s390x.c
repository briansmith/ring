/*
 * Copyright 2010-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/auxv.h>
#include "GFp/s390x_arch.h"

#define LEN	128
#define STR_(S)	#S
#define STR(S)	STR_(S)

#define TOK_FUNC(NAME)							\
    (sscanf(tok_begin,							\
            " " STR(NAME) " : %" STR(LEN) "[^:] : "			\
            "%" STR(LEN) "s %" STR(LEN) "s ",				\
            tok[0], tok[1], tok[2]) == 2) {				\
									\
        off = (tok[0][0] == '~') ? 1 : 0;				\
        if (sscanf(tok[0] + off, "%llx", &cap->NAME[0]) != 1)		\
            goto ret;							\
        if (off)							\
            cap->NAME[0] = ~cap->NAME[0];				\
									\
        off = (tok[1][0] == '~') ? 1 : 0;				\
        if (sscanf(tok[1] + off, "%llx", &cap->NAME[1]) != 1)		\
            goto ret;							\
        if (off)							\
            cap->NAME[1] = ~cap->NAME[1];				\
    }

#define TOK_CPU(NAME)							\
    (sscanf(tok_begin,							\
            " %" STR(LEN) "s %" STR(LEN) "s ",				\
            tok[0], tok[1]) == 1					\
     && !strcmp(tok[0], #NAME)) {					\
            memcpy(cap, &NAME, sizeof(*cap));				\
    }

static int parse_env(const char *env, struct GFp_s390xcap_st *cap);

static inline void s390x_stfle(void *ptr, size_t size)
{
  typedef unsigned char buf_t[size];
  register size_t _size __asm__ ("%r0") = size;
  __asm__ volatile (".insn s,0xb2b00000,%0"
                    : "+Q" (* (buf_t *) ptr) : "r" (_size));
}

static inline void s390x_kimd_query(void *ptr)
{
  typedef unsigned char buf_t[16];
  register size_t _function __asm__ ("%r0") = S390X_QUERY;
  register void * _param __asm__ ("%r1") = ptr;
  __asm__ volatile (".long 0xb93e0002"
                    : "+m" (* (buf_t *) ptr) : "r" (_function), "r" (_param));
}

static inline void s390x_klmd_query(void *ptr)
{
  typedef unsigned char buf_t[16];
  register size_t _function __asm__ ("%r0") = S390X_QUERY;
  register void * _param __asm__ ("%r1") = ptr;
  __asm__ volatile (".long 0xb93f0002"
                    : "+m" (* (buf_t *) ptr) : "r" (_function), "r" (_param));
}

static inline void s390x_km_query(void *ptr)
{
  typedef unsigned char buf_t[16];
  register size_t _function __asm__ ("%r0") = S390X_QUERY;
  register void * _param __asm__ ("%r1") = ptr;
  __asm__ volatile (".long 0xb92e0042"
                    : "+m" (* (buf_t *) ptr) : "r" (_function), "r" (_param));
}

static inline void s390x_kmc_query(void *ptr)
{
  typedef unsigned char buf_t[16];
  register size_t _function __asm__ ("%r0") = S390X_QUERY;
  register void * _param __asm__ ("%r1") = ptr;
  __asm__ volatile (".long 0xb92f0042"
                    : "+m" (* (buf_t *) ptr) : "r" (_function), "r" (_param));
}

static inline void s390x_kmac_query(void *ptr)
{
  typedef unsigned char buf_t[16];
  register size_t _function __asm__ ("%r0") = S390X_QUERY;
  register void * _param __asm__ ("%r1") = ptr;
  __asm__ volatile (".long 0xb91e0042"
                    : "+m" (* (buf_t *) ptr) : "r" (_function), "r" (_param));
}

static inline void s390x_kmctr_query(void *ptr)
{
  typedef unsigned char buf_t[16];
  register size_t _function __asm__ ("%r0") = S390X_QUERY;
  register void * _param __asm__ ("%r1") = ptr;
  __asm__ volatile (".long 0xb92d2042"
                    : "+m" (* (buf_t *) ptr) : "r" (_function), "r" (_param));
}

static inline void s390x_kmo_query(void *ptr)
{
  typedef unsigned char buf_t[16];
  register size_t _function __asm__ ("%r0") = S390X_QUERY;
  register void * _param __asm__ ("%r1") = ptr;
  __asm__ volatile (".long 0xb92b0042"
                    : "+m" (* (buf_t *) ptr) : "r" (_function), "r" (_param));
}

static inline void s390x_kmf_query(void *ptr)
{
  typedef unsigned char buf_t[16];
  register size_t _function __asm__ ("%r0") = S390X_QUERY;
  register void * _param __asm__ ("%r1") = ptr;
  __asm__ volatile (".long 0xb92a0042"
                    : "+m" (* (buf_t *) ptr) : "r" (_function), "r" (_param));
}

static inline void s390x_prno_query(void *ptr)
{
  typedef unsigned char buf_t[16];
  register size_t _function __asm__ ("%r0") = S390X_QUERY;
  register void * _param __asm__ ("%r1") = ptr;
  __asm__ volatile (".long 0xb93c0042"
                    : "+m" (* (buf_t *) ptr) : "r" (_function), "r" (_param));
}

static inline void s390x_kma_query(void *ptr)
{
  typedef unsigned char buf_t[16];
  register size_t _function __asm__ ("%r0") = S390X_QUERY;
  register void * _param __asm__ ("%r1") = ptr;
  __asm__ volatile (".long 0xb9294022"
                    : "+m" (* (buf_t *) ptr) : "r" (_function), "r" (_param));
}

struct GFp_s390xcap_st GFp_s390xcap_P;

void GFp_cpuid_setup(void)
{
    unsigned long long hwcap = getauxval(AT_HWCAP);
    struct GFp_s390xcap_st cap;
    const char *env;

    if (GFp_s390xcap_P.stfle[0])
        return;

    memset(&GFp_s390xcap_P, 0, sizeof GFp_s390xcap_P);

    /* set a bit that will not be tested later */
    GFp_s390xcap_P.stfle[0] |= S390X_CAPBIT(0);

    env = getenv("OPENSSL_s390xcap");
    if (env != NULL) {
        if (!parse_env(env, &cap))
            env = NULL;
    }

    /* protection against missing store-facility-list-extended */
    if (hwcap & HWCAP_S390_STFLE) {
        s390x_stfle(&GFp_s390xcap_P.stfle, sizeof GFp_s390xcap_P.stfle);
    }

    if (env != NULL) {
        GFp_s390xcap_P.stfle[0] &= cap.stfle[0];
        GFp_s390xcap_P.stfle[1] &= cap.stfle[1];
        GFp_s390xcap_P.stfle[2] &= cap.stfle[2];
    }

    /* protection against disabled vector facility */
    if (!(hwcap & HWCAP_S390_VX)) {
        GFp_s390xcap_P.stfle[2] &= ~(S390X_CAPBIT(S390X_VX)
                                     | S390X_CAPBIT(S390X_VXD)
                                     | S390X_CAPBIT(S390X_VXE));
    }

    /* query message-security-assist capabilities */
    if (GFp_s390xcap_P.stfle[0] & S390X_CAPBIT(S390X_MSA)) {
        s390x_kimd_query(&GFp_s390xcap_P.kimd);
        s390x_klmd_query(&GFp_s390xcap_P.klmd);
        s390x_km_query(&GFp_s390xcap_P.km);
        s390x_kmc_query(&GFp_s390xcap_P.kmc);
        s390x_kmac_query(&GFp_s390xcap_P.kmac);
    }
    if (GFp_s390xcap_P.stfle[1] & S390X_CAPBIT(S390X_MSA4)) {
        s390x_kmctr_query(&GFp_s390xcap_P.kmctr);
        s390x_kmo_query(&GFp_s390xcap_P.kmo);
        s390x_kmf_query(&GFp_s390xcap_P.kmf);
    }
    if (GFp_s390xcap_P.stfle[0] & S390X_CAPBIT(S390X_MSA5)) {
        s390x_prno_query(&GFp_s390xcap_P.prno);
    }
    if (GFp_s390xcap_P.stfle[2] & S390X_CAPBIT(S390X_MSA8)) {
        s390x_kma_query(&GFp_s390xcap_P.kma);
    }

    if (env != NULL) {
        GFp_s390xcap_P.kimd[0] &= cap.kimd[0];
        GFp_s390xcap_P.kimd[1] &= cap.kimd[1];
        GFp_s390xcap_P.klmd[0] &= cap.klmd[0];
        GFp_s390xcap_P.klmd[1] &= cap.klmd[1];
        GFp_s390xcap_P.km[0] &= cap.km[0];
        GFp_s390xcap_P.km[1] &= cap.km[1];
        GFp_s390xcap_P.kmc[0] &= cap.kmc[0];
        GFp_s390xcap_P.kmc[1] &= cap.kmc[1];
        GFp_s390xcap_P.kmac[0] &= cap.kmac[0];
        GFp_s390xcap_P.kmac[1] &= cap.kmac[1];
        GFp_s390xcap_P.kmctr[0] &= cap.kmctr[0];
        GFp_s390xcap_P.kmctr[1] &= cap.kmctr[1];
        GFp_s390xcap_P.kmo[0] &= cap.kmo[0];
        GFp_s390xcap_P.kmo[1] &= cap.kmo[1];
        GFp_s390xcap_P.kmf[0] &= cap.kmf[0];
        GFp_s390xcap_P.kmf[1] &= cap.kmf[1];
        GFp_s390xcap_P.prno[0] &= cap.prno[0];
        GFp_s390xcap_P.prno[1] &= cap.prno[1];
        GFp_s390xcap_P.kma[0] &= cap.kma[0];
        GFp_s390xcap_P.kma[1] &= cap.kma[1];
    }
}

static int parse_env(const char *env, struct GFp_s390xcap_st *cap)
{
    /*-
     * CPU model data
     * (only the STFLE- and QUERY-bits relevant to libcrypto are set)
     */

    /*-
     * z900 (2000) - z/Architecture POP SA22-7832-00
     * Facility detection would fail on real hw (no STFLE).
     */
    static const struct GFp_s390xcap_st z900 = {
        /*.stfle  = */{0ULL, 0ULL, 0ULL, 0ULL},
        /*.kimd   = */{0ULL, 0ULL},
        /*.klmd   = */{0ULL, 0ULL},
        /*.km     = */{0ULL, 0ULL},
        /*.kmc    = */{0ULL, 0ULL},
        /*.kmac   = */{0ULL, 0ULL},
        /*.kmctr  = */{0ULL, 0ULL},
        /*.kmo    = */{0ULL, 0ULL},
        /*.kmf    = */{0ULL, 0ULL},
        /*.prno   = */{0ULL, 0ULL},
        /*.kma    = */{0ULL, 0ULL},
    };

    /*-
     * z990 (2003) - z/Architecture POP SA22-7832-02
     * Implements MSA. Facility detection would fail on real hw (no STFLE).
     */
    static const struct GFp_s390xcap_st z990 = {
        /*.stfle  = */{S390X_CAPBIT(S390X_MSA),
                       0ULL, 0ULL, 0ULL},
        /*.kimd   = */{S390X_CAPBIT(S390X_QUERY)
                       | S390X_CAPBIT(S390X_SHA_1),
                       0ULL},
        /*.klmd   = */{S390X_CAPBIT(S390X_QUERY)
                       | S390X_CAPBIT(S390X_SHA_1),
                       0ULL},
        /*.km     = */{S390X_CAPBIT(S390X_QUERY),
                       0ULL},
        /*.kmc    = */{S390X_CAPBIT(S390X_QUERY),
                       0ULL},
        /*.kmac   = */{S390X_CAPBIT(S390X_QUERY),
                       0ULL},
        /*.kmctr  = */{0ULL, 0ULL},
        /*.kmo    = */{0ULL, 0ULL},
        /*.kmf    = */{0ULL, 0ULL},
        /*.prno   = */{0ULL, 0ULL},
        /*.kma    = */{0ULL, 0ULL},
    };

    /*-
     * z9 (2005) - z/Architecture POP SA22-7832-04
     * Implements MSA and MSA1.
     */
    static const struct GFp_s390xcap_st z9 = {
        /*.stfle  = */{S390X_CAPBIT(S390X_MSA)
                       | S390X_CAPBIT(S390X_STCKF),
                       0ULL, 0ULL, 0ULL},
        /*.kimd   = */{S390X_CAPBIT(S390X_QUERY)
                       | S390X_CAPBIT(S390X_SHA_1)
                       | S390X_CAPBIT(S390X_SHA_256),
                       0ULL},
        /*.klmd   = */{S390X_CAPBIT(S390X_QUERY)
                       | S390X_CAPBIT(S390X_SHA_1)
                       | S390X_CAPBIT(S390X_SHA_256),
                       0ULL},
        /*.km     = */{S390X_CAPBIT(S390X_QUERY)
                       | S390X_CAPBIT(S390X_AES_128),
                       0ULL},
        /*.kmc    = */{S390X_CAPBIT(S390X_QUERY)
                       | S390X_CAPBIT(S390X_AES_128),
                       0ULL},
        /*.kmac   = */{S390X_CAPBIT(S390X_QUERY),
                       0ULL},
        /*.kmctr  = */{0ULL, 0ULL},
        /*.kmo    = */{0ULL, 0ULL},
        /*.kmf    = */{0ULL, 0ULL},
        /*.prno   = */{0ULL, 0ULL},
        /*.kma    = */{0ULL, 0ULL},
    };

    /*-
     * z10 (2008) - z/Architecture POP SA22-7832-06
     * Implements MSA and MSA1-2.
     */
    static const struct GFp_s390xcap_st z10 = {
        /*.stfle  = */{S390X_CAPBIT(S390X_MSA)
                       | S390X_CAPBIT(S390X_STCKF),
                       0ULL, 0ULL, 0ULL},
        /*.kimd   = */{S390X_CAPBIT(S390X_QUERY)
                       | S390X_CAPBIT(S390X_SHA_1)
                       | S390X_CAPBIT(S390X_SHA_256)
                       | S390X_CAPBIT(S390X_SHA_512),
                       0ULL},
        /*.klmd   = */{S390X_CAPBIT(S390X_QUERY)
                       | S390X_CAPBIT(S390X_SHA_1)
                       | S390X_CAPBIT(S390X_SHA_256)
                       | S390X_CAPBIT(S390X_SHA_512),
                       0ULL},
        /*.km     = */{S390X_CAPBIT(S390X_QUERY)
                       | S390X_CAPBIT(S390X_AES_128)
                       | S390X_CAPBIT(S390X_AES_192)
                       | S390X_CAPBIT(S390X_AES_256),
                       0ULL},
        /*.kmc    = */{S390X_CAPBIT(S390X_QUERY)
                       | S390X_CAPBIT(S390X_AES_128)
                       | S390X_CAPBIT(S390X_AES_192)
                       | S390X_CAPBIT(S390X_AES_256),
                       0ULL},
        /*.kmac   = */{S390X_CAPBIT(S390X_QUERY),
                       0ULL},
        /*.kmctr  = */{0ULL, 0ULL},
        /*.kmo    = */{0ULL, 0ULL},
        /*.kmf    = */{0ULL, 0ULL},
        /*.prno   = */{0ULL, 0ULL},
        /*.kma    = */{0ULL, 0ULL},
    };

    /*-
     * z196 (2010) - z/Architecture POP SA22-7832-08
     * Implements MSA and MSA1-4.
     */
    static const struct GFp_s390xcap_st z196 = {
        /*.stfle  = */{S390X_CAPBIT(S390X_MSA)
                       | S390X_CAPBIT(S390X_STCKF),
                       S390X_CAPBIT(S390X_MSA3)
                       | S390X_CAPBIT(S390X_MSA4),
                       0ULL, 0ULL},
        /*.kimd   = */{S390X_CAPBIT(S390X_QUERY)
                       | S390X_CAPBIT(S390X_SHA_1)
                       | S390X_CAPBIT(S390X_SHA_256)
                       | S390X_CAPBIT(S390X_SHA_512),
                       S390X_CAPBIT(S390X_GHASH)},
        /*.klmd   = */{S390X_CAPBIT(S390X_QUERY)
                       | S390X_CAPBIT(S390X_SHA_1)
                       | S390X_CAPBIT(S390X_SHA_256)
                       | S390X_CAPBIT(S390X_SHA_512),
                       0ULL},
        /*.km     = */{S390X_CAPBIT(S390X_QUERY)
                       | S390X_CAPBIT(S390X_AES_128)
                       | S390X_CAPBIT(S390X_AES_192)
                       | S390X_CAPBIT(S390X_AES_256)
                       | S390X_CAPBIT(S390X_XTS_AES_128)
                       | S390X_CAPBIT(S390X_XTS_AES_256),
                       0ULL},
        /*.kmc    = */{S390X_CAPBIT(S390X_QUERY)
                       | S390X_CAPBIT(S390X_AES_128)
                       | S390X_CAPBIT(S390X_AES_192)
                       | S390X_CAPBIT(S390X_AES_256),
                       0ULL},
        /*.kmac   = */{S390X_CAPBIT(S390X_QUERY)
                       | S390X_CAPBIT(S390X_AES_128)
                       | S390X_CAPBIT(S390X_AES_192)
                       | S390X_CAPBIT(S390X_AES_256),
                       0ULL},
        /*.kmctr  = */{S390X_CAPBIT(S390X_QUERY)
                       | S390X_CAPBIT(S390X_AES_128)
                       | S390X_CAPBIT(S390X_AES_192)
                       | S390X_CAPBIT(S390X_AES_256),
                       0ULL},
        /*.kmo    = */{S390X_CAPBIT(S390X_QUERY)
                       | S390X_CAPBIT(S390X_AES_128)
                       | S390X_CAPBIT(S390X_AES_192)
                       | S390X_CAPBIT(S390X_AES_256),
                       0ULL},
        /*.kmf    = */{S390X_CAPBIT(S390X_QUERY)
                       | S390X_CAPBIT(S390X_AES_128)
                       | S390X_CAPBIT(S390X_AES_192)
                       | S390X_CAPBIT(S390X_AES_256),
                       0ULL},
        /*.prno   = */{0ULL, 0ULL},
        /*.kma    = */{0ULL, 0ULL},
    };

    /*-
     * zEC12 (2012) - z/Architecture POP SA22-7832-09
     * Implements MSA and MSA1-4.
     */
    static const struct GFp_s390xcap_st zEC12 = {
        /*.stfle  = */{S390X_CAPBIT(S390X_MSA)
                       | S390X_CAPBIT(S390X_STCKF),
                       S390X_CAPBIT(S390X_MSA3)
                       | S390X_CAPBIT(S390X_MSA4),
                       0ULL, 0ULL},
        /*.kimd   = */{S390X_CAPBIT(S390X_QUERY)
                       | S390X_CAPBIT(S390X_SHA_1)
                       | S390X_CAPBIT(S390X_SHA_256)
                       | S390X_CAPBIT(S390X_SHA_512),
                   S390X_CAPBIT(S390X_GHASH)},
        /*.klmd   = */{S390X_CAPBIT(S390X_QUERY)
                       | S390X_CAPBIT(S390X_SHA_1)
                       | S390X_CAPBIT(S390X_SHA_256)
                       | S390X_CAPBIT(S390X_SHA_512),
                       0ULL},
        /*.km     = */{S390X_CAPBIT(S390X_QUERY)
                       | S390X_CAPBIT(S390X_AES_128)
                       | S390X_CAPBIT(S390X_AES_192)
                       | S390X_CAPBIT(S390X_AES_256)
                       | S390X_CAPBIT(S390X_XTS_AES_128)
                       | S390X_CAPBIT(S390X_XTS_AES_256),
                       0ULL},
        /*.kmc    = */{S390X_CAPBIT(S390X_QUERY)
                       | S390X_CAPBIT(S390X_AES_128)
                       | S390X_CAPBIT(S390X_AES_192)
                       | S390X_CAPBIT(S390X_AES_256),
                       0ULL},
        /*.kmac   = */{S390X_CAPBIT(S390X_QUERY)
                       | S390X_CAPBIT(S390X_AES_128)
                       | S390X_CAPBIT(S390X_AES_192)
                       | S390X_CAPBIT(S390X_AES_256),
                       0ULL},
        /*.kmctr  = */{S390X_CAPBIT(S390X_QUERY)
                       | S390X_CAPBIT(S390X_AES_128)
                       | S390X_CAPBIT(S390X_AES_192)
                       | S390X_CAPBIT(S390X_AES_256),
                       0ULL},
        /*.kmo    = */{S390X_CAPBIT(S390X_QUERY)
                       | S390X_CAPBIT(S390X_AES_128)
                       | S390X_CAPBIT(S390X_AES_192)
                       | S390X_CAPBIT(S390X_AES_256),
                       0ULL},
        /*.kmf    = */{S390X_CAPBIT(S390X_QUERY)
                       | S390X_CAPBIT(S390X_AES_128)
                       | S390X_CAPBIT(S390X_AES_192)
                       | S390X_CAPBIT(S390X_AES_256),
                       0ULL},
        /*.prno   = */{0ULL, 0ULL},
        /*.kma    = */{0ULL, 0ULL},
    };

    /*-
     * z13 (2015) - z/Architecture POP SA22-7832-10
     * Implements MSA and MSA1-5.
     */
    static const struct GFp_s390xcap_st z13 = {
        /*.stfle  = */{S390X_CAPBIT(S390X_MSA)
                       | S390X_CAPBIT(S390X_STCKF)
                       | S390X_CAPBIT(S390X_MSA5),
                       S390X_CAPBIT(S390X_MSA3)
                       | S390X_CAPBIT(S390X_MSA4),
                       S390X_CAPBIT(S390X_VX),
                       0ULL},
        /*.kimd   = */{S390X_CAPBIT(S390X_QUERY)
                       | S390X_CAPBIT(S390X_SHA_1)
                       | S390X_CAPBIT(S390X_SHA_256)
                       | S390X_CAPBIT(S390X_SHA_512),
                       S390X_CAPBIT(S390X_GHASH)},
        /*.klmd   = */{S390X_CAPBIT(S390X_QUERY)
                       | S390X_CAPBIT(S390X_SHA_1)
                       | S390X_CAPBIT(S390X_SHA_256)
                       | S390X_CAPBIT(S390X_SHA_512),
                       0ULL},
        /*.km     = */{S390X_CAPBIT(S390X_QUERY)
                       | S390X_CAPBIT(S390X_AES_128)
                       | S390X_CAPBIT(S390X_AES_192)
                       | S390X_CAPBIT(S390X_AES_256)
                       | S390X_CAPBIT(S390X_XTS_AES_128)
                       | S390X_CAPBIT(S390X_XTS_AES_256),
                       0ULL},
        /*.kmc    = */{S390X_CAPBIT(S390X_QUERY)
                       | S390X_CAPBIT(S390X_AES_128)
                       | S390X_CAPBIT(S390X_AES_192)
                       | S390X_CAPBIT(S390X_AES_256),
                       0ULL},
        /*.kmac   = */{S390X_CAPBIT(S390X_QUERY)
                       | S390X_CAPBIT(S390X_AES_128)
                       | S390X_CAPBIT(S390X_AES_192)
                       | S390X_CAPBIT(S390X_AES_256),
                       0ULL},
        /*.kmctr  = */{S390X_CAPBIT(S390X_QUERY)
                       | S390X_CAPBIT(S390X_AES_128)
                       | S390X_CAPBIT(S390X_AES_192)
                       | S390X_CAPBIT(S390X_AES_256),
                       0ULL},
        /*.kmo    = */{S390X_CAPBIT(S390X_QUERY)
                       | S390X_CAPBIT(S390X_AES_128)
                       | S390X_CAPBIT(S390X_AES_192)
                       | S390X_CAPBIT(S390X_AES_256),
                       0ULL},
        /*.kmf    = */{S390X_CAPBIT(S390X_QUERY)
                       | S390X_CAPBIT(S390X_AES_128)
                       | S390X_CAPBIT(S390X_AES_192)
                       | S390X_CAPBIT(S390X_AES_256),
                       0ULL},
        /*.prno   = */{S390X_CAPBIT(S390X_QUERY)
                       | S390X_CAPBIT(S390X_SHA_512_DRNG),
                       0ULL},
        /*.kma    = */{0ULL, 0ULL},
    };

    /*-
     * z14 (2017) - z/Architecture POP SA22-7832-11
     * Implements MSA and MSA1-8.
     */
    static const struct GFp_s390xcap_st z14 = {
        /*.stfle  = */{S390X_CAPBIT(S390X_MSA)
                       | S390X_CAPBIT(S390X_STCKF)
                       | S390X_CAPBIT(S390X_MSA5),
                       S390X_CAPBIT(S390X_MSA3)
                       | S390X_CAPBIT(S390X_MSA4),
                       S390X_CAPBIT(S390X_VX)
                       | S390X_CAPBIT(S390X_VXD)
                       | S390X_CAPBIT(S390X_VXE)
                       | S390X_CAPBIT(S390X_MSA8),
                       0ULL},
        /*.kimd   = */{S390X_CAPBIT(S390X_QUERY)
                       | S390X_CAPBIT(S390X_SHA_1)
                       | S390X_CAPBIT(S390X_SHA_256)
                       | S390X_CAPBIT(S390X_SHA_512)
                       | S390X_CAPBIT(S390X_SHA3_224)
                       | S390X_CAPBIT(S390X_SHA3_256)
                       | S390X_CAPBIT(S390X_SHA3_384)
                       | S390X_CAPBIT(S390X_SHA3_512)
                       | S390X_CAPBIT(S390X_SHAKE_128)
                       | S390X_CAPBIT(S390X_SHAKE_256),
                       S390X_CAPBIT(S390X_GHASH)},
        /*.klmd   = */{S390X_CAPBIT(S390X_QUERY)
                       | S390X_CAPBIT(S390X_SHA_1)
                       | S390X_CAPBIT(S390X_SHA_256)
                       | S390X_CAPBIT(S390X_SHA_512)
                       | S390X_CAPBIT(S390X_SHA3_224)
                       | S390X_CAPBIT(S390X_SHA3_256)
                       | S390X_CAPBIT(S390X_SHA3_384)
                       | S390X_CAPBIT(S390X_SHA3_512)
                       | S390X_CAPBIT(S390X_SHAKE_128)
                       | S390X_CAPBIT(S390X_SHAKE_256),
                       0ULL},
        /*.km     = */{S390X_CAPBIT(S390X_QUERY)
                       | S390X_CAPBIT(S390X_AES_128)
                       | S390X_CAPBIT(S390X_AES_192)
                       | S390X_CAPBIT(S390X_AES_256)
                       | S390X_CAPBIT(S390X_XTS_AES_128)
                       | S390X_CAPBIT(S390X_XTS_AES_256),
                       0ULL},
        /*.kmc    = */{S390X_CAPBIT(S390X_QUERY)
                       | S390X_CAPBIT(S390X_AES_128)
                       | S390X_CAPBIT(S390X_AES_192)
                       | S390X_CAPBIT(S390X_AES_256),
                       0ULL},
        /*.kmac   = */{S390X_CAPBIT(S390X_QUERY)
                       | S390X_CAPBIT(S390X_AES_128)
                       | S390X_CAPBIT(S390X_AES_192)
                       | S390X_CAPBIT(S390X_AES_256),
                       0ULL},
        /*.kmctr  = */{S390X_CAPBIT(S390X_QUERY)
                       | S390X_CAPBIT(S390X_AES_128)
                       | S390X_CAPBIT(S390X_AES_192)
                       | S390X_CAPBIT(S390X_AES_256),
                       0ULL},
        /*.kmo    = */{S390X_CAPBIT(S390X_QUERY)
                       | S390X_CAPBIT(S390X_AES_128)
                       | S390X_CAPBIT(S390X_AES_192)
                       | S390X_CAPBIT(S390X_AES_256),
                       0ULL},
        /*.kmf    = */{S390X_CAPBIT(S390X_QUERY)
                       | S390X_CAPBIT(S390X_AES_128)
                       | S390X_CAPBIT(S390X_AES_192)
                       | S390X_CAPBIT(S390X_AES_256),
                       0ULL},
        /*.prno   = */{S390X_CAPBIT(S390X_QUERY)
                       | S390X_CAPBIT(S390X_SHA_512_DRNG),
                       S390X_CAPBIT(S390X_TRNG)},
        /*.kma    = */{S390X_CAPBIT(S390X_QUERY)
                       | S390X_CAPBIT(S390X_AES_128)
                       | S390X_CAPBIT(S390X_AES_192)
                       | S390X_CAPBIT(S390X_AES_256),
                       0ULL},
    };

    char *tok_begin, *tok_end, *buff, tok[S390X_STFLE_MAX][LEN + 1];
    int rc, off, i, n;

    buff = malloc(strlen(env) + 1);
    if (buff == NULL)
        return 0;

    rc = 0;
    memset(cap, ~0, sizeof(*cap));
    strcpy(buff, env);

    tok_begin = buff + strspn(buff, ";");
    strtok(tok_begin, ";");
    tok_end = strtok(NULL, ";");

    while (tok_begin != NULL) {
        /* stfle token */
        if ((n = sscanf(tok_begin,
                        " stfle : %" STR(LEN) "[^:] : "
                        "%" STR(LEN) "[^:] : %" STR(LEN) "s ",
                        tok[0], tok[1], tok[2]))) {
            for (i = 0; i < n; i++) {
                off = (tok[i][0] == '~') ? 1 : 0;
                if (sscanf(tok[i] + off, "%llx", &cap->stfle[i]) != 1)
                    goto ret;
                if (off)
                    cap->stfle[i] = ~cap->stfle[i];
            }
        }

        /* query function tokens */
        else if TOK_FUNC(kimd)
        else if TOK_FUNC(klmd)
        else if TOK_FUNC(km)
        else if TOK_FUNC(kmc)
        else if TOK_FUNC(kmac)
        else if TOK_FUNC(kmctr)
        else if TOK_FUNC(kmo)
        else if TOK_FUNC(kmf)
        else if TOK_FUNC(prno)
        else if TOK_FUNC(kma)

        /* CPU model tokens */
        else if TOK_CPU(z900)
        else if TOK_CPU(z990)
        else if TOK_CPU(z9)
        else if TOK_CPU(z10)
        else if TOK_CPU(z196)
        else if TOK_CPU(zEC12)
        else if TOK_CPU(z13)
        else if TOK_CPU(z14)

        /* whitespace(ignored) or invalid tokens */
        else {
            while (*tok_begin != '\0') {
                if (!isspace(*tok_begin))
                    goto ret;
                tok_begin++;
            }
        }

        tok_begin = tok_end;
        tok_end = strtok(NULL, ";");
    }

    rc = 1;
ret:
    free(buff);
    return rc;
}
