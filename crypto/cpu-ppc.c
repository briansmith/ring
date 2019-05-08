/*
 * Copyright 2009-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <setjmp.h>
#include <signal.h>
#include <unistd.h>
#include <sys/utsname.h>

# define PPC_FPU64       (1<<0)
# define PPC_ALTIVEC     (1<<1)
# define PPC_CRYPTO207   (1<<2)
# define PPC_FPU         (1<<3)
# define PPC_MADD300     (1<<4)
# define PPC_MFTB        (1<<5)
# define PPC_MFSPR268    (1<<6)

unsigned int GFp_ppccap_P = 0;

static sigset_t all_masked;

int bn_mul_mont_int(unsigned long *rp, const unsigned long *ap, const unsigned long *bp,
                    const unsigned long *np, const unsigned long *n0, int num);
int bn_mul4x_mont_int(unsigned long *rp, const unsigned long *ap, const unsigned long *bp,
                      const unsigned long *np, const unsigned long *n0, int num);

int GFp_bn_mul_mont(unsigned long *rp, const unsigned long *ap, const unsigned long *bp,
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

void sha256_block_p8(void *ctx, const void *inp, size_t len);
void sha256_block_ppc(void *ctx, const void *inp, size_t len);
void GFp_sha256_block_data_order(void *ctx, const void *inp, size_t len);
void GFp_sha256_block_data_order(void *ctx, const void *inp, size_t len)
{
    GFp_ppccap_P & PPC_CRYPTO207 ? sha256_block_p8(ctx, inp, len) :
        sha256_block_ppc(ctx, inp, len);
}

void sha512_block_p8(void *ctx, const void *inp, size_t len);
void sha512_block_ppc(void *ctx, const void *inp, size_t len);
void GFp_sha512_block_data_order(void *ctx, const void *inp, size_t len);
void GFp_sha512_block_data_order(void *ctx, const void *inp, size_t len)
{
    GFp_ppccap_P & PPC_CRYPTO207 ? sha512_block_p8(ctx, inp, len) :
        sha512_block_ppc(ctx, inp, len);
}

void ChaCha20_ctr32_int(unsigned char *out, const unsigned char *inp,
                        size_t len, const unsigned int key[8],
                        const unsigned int counter[4]);
void ChaCha20_ctr32_vmx(unsigned char *out, const unsigned char *inp,
                        size_t len, const unsigned int key[8],
                        const unsigned int counter[4]);
void ChaCha20_ctr32_vsx(unsigned char *out, const unsigned char *inp,
                        size_t len, const unsigned int key[8],
                        const unsigned int counter[4]);
void GFp_ChaCha20_ctr32(unsigned char *out, const unsigned char *inp,
                    size_t len, const unsigned int key[8],
                    const unsigned int counter[4])
{
    /* ring does not check and vsx ver crashes with 0-length input */
    if (!len)
        return;
    (GFp_ppccap_P & PPC_CRYPTO207)
        ? ChaCha20_ctr32_vsx(out, inp, len, key, counter)
        : GFp_ppccap_P & PPC_ALTIVEC
            ? ChaCha20_ctr32_vmx(out, inp, len, key, counter)
            : ChaCha20_ctr32_int(out, inp, len, key, counter);
}

void GFp_poly1305_init_int(void *ctx, const unsigned char key[16]);
void GFp_poly1305_blocks(void *ctx, const unsigned char *inp, size_t len,
                         unsigned int padbit);
void GFp_poly1305_emit(void *ctx, unsigned char mac[16],
                       const unsigned int nonce[4]);
void GFp_poly1305_init_fpu(void *ctx, const unsigned char key[16]);
void GFp_poly1305_blocks_fpu(void *ctx, const unsigned char *inp, size_t len,
                         unsigned int padbit);
void GFp_poly1305_emit_fpu(void *ctx, unsigned char mac[16],
                       const unsigned int nonce[4]);
void GFp_poly1305_init_vsx(void *ctx, const unsigned char key[16]);
void GFp_poly1305_blocks_vsx(void *ctx, const unsigned char *inp, size_t len,
                         unsigned int padbit);
void GFp_poly1305_emit_vsx(void *ctx, unsigned char mac[16],
                       const unsigned int nonce[4]);
int GFp_poly1305_init_asm(void *ctx, const unsigned char key[16], void *func[2]);
int GFp_poly1305_init_asm(void *ctx, const unsigned char key[16], void *func[2])
{
    if (GFp_ppccap_P & PPC_CRYPTO207) {
        GFp_poly1305_init_int(ctx, key);
        func[0] = (void*)(uintptr_t)GFp_poly1305_blocks_vsx;
        func[1] = (void*)(uintptr_t)GFp_poly1305_emit;
    } else if (sizeof(size_t) == 4 && (GFp_ppccap_P & PPC_FPU)) {
        GFp_poly1305_init_fpu(ctx, key);
        func[0] = (void*)(uintptr_t)GFp_poly1305_blocks_fpu;
        func[1] = (void*)(uintptr_t)GFp_poly1305_emit_fpu;
    } else {
        GFp_poly1305_init_int(ctx, key);
        func[0] = (void*)(uintptr_t)GFp_poly1305_blocks;
        func[1] = (void*)(uintptr_t)GFp_poly1305_emit;
    }
    return 1;
}

void GFp_nistz256_mul_mont(unsigned long res[4], const unsigned long a[4],
                           const unsigned long b[4]);

void GFp_nistz256_to_mont(unsigned long res[4], const unsigned long in[4]);
void GFp_nistz256_to_mont(unsigned long res[4], const unsigned long in[4])
{
    static const unsigned long RR[] = { 0x0000000000000003U,
                                        0xfffffffbffffffffU,
                                        0xfffffffffffffffeU,
                                        0x00000004fffffffdU };

    GFp_nistz256_mul_mont(res, in, RR);
}

void GFp_nistz256_from_mont(unsigned long res[4], const unsigned long in[4]);
void GFp_nistz256_from_mont(unsigned long res[4], const unsigned long in[4])
{
    static const unsigned long one[] = { 1, 0, 0, 0 };

    GFp_nistz256_mul_mont(res, in, one);
}

static sigjmp_buf ill_jmp;
static void ill_handler(int sig)
{
    siglongjmp(ill_jmp, sig);
}

void OPENSSL_fpu_probe(void);
void OPENSSL_ppc64_probe(void);
void OPENSSL_altivec_probe(void);
void OPENSSL_crypto207_probe(void);
void OPENSSL_madd300_probe(void);

long OPENSSL_rdtsc_mftb(void);
long OPENSSL_rdtsc_mfspr268(void);

#if defined(__GLIBC__) && defined(__GLIBC_PREREQ)
# if __GLIBC_PREREQ(2, 16)
#  include <sys/auxv.h>
#  define OSSL_IMPLEMENT_GETAUXVAL
# endif
#endif

/* I wish <sys/auxv.h> was universally available */
#define HWCAP                   16      /* AT_HWCAP */
#define HWCAP_PPC64             (1U << 30)
#define HWCAP_ALTIVEC           (1U << 28)
#define HWCAP_FPU               (1U << 27)
#define HWCAP_POWER6_EXT        (1U << 9)
#define HWCAP_VSX               (1U << 7)

#define HWCAP2                  26      /* AT_HWCAP2 */
#define HWCAP_VEC_CRYPTO        (1U << 25)
#define HWCAP_ARCH_3_00         (1U << 23)

void GFp_cpuid_setup(void)
{
    struct sigaction ill_oact, ill_act;
    sigset_t oset;
    static int trigger = 0;

    if (trigger)
        return;
    trigger = 1;

    GFp_ppccap_P = 0;

#ifdef OSSL_IMPLEMENT_GETAUXVAL
    {
        unsigned long hwcap = getauxval(HWCAP);

        if (hwcap & HWCAP_FPU) {
            GFp_ppccap_P |= PPC_FPU;

            if (sizeof(size_t) == 4) {
                /* In 32-bit case PPC_FPU64 is always fastest [if option] */
                if (hwcap & HWCAP_PPC64)
                    GFp_ppccap_P |= PPC_FPU64;
            } else {
                /* In 64-bit case PPC_FPU64 is fastest only on POWER6 */
                if (hwcap & HWCAP_POWER6_EXT)
                    GFp_ppccap_P |= PPC_FPU64;
            }
        }

        if (hwcap & HWCAP_ALTIVEC) {
            GFp_ppccap_P |= PPC_ALTIVEC;

            if ((hwcap & HWCAP_VSX) && (getauxval(HWCAP2) & HWCAP_VEC_CRYPTO))
                GFp_ppccap_P |= PPC_CRYPTO207;
        }

        if (hwcap & HWCAP_ARCH_3_00) {
            GFp_ppccap_P |= PPC_MADD300;
        }
    }
#endif

    sigfillset(&all_masked);
    sigdelset(&all_masked, SIGILL);
    sigdelset(&all_masked, SIGTRAP);
#ifdef SIGEMT
    sigdelset(&all_masked, SIGEMT);
#endif
    sigdelset(&all_masked, SIGFPE);
    sigdelset(&all_masked, SIGBUS);
    sigdelset(&all_masked, SIGSEGV);

    memset(&ill_act, 0, sizeof(ill_act));
    ill_act.sa_handler = ill_handler;
    ill_act.sa_mask = all_masked;

    sigprocmask(SIG_SETMASK, &ill_act.sa_mask, &oset);
    sigaction(SIGILL, &ill_act, &ill_oact);

#ifndef OSSL_IMPLEMENT_GETAUXVAL
    if (sigsetjmp(ill_jmp,1) == 0) {
        OPENSSL_fpu_probe();
        GFp_ppccap_P |= PPC_FPU;

        if (sizeof(size_t) == 4) {
# ifdef __linux
            struct utsname uts;
            if (uname(&uts) == 0 && strcmp(uts.machine, "ppc64") == 0)
# endif
                if (sigsetjmp(ill_jmp, 1) == 0) {
                    OPENSSL_ppc64_probe();
                    GFp_ppccap_P |= PPC_FPU64;
                }
        } else {
            /*
             * Wanted code detecting POWER6 CPU and setting PPC_FPU64
             */
        }
    }

    if (sigsetjmp(ill_jmp, 1) == 0) {
        OPENSSL_altivec_probe();
        GFp_ppccap_P |= PPC_ALTIVEC;
        if (sigsetjmp(ill_jmp, 1) == 0) {
            OPENSSL_crypto207_probe();
            GFp_ppccap_P |= PPC_CRYPTO207;
        }
    }

    if (sigsetjmp(ill_jmp, 1) == 0) {
        OPENSSL_madd300_probe();
        GFp_ppccap_P |= PPC_MADD300;
    }
#endif

    if (sigsetjmp(ill_jmp, 1) == 0) {
        OPENSSL_rdtsc_mftb();
        GFp_ppccap_P |= PPC_MFTB;
    } else if (sigsetjmp(ill_jmp, 1) == 0) {
        OPENSSL_rdtsc_mfspr268();
        GFp_ppccap_P |= PPC_MFSPR268;
    }

    sigaction(SIGILL, &ill_oact, NULL);
    sigprocmask(SIG_SETMASK, &oset, NULL);
}
