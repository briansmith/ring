/* ====================================================================
 * Copyright (c) 2008 The OpenSSL Project.  All rights reserved.
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
 * ==================================================================== */

#include <GFp/base.h>

#include <GFp/cpu.h>

#include "internal.h"
#include "../../internal.h"
#include "../../block.h"

void GFp_gcm128_ghash(GCM128_CONTEXT *ctx, const uint8_t input[], size_t input_len);
void GFp_gcm128_gmult(GCM128_CONTEXT *ctx);
int GFp_gcm_clmul_enabled(void);

#define PACK(s) ((size_t)(s) << (sizeof(size_t) * 8 - 16))
#define REDUCE1BIT(V)                                                 \
  do {                                                                \
    if (sizeof(size_t) == 8) {                                        \
      uint64_t T = UINT64_C(0xe100000000000000) & (0 - ((V).lo & 1)); \
      (V).lo = ((V).hi << 63) | ((V).lo >> 1);                        \
      (V).hi = ((V).hi >> 1) ^ T;                                     \
    } else {                                                          \
      uint32_t T = 0xe1000000U & (0 - (uint32_t)((V).lo & 1));        \
      (V).lo = ((V).hi << 63) | ((V).lo >> 1);                        \
      (V).hi = ((V).hi >> 1) ^ ((uint64_t)T << 32);                   \
    }                                                                 \
  } while (0)

static void gcm_init_4bit(u128 Htable[16], const uint64_t H[2]) {
  u128 V;

  Htable[0].hi = 0;
  Htable[0].lo = 0;
  V.hi = H[0];
  V.lo = H[1];

  Htable[8] = V;
  REDUCE1BIT(V);
  Htable[4] = V;
  REDUCE1BIT(V);
  Htable[2] = V;
  REDUCE1BIT(V);
  Htable[1] = V;
  Htable[3].hi = V.hi ^ Htable[2].hi, Htable[3].lo = V.lo ^ Htable[2].lo;
  V = Htable[4];
  Htable[5].hi = V.hi ^ Htable[1].hi, Htable[5].lo = V.lo ^ Htable[1].lo;
  Htable[6].hi = V.hi ^ Htable[2].hi, Htable[6].lo = V.lo ^ Htable[2].lo;
  Htable[7].hi = V.hi ^ Htable[3].hi, Htable[7].lo = V.lo ^ Htable[3].lo;
  V = Htable[8];
  Htable[9].hi = V.hi ^ Htable[1].hi, Htable[9].lo = V.lo ^ Htable[1].lo;
  Htable[10].hi = V.hi ^ Htable[2].hi, Htable[10].lo = V.lo ^ Htable[2].lo;
  Htable[11].hi = V.hi ^ Htable[3].hi, Htable[11].lo = V.lo ^ Htable[3].lo;
  Htable[12].hi = V.hi ^ Htable[4].hi, Htable[12].lo = V.lo ^ Htable[4].lo;
  Htable[13].hi = V.hi ^ Htable[5].hi, Htable[13].lo = V.lo ^ Htable[5].lo;
  Htable[14].hi = V.hi ^ Htable[6].hi, Htable[14].lo = V.lo ^ Htable[6].lo;
  Htable[15].hi = V.hi ^ Htable[7].hi, Htable[15].lo = V.lo ^ Htable[7].lo;

#if defined(OPENSSL_ARM)
  // ARM assembler expects specific dword order in Htable.
  {
    int j;

    for (j = 0; j < 16; ++j) {
      V = Htable[j];
#if OPENSSL_ENDIAN == OPENSSL_LITTLE_ENDIAN
      Htable[j].hi = V.lo;
      Htable[j].lo = V.hi;
#elif OPENSSL_ENDIAN == OPENSSL_BIG_ENDIAN
      Htable[j].hi = V.lo << 32 | V.lo >> 32;
      Htable[j].lo = V.hi << 32 | V.hi >> 32;
#else
#error "OPENSSL_ENDIAN not set."
#endif
    }
  }
#endif
}

#if defined(OPENSSL_AARCH64) || defined(OPENSSL_PPC64LE) || defined(OPENSSL_X86_64)
static const size_t rem_4bit[16] = {
    PACK(0x0000), PACK(0x1C20), PACK(0x3840), PACK(0x2460),
    PACK(0x7080), PACK(0x6CA0), PACK(0x48C0), PACK(0x54E0),
    PACK(0xE100), PACK(0xFD20), PACK(0xD940), PACK(0xC560),
    PACK(0x9180), PACK(0x8DA0), PACK(0xA9C0), PACK(0xB5E0)};

static void GFp_gcm_gmult_4bit(uint8_t Xi[16], const u128 Htable[16]) {
  u128 Z;
  int cnt = 15;
  size_t rem, nlo, nhi;

  nlo = Xi[15];
  nhi = nlo >> 4;
  nlo &= 0xf;

  Z.hi = Htable[nlo].hi;
  Z.lo = Htable[nlo].lo;

  while (1) {
    rem = (size_t)Z.lo & 0xf;
    Z.lo = (Z.hi << 60) | (Z.lo >> 4);
    Z.hi = (Z.hi >> 4);
    if (sizeof(size_t) == 8) {
      Z.hi ^= rem_4bit[rem];
    } else {
      Z.hi ^= (uint64_t)rem_4bit[rem] << 32;
    }

    Z.hi ^= Htable[nhi].hi;
    Z.lo ^= Htable[nhi].lo;

    if (--cnt < 0) {
      break;
    }

    nlo = Xi[cnt];
    nhi = nlo >> 4;
    nlo &= 0xf;

    rem = (size_t)Z.lo & 0xf;
    Z.lo = (Z.hi << 60) | (Z.lo >> 4);
    Z.hi = (Z.hi >> 4);
    if (sizeof(size_t) == 8) {
      Z.hi ^= rem_4bit[rem];
    } else {
      Z.hi ^= (uint64_t)rem_4bit[rem] << 32;
    }

    Z.hi ^= Htable[nlo].hi;
    Z.lo ^= Htable[nlo].lo;
  }

  to_be_u64_ptr(Xi, Z.hi);
  to_be_u64_ptr(Xi + 8, Z.lo);
}

// Streamed gcm_mult_4bit, see GFp_gcm128_[en|de]crypt for
// details... Compiler-generated code doesn't seem to give any
// performance improvement, at least not on x86[_64]. It's here
// mostly as reference and a placeholder for possible future
// non-trivial optimization[s]...
static void GFp_gcm_ghash_4bit(uint8_t Xi[16], const u128 Htable[16],
                               const uint8_t *inp, size_t len) {
  u128 Z;
  int cnt;
  size_t rem, nlo, nhi;

  do {
    cnt = 15;
    nlo = Xi[15];
    nlo ^= inp[15];
    nhi = nlo >> 4;
    nlo &= 0xf;

    Z.hi = Htable[nlo].hi;
    Z.lo = Htable[nlo].lo;

    while (1) {
      rem = (size_t)Z.lo & 0xf;
      Z.lo = (Z.hi << 60) | (Z.lo >> 4);
      Z.hi = (Z.hi >> 4);
      if (sizeof(size_t) == 8) {
        Z.hi ^= rem_4bit[rem];
      } else {
        Z.hi ^= (uint64_t)rem_4bit[rem] << 32;
      }

      Z.hi ^= Htable[nhi].hi;
      Z.lo ^= Htable[nhi].lo;

      if (--cnt < 0) {
        break;
      }

      nlo = Xi[cnt];
      nlo ^= inp[cnt];
      nhi = nlo >> 4;
      nlo &= 0xf;

      rem = (size_t)Z.lo & 0xf;
      Z.lo = (Z.hi << 60) | (Z.lo >> 4);
      Z.hi = (Z.hi >> 4);
      if (sizeof(size_t) == 8) {
        Z.hi ^= rem_4bit[rem];
      } else {
        Z.hi ^= (uint64_t)rem_4bit[rem] << 32;
      }

      Z.hi ^= Htable[nlo].hi;
      Z.lo ^= Htable[nlo].lo;
    }

    to_be_u64_ptr(Xi, Z.hi);
    to_be_u64_ptr(Xi + 8, Z.lo);
  } while (inp += 16, len -= 16);
}
#else
void GFp_gcm_gmult_4bit(uint8_t Xi[16], const u128 Htable[16]);
void GFp_gcm_ghash_4bit(uint8_t Xi[16], const u128 Htable[16],
                        const uint8_t *inp, size_t len);
#endif

#if defined(OPENSSL_X86) || defined(OPENSSL_X86_64)
void GFp_gcm_init_clmul(u128 Htable[16], const uint64_t Xi[2]);
void GFp_gcm_gmult_clmul(uint8_t Xi[16], const u128 Htable[16]);
void GFp_gcm_ghash_clmul(uint8_t Xi[16], const u128 Htable[16],
                         const uint8_t *inp, size_t len);

#if defined(OPENSSL_X86_64)
#define GHASH_ASM_X86_64
void GFp_gcm_init_avx(u128 Htable[16], const uint64_t Xi[2]);
void GFp_gcm_ghash_avx(uint8_t Xi[16], const u128 Htable[16], const uint8_t *in,
                       size_t len);
int GFp_aesni_gcm_capable(void);

int GFp_aesni_gcm_capable(void) {
  return ((GFp_ia32cap_P[1] >> 22) & 0x41) == 0x41; // AVX+MOVBE
}
#endif

#if defined(OPENSSL_X86)
#define GHASH_ASM_X86
void GFp_gcm_gmult_4bit_mmx(uint8_t Xi[16], const u128 Htable[16]);
void GFp_gcm_ghash_4bit_mmx(uint8_t Xi[16], const u128 Htable[16],
                            const uint8_t *inp, size_t len);
#endif

#elif defined(OPENSSL_ARM) || defined(OPENSSL_AARCH64)

#include <GFp/arm_arch.h>

#if __ARM_MAX_ARCH__ >= 8
#define ARM_PMULL_ASM
void GFp_gcm_init_v8(u128 Htable[16], const uint64_t Xi[2]);
void GFp_gcm_gmult_v8(uint8_t Xi[16], const u128 Htable[16]);
void GFp_gcm_ghash_v8(uint8_t Xi[16], const u128 Htable[16], const uint8_t *inp,
                      size_t len);
#endif

#if defined(OPENSSL_ARM) && __ARM_MAX_ARCH__ >= 7
// 32-bit ARM also has support for doing GCM with NEON instructions.
void GFp_gcm_init_neon(u128 Htable[16], const uint64_t Xi[2]);
void GFp_gcm_gmult_neon(uint8_t Xi[16], const u128 Htable[16]);
void GFp_gcm_ghash_neon(uint8_t Xi[16], const u128 Htable[16],
                        const uint8_t *inp, size_t len);
#endif

#elif defined(OPENSSL_PPC64LE)
#define GHASH_ASM_PPC64LE
void GFp_gcm_init_p8(u128 Htable[16], const uint64_t Xi[2]);
void GFp_gcm_gmult_p8(uint64_t Xi[2], const u128 Htable[16]);
void GFp_gcm_ghash_p8(uint64_t Xi[2], const u128 Htable[16], const uint8_t *inp,
                      size_t len);
#endif // Platform

void GFp_gcm128_init_htable(GCM128_KEY *r, Block h_block);

void GFp_gcm128_init_htable(GCM128_KEY *r, Block h_block) {

  // H is stored in host byte order
  alignas(16) uint64_t H[2];
  H[0] = from_be_u64(h_block.subblocks[0]);
  H[1] = from_be_u64(h_block.subblocks[1]);

  u128 *Htable = r->Htable;

  // Keep in sync with |gcm128_init_gmult_ghash|.

#if defined(GHASH_ASM_X86_64) || defined(GHASH_ASM_X86)
  if (GFp_gcm_clmul_enabled()) {
#if defined(GHASH_ASM_X86_64)
    if (GFp_aesni_gcm_capable()) {
      GFp_gcm_init_avx(Htable, H);
      return;
    }
#endif
    GFp_gcm_init_clmul(Htable, H);
    return;
  }
#endif
#if defined(ARM_PMULL_ASM)
  if (GFp_is_ARMv8_PMULL_capable()) {
    GFp_gcm_init_v8(Htable, H);
    return;
  }
#endif
#if defined(OPENSSL_ARM)
  if (GFp_is_NEON_capable()) {
    GFp_gcm_init_neon(Htable, H);
    return;
  }
#endif
#if defined(GHASH_ASM_PPC64LE)
  if (GFp_is_PPC64LE_vcrypto_capable()) {
    GFp_gcm_init_p8(ctx->Htable, ctx->H.u);
    return;
  }
#endif

  gcm_init_4bit(Htable, H);
}

void GFp_gcm128_gmult(GCM128_CONTEXT *ctx) {
  // Keep in sync with |gcm128_ghash|, gcm128_init_htable| and |GFp_AES_set_encrypt_key|.

#if defined(GHASH_ASM_X86_64) || defined(GHASH_ASM_X86)
  if (GFp_gcm_clmul_enabled()) {
    // GFp_gcm_gmult_avx2 was an alias for GFp_gcm_gmult_clmul so there's no need
    // for x86-64 MOVEBE+AVX2 stuff here. Apparently GFp_gcm_gmult_clmul doesn't need
    // that stuff.
    GFp_gcm_gmult_clmul(ctx->Xi, ctx->key.Htable);
    return;
  }
#endif
#if defined(ARM_PMULL_ASM)
  if (GFp_is_ARMv8_PMULL_capable()) {
    GFp_gcm_gmult_v8(ctx->Xi, ctx->key.Htable);
    return;
  }
#endif
#if defined(OPENSSL_ARM)
  if (GFp_is_NEON_capable()) {
    GFp_gcm_gmult_neon(ctx->Xi, ctx->key.Htable);
    return;
  }
#endif
#if defined(GHASH_ASM_PPC64LE)
  if (GFp_is_PPC64LE_vcrypto_capable()) {
    GFp_gcm_gmult_p8(ctx->Xi, ctx->key.Htable);
    return;
  }
#endif

#if defined(GHASH_ASM_X86)
  GFp_gcm_gmult_4bit_mmx(ctx->Xi, ctx->key.Htable);
#else
  GFp_gcm_gmult_4bit(ctx->Xi, ctx->key.Htable);
#endif
}

void GFp_gcm128_ghash(GCM128_CONTEXT *ctx, const uint8_t input[], size_t input_len) {
  assert(input_len % 16 == 0);
  // Keep in sync with |gcm128_init_htable| and |GFp_AES_set_encrypt_key|.

#if defined(GHASH_ASM_X86_64) || defined(GHASH_ASM_X86)
  if (GFp_gcm_clmul_enabled()) {
#if defined(GHASH_ASM_X86_64)
    if (((GFp_ia32cap_P[1] >> 22) & 0x41) == 0x41) { // AVX+MOVBE
      GFp_gcm_ghash_avx(ctx->Xi, ctx->key.Htable, input, input_len);
      return;
    }
#endif
    GFp_gcm_ghash_clmul(ctx->Xi, ctx->key.Htable, input, input_len);
    return;
  }
#endif
#if defined(ARM_PMULL_ASM)
  if (GFp_is_ARMv8_PMULL_capable()) {
    GFp_gcm_ghash_v8(ctx->Xi, ctx->key.Htable, input, input_len);
    return;
  }
#endif
#if defined(OPENSSL_ARM)
  if (GFp_is_NEON_capable()) {
    GFp_gcm_ghash_neon(ctx->Xi, ctx->key.Htable, input, input_len);
    return;
  }
#endif
#if defined(GHASH_ASM_PPC64LE)
  if (GFp_is_PPC64LE_vcrypto_capable()) {
    GFp_gcm_ghash_p8(ctx->Xi, ctx->key.Htable, input, input_len);
    return;
  }
#endif

#if defined(GHASH_ASM_X86)
  GFp_gcm_ghash_4bit_mmx(ctx->Xi, ctx->key.Htable, input, input_len);
#else
  GFp_gcm_ghash_4bit(ctx->Xi, ctx->key.Htable, input, input_len);
#endif
}

#if defined(OPENSSL_X86) || defined(OPENSSL_X86_64)
int GFp_gcm_clmul_enabled(void) {
  return GFp_ia32cap_P[0] & (1 << 24) && // check FXSR bit
         GFp_ia32cap_P[1] & (1 << 1);    // check PCLMULQDQ bit
}
#endif
