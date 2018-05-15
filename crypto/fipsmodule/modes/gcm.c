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

#include <assert.h>
#include <string.h>

#include <GFp/mem.h>
#include <GFp/cpu.h>
#include <GFp/type_check.h>

#include "internal.h"
#include "../../internal.h"
#include "../aes/internal.h"

#if !defined(OPENSSL_NO_ASM) &&                         \
    (defined(OPENSSL_X86) || defined(OPENSSL_X86_64) || \
     defined(OPENSSL_ARM) || defined(OPENSSL_AARCH64) || \
     defined(OPENSSL_PPC64LE))
#define GHASH_ASM
#endif

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

// kSizeTWithoutLower4Bits is a mask that can be used to zero the lower four
// bits of a |size_t|.
static const size_t kSizeTWithoutLower4Bits = (size_t) -16;

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

#if defined(GHASH_ASM) && defined(OPENSSL_ARM)
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

#if !defined(GHASH_ASM) || defined(OPENSSL_AARCH64) || defined(OPENSSL_PPC64LE)
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

    Xi[0] = from_be_u64(Z.hi);
    Xi[1] = from_be_u64(Z.lo);
  } while (inp += 16, len -= 16);
}
#else // GHASH_ASM
void GFp_gcm_gmult_4bit(uint8_t Xi[16], const u128 Htable[16]);
void GFp_gcm_ghash_4bit(uint8_t Xi[16], const u128 Htable[16],
                        const uint8_t *inp, size_t len);
#endif

#define GCM_MUL(ctx, Xi) GFp_gcm_gmult_4bit((ctx)->Xi, (ctx)->Htable)
#if defined(GHASH_ASM)
#define GHASH(ctx, in, len) GFp_gcm_ghash_4bit((ctx)->Xi, (ctx)->Htable, in, len)
// GHASH_CHUNK is "stride parameter" missioned to mitigate cache
// trashing effect. In other words idea is to hash data while it's
// still in L1 cache after encryption pass...
#define GHASH_CHUNK (3 * 1024)
#endif


#if defined(GHASH_ASM)

#if defined(OPENSSL_X86) || defined(OPENSSL_X86_64)
#define GCM_FUNCREF_4BIT
void GFp_gcm_init_clmul(u128 Htable[16], const uint64_t Xi[2]);
void GFp_gcm_gmult_clmul(uint8_t Xi[16], const u128 Htable[16]);
void GFp_gcm_ghash_clmul(uint8_t Xi[16], const u128 Htable[16],
                         const uint8_t *inp, size_t len);

#if defined(OPENSSL_X86_64)
#define GHASH_ASM_X86_64
void GFp_gcm_init_avx(u128 Htable[16], const uint64_t Xi[2]);
void GFp_gcm_gmult_avx(uint8_t Xi[16], const u128 Htable[16]);
void GFp_gcm_ghash_avx(uint8_t Xi[16], const u128 Htable[16], const uint8_t *in,
                       size_t len);
#define AESNI_GCM
size_t GFp_aesni_gcm_encrypt(const uint8_t *in, uint8_t *out, size_t len,
                             const void *key, uint8_t ivec[16], uint8_t Xi[16]);
size_t GFp_aesni_gcm_decrypt(const uint8_t *in, uint8_t *out, size_t len,
                             const void *key, uint8_t ivec[16], uint8_t Xi[16]);
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
#define GCM_FUNCREF_4BIT
void GFp_gcm_init_v8(u128 Htable[16], const uint64_t Xi[2]);
void GFp_gcm_gmult_v8(uint8_t Xi[16], const u128 Htable[16]);
void GFp_gcm_ghash_v8(uint8_t Xi[16], const u128 Htable[16], const uint8_t *inp,
                      size_t len);
#endif

#if defined(OPENSSL_ARM) && __ARM_MAX_ARCH__ >= 7
#define GCM_FUNCREF_4BIT
// 32-bit ARM also has support for doing GCM with NEON instructions.
void GFp_gcm_init_neon(u128 Htable[16], const uint64_t Xi[2]);
void GFp_gcm_gmult_neon(uint8_t Xi[16], const u128 Htable[16]);
void GFp_gcm_ghash_neon(uint8_t Xi[16], const u128 Htable[16],
                        const uint8_t *inp, size_t len);
#endif

#elif defined(OPENSSL_PPC64LE)
#define GHASH_ASM_PPC64LE
#define GCM_FUNCREF_4BIT
void GFp_gcm_init_p8(u128 Htable[16], const uint64_t Xi[2]);
void GFp_gcm_gmult_p8(uint64_t Xi[2], const u128 Htable[16]);
void GFp_gcm_ghash_p8(uint64_t Xi[2], const u128 Htable[16], const uint8_t *inp,
                      size_t len);
#endif // Platform

#endif // GHASH_ASM

#ifdef GCM_FUNCREF_4BIT
#undef GCM_MUL
#define GCM_MUL(ctx, Xi) (*gcm_gmult_p)((ctx)->Xi, (ctx)->Htable)
#ifdef GHASH
#undef GHASH
#define GHASH(ctx, in, len) (*gcm_ghash_p)((ctx)->Xi, (ctx)->Htable, in, len)
#endif
#endif

static void gcm128_init_htable(u128 Htable[GCM128_HTABLE_LEN],
                               const uint64_t H[2]);

void GFp_gcm128_init_serialized(
    uint8_t serialized_ctx[GCM128_SERIALIZED_LEN], const AES_KEY *key,
    aes_block_f block) {
  static const alignas(16) uint8_t ZEROS[16] = { 0 };
  uint8_t H_be[16];
  (*block)(ZEROS, H_be, key);

  // H is stored in host byte order
  alignas(16) uint64_t H[2];
  H[0] = from_be_u64_ptr(H_be);
  H[1] = from_be_u64_ptr(H_be + 8);

  alignas(16) u128 Htable[GCM128_HTABLE_LEN];
  gcm128_init_htable(Htable, H);

  OPENSSL_COMPILE_ASSERT(sizeof(Htable) == GCM128_SERIALIZED_LEN,
                         GCM128_SERIALIZED_LEN_is_wrong);

  memcpy(serialized_ctx, Htable, GCM128_SERIALIZED_LEN);
}

static void gcm128_init_htable(u128 Htable[GCM128_HTABLE_LEN],
                               const uint64_t H[2]) {
  // Keep in sync with |gcm128_init_gmult_ghash|.

#if defined(GHASH_ASM_X86_64) || defined(GHASH_ASM_X86)
  if (GFp_gcm_clmul_enabled()) {
#if defined(GHASH_ASM_X86_64)
    if (((GFp_ia32cap_P[1] >> 22) & 0x41) == 0x41) { // AVX+MOVBE
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

static void gcm128_init_gmult_ghash(GCM128_CONTEXT *ctx) {
  // Keep in sync with |gcm128_init_htable| and |GFp_AES_set_encrypt_key|.

#if defined(GHASH_ASM_X86_64) || defined(GHASH_ASM_X86)
  if (GFp_gcm_clmul_enabled()) {
#if defined(GHASH_ASM_X86_64)
    if (((GFp_ia32cap_P[1] >> 22) & 0x41) == 0x41) { // AVX+MOVBE
      ctx->gmult = GFp_gcm_gmult_avx;
      ctx->ghash = GFp_gcm_ghash_avx;
      ctx->use_aesni_gcm_crypt = hwaes_capable() ? 1 : 0;
      return;
    }
#endif
    ctx->gmult = GFp_gcm_gmult_clmul;
    ctx->ghash = GFp_gcm_ghash_clmul;
    return;
  }
#endif
#if defined(ARM_PMULL_ASM)
  if (GFp_is_ARMv8_PMULL_capable()) {
    ctx->gmult = GFp_gcm_gmult_v8;
    ctx->ghash = GFp_gcm_ghash_v8;
    return;
  }
#endif
#if defined(OPENSSL_ARM)
  if (GFp_is_NEON_capable()) {
    ctx->gmult = GFp_gcm_gmult_neon;
    ctx->ghash = GFp_gcm_ghash_neon;
    return;
  }
#endif
#if defined(GHASH_ASM_PPC64LE)
  if (GFp_is_PPC64LE_vcrypto_capable()) {
    ctx->gmult = GFp_gcm_gmult_p8;
    ctx->ghash = GFp_gcm_ghash_p8;
    return;
  }
#endif

#if defined(GHASH_ASM_X86)
  ctx->gmult = GFp_gcm_gmult_4bit_mmx;
  ctx->ghash = GFp_gcm_ghash_4bit_mmx;
#else
  ctx->gmult = GFp_gcm_gmult_4bit;
  ctx->ghash = GFp_gcm_ghash_4bit;
#endif
}

void GFp_gcm128_init(GCM128_CONTEXT *ctx, const AES_KEY *key,
                        aes_block_f block,
                        const uint8_t serialized_ctx[GCM128_SERIALIZED_LEN],
                        const uint8_t *iv) {
  uint32_t ctr = 1;

  memset(ctx, 0, sizeof(*ctx));
  memcpy(ctx->Yi, iv, 12);
  to_be_u32_ptr(ctx->Yi + 12, ctr);
  (block)(ctx->Yi, ctx->EK0, key);
  ++ctr;
  to_be_u32_ptr(ctx->Yi + 12, ctr);

  OPENSSL_COMPILE_ASSERT(sizeof(ctx->Htable) == GCM128_SERIALIZED_LEN,
                         GCM128_SERIALIZED_LEN_is_wrong);

  memcpy(ctx->Htable, serialized_ctx, GCM128_SERIALIZED_LEN);
  ctx->block = block;
  gcm128_init_gmult_ghash(ctx);
}

int GFp_gcm128_aad(GCM128_CONTEXT *ctx, const uint8_t *aad, size_t len) {
  assert(ctx->len.u[0] == 0);
  assert(ctx->len.u[1] == 0);

#ifdef GCM_FUNCREF_4BIT
  gcm128_gmult_f gcm_gmult_p = ctx->gmult;
#endif

  ctx->len.u[0] = len;
  if (ctx->len.u[0] > (UINT64_C(1) << 61)) {
    return 0;
  }

  if (len > 0) {
    for (;;) {
      for (size_t i = 0; i < 16 && i < len; ++i) {
        ctx->Xi[i] ^= aad[i];
      }
      GCM_MUL(ctx, Xi);
      if (len <= 16) {
        break;
      }
      aad += 16;
      len -= 16;
    }
  }

  return 1;
}

int GFp_gcm128_encrypt_ctr32(GCM128_CONTEXT *ctx, const AES_KEY *key,
                                const uint8_t *in, uint8_t *out, size_t len,
                                aes_ctr_f stream) {
  assert(ctx->len.u[1] == 0);

  unsigned int ctr;
#ifdef GCM_FUNCREF_4BIT
  gcm128_gmult_f gcm_gmult_p = ctx->gmult;
#ifdef GHASH
  gcm128_ghash_f gcm_ghash_p = ctx->ghash;
#endif
#endif

  ctx->len.u[1] = len;
  if (ctx->len.u[1] > ((UINT64_C(1) << 36) - 32)) {
    return 0;
  }

#if defined(AESNI_GCM)
  if (ctx->use_aesni_gcm_crypt) {
    // |aesni_gcm_encrypt| may not process all the input given to it. It may
    // not process *any* of its input if it is deemed too small.
    size_t bulk = GFp_aesni_gcm_encrypt(in, out, len, key, ctx->Yi, ctx->Xi);
    in += bulk;
    out += bulk;
    len -= bulk;
  }
#endif

  ctr = from_be_u32_ptr(ctx->Yi + 12);

#if defined(GHASH)
  while (len >= GHASH_CHUNK) {
    (*stream)(in, out, GHASH_CHUNK / 16, key, ctx->Yi);
    ctr += GHASH_CHUNK / 16;
    to_be_u32_ptr(ctx->Yi + 12, ctr);
    GHASH(ctx, out, GHASH_CHUNK);
    out += GHASH_CHUNK;
    in += GHASH_CHUNK;
    len -= GHASH_CHUNK;
  }
#endif
  size_t i = len & kSizeTWithoutLower4Bits;
  if (i != 0) {
    size_t j = i / 16;

    (*stream)(in, out, j, key, ctx->Yi);
    ctr += (unsigned int)j;
    to_be_u32_ptr(ctx->Yi + 12, ctr);
    in += i;
    len -= i;
#if defined(GHASH)
    GHASH(ctx, out, i);
    out += i;
#else
    while (j--) {
      for (i = 0; i < 16; ++i) {
        ctx->Xi[i] ^= out[i];
      }
      GCM_MUL(ctx, Xi);
      out += 16;
    }
#endif
  }
  if (len) {
    (*ctx->block)(ctx->Yi, ctx->EKi, key);
    ++ctr;
    to_be_u32_ptr(ctx->Yi + 12, ctr);
    size_t n = 0;
    while (len--) {
      ctx->Xi[n] ^= out[n] = in[n] ^ ctx->EKi[n];
      ++n;
    }
    GCM_MUL(ctx, Xi);
  }

  return 1;
}

int GFp_gcm128_decrypt_ctr32(GCM128_CONTEXT *ctx, const AES_KEY *key,
                                const uint8_t *in, uint8_t *out, size_t len,
                                aes_ctr_f stream) {
  assert(ctx->len.u[1] == 0);

  unsigned int ctr;
#ifdef GCM_FUNCREF_4BIT
  gcm128_gmult_f gcm_gmult_p = ctx->gmult;
#ifdef GHASH
  gcm128_ghash_f gcm_ghash_p = ctx->ghash;
#endif
#endif

  ctx->len.u[1] = len;
  if (ctx->len.u[1] > ((UINT64_C(1) << 36) - 32)) {
    return 0;
  }

#if defined(AESNI_GCM)
  if (ctx->use_aesni_gcm_crypt) {
    // |aesni_gcm_decrypt| may not process all the input given to it. It may
    // not process *any* of its input if it is deemed too small.
    size_t bulk = GFp_aesni_gcm_decrypt(in, out, len, key, ctx->Yi, ctx->Xi);
    in += bulk;
    out += bulk;
    len -= bulk;
  }
#endif

  ctr = from_be_u32_ptr(ctx->Yi + 12);

#if defined(GHASH)
  while (len >= GHASH_CHUNK) {
    GHASH(ctx, in, GHASH_CHUNK);
    (*stream)(in, out, GHASH_CHUNK / 16, key, ctx->Yi);
    ctr += GHASH_CHUNK / 16;
    to_be_u32_ptr(ctx->Yi + 12, ctr);
    out += GHASH_CHUNK;
    in += GHASH_CHUNK;
    len -= GHASH_CHUNK;
  }
#endif
  size_t i = len & kSizeTWithoutLower4Bits;
  if (i != 0) {
    size_t j = i / 16;

#if defined(GHASH)
    GHASH(ctx, in, i);
#else
    while (j--) {
      size_t k;
      for (k = 0; k < 16; ++k) {
        ctx->Xi[k] ^= in[k];
      }
      GCM_MUL(ctx, Xi);
      in += 16;
    }
    j = i / 16;
    in -= i;
#endif
    (*stream)(in, out, j, key, ctx->Yi);
    ctr += (unsigned int)j;
    to_be_u32_ptr(ctx->Yi + 12, ctr);
    out += i;
    in += i;
    len -= i;
  }
  if (len) {
    (*ctx->block)(ctx->Yi, ctx->EKi, key);
    ++ctr;
    to_be_u32_ptr(ctx->Yi + 12, ctr);
    size_t n = 0;
    while (len--) {
      uint8_t c = in[n];
      ctx->Xi[n] ^= c;
      out[n] = c ^ ctx->EKi[n];
      ++n;
    }
    GCM_MUL(ctx, Xi);
  }

  return 1;
}

void GFp_gcm128_tag(GCM128_CONTEXT *ctx, uint8_t tag[16]) {
  uint64_t alen = ctx->len.u[0] << 3;
  uint64_t clen = ctx->len.u[1] << 3;
#ifdef GCM_FUNCREF_4BIT
  gcm128_gmult_f gcm_gmult_p = ctx->gmult;
#endif

  uint8_t a_c_len[16];
  to_be_u64_ptr(a_c_len, alen);
  to_be_u64_ptr(a_c_len + 8, clen);
  for (size_t i = 0; i < 16; ++i) {
    ctx->Xi[i] ^= a_c_len[i];
  }
  GCM_MUL(ctx, Xi);

  for (size_t i = 0; i < 16; ++i) {
    tag[i] = ctx->Xi[i] ^ ctx->EK0[i];
  }
}

#if defined(OPENSSL_X86) || defined(OPENSSL_X86_64)
int GFp_gcm_clmul_enabled(void) {
#ifdef GHASH_ASM
  return GFp_ia32cap_P[0] & (1 << 24) && // check FXSR bit
         GFp_ia32cap_P[1] & (1 << 1);    // check PCLMULQDQ bit
#else
  return 0;
#endif
}
#endif
