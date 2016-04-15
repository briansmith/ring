/* ====================================================================
 * Copyright (c) 2002-2006 The OpenSSL Project.  All rights reserved.
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

#include <openssl/aes.h>

#include <assert.h>

#include <openssl/cpu.h>

#include "../internal.h"


#if defined(OPENSSL_ARM) || defined(OPENSSL_AARCH64)

#define HWAES
static int hwaes_capable(void) {
  return CRYPTO_is_ARMv8_AES_capable();
}

int aes_v8_set_encrypt_key(const uint8_t *user_key, const int bits,
                           AES_KEY *key);
int aes_v8_set_decrypt_key(const uint8_t *user_key, const int bits,
                           AES_KEY *key);
void aes_v8_encrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key);
void aes_v8_decrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key);

#endif

/* In this case several functions are provided by asm code. However, one cannot
 * control asm symbol visibility with command line flags and such so they are
 * always hidden and wrapped by these C functions, which can be so
 * controlled. */

void asm_AES_encrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key);
void AES_encrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key) {
#if defined(HWAES)
  if (hwaes_capable()) {
    aes_v8_encrypt(in, out, key);
    return;
  }
#endif
  asm_AES_encrypt(in, out, key);
}

void asm_AES_decrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key);
void AES_decrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key) {
#if defined(HWAES)
  if (hwaes_capable()) {
    aes_v8_decrypt(in, out, key);
    return;
  }
#endif
  asm_AES_decrypt(in, out, key);
}

int asm_AES_set_encrypt_key(const uint8_t *key, unsigned bits, AES_KEY *aeskey);
int AES_set_encrypt_key(const uint8_t *key, unsigned bits, AES_KEY *aeskey) {
#if defined(HWAES)
  if (hwaes_capable()) {
    return aes_v8_set_encrypt_key(key, bits, aeskey);
  }
#endif
  return asm_AES_set_encrypt_key(key, bits, aeskey);
}

int asm_AES_set_decrypt_key(const uint8_t *key, unsigned bits, AES_KEY *aeskey);
int AES_set_decrypt_key(const uint8_t *key, unsigned bits, AES_KEY *aeskey) {
#if defined(HWAES)
  if (hwaes_capable()) {
    return aes_v8_set_decrypt_key(key, bits, aeskey);
  }
#endif
  return asm_AES_set_decrypt_key(key, bits, aeskey);
}
