/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.] */

#ifndef OPENSSL_HEADER_RSA_H
#define OPENSSL_HEADER_RSA_H

#include <openssl/base.h>

#if defined(__cplusplus)
extern "C" {
#endif


/* rsa.h contains functions for handling encryption and signature using RSA. */


/* Blinding.
 *
 * TODO: The way blinding is done is being changed and that change is not
 * complete. In particular, the new signing API requires the caller to supply
 * the |BN_BLINDING| but there's no public API for creating & destroying
 * |BN_BLINDING|s. */
typedef struct bn_blinding_st BN_BLINDING;


/* Allocation and destruction. */

/* RSA_free decrements the reference count of |rsa| and frees it if the
 * reference count drops to zero. */
OPENSSL_EXPORT void RSA_free(RSA *rsa);


/* Key generation. */

/* RSA_generate generates a new RSA key where the modulus has size |bits| and
 * the public exponent is |e|. If unsure, |RSA_F4| is a good value
 * for |e|. If |cb| is not NULL then it is called during the key generation
 * process. In addition to the calls documented for |BN_generate_prime_ex|, it
 * is called with event=2 when the n'th prime is rejected as unsuitable and
 * with event=3 when a suitable value for |p| is found.
 *
 * |e| is a |uint32_t| because the Windows CryptoAPI RSA implementation
 * only accepts 32-bit exponents.
 * https://msdn.microsoft.com/en-us/library/windows/desktop/aa387685(v=vs.85).aspx
 *
 * It returns one on success or zero on error. */
OPENSSL_EXPORT RSA *RSA_generate(int bits, uint32_t e, RAND *rng, BN_GENCB *cb);


/* Encryption / Decryption */

/* Padding types for encryption. */
#define RSA_PKCS1_PADDING 1
#define RSA_NO_PADDING 3
#define RSA_PKCS1_OAEP_PADDING 4
/* RSA_PKCS1_PSS_PADDING can only be used via the EVP interface. */
#define RSA_PKCS1_PSS_PADDING 6

/* RSA_encrypt encrypts |in_len| bytes from |in| to the public key with modulus
 * |n| and exponent |e| and writes, at most, |max_out| bytes of encrypted data
 * to |out|. The |max_out| argument must be, at least, |RSA_size| in order to
 * ensure success.
 *
 * It returns 1 on success or zero on error.
 *
 * The |padding| argument must be one of the |RSA_*_PADDING| values. */
OPENSSL_EXPORT int RSA_encrypt(const BIGNUM *n, const BIGNUM *e,
                               size_t *out_len, uint8_t *out, size_t max_out,
                               const uint8_t *in, size_t in_len, int padding,
                               RAND *rng);

/* Signing / Verification */

/* RSA_sign signs |in_len| bytes of digest from |in| with |rsa| using
 * RSASSA-PKCS1-v1_5. It writes, at most, |RSA_size(rsa)| bytes to |out|. On
 * successful return, the actual number of bytes written is written to
 * |*out_len|.
 *
 * The |hash_nid| argument identifies the hash function used to calculate |in|
 * and is embedded in the resulting signature. For example, it might be
 * |NID_sha256|.
 *
 * It returns 1 on success and zero on error. */
OPENSSL_EXPORT int RSA_sign(int hash_nid, const uint8_t *in,
                            unsigned int in_len, uint8_t *out,
                            unsigned int *out_len, RSA *rsa,
                            BN_BLINDING *blinding, RAND *rng);

/* RSA_sign_raw signs |in_len| bytes from |in| with the public key from |rsa|
 * and writes, at most, |max_out| bytes of signature data to |out|. The
 * |max_out| argument must be, at least, |RSA_size| in order to ensure success.
 *
 * It returns 1 on success or zero on error.
 *
 * The |padding| argument must be one of the |RSA_*_PADDING| values. */
OPENSSL_EXPORT int RSA_sign_raw(RSA *rsa, size_t *out_len, uint8_t *out,
                                size_t max_out, const uint8_t *in,
                                size_t in_len, int padding,
                                BN_BLINDING *blinding, RAND *rng);


/* Utility functions. */

/* RSA_size returns the number of bytes in the modulus, which is also the size
 * of a signature or encrypted value using |rsa|. */
OPENSSL_EXPORT unsigned RSA_size(const RSA *rsa);

/* RSAPrivateKey_dup allocates a fresh |RSA| and copies the private key from
 * |rsa| into it. It returns the fresh |RSA| object, or NULL on error. */
OPENSSL_EXPORT RSA *RSAPrivateKey_dup(const RSA *rsa);

/* RSA_check_key performs basic validatity tests on |rsa|. It returns one if
 * they pass and zero otherwise. Opaque keys and public keys always pass. If it
 * returns zero then a more detailed error is available on the error queue. */
OPENSSL_EXPORT int RSA_check_key(const RSA *rsa, BN_CTX *ctx);

/* RSA_add_pkcs1_prefix builds a version of |msg| prefixed with the DigestInfo
 * header for the given hash function and sets |out_msg| to point to it. On
 * successful return, |*out_msg| will be allocated memory and so will need to
 * be freed with OPENSSL_free. */
OPENSSL_EXPORT int RSA_add_pkcs1_prefix(uint8_t **out_msg, size_t *out_msg_len,
                                        int hash_nid, const uint8_t *msg,
                                        size_t msg_len);


/* Flags. */

/* RSA_FLAG_CACHE_PUBLIC causes a precomputed Montgomery context to be created,
 * on demand, for the public key operations. */
#define RSA_FLAG_CACHE_PUBLIC 2

/* RSA_FLAG_CACHE_PRIVATE causes a precomputed Montgomery context to be
 * created, on demand, for the private key operations. */
#define RSA_FLAG_CACHE_PRIVATE 4

/* RSA_FLAG_NO_BLINDING disables blinding of private operations. */
#define RSA_FLAG_NO_BLINDING 8


/* RSA public exponent values. */

#define RSA_3 0x3
#define RSA_F4 0x10001


/* Private functions. */

struct rsa_st {
  BIGNUM *n;
  BIGNUM *e;
  BIGNUM *d;
  BIGNUM *p;
  BIGNUM *q;
  BIGNUM *dmp1;
  BIGNUM *dmq1;
  BIGNUM *iqmp;

  int flags;

  /* Used to cache montgomery values. The creation of these values is protected
   * by |lock|. */
  BN_MONT_CTX *mont_n;
  BN_MONT_CTX *mont_p;
  BN_MONT_CTX *mont_q;
  BN_MONT_CTX *mont_qq;

  BIGNUM *qmn_mont; /* |q|, Montgomery-encoded using |mont_n|. */
  BIGNUM *iqmp_mont; /* |iqmp|, Montgomery-encoded using |mont_p|. */
};


#if defined(__cplusplus)
}  /* extern C */
#endif

#define RSA_R_BAD_ENCODING 100
#define RSA_R_BAD_E_VALUE 101
#define RSA_R_BAD_FIXED_HEADER_DECRYPT 102
#define RSA_R_BAD_PAD_BYTE_COUNT 103
#define RSA_R_BAD_RSA_PARAMETERS 104
#define RSA_R_BAD_SIGNATURE 105
#define RSA_R_BAD_VERSION 106
#define RSA_R_BLOCK_TYPE_IS_NOT_01 107
#define RSA_R_BN_NOT_INITIALIZED 108
#define RSA_R_CANNOT_RECOVER_MULTI_PRIME_KEY 109
#define RSA_R_CRT_PARAMS_ALREADY_GIVEN 110
#define RSA_R_CRT_VALUES_INCORRECT 111
#define RSA_R_DATA_LEN_NOT_EQUAL_TO_MOD_LEN 112
#define RSA_R_DATA_TOO_LARGE 113
#define RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE 114
#define RSA_R_DATA_TOO_LARGE_FOR_MODULUS 115
#define RSA_R_DATA_TOO_SMALL 116
#define RSA_R_DATA_TOO_SMALL_FOR_KEY_SIZE 117
#define RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY 118
#define RSA_R_D_E_NOT_CONGRUENT_TO_1 119
#define RSA_R_EMPTY_PUBLIC_KEY 120
#define RSA_R_ENCODE_ERROR 121
#define RSA_R_FIRST_OCTET_INVALID 122
#define RSA_R_INCONSISTENT_SET_OF_CRT_VALUES 123
#define RSA_R_INTERNAL_ERROR 124
#define RSA_R_INVALID_MESSAGE_LENGTH 125
#define RSA_R_KEY_SIZE_TOO_SMALL 126
#define RSA_R_LAST_OCTET_INVALID 127
#define RSA_R_MODULUS_TOO_LARGE 128
#define RSA_R_MUST_HAVE_AT_LEAST_TWO_PRIMES 129
#define RSA_R_NO_PUBLIC_EXPONENT 130
#define RSA_R_NULL_BEFORE_BLOCK_MISSING 131
#define RSA_R_N_NOT_EQUAL_P_Q 132
#define RSA_R_OAEP_DECODING_ERROR 133
#define RSA_R_ONLY_ONE_OF_P_Q_GIVEN 134
#define RSA_R_OUTPUT_BUFFER_TOO_SMALL 135
#define RSA_R_PADDING_CHECK_FAILED 136
#define RSA_R_PKCS_DECODING_ERROR 137
#define RSA_R_SLEN_CHECK_FAILED 138
#define RSA_R_SLEN_RECOVERY_FAILED 139
#define RSA_R_TOO_LONG 140
#define RSA_R_TOO_MANY_ITERATIONS 141
#define RSA_R_UNKNOWN_ALGORITHM_TYPE 142
#define RSA_R_UNKNOWN_PADDING_TYPE 143
#define RSA_R_VALUE_MISSING 144
#define RSA_R_WRONG_SIGNATURE_LENGTH 145

#endif  /* OPENSSL_HEADER_RSA_H */
