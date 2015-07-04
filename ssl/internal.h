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
 * [including the GNU Public Licence.]
 */
/* ====================================================================
 * Copyright (c) 1998-2007 The OpenSSL Project.  All rights reserved.
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
 * ECC cipher suite support in OpenSSL originally developed by
 * SUN MICROSYSTEMS, INC., and contributed to the OpenSSL project.
 */
/* ====================================================================
 * Copyright 2005 Nokia. All rights reserved.
 *
 * The portions of the attached software ("Contribution") is developed by
 * Nokia Corporation and is licensed pursuant to the OpenSSL open source
 * license.
 *
 * The Contribution, originally written by Mika Kousa and Pasi Eronen of
 * Nokia Corporation, consists of the "PSK" (Pre-Shared Key) ciphersuites
 * support (see RFC 4279) to OpenSSL.
 *
 * No patent licenses or other rights except those expressly stated in
 * the OpenSSL open source license shall be deemed granted or received
 * expressly, by implication, estoppel, or otherwise.
 *
 * No assurances are provided by Nokia that the Contribution does not
 * infringe the patent or other intellectual property rights of any third
 * party or that the license provides you with all the necessary rights
 * to make use of the Contribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND. IN
 * ADDITION TO THE DISCLAIMERS INCLUDED IN THE LICENSE, NOKIA
 * SPECIFICALLY DISCLAIMS ANY LIABILITY FOR CLAIMS BROUGHT BY YOU OR ANY
 * OTHER ENTITY BASED ON INFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS OR
 * OTHERWISE.
 */

#ifndef OPENSSL_HEADER_SSL_INTERNAL_H
#define OPENSSL_HEADER_SSL_INTERNAL_H

#include <openssl/base.h>

#include <openssl/aead.h>
#include <openssl/pqueue.h>
#include <openssl/ssl.h>
#include <openssl/stack.h>

#if defined(OPENSSL_WINDOWS)
/* Windows defines struct timeval in winsock2.h. */
#pragma warning(push, 3)
#include <winsock2.h>
#pragma warning(pop)
#else
#include <sys/types.h>
#endif


/* Cipher suites. */

/* Bits for |algorithm_mkey| (key exchange algorithm). */
#define SSL_kRSA 0x00000001L
#define SSL_kDHE 0x00000002L
#define SSL_kECDHE 0x00000004L
/* SSL_kPSK is only set for plain PSK, not ECDHE_PSK. */
#define SSL_kPSK 0x00000008L

/* Bits for |algorithm_auth| (server authentication). */
#define SSL_aRSA 0x00000001L
#define SSL_aECDSA 0x00000002L
/* SSL_aPSK is set for both PSK and ECDHE_PSK. */
#define SSL_aPSK 0x00000004L

/* Bits for |algorithm_enc| (symmetric encryption). */
#define SSL_3DES 0x00000001L
#define SSL_RC4 0x00000002L
#define SSL_AES128 0x00000004L
#define SSL_AES256 0x00000008L
#define SSL_AES128GCM 0x00000010L
#define SSL_AES256GCM 0x00000020L
#define SSL_CHACHA20POLY1305 0x00000040L

#define SSL_AES (SSL_AES128 | SSL_AES256 | SSL_AES128GCM | SSL_AES256GCM)

/* Bits for |algorithm_mac| (symmetric authentication). */
#define SSL_MD5 0x00000001L
#define SSL_SHA1 0x00000002L
#define SSL_SHA256 0x00000004L
#define SSL_SHA384 0x00000008L
/* SSL_AEAD is set for all AEADs. */
#define SSL_AEAD 0x00000010L

/* Bits for |algorithm_ssl| (protocol version). These denote the first protocol
 * version which introduced the cipher.
 *
 * TODO(davidben): These are extremely confusing, both in code and in
 * cipher rules. Try to remove them. */
#define SSL_SSLV3 0x00000002L
#define SSL_TLSV1 SSL_SSLV3
#define SSL_TLSV1_2 0x00000004L

/* Bits for |algorithm2| (handshake digests and other extra flags). */

#define SSL_HANDSHAKE_MAC_MD5 0x10
#define SSL_HANDSHAKE_MAC_SHA 0x20
#define SSL_HANDSHAKE_MAC_SHA256 0x40
#define SSL_HANDSHAKE_MAC_SHA384 0x80
#define SSL_HANDSHAKE_MAC_DEFAULT \
  (SSL_HANDSHAKE_MAC_MD5 | SSL_HANDSHAKE_MAC_SHA)

/* SSL_MAX_DIGEST is the number of digest types which exist. When adding a new
 * one, update the table in ssl_cipher.c. */
#define SSL_MAX_DIGEST 4

/* SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_INCLUDED_IN_RECORD is a flag in
 * SSL_CIPHER.algorithm2 which indicates that the variable part of the nonce is
 * included as a prefix of the record. (AES-GCM, for example, does with with an
 * 8-byte variable nonce.) */
#define SSL_CIPHER_ALGORITHM2_VARIABLE_NONCE_INCLUDED_IN_RECORD (1<<22)

/* Bits for |algo_strength|, cipher strength information. */
#define SSL_MEDIUM 0x00000001L
#define SSL_HIGH 0x00000002L
#define SSL_FIPS 0x00000004L

/* ssl_cipher_get_evp_aead sets |*out_aead| to point to the correct EVP_AEAD
 * object for |cipher| protocol version |version|. It sets |*out_mac_secret_len|
 * and |*out_fixed_iv_len| to the MAC key length and fixed IV length,
 * respectively. The MAC key length is zero except for legacy block and stream
 * ciphers. It returns 1 on success and 0 on error. */
int ssl_cipher_get_evp_aead(const EVP_AEAD **out_aead,
                            size_t *out_mac_secret_len,
                            size_t *out_fixed_iv_len,
                            const SSL_CIPHER *cipher, uint16_t version);

/* ssl_get_handshake_digest looks up the |i|th handshake digest type and sets
 * |*out_mask| to the |SSL_HANDSHAKE_MAC_*| mask and |*out_md| to the
 * |EVP_MD|. It returns one on successs and zero if |i| >= |SSL_MAX_DIGEST|. */
int ssl_get_handshake_digest(uint32_t *out_mask, const EVP_MD **out_md,
                             size_t i);

/* ssl_create_cipher_list evaluates |rule_str| according to the ciphers in
 * |ssl_method|. It sets |*out_cipher_list| to a newly-allocated
 * |ssl_cipher_preference_list_st| containing the result.
 * |*out_cipher_list_by_id| is set to a list of selected ciphers sorted by
 * id. It returns |(*out_cipher_list)->ciphers| on success and NULL on
 * failure. */
STACK_OF(SSL_CIPHER) *
ssl_create_cipher_list(const SSL_PROTOCOL_METHOD *ssl_method,
                       struct ssl_cipher_preference_list_st **out_cipher_list,
                       STACK_OF(SSL_CIPHER) **out_cipher_list_by_id,
                       const char *rule_str);

/* SSL_PKEY_* denote certificate types. */
#define SSL_PKEY_RSA 0
#define SSL_PKEY_ECC 1
#define SSL_PKEY_NUM 2

/* ssl_cipher_get_value returns the cipher suite id of |cipher|. */
uint16_t ssl_cipher_get_value(const SSL_CIPHER *cipher);

/* ssl_cipher_get_cert_index returns the |SSL_PKEY_*| value corresponding to the
 * certificate type of |cipher| or -1 if there is none. */
int ssl_cipher_get_cert_index(const SSL_CIPHER *cipher);

/* ssl_cipher_has_server_public_key returns 1 if |cipher| involves a server
 * public key in the key exchange, sent in a server Certificate message.
 * Otherwise it returns 0. */
int ssl_cipher_has_server_public_key(const SSL_CIPHER *cipher);

/* ssl_cipher_requires_server_key_exchange returns 1 if |cipher| requires a
 * ServerKeyExchange message. Otherwise it returns 0.
 *
 * Unlike ssl_cipher_has_server_public_key, some ciphers take optional
 * ServerKeyExchanges. PSK and RSA_PSK only use the ServerKeyExchange to
 * communicate a psk_identity_hint, so it is optional. */
int ssl_cipher_requires_server_key_exchange(const SSL_CIPHER *cipher);


/* Encryption layer. */

/* SSL_AEAD_CTX contains information about an AEAD that is being used to encrypt
 * an SSL connection. */
struct ssl_aead_ctx_st {
  const SSL_CIPHER *cipher;
  EVP_AEAD_CTX ctx;
  /* fixed_nonce contains any bytes of the nonce that are fixed for all
   * records. */
  uint8_t fixed_nonce[8];
  uint8_t fixed_nonce_len, variable_nonce_len;
  /* variable_nonce_included_in_record is non-zero if the variable nonce
   * for a record is included as a prefix before the ciphertext. */
  char variable_nonce_included_in_record;
  /* random_variable_nonce is non-zero if the variable nonce is
   * randomly generated, rather than derived from the sequence
   * number. */
  char random_variable_nonce;
  /* omit_length_in_ad is non-zero if the length should be omitted in the
   * AEAD's ad parameter. */
  char omit_length_in_ad;
  /* omit_version_in_ad is non-zero if the version should be omitted
   * in the AEAD's ad parameter. */
  char omit_version_in_ad;
} /* SSL_AEAD_CTX */;

/* SSL_AEAD_CTX_new creates a newly-allocated |SSL_AEAD_CTX| using the supplied
 * key material. It returns NULL on error. Only one of |SSL_AEAD_CTX_open| or
 * |SSL_AEAD_CTX_seal| may be used with the resulting object, depending on
 * |direction|. |version| is the normalized protocol version, so DTLS 1.0 is
 * represented as 0x0301, not 0xffef. */
SSL_AEAD_CTX *SSL_AEAD_CTX_new(enum evp_aead_direction_t direction,
                               uint16_t version, const SSL_CIPHER *cipher,
                               const uint8_t *enc_key, size_t enc_key_len,
                               const uint8_t *mac_key, size_t mac_key_len,
                               const uint8_t *fixed_iv, size_t fixed_iv_len);

/* SSL_AEAD_CTX_free frees |ctx|. */
void SSL_AEAD_CTX_free(SSL_AEAD_CTX *ctx);

/* SSL_AEAD_CTX_explicit_nonce_len returns the length of the explicit nonce for
 * |ctx|, if any. |ctx| may be NULL to denote the null cipher. */
size_t SSL_AEAD_CTX_explicit_nonce_len(SSL_AEAD_CTX *ctx);

/* SSL_AEAD_CTX_max_overhead returns the maximum overhead of calling
 * |SSL_AEAD_CTX_seal|. |ctx| may be NULL to denote the null cipher. */
size_t SSL_AEAD_CTX_max_overhead(SSL_AEAD_CTX *ctx);

/* SSL_AEAD_CTX_open authenticates and decrypts |in_len| bytes from |in| and
 * writes the result to |out|. It returns one on success and zero on
 * error. |ctx| may be NULL to denote the null cipher.
 *
 * If |in| and |out| alias then |out| must be <= |in| + |explicit_nonce_len|. */
int SSL_AEAD_CTX_open(SSL_AEAD_CTX *ctx, uint8_t *out, size_t *out_len,
                      size_t max_out, uint8_t type, uint16_t wire_version,
                      const uint8_t seqnum[8], const uint8_t *in,
                      size_t in_len);

/* SSL_AEAD_CTX_seal encrypts and authenticates |in_len| bytes from |in| and
 * writes the result to |out|. It returns one on success and zero on
 * error. |ctx| may be NULL to denote the null cipher.
 *
 * If |in| and |out| alias then |out| + |explicit_nonce_len| must be <= |in| */
int SSL_AEAD_CTX_seal(SSL_AEAD_CTX *ctx, uint8_t *out, size_t *out_len,
                      size_t max_out, uint8_t type, uint16_t wire_version,
                      const uint8_t seqnum[8], const uint8_t *in,
                      size_t in_len);


/* Private key operations. */

/* ssl_private_key_* call the corresponding function on the
 * |SSL_PRIVATE_KEY_METHOD| for |ssl|, if configured. Otherwise, they implement
 * the operation on |pkey|.
 *
 * TODO(davidben): The |EVP_PKEY| must be passed in to due to the multiple
 * certificate slots feature. Remove it. */

int ssl_private_key_type(SSL *ssl, const EVP_PKEY *pkey);

int ssl_private_key_supports_digest(SSL *ssl, const EVP_PKEY *pkey,
                                    const EVP_MD *md);

size_t ssl_private_key_max_signature_len(SSL *ssl, const EVP_PKEY *pkey);

enum ssl_private_key_result_t ssl_private_key_sign(
    SSL *ssl, EVP_PKEY *pkey, uint8_t *out, size_t *out_len, size_t max_out,
    const EVP_MD *md, const uint8_t *in, size_t in_len);

enum ssl_private_key_result_t ssl_private_key_sign_complete(
    SSL *ssl, uint8_t *out, size_t *out_len, size_t max_out);


/* Underdocumented functions.
 *
 * Functions below here haven't been touched up and may be underdocumented. */

#define c2l(c, l)                                                            \
  (l = ((unsigned long)(*((c)++))), l |= (((unsigned long)(*((c)++))) << 8), \
   l |= (((unsigned long)(*((c)++))) << 16),                                 \
   l |= (((unsigned long)(*((c)++))) << 24))

/* NOTE - c is not incremented as per c2l */
#define c2ln(c, l1, l2, n)                       \
  {                                              \
    c += n;                                      \
    l1 = l2 = 0;                                 \
    switch (n) {                                 \
      case 8:                                    \
        l2 = ((unsigned long)(*(--(c)))) << 24;  \
      case 7:                                    \
        l2 |= ((unsigned long)(*(--(c)))) << 16; \
      case 6:                                    \
        l2 |= ((unsigned long)(*(--(c)))) << 8;  \
      case 5:                                    \
        l2 |= ((unsigned long)(*(--(c))));       \
      case 4:                                    \
        l1 = ((unsigned long)(*(--(c)))) << 24;  \
      case 3:                                    \
        l1 |= ((unsigned long)(*(--(c)))) << 16; \
      case 2:                                    \
        l1 |= ((unsigned long)(*(--(c)))) << 8;  \
      case 1:                                    \
        l1 |= ((unsigned long)(*(--(c))));       \
    }                                            \
  }

#define l2c(l, c)                            \
  (*((c)++) = (uint8_t)(((l)) & 0xff),       \
   *((c)++) = (uint8_t)(((l) >> 8) & 0xff),  \
   *((c)++) = (uint8_t)(((l) >> 16) & 0xff), \
   *((c)++) = (uint8_t)(((l) >> 24) & 0xff))

#define n2l(c, l)                          \
  (l = ((unsigned long)(*((c)++))) << 24,  \
   l |= ((unsigned long)(*((c)++))) << 16, \
   l |= ((unsigned long)(*((c)++))) << 8, l |= ((unsigned long)(*((c)++))))

#define l2n(l, c)                            \
  (*((c)++) = (uint8_t)(((l) >> 24) & 0xff), \
   *((c)++) = (uint8_t)(((l) >> 16) & 0xff), \
   *((c)++) = (uint8_t)(((l) >> 8) & 0xff),  \
   *((c)++) = (uint8_t)(((l)) & 0xff))

#define l2n8(l, c)                           \
  (*((c)++) = (uint8_t)(((l) >> 56) & 0xff), \
   *((c)++) = (uint8_t)(((l) >> 48) & 0xff), \
   *((c)++) = (uint8_t)(((l) >> 40) & 0xff), \
   *((c)++) = (uint8_t)(((l) >> 32) & 0xff), \
   *((c)++) = (uint8_t)(((l) >> 24) & 0xff), \
   *((c)++) = (uint8_t)(((l) >> 16) & 0xff), \
   *((c)++) = (uint8_t)(((l) >> 8) & 0xff),  \
   *((c)++) = (uint8_t)(((l)) & 0xff))

/* NOTE - c is not incremented as per l2c */
#define l2cn(l1, l2, c, n)                               \
  {                                                      \
    c += n;                                              \
    switch (n) {                                         \
      case 8:                                            \
        *(--(c)) = (uint8_t)(((l2) >> 24) & 0xff); \
      case 7:                                            \
        *(--(c)) = (uint8_t)(((l2) >> 16) & 0xff); \
      case 6:                                            \
        *(--(c)) = (uint8_t)(((l2) >> 8) & 0xff);  \
      case 5:                                            \
        *(--(c)) = (uint8_t)(((l2)) & 0xff);       \
      case 4:                                            \
        *(--(c)) = (uint8_t)(((l1) >> 24) & 0xff); \
      case 3:                                            \
        *(--(c)) = (uint8_t)(((l1) >> 16) & 0xff); \
      case 2:                                            \
        *(--(c)) = (uint8_t)(((l1) >> 8) & 0xff);  \
      case 1:                                            \
        *(--(c)) = (uint8_t)(((l1)) & 0xff);       \
    }                                                    \
  }

#define n2s(c, s) \
  ((s = (((unsigned int)(c[0])) << 8) | (((unsigned int)(c[1])))), c += 2)

#define s2n(s, c)                              \
  ((c[0] = (uint8_t)(((s) >> 8) & 0xff), \
    c[1] = (uint8_t)(((s)) & 0xff)),     \
   c += 2)

#define n2l3(c, l)                                                         \
  ((l = (((unsigned long)(c[0])) << 16) | (((unsigned long)(c[1])) << 8) | \
        (((unsigned long)(c[2])))),                                        \
   c += 3)

#define l2n3(l, c)                              \
  ((c[0] = (uint8_t)(((l) >> 16) & 0xff), \
    c[1] = (uint8_t)(((l) >> 8) & 0xff),  \
    c[2] = (uint8_t)(((l)) & 0xff)),      \
   c += 3)

/* LOCAL STUFF */

#define TLSEXT_CHANNEL_ID_SIZE 128

/* Check if an SSL structure is using DTLS */
#define SSL_IS_DTLS(s) (s->method->is_dtls)
/* See if we need explicit IV */
#define SSL_USE_EXPLICIT_IV(s) \
  (s->enc_method->enc_flags & SSL_ENC_FLAG_EXPLICIT_IV)
/* See if we use signature algorithms extension and signature algorithm before
 * signatures. */
#define SSL_USE_SIGALGS(s) (s->enc_method->enc_flags & SSL_ENC_FLAG_SIGALGS)
/* Allow TLS 1.2 ciphersuites: applies to DTLS 1.2 as well as TLS 1.2: may
 * apply to others in future. */
#define SSL_USE_TLS1_2_CIPHERS(s) \
  (s->enc_method->enc_flags & SSL_ENC_FLAG_TLS1_2_CIPHERS)
/* Determine if a client can use TLS 1.2 ciphersuites: can't rely on method
 * flags because it may not be set to correct version yet. */
#define SSL_CLIENT_USE_TLS1_2_CIPHERS(s)                       \
  ((SSL_IS_DTLS(s) && s->client_version <= DTLS1_2_VERSION) || \
   (!SSL_IS_DTLS(s) && s->client_version >= TLS1_2_VERSION))

/* SSL_kRSA <- RSA_ENC | (RSA_TMP & RSA_SIGN) |
 * 	    <- (EXPORT & (RSA_ENC | RSA_TMP) & RSA_SIGN)
 * SSL_kDH  <- DH_ENC & (RSA_ENC | RSA_SIGN | DSA_SIGN)
 * SSL_kDHE <- RSA_ENC | RSA_SIGN | DSA_SIGN
 * SSL_aRSA <- RSA_ENC | RSA_SIGN
 * SSL_aDSS <- DSA_SIGN */

/* From RFC4492, used in encoding the curve type in ECParameters */
#define EXPLICIT_PRIME_CURVE_TYPE 1
#define EXPLICIT_CHAR2_CURVE_TYPE 2
#define NAMED_CURVE_TYPE 3

enum ssl_hash_message_t {
  ssl_dont_hash_message,
  ssl_hash_message,
};

typedef struct cert_pkey_st {
  X509 *x509;
  EVP_PKEY *privatekey;
  /* Chain for this certificate */
  STACK_OF(X509) *chain;
} CERT_PKEY;

/* Structure containing decoded values of signature algorithms extension */
typedef struct tls_sigalgs_st {
  uint8_t rsign;
  uint8_t rhash;
} TLS_SIGALGS;

typedef struct cert_st {
  /* Current active set */
  CERT_PKEY *key; /* ALWAYS points to an element of the pkeys array
                   * Probably it would make more sense to store
                   * an index, not a pointer. */

  /* key_method, if non-NULL, is a set of callbacks to call for private key
   * operations. */
  const SSL_PRIVATE_KEY_METHOD *key_method;

  /* For clients the following masks are of *disabled* key and auth algorithms
   * based on the current session.
   *
   * TODO(davidben): Remove these. They get checked twice: when sending the
   * ClientHello and when processing the ServerHello. However, mask_ssl is a
   * different value both times. mask_k and mask_a are not, but is a
   * round-about way of checking the server's cipher was one of the advertised
   * ones. (Currently it checks the masks and then the list of ciphers prior to
   * applying the masks in ClientHello.) */
  uint32_t mask_k;
  uint32_t mask_a;
  uint32_t mask_ssl;

  DH *dh_tmp;
  DH *(*dh_tmp_cb)(SSL *ssl, int is_export, int keysize);

  /* ecdh_nid, if not |NID_undef|, is the NID of the curve to use for ephemeral
   * ECDH keys. If unset, |ecdh_tmp_cb| is consulted. */
  int ecdh_nid;
  /* ecdh_tmp_cb is a callback for selecting the curve to use for ephemeral ECDH
   * keys. If NULL, a curve is selected automatically. See
   * |SSL_CTX_set_tmp_ecdh_callback|. */
  EC_KEY *(*ecdh_tmp_cb)(SSL *ssl, int is_export, int keysize);
  CERT_PKEY pkeys[SSL_PKEY_NUM];

  /* Server-only: client_certificate_types is list of certificate types to
   * include in the CertificateRequest message.
   */
  uint8_t *client_certificate_types;
  size_t num_client_certificate_types;

  /* signature algorithms peer reports: e.g. supported signature
   * algorithms extension for server or as part of a certificate
   * request for client. */
  uint8_t *peer_sigalgs;
  /* Size of above array */
  size_t peer_sigalgslen;
  /* suppported signature algorithms.
   * When set on a client this is sent in the client hello as the
   * supported signature algorithms extension. For servers
   * it represents the signature algorithms we are willing to use. */
  uint8_t *conf_sigalgs;
  /* Size of above array */
  size_t conf_sigalgslen;
  /* Client authentication signature algorithms, if not set then
   * uses conf_sigalgs. On servers these will be the signature
   * algorithms sent to the client in a cerificate request for TLS 1.2.
   * On a client this represents the signature algortithms we are
   * willing to use for client authentication. */
  uint8_t *client_sigalgs;
  /* Size of above array */
  size_t client_sigalgslen;
  /* Signature algorithms shared by client and server: cached
   * because these are used most often. */
  TLS_SIGALGS *shared_sigalgs;
  size_t shared_sigalgslen;

  /* Certificate setup callback: if set is called whenever a
   * certificate may be required (client or server). the callback
   * can then examine any appropriate parameters and setup any
   * certificates required. This allows advanced applications
   * to select certificates on the fly: for example based on
   * supported signature algorithms or curves. */
  int (*cert_cb)(SSL *ssl, void *arg);
  void *cert_cb_arg;

  /* Optional X509_STORE for chain building or certificate validation
   * If NULL the parent SSL_CTX store is used instead. */
  X509_STORE *chain_store;
  X509_STORE *verify_store;
} CERT;

typedef struct sess_cert_st {
  /* cert_chain is the certificate chain sent by the peer. NOTE: for a client,
   * this does includes the server's leaf certificate, but, for a server, this
   * does NOT include the client's leaf. */
  STACK_OF(X509) *cert_chain;

  /* peer_cert, on a client, is the leaf certificate of the peer. */
  X509 *peer_cert;

  DH *peer_dh_tmp;
  EC_KEY *peer_ecdh_tmp;
} SESS_CERT;

/* SSL_METHOD is a compatibility structure to support the legacy version-locked
 * methods. */
struct ssl_method_st {
  /* version, if non-zero, is the only protocol version acceptable to an
   * SSL_CTX initialized from this method. */
  uint16_t version;
  /* method is the underlying SSL_PROTOCOL_METHOD that initializes the
   * SSL_CTX. */
  const SSL_PROTOCOL_METHOD *method;
};

/* Used to hold functions for SSLv2 or SSLv3/TLSv1 functions */
struct ssl_protocol_method_st {
  /* is_dtls is one if the protocol is DTLS and zero otherwise. */
  char is_dtls;
  int (*ssl_new)(SSL *s);
  void (*ssl_free)(SSL *s);
  int (*ssl_accept)(SSL *s);
  int (*ssl_connect)(SSL *s);
  long (*ssl_get_message)(SSL *s, int header_state, int body_state,
                          int msg_type, long max,
                          enum ssl_hash_message_t hash_message, int *ok);
  int (*ssl_read_app_data)(SSL *s, uint8_t *buf, int len, int peek);
  void (*ssl_read_close_notify)(SSL *s);
  int (*ssl_write_app_data)(SSL *s, const void *buf_, int len);
  int (*ssl_dispatch_alert)(SSL *s);
  long (*ssl_ctrl)(SSL *s, int cmd, long larg, void *parg);
  long (*ssl_ctx_ctrl)(SSL_CTX *ctx, int cmd, long larg, void *parg);
  /* supports_cipher returns one if |cipher| is supported by this protocol and
   * zero otherwise. */
  int (*supports_cipher)(const SSL_CIPHER *cipher);
  /* Handshake header length */
  unsigned int hhlen;
  /* Set the handshake header */
  int (*set_handshake_header)(SSL *s, int type, unsigned long len);
  /* Write out handshake message */
  int (*do_write)(SSL *s);
};

/* This is for the SSLv3/TLSv1.0 differences in crypto/hash stuff It is a bit
 * of a mess of functions, but hell, think of it as an opaque structure. */
struct ssl3_enc_method {
  int (*prf)(SSL *, uint8_t *, size_t, const uint8_t *, size_t, const char *,
             size_t, const uint8_t *, size_t, const uint8_t *, size_t);
  int (*setup_key_block)(SSL *);
  int (*generate_master_secret)(SSL *, uint8_t *, const uint8_t *, size_t);
  int (*change_cipher_state)(SSL *, int);
  int (*final_finish_mac)(SSL *, const char *, int, uint8_t *);
  int (*cert_verify_mac)(SSL *, int, uint8_t *);
  const char *client_finished_label;
  int client_finished_label_len;
  const char *server_finished_label;
  int server_finished_label_len;
  int (*alert_value)(int);
  int (*export_keying_material)(SSL *, uint8_t *, size_t, const char *, size_t,
                                const uint8_t *, size_t, int use_context);
  /* Various flags indicating protocol version requirements */
  unsigned int enc_flags;
};

#define SSL_HM_HEADER_LENGTH(s) s->method->hhlen
#define ssl_handshake_start(s) \
  (((uint8_t *)s->init_buf->data) + s->method->hhlen)
#define ssl_set_handshake_header(s, htype, len) \
  s->method->set_handshake_header(s, htype, len)
#define ssl_do_write(s) s->method->do_write(s)

/* Values for enc_flags */

/* Uses explicit IV for CBC mode */
#define SSL_ENC_FLAG_EXPLICIT_IV 0x1
/* Uses signature algorithms extension */
#define SSL_ENC_FLAG_SIGALGS 0x2
/* Uses SHA256 default PRF */
#define SSL_ENC_FLAG_SHA256_PRF 0x4
/* Allow TLS 1.2 ciphersuites: applies to DTLS 1.2 as well as TLS 1.2:
 * may apply to others in future. */
#define SSL_ENC_FLAG_TLS1_2_CIPHERS 0x8

/* lengths of messages */
#define DTLS1_COOKIE_LENGTH 256

#define DTLS1_RT_HEADER_LENGTH 13

#define DTLS1_HM_HEADER_LENGTH 12

#define DTLS1_CCS_HEADER_LENGTH 1

#define DTLS1_AL_HEADER_LENGTH 2

typedef struct dtls1_bitmap_st {
  /* map is a bit mask of the last 64 sequence numbers. Bit
   * |1<<i| corresponds to |max_seq_num - i|. */
  uint64_t map;
  /* max_seq_num is the largest sequence number seen so far. It
   * is a 64-bit value in big-endian encoding. */
  uint8_t max_seq_num[8];
} DTLS1_BITMAP;

/* TODO(davidben): This structure is used for both incoming messages and
 * outgoing messages. |is_ccs| and |epoch| are only used in the latter and
 * should be moved elsewhere. */
struct hm_header_st {
  uint8_t type;
  uint32_t msg_len;
  uint16_t seq;
  uint32_t frag_off;
  uint32_t frag_len;
  int is_ccs;
  /* epoch, for buffered outgoing messages, is the epoch the message was
   * originally sent in. */
  uint16_t epoch;
};

/* TODO(davidben): This structure is used for both incoming messages and
 * outgoing messages. |fragment| and |reassembly| are only used in the former
 * and should be moved elsewhere. */
typedef struct hm_fragment_st {
  struct hm_header_st msg_header;
  uint8_t *fragment;
  uint8_t *reassembly;
} hm_fragment;

typedef struct dtls1_state_st {
  /* send_cookie is true if we are resending the ClientHello
   * with a cookie from a HelloVerifyRequest. */
  unsigned int send_cookie;

  uint8_t cookie[DTLS1_COOKIE_LENGTH];
  size_t cookie_len;

  /* The current data and handshake epoch.  This is initially undefined, and
   * starts at zero once the initial handshake is completed. */
  uint16_t r_epoch;
  uint16_t w_epoch;

  /* records being received in the current epoch */
  DTLS1_BITMAP bitmap;

  /* handshake message numbers */
  uint16_t handshake_write_seq;
  uint16_t next_handshake_write_seq;

  uint16_t handshake_read_seq;

  /* save last sequence number for retransmissions */
  uint8_t last_write_sequence[8];

  /* buffered_messages is a priority queue of incoming handshake messages that
   * have yet to be processed.
   *
   * TODO(davidben): This data structure may as well be a ring buffer of fixed
   * size. */
  pqueue buffered_messages;

  /* send_messages is a priority queue of outgoing handshake messages sent in
   * the most recent handshake flight.
   *
   * TODO(davidben): This data structure may as well be a STACK_OF(T). */
  pqueue sent_messages;

  unsigned int mtu; /* max DTLS packet size */

  struct hm_header_st w_msg_hdr;

  /* num_timeouts is the number of times the retransmit timer has fired since
   * the last time it was reset. */
  unsigned int num_timeouts;

  /* Indicates when the last handshake msg or heartbeat sent will
   * timeout. */
  struct timeval next_timeout;

  /* Timeout duration */
  unsigned short timeout_duration;

  unsigned int change_cipher_spec_ok;
} DTLS1_STATE;

extern const SSL3_ENC_METHOD TLSv1_enc_data;
extern const SSL3_ENC_METHOD TLSv1_1_enc_data;
extern const SSL3_ENC_METHOD TLSv1_2_enc_data;
extern const SSL3_ENC_METHOD SSLv3_enc_data;

void ssl_clear_cipher_ctx(SSL *s);
int ssl_clear_bad_session(SSL *s);
CERT *ssl_cert_new(void);
CERT *ssl_cert_dup(CERT *cert);
void ssl_cert_clear_certs(CERT *c);
void ssl_cert_free(CERT *c);
SESS_CERT *ssl_sess_cert_new(void);
SESS_CERT *ssl_sess_cert_dup(const SESS_CERT *sess_cert);
void ssl_sess_cert_free(SESS_CERT *sess_cert);
int ssl_get_new_session(SSL *s, int session);

enum ssl_session_result_t {
  ssl_session_success,
  ssl_session_error,
  ssl_session_retry,
};

/* ssl_get_prev_session looks up the previous session based on |ctx|. On
 * success, it sets |*out_session| to the session or NULL if none was found. It
 * sets |*out_send_ticket| to whether a ticket should be sent at the end of the
 * handshake. If the session could not be looked up synchronously, it returns
 * |ssl_session_retry| and should be called again. Otherwise, it returns
 * |ssl_session_error|.  */
enum ssl_session_result_t ssl_get_prev_session(
    SSL *ssl, SSL_SESSION **out_session, int *out_send_ticket,
    const struct ssl_early_callback_ctx *ctx);

STACK_OF(SSL_CIPHER) *ssl_bytes_to_cipher_list(SSL *s, const CBS *cbs);
int ssl_cipher_list_to_bytes(SSL *s, STACK_OF(SSL_CIPHER) *sk, uint8_t *p);
struct ssl_cipher_preference_list_st *ssl_cipher_preference_list_dup(
    struct ssl_cipher_preference_list_st *cipher_list);
void ssl_cipher_preference_list_free(
    struct ssl_cipher_preference_list_st *cipher_list);
struct ssl_cipher_preference_list_st *ssl_cipher_preference_list_from_ciphers(
    STACK_OF(SSL_CIPHER) *ciphers);
struct ssl_cipher_preference_list_st *ssl_get_cipher_preferences(SSL *s);

int ssl_cert_set0_chain(CERT *c, STACK_OF(X509) *chain);
int ssl_cert_set1_chain(CERT *c, STACK_OF(X509) *chain);
int ssl_cert_add0_chain_cert(CERT *c, X509 *x);
int ssl_cert_add1_chain_cert(CERT *c, X509 *x);
int ssl_cert_select_current(CERT *c, X509 *x);
void ssl_cert_set_cert_cb(CERT *c, int (*cb)(SSL *ssl, void *arg), void *arg);

int ssl_verify_cert_chain(SSL *s, STACK_OF(X509) *sk);
int ssl_add_cert_chain(SSL *s, CERT_PKEY *cpk, unsigned long *l);
int ssl_build_cert_chain(CERT *c, X509_STORE *chain_store, int flags);
int ssl_cert_set_cert_store(CERT *c, X509_STORE *store, int chain, int ref);
CERT_PKEY *ssl_get_server_send_pkey(const SSL *s);
EVP_PKEY *ssl_get_sign_pkey(SSL *s, const SSL_CIPHER *c);
void ssl_update_cache(SSL *s, int mode);
int ssl_cert_type(EVP_PKEY *pkey);

/* ssl_get_compatible_server_ciphers determines the key exchange and
 * authentication cipher suite masks compatible with the server configuration
 * and current ClientHello parameters of |s|. It sets |*out_mask_k| to the key
 * exchange mask and |*out_mask_a| to the authentication mask. */
void ssl_get_compatible_server_ciphers(SSL *s, uint32_t *out_mask_k,
                                       uint32_t *out_mask_a);

STACK_OF(SSL_CIPHER) *ssl_get_ciphers_by_id(SSL *s);
int ssl_verify_alarm_type(long type);

/* ssl_fill_hello_random fills a client_random or server_random field of length
 * |len|. It returns one on success and zero on failure. */
int ssl_fill_hello_random(uint8_t *out, size_t len, int is_server);

int ssl3_init_finished_mac(SSL *s);
int ssl3_send_server_certificate(SSL *s);
int ssl3_send_new_session_ticket(SSL *s);
int ssl3_send_cert_status(SSL *s);
int ssl3_get_finished(SSL *s, int state_a, int state_b);
int ssl3_send_change_cipher_spec(SSL *s, int state_a, int state_b);
int ssl3_prf(SSL *s, uint8_t *out, size_t out_len, const uint8_t *secret,
             size_t secret_len, const char *label, size_t label_len,
             const uint8_t *seed1, size_t seed1_len,
             const uint8_t *seed2, size_t seed2_len);
void ssl3_cleanup_key_block(SSL *s);
int ssl3_do_write(SSL *s, int type);
int ssl3_send_alert(SSL *s, int level, int desc);
int ssl3_get_req_cert_type(SSL *s, uint8_t *p);
long ssl3_get_message(SSL *s, int header_state, int body_state, int msg_type,
                      long max, enum ssl_hash_message_t hash_message, int *ok);

/* ssl3_hash_current_message incorporates the current handshake message into the
 * handshake hash. It returns one on success and zero on allocation failure. */
int ssl3_hash_current_message(SSL *s);

/* ssl3_cert_verify_hash writes the CertificateVerify hash into the bytes
 * pointed to by |out| and writes the number of bytes to |*out_len|. |out| must
 * have room for EVP_MAX_MD_SIZE bytes. For TLS 1.2 and up, |*out_md| is used
 * for the hash function, otherwise the hash function depends on |pkey_type|
 * and is written to |*out_md|. It returns one on success and zero on
 * failure. */
int ssl3_cert_verify_hash(SSL *s, uint8_t *out, size_t *out_len,
                          const EVP_MD **out_md, int pkey_type);

int ssl3_send_finished(SSL *s, int a, int b, const char *sender, int slen);
int ssl3_supports_cipher(const SSL_CIPHER *cipher);
int ssl3_dispatch_alert(SSL *s);
int ssl3_expect_change_cipher_spec(SSL *s);
int ssl3_read_app_data(SSL *ssl, uint8_t *buf, int len, int peek);
void ssl3_read_close_notify(SSL *ssl);
int ssl3_read_bytes(SSL *s, int type, uint8_t *buf, int len, int peek);
int ssl3_write_app_data(SSL *ssl, const void *buf, int len);
int ssl3_write_bytes(SSL *s, int type, const void *buf, int len);
int ssl3_final_finish_mac(SSL *s, const char *sender, int slen, uint8_t *p);
int ssl3_cert_verify_mac(SSL *s, int md_nid, uint8_t *p);
int ssl3_finish_mac(SSL *s, const uint8_t *buf, int len);
void ssl3_free_digest_list(SSL *s);
int ssl3_output_cert_chain(SSL *s, CERT_PKEY *cpk);
const SSL_CIPHER *ssl3_choose_cipher(
    SSL *ssl, STACK_OF(SSL_CIPHER) *clnt,
    struct ssl_cipher_preference_list_st *srvr);
int ssl3_setup_read_buffer(SSL *s);
int ssl3_setup_write_buffer(SSL *s);
int ssl3_release_read_buffer(SSL *s);
int ssl3_release_write_buffer(SSL *s);

enum should_free_handshake_buffer_t {
  free_handshake_buffer,
  dont_free_handshake_buffer,
};
int ssl3_digest_cached_records(SSL *s, enum should_free_handshake_buffer_t);

int ssl3_new(SSL *s);
void ssl3_free(SSL *s);
int ssl3_accept(SSL *s);
int ssl3_connect(SSL *s);
long ssl3_ctrl(SSL *s, int cmd, long larg, void *parg);
long ssl3_ctx_ctrl(SSL_CTX *s, int cmd, long larg, void *parg);

/* ssl3_record_sequence_update increments the sequence number in |seq|. It
 * returns one on success and zero on wraparound. */
int ssl3_record_sequence_update(uint8_t *seq, size_t seq_len);

int ssl3_do_change_cipher_spec(SSL *ssl);

int ssl3_set_handshake_header(SSL *s, int htype, unsigned long len);
int ssl3_handshake_write(SSL *s);

enum dtls1_use_epoch_t {
  dtls1_use_previous_epoch,
  dtls1_use_current_epoch,
};

int dtls1_do_write(SSL *s, int type, enum dtls1_use_epoch_t use_epoch);
int ssl3_read_n(SSL *s, int n, int extend);
int dtls1_read_app_data(SSL *ssl, uint8_t *buf, int len, int peek);
void dtls1_read_close_notify(SSL *ssl);
int dtls1_read_bytes(SSL *s, int type, uint8_t *buf, int len, int peek);
int ssl3_write_pending(SSL *s, int type, const uint8_t *buf, unsigned int len);
void dtls1_set_message_header(SSL *s, uint8_t mt, unsigned long len,
                              unsigned short seq_num, unsigned long frag_off,
                              unsigned long frag_len);

int dtls1_write_app_data(SSL *s, const void *buf, int len);
int dtls1_write_bytes(SSL *s, int type, const void *buf, int len,
                      enum dtls1_use_epoch_t use_epoch);

int dtls1_send_change_cipher_spec(SSL *s, int a, int b);
int dtls1_send_finished(SSL *s, int a, int b, const char *sender, int slen);
int dtls1_read_failed(SSL *s, int code);
int dtls1_buffer_message(SSL *s, int ccs);
int dtls1_get_queue_priority(unsigned short seq, int is_ccs);
int dtls1_retransmit_buffered_messages(SSL *s);
void dtls1_clear_record_buffer(SSL *s);
void dtls1_get_message_header(uint8_t *data, struct hm_header_st *msg_hdr);
void dtls1_reset_seq_numbers(SSL *s, int rw);
int dtls1_check_timeout_num(SSL *s);
int dtls1_set_handshake_header(SSL *s, int type, unsigned long len);
int dtls1_handshake_write(SSL *s);

int dtls1_supports_cipher(const SSL_CIPHER *cipher);
void dtls1_start_timer(SSL *s);
void dtls1_stop_timer(SSL *s);
int dtls1_is_timer_expired(SSL *s);
void dtls1_double_timeout(SSL *s);
unsigned int dtls1_min_mtu(void);
void dtls1_hm_fragment_free(hm_fragment *frag);

/* some client-only functions */
int ssl3_send_client_hello(SSL *s);
int ssl3_get_server_hello(SSL *s);
int ssl3_get_certificate_request(SSL *s);
int ssl3_get_new_session_ticket(SSL *s);
int ssl3_get_cert_status(SSL *s);
int ssl3_get_server_done(SSL *s);
int ssl3_send_cert_verify(SSL *s);
int ssl3_send_client_certificate(SSL *s);
int ssl_do_client_cert_cb(SSL *s, X509 **px509, EVP_PKEY **ppkey);
int ssl3_send_client_key_exchange(SSL *s);
int ssl3_get_server_key_exchange(SSL *s);
int ssl3_get_server_certificate(SSL *s);
int ssl3_send_next_proto(SSL *s);
int ssl3_send_channel_id(SSL *s);

int dtls1_client_hello(SSL *s);

/* some server-only functions */
int ssl3_get_initial_bytes(SSL *s);
int ssl3_get_v2_client_hello(SSL *s);
int ssl3_get_client_hello(SSL *s);
int ssl3_send_server_hello(SSL *s);
int ssl3_send_server_key_exchange(SSL *s);
int ssl3_send_certificate_request(SSL *s);
int ssl3_send_server_done(SSL *s);
int ssl3_get_client_certificate(SSL *s);
int ssl3_get_client_key_exchange(SSL *s);
int ssl3_get_cert_verify(SSL *s);
int ssl3_get_next_proto(SSL *s);
int ssl3_get_channel_id(SSL *s);

int dtls1_new(SSL *s);
int dtls1_accept(SSL *s);
int dtls1_connect(SSL *s);
void dtls1_free(SSL *s);

long dtls1_get_message(SSL *s, int st1, int stn, int mt, long max,
                       enum ssl_hash_message_t hash_message, int *ok);
int dtls1_get_record(SSL *s);
int dtls1_dispatch_alert(SSL *s);

int ssl_init_wbio_buffer(SSL *s, int push);
void ssl_free_wbio_buffer(SSL *s);

/* tls1_prf computes the TLS PRF function for |s| as described in RFC 5246,
 * section 5 and RFC 2246 section 5. It writes |out_len| bytes to |out|, using
 * |secret| as the secret and |label| as the label. |seed1| and |seed2| are
 * concatenated to form the seed parameter. It returns one on success and zero
 * on failure. */
int tls1_prf(SSL *s, uint8_t *out, size_t out_len, const uint8_t *secret,
             size_t secret_len, const char *label, size_t label_len,
             const uint8_t *seed1, size_t seed1_len,
             const uint8_t *seed2, size_t seed2_len);

int tls1_change_cipher_state(SSL *s, int which);
int tls1_setup_key_block(SSL *s);
int tls1_handshake_digest(SSL *s, uint8_t *out, size_t out_len);
int tls1_final_finish_mac(SSL *s, const char *str, int slen, uint8_t *p);
int tls1_cert_verify_mac(SSL *s, int md_nid, uint8_t *p);
int tls1_generate_master_secret(SSL *s, uint8_t *out, const uint8_t *premaster,
                                size_t premaster_len);
int tls1_export_keying_material(SSL *s, uint8_t *out, size_t out_len,
                                const char *label, size_t label_len,
                                const uint8_t *context, size_t context_len,
                                int use_context);
int tls1_alert_code(int code);
int ssl3_alert_code(int code);

char ssl_early_callback_init(struct ssl_early_callback_ctx *ctx);
int tls1_ec_curve_id2nid(uint16_t curve_id);
int tls1_ec_nid2curve_id(uint16_t *out_curve_id, int nid);

/* tls1_check_curve parses ECParameters out of |cbs|, modifying it. It
 * checks the curve is one of our preferences and writes the
 * NamedCurve value to |*out_curve_id|. It returns one on success and
 * zero on error. */
int tls1_check_curve(SSL *s, CBS *cbs, uint16_t *out_curve_id);

/* tls1_get_shared_curve returns the NID of the first preferred shared curve
 * between client and server preferences. If none can be found, it returns
 * NID_undef. */
int tls1_get_shared_curve(SSL *s);

/* tls1_set_curves converts the array of |ncurves| NIDs pointed to by |curves|
 * into a newly allocated array of TLS curve IDs. On success, the function
 * returns one and writes the array to |*out_curve_ids| and its size to
 * |*out_curve_ids_len|. Otherwise, it returns zero. */
int tls1_set_curves(uint16_t **out_curve_ids, size_t *out_curve_ids_len,
                    const int *curves, size_t ncurves);

/* tls1_check_ec_cert returns one if |x| is an ECC certificate with curve and
 * point format compatible with the client's preferences. Otherwise it returns
 * zero. */
int tls1_check_ec_cert(SSL *s, X509 *x);

/* tls1_check_ec_tmp_key returns one if the EC temporary key is compatible with
 * client extensions and zero otherwise. */
int tls1_check_ec_tmp_key(SSL *s);

int tls1_shared_list(SSL *s, const uint8_t *l1, size_t l1len, const uint8_t *l2,
                     size_t l2len, int nmatch);
uint8_t *ssl_add_clienthello_tlsext(SSL *s, uint8_t *const buf,
                                    uint8_t *const limit, size_t header_len);
uint8_t *ssl_add_serverhello_tlsext(SSL *s, uint8_t *const buf,
                                    uint8_t *const limit);
int ssl_parse_clienthello_tlsext(SSL *s, CBS *cbs);
int ssl_parse_serverhello_tlsext(SSL *s, CBS *cbs);
int ssl_prepare_clienthello_tlsext(SSL *s);
int ssl_prepare_serverhello_tlsext(SSL *s);

#define tlsext_tick_md EVP_sha256

/* tls_process_ticket processes the session ticket extension. On success, it
 * sets |*out_session| to the decrypted session or NULL if the ticket was
 * rejected. It sets |*out_send_ticket| to whether a new ticket should be sent
 * at the end of the handshake. It returns one on success and zero on fatal
 * error. */
int tls_process_ticket(SSL *ssl, SSL_SESSION **out_session,
                       int *out_send_ticket, const uint8_t *ticket,
                       size_t ticket_len, const uint8_t *session_id,
                       size_t session_id_len);

int tls12_get_sigandhash(SSL *ssl, uint8_t *p, const EVP_PKEY *pk,
                         const EVP_MD *md);
int tls12_get_sigid(int pkey_type);
const EVP_MD *tls12_get_hash(uint8_t hash_alg);

int tls1_channel_id_hash(EVP_MD_CTX *ctx, SSL *s);
int tls1_record_handshake_hashes_for_channel_id(SSL *s);

int tls1_set_sigalgs_list(CERT *c, const char *str, int client);
int tls1_set_sigalgs(CERT *c, const int *salg, size_t salglen, int client);

/* ssl_ctx_log_rsa_client_key_exchange logs |premaster| to |ctx|, if logging is
 * enabled. It returns one on success and zero on failure. The entry is
 * identified by the first 8 bytes of |encrypted_premaster|. */
int ssl_ctx_log_rsa_client_key_exchange(SSL_CTX *ctx,
                                        const uint8_t *encrypted_premaster,
                                        size_t encrypted_premaster_len,
                                        const uint8_t *premaster,
                                        size_t premaster_len);

/* ssl_ctx_log_master_secret logs |master| to |ctx|, if logging is enabled. It
 * returns one on success and zero on failure. The entry is identified by
 * |client_random|. */
int ssl_ctx_log_master_secret(SSL_CTX *ctx, const uint8_t *client_random,
                              size_t client_random_len, const uint8_t *master,
                              size_t master_len);

/* ssl3_can_false_start returns one if |s| is allowed to False Start and zero
 * otherwise. */
int ssl3_can_false_start(const SSL *s);

/* ssl3_get_enc_method returns the SSL3_ENC_METHOD corresponding to
 * |version|. */
const SSL3_ENC_METHOD *ssl3_get_enc_method(uint16_t version);

/* ssl3_get_max_server_version returns the maximum SSL/TLS version number
 * supported by |s| as a server, or zero if all versions are disabled. */
uint16_t ssl3_get_max_server_version(const SSL *s);

/* ssl3_get_mutual_version selects the protocol version on |s| for a client
 * which advertises |client_version|. If no suitable version exists, it returns
 * zero. */
uint16_t ssl3_get_mutual_version(SSL *s, uint16_t client_version);

/* ssl3_get_max_client_version returns the maximum protocol version configured
 * for the client. It is guaranteed that the set of allowed versions at or below
 * this maximum version is contiguous. If all versions are disabled, it returns
 * zero. */
uint16_t ssl3_get_max_client_version(SSL *s);

/* ssl3_is_version_enabled returns one if |version| is an enabled protocol
 * version for |s| and zero otherwise. */
int ssl3_is_version_enabled(SSL *s, uint16_t version);

/* ssl3_version_from_wire maps |wire_version| to a protocol version. For
 * SSLv3/TLS, the version is returned as-is. For DTLS, the corresponding TLS
 * version is used. Note that this mapping is not injective but preserves
 * comparisons.
 *
 * TODO(davidben): To normalize some DTLS-specific code, move away from using
 * the wire version except at API boundaries. */
uint16_t ssl3_version_from_wire(SSL *s, uint16_t wire_version);

uint32_t ssl_get_algorithm2(SSL *s);
int tls1_process_sigalgs(SSL *s, const CBS *sigalgs);

/* tls1_choose_signing_digest returns a digest for use with |pkey| based on the
 * peer's preferences recorded for |s| and the digests supported by |pkey|. */
const EVP_MD *tls1_choose_signing_digest(SSL *s, EVP_PKEY *pkey);

size_t tls12_get_psigalgs(SSL *s, const uint8_t **psigs);
int tls12_check_peer_sigalg(const EVP_MD **out_md, int *out_alert, SSL *s,
                            CBS *cbs, EVP_PKEY *pkey);
void ssl_set_client_disabled(SSL *s);

int ssl_add_clienthello_use_srtp_ext(SSL *s, uint8_t *p, int *len, int maxlen);
int ssl_parse_clienthello_use_srtp_ext(SSL *s, CBS *cbs, int *out_alert);
int ssl_add_serverhello_use_srtp_ext(SSL *s, uint8_t *p, int *len, int maxlen);
int ssl_parse_serverhello_use_srtp_ext(SSL *s, CBS *cbs, int *out_alert);

#endif /* OPENSSL_HEADER_SSL_INTERNAL_H */
