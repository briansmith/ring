/* Copyright (c) 2019, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#ifndef OPENSSL_HEADER_TRUST_TOKEN_INTERNAL_H
#define OPENSSL_HEADER_TRUST_TOKEN_INTERNAL_H

#include <openssl/base.h>
#include <openssl/ec.h>
#include <openssl/ec_key.h>
#include <openssl/nid.h>

#include "../fipsmodule/ec/internal.h"

#include <openssl/trust_token.h>


#if defined(__cplusplus)
extern "C" {
#endif


// PMBTokens is described in https://eprint.iacr.org/2020/072/20200324:214215
// and provides anonymous tokens with private metadata. We implement the
// construction with validity verification, described in appendix H,
// construction 6, using P-521 as the group.

// PMBTOKEN_NONCE_SIZE is the size of nonces used as part of the PMBToken
// protocol.
#define PMBTOKEN_NONCE_SIZE 64

typedef struct {
  EC_RAW_POINT pub0;
  EC_RAW_POINT pub1;
  EC_RAW_POINT pubs;
} PMBTOKEN_CLIENT_KEY;

typedef struct {
  EC_SCALAR x0;
  EC_SCALAR y0;
  EC_SCALAR x1;
  EC_SCALAR y1;
  EC_SCALAR xs;
  EC_SCALAR ys;
  EC_RAW_POINT pub0;
  EC_RAW_POINT pub1;
  EC_RAW_POINT pubs;
} PMBTOKEN_ISSUER_KEY;

// PMBTOKEN_PRETOKEN represents the intermediate state a client keeps during a
// PMBToken issuance operation.
typedef struct pmb_pretoken_st {
  uint8_t t[PMBTOKEN_NONCE_SIZE];
  EC_SCALAR r;
  EC_RAW_POINT Tp;
} PMBTOKEN_PRETOKEN;

// PMBTOKEN_PRETOKEN_free releases the memory associated with |token|.
OPENSSL_EXPORT void PMBTOKEN_PRETOKEN_free(PMBTOKEN_PRETOKEN *token);

DEFINE_STACK_OF(PMBTOKEN_PRETOKEN)

// PMBTOKEN_TOKEN represents the final token generated as part of a PMBToken
// issuance operation.
typedef struct pmb_token_st {
  uint8_t t[PMBTOKEN_NONCE_SIZE];
  EC_RAW_POINT S;
  EC_RAW_POINT W;
  EC_RAW_POINT Ws;
} PMBTOKEN_TOKEN;

// PMBTOKEN_TOKEN_free releases the memory associated with |token|.
void PMBTOKEN_TOKEN_free(PMBTOKEN_TOKEN *token);

// pmbtoken_generate_key generates a fresh keypair and writes their serialized
// forms into |out_private| and |out_public|. It returns one on success and zero
// on failure.
int pmbtoken_generate_key(CBB *out_private, CBB *out_public);

// pmbtoken_client_key_from_bytes decodes a client key from |in| and sets |key|
// to the resulting key. It returns one on success and zero
// on failure.
int pmbtoken_client_key_from_bytes(PMBTOKEN_CLIENT_KEY *key, const uint8_t *in,
                                   size_t len);

// pmbtoken_issuer_key_from_bytes decodes a issuer key from |in| and sets |key|
// to the resulting key. It returns one on success and zero
// on failure.
int pmbtoken_issuer_key_from_bytes(PMBTOKEN_ISSUER_KEY *key, const uint8_t *in,
                                   size_t len);

// pmbtoken_blind generates a new blinded pretoken based on the configuration of
// |ctx| as per the first stage of the AT.Usr operation and returns the
// resulting pretoken.
PMBTOKEN_PRETOKEN *pmbtoken_blind(void);

// pmbtoken_sign signs a blinded point with |key| and a private metadata value
// of |private_metadata| as per the AT.Sig operation and stores the resulting
// nonce and points in |*out_s|, |*out_Wp|, and |*out_Wsp| and the resulting
// DLEQ proof in |*out_proof|. The caller takes ownership of |*out_proof| and is
// responsible for freeing it using |OPENSSL_free|. It returns one on success
// and zero on failure.
int pmbtoken_sign(const PMBTOKEN_ISSUER_KEY *key,
                  uint8_t out_s[PMBTOKEN_NONCE_SIZE], EC_RAW_POINT *out_Wp,
                  EC_RAW_POINT *out_Wsp, uint8_t **out_proof,
                  size_t *out_proof_len, const EC_RAW_POINT *Tp,
                  uint8_t private_metadata);

// pmbtoken_unblind unblinds the result of an AT.Sig operation as per the final
// stage of the AT.Usr operation and sets |*out_token| to the resulting token.
// It returns one on success and zero on failure.
int pmbtoken_unblind(const PMBTOKEN_CLIENT_KEY *key, PMBTOKEN_TOKEN *out_token,
                     const uint8_t s[PMBTOKEN_NONCE_SIZE],
                     const EC_RAW_POINT *Wp, const EC_RAW_POINT *Wsp,
                     const uint8_t *proof, size_t proof_len,
                     const PMBTOKEN_PRETOKEN *pretoken);

// pmbtoken_read verifies a PMBToken |token| using |key| and stores the value of
// the private metadata bit in |*out_private_metadata|. It returns one if the
// token is valid and zero otherwise.
int pmbtoken_read(const PMBTOKEN_ISSUER_KEY *key, uint8_t *out_private_metadata,
                  const PMBTOKEN_TOKEN *token);


// Structure representing a single Trust Token public key with the specified ID.
struct trust_token_client_key_st {
  uint32_t id;
  PMBTOKEN_CLIENT_KEY key;
};

// Structure representing a single Trust Token private key with the specified
// ID.
struct trust_token_issuer_key_st {
  uint32_t id;
  PMBTOKEN_ISSUER_KEY key;
};

struct trust_token_client_st {
  // max_batchsize is the maximum supported batchsize.
  uint16_t max_batchsize;

  // keys is the set of public keys that are supported by the client for
  // issuance/redemptions.
  struct trust_token_client_key_st keys[3];

  // num_keys is the number of keys currently configured.
  size_t num_keys;

  // pretokens is the intermediate state during an active issuance.
  STACK_OF(PMBTOKEN_PRETOKEN)* pretokens;

  // srr_key is the public key used to verify the signature of the SRR.
  EVP_PKEY *srr_key;
};


struct trust_token_issuer_st {
  // max_batchsize is the maximum supported batchsize.
  uint16_t max_batchsize;

  // keys is the set of private keys that are supported by the issuer for
  // issuance/redemptions. The public metadata is an index into this list of
  // keys.
  struct trust_token_issuer_key_st keys[3];

  // num_keys is the number of keys currently configured.
  size_t num_keys;

  // srr_key is the private key used to sign the SRR.
  EVP_PKEY *srr_key;

  // metadata_key is the secret material used to encode the private metadata bit
  // in the SRR.
  uint8_t *metadata_key;
  size_t metadata_key_len;
};


#if defined(__cplusplus)
}  // extern C

extern "C++" {

BSSL_NAMESPACE_BEGIN

BORINGSSL_MAKE_DELETER(PMBTOKEN_PRETOKEN, PMBTOKEN_PRETOKEN_free)

BSSL_NAMESPACE_END

}  // extern C++
#endif

#endif  // OPENSSL_HEADER_TRUST_TOKEN_INTERNAL_H
