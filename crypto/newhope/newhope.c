/* Copyright (c) 2016, Google Inc.
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

#include <string.h>

#include <openssl/mem.h>
#include <openssl/rand.h>

#include "internal.h"


NEWHOPE_POLY *NEWHOPE_POLY_new(void) {
  return (NEWHOPE_POLY *)OPENSSL_malloc(sizeof(NEWHOPE_POLY));
}

void NEWHOPE_POLY_free(NEWHOPE_POLY *p) { OPENSSL_free(p); }

/* Encodes reconciliation data from |c| into |r|. */
static void encode_rec(const NEWHOPE_POLY *c, uint8_t *r) {
  int i;
  for (i = 0; i < PARAM_N / 4; i++) {
    r[i] = c->coeffs[4 * i] | (c->coeffs[4 * i + 1] << 2) |
           (c->coeffs[4 * i + 2] << 4) | (c->coeffs[4 * i + 3] << 6);
  }
}

/* Decodes reconciliation data from |r| into |c|. */
static void decode_rec(const uint8_t *r, NEWHOPE_POLY *c) {
  int i;
  for (i = 0; i < PARAM_N / 4; i++) {
    c->coeffs[4 * i + 0] = r[i] & 0x03;
    c->coeffs[4 * i + 1] = (r[i] >> 2) & 0x03;
    c->coeffs[4 * i + 2] = (r[i] >> 4) & 0x03;
    c->coeffs[4 * i + 3] = (r[i] >> 6);
  }
}

void NEWHOPE_keygen(uint8_t *servermsg, NEWHOPE_POLY *sk) {
  newhope_poly_getnoise(sk);
  newhope_poly_ntt(sk);

  /* The first part of the server's message is the seed, which compactly encodes
   * a. */
  NEWHOPE_POLY a;
  uint8_t *seed = &servermsg[POLY_BYTES];
  RAND_bytes(seed, SEED_LENGTH);
  newhope_poly_uniform(&a, seed);

  NEWHOPE_POLY e;
  newhope_poly_getnoise(&e);
  newhope_poly_ntt(&e);

  /* The second part of the server's message is the polynomial pk = a*sk+e */
  NEWHOPE_POLY r, pk;
  newhope_poly_pointwise(&r, sk, &a);
  newhope_poly_add(&pk, &e, &r);
  newhope_poly_tobytes(servermsg, &pk);
}

int NEWHOPE_client_compute_key(
    uint8_t key[SHA256_DIGEST_LENGTH],
    uint8_t clientmsg[NEWHOPE_CLIENTMSG_LENGTH],
    const uint8_t servermsg[NEWHOPE_SERVERMSG_LENGTH], size_t msg_len) {
  if (msg_len != NEWHOPE_SERVERMSG_LENGTH) {
    return 0;
  }

  NEWHOPE_POLY sp;
  newhope_poly_getnoise(&sp);
  newhope_poly_ntt(&sp);

  /* The first part of the client's message is the polynomial bp=e'+a*s' */
  {
    NEWHOPE_POLY ep;
    newhope_poly_getnoise(&ep);
    newhope_poly_ntt(&ep);

    /* Generate the same |a| as the server, from the server's seed. */
    NEWHOPE_POLY a;
    const uint8_t *seed = &servermsg[POLY_BYTES];
    newhope_poly_uniform(&a, seed);

    NEWHOPE_POLY bp;
    newhope_poly_pointwise(&bp, &a, &sp);
    newhope_poly_add(&bp, &bp, &ep);
    newhope_poly_tobytes(clientmsg, &bp);
  }

  /* v = pk * s' + e'' */
  NEWHOPE_POLY v;
  {
    NEWHOPE_POLY pk;
    newhope_poly_frombytes(&pk, servermsg);

    NEWHOPE_POLY epp;
    newhope_poly_getnoise(&epp);

    newhope_poly_pointwise(&v, &pk, &sp);
    newhope_poly_invntt(&v);
    newhope_poly_add(&v, &v, &epp);
  }

  /* The second part of the client's message is the reconciliation data derived
   * from v. */
  NEWHOPE_POLY c;
  uint8_t *reconciliation = &clientmsg[POLY_BYTES];
  newhope_helprec(&c, &v);
  encode_rec(&c, reconciliation);

  uint8_t k[KEY_LENGTH];
  newhope_reconcile(k, &v, &c);
  SHA256_CTX ctx;
  if (!SHA256_Init(&ctx) ||
      !SHA256_Update(&ctx, k, KEY_LENGTH) ||
      !SHA256_Final(key, &ctx)) {
    return 0;
  }

  return 1;
}

int NEWHOPE_server_compute_key(
    uint8_t key[SHA256_DIGEST_LENGTH], const NEWHOPE_POLY *sk,
    const uint8_t clientmsg[NEWHOPE_CLIENTMSG_LENGTH], size_t msg_len) {
  if (msg_len != NEWHOPE_CLIENTMSG_LENGTH) {
    return 0;
  }
  NEWHOPE_POLY bp;
  newhope_poly_frombytes(&bp, clientmsg);

  NEWHOPE_POLY v;
  newhope_poly_pointwise(&v, sk, &bp);
  newhope_poly_invntt(&v);

  NEWHOPE_POLY c;
  const uint8_t *reconciliation = &clientmsg[POLY_BYTES];
  decode_rec(reconciliation, &c);

  uint8_t k[KEY_LENGTH];
  newhope_reconcile(k, &v, &c);
  SHA256_CTX ctx;
  if (!SHA256_Init(&ctx) ||
      !SHA256_Update(&ctx, k, KEY_LENGTH) ||
      !SHA256_Final(key, &ctx)) {
    return 0;
  }

  return 1;
}
