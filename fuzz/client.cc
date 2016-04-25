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

#include <assert.h>

#include <openssl/rand.h>
#include <openssl/ssl.h>

struct GlobalState {
  GlobalState() : ctx(SSL_CTX_new(SSLv23_method())) {}

  ~GlobalState() {
    SSL_CTX_free(ctx);
  }

  SSL_CTX *const ctx;
};

static GlobalState g_state;

extern "C" int LLVMFuzzerTestOneInput(uint8_t *buf, size_t len) {
  RAND_reset_for_fuzzing();

  SSL *client = SSL_new(g_state.ctx);
  BIO *in = BIO_new(BIO_s_mem());
  BIO *out = BIO_new(BIO_s_mem());
  SSL_set_bio(client, in, out);
  SSL_set_connect_state(client);
  SSL_set_renegotiate_mode(client, ssl_renegotiate_freely);

  BIO_write(in, buf, len);
  if (SSL_do_handshake(client) == 1) {
    // Keep reading application data until error or EOF.
    uint8_t tmp[1024];
    for (;;) {
      if (SSL_read(client, tmp, sizeof(tmp)) <= 0) {
        break;
      }
    }
  }
  SSL_free(client);

  return 0;
}
