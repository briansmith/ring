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
