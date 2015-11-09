#include <assert.h>

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
  // This only fuzzes the initial flow from the server so far.
  SSL *client = SSL_new(g_state.ctx);
  BIO *in = BIO_new(BIO_s_mem());
  BIO *out = BIO_new(BIO_s_mem());
  SSL_set_bio(client, in, out);
  SSL_set_connect_state(client);

  BIO_write(in, buf, len);
  SSL_do_handshake(client);
  SSL_free(client);

  return 0;
}
