#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>


SSL *setup_test() {
  if (!SSL_library_init()) {
    return NULL;
  }

  SSL_CTX *client_ctx = NULL;
  SSL *client = NULL;
  BIO *bio = NULL;

  client_ctx = SSL_CTX_new(SSLv23_client_method());
  if (client_ctx == NULL) {
    goto err;
  }

  if (!SSL_CTX_set_cipher_list(client_ctx, "ALL")) {
    goto err;
  }

  client = SSL_new(client_ctx);
  if (client == NULL) {
    goto err;
  }

  bio = BIO_new_fd(3, 1 /* take ownership */);
  if (bio == NULL) {
    goto err;
  }

  SSL_set_bio(client, bio, bio);
  SSL_CTX_free(client_ctx);

  return client;

err:
  if (bio != NULL) {
    BIO_free(bio);
  }
  if (client != NULL) {
    SSL_free(client);
  }
  if (client_ctx != NULL) {
    SSL_CTX_free(client_ctx);
  }
  return NULL;
}

int main() {
  SSL *client = setup_test();
  if (client == NULL) {
    BIO_print_errors_fp(stdout);
    return 1;
  }

  if (SSL_connect(client) != 1) {
    SSL_free(client);
    BIO_print_errors_fp(stdout);
    return 2;
  }

  for (;;) {
    uint8_t buf[512];
    int n = SSL_read(client, buf, sizeof(buf));
    if (n < 0) {
      SSL_free(client);
      BIO_print_errors_fp(stdout);
      return 3;
    } else if (n == 0) {
      break;
    } else {
      for (int i = 0; i < n; i++) {
        buf[i] ^= 0xff;
      }
      int w = SSL_write(client, buf, n);
      if (w != n) {
        SSL_free(client);
        BIO_print_errors_fp(stdout);
        return 4;
      }
    }
  }

  SSL_free(client);
  return 0;
}
