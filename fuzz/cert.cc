#include <openssl/x509.h>

extern "C" int LLVMFuzzerTestOneInput(uint8_t *buf, size_t len) {
  const uint8_t *bufp = buf;
  X509 *x509 = d2i_X509(NULL, &bufp, len);
  if (x509 != NULL) {
    /* Also extract the public key. */
    EVP_PKEY_free(X509_get_pubkey(x509));
  }
  X509_free(x509);
  return 0;
}
