#include <openssl/x509.h>

extern "C" int LLVMFuzzerTestOneInput(uint8_t *buf, size_t len) {
  const uint8_t *bufp = buf;
  X509_free(d2i_X509(NULL, &bufp, len));
  return 0;
}
