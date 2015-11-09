#include <openssl/evp.h>

extern "C" int LLVMFuzzerTestOneInput(uint8_t *buf, size_t len) {
  const uint8_t *bufp = buf;
  EVP_PKEY_free(d2i_AutoPrivateKey(NULL, &bufp, len));
  return 0;
}
