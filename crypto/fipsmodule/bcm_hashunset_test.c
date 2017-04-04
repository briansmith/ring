#include <openssl/digest.h>

#if !defined(BORINGSSL_FIPS)
#error "This file should not be built outside of the FIPS build."
#endif

int main(void) {
  /* This program only needs to trigger the FIPS power-on self-test. */
  EVP_sha256();
  return 0;
}
