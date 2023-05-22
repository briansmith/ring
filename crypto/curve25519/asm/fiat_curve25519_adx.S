#if !defined(OPENSSL_NO_ASM) && !defined(OPENSSL_SMALL) && defined(__x86_64__)

#if defined(BORINGSSL_PREFIX)
#include <boringssl_prefix_symbols_asm.h>
#endif

.intel_syntax noprefix
#include "../../../third_party/fiat/asm/fiat_curve25519_adx_mul.S"
#include "../../../third_party/fiat/asm/fiat_curve25519_adx_square.S"

#endif
