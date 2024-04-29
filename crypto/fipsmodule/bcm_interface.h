/* Copyright (c) 2024, Google Inc.
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

#ifndef OPENSSL_HEADER_CRYPTO_BCM_INTERFACE_H
#define OPENSSL_HEADER_CRYPTO_BCM_INTERFACE_H

// This header will eventually become the interface between BCM and the
// rest of libcrypto. More cleanly separating the two is still a work in
// progress (see https://crbug.com/boringssl/722) so, at the moment, we
// consider this no different from any other header in BCM.
//
// Over time, calls from libcrypto to BCM will all move to this header
// and the separation will become more meaningful.

#if defined(__cplusplus)
extern "C" {
#endif

// Enumerated types for return values from bcm functions, both infallible
// and fallible functions. Two success values are used to correspond to the
// FIPS service indicator. For the moment, the official service indicator
// remains the counter, not these values. Once we fully transition to
// these return values from bcm we will change that.
enum bcm_infallible_t {
  bcm_infallible_approved,
  bcm_infallible_not_approved,
};

enum bcm_status_t {
  bcm_status_approved,
  bcm_status_not_approved,

  // Failure codes, which must all be negative.
  bcm_status_failure,
};
typedef enum bcm_status_t bcm_status;
typedef enum bcm_infallible_t bcm_infallible;

OPENSSL_INLINE int bcm_success(bcm_status status) {
  return status == bcm_status_approved || status == bcm_status_not_approved;
}

#if defined(BORINGSSL_FIPS)

// We overread from /dev/urandom or RDRAND by a factor of 10 and XOR to whiten.
// TODO(bbe): disentangle this value which is used to calculate the size of the
// stack buffer in RAND_need entropy based on a calculation.
#define BORINGSSL_FIPS_OVERREAD 10

#endif  // BORINGSSL_FIPS

// BCM_rand_load_entropy supplies |entropy_len| bytes of entropy to the BCM
// module. The |want_additional_input| parameter is true iff the entropy was
// obtained from a source other than the system, e.g. directly from the CPU.
bcm_infallible BCM_rand_load_entropy(const uint8_t *entropy, size_t entropy_len,
                       int want_additional_input);

// BCM_rand_bytes is the same as the public |RAND_bytes| function, other
// than returning a bcm_infallible status indicator.
OPENSSL_EXPORT bcm_infallible BCM_rand_bytes(uint8_t *out, size_t out_len);

// BCM_rand_bytes_hwrng attempts to fill |out| with |len| bytes of entropy from
// the CPU hardware random number generator if one is present.
// bcm_status_approved is returned on success, and a failure status is
// returned otherwise.
bcm_status BCM_rand_bytes_hwrng(uint8_t *out, size_t len);

// BCM_rand_bytes_with_additional_data samples from the RNG after mixing 32
// bytes from |user_additional_data| in.
bcm_infallible BCM_rand_bytes_with_additional_data(
    uint8_t *out, size_t out_len, const uint8_t user_additional_data[32]);


#if defined(__cplusplus)
}  // extern C
#endif

#endif  // OPENSSL_HEADER_CRYPTO_BCM_INTERFACE_H
