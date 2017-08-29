/* Copyright (c) 2015, Google Inc.
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

#include <openssl/ssl.h>

#include <assert.h>
#include <string.h>

#include <openssl/aead.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "../crypto/internal.h"
#include "internal.h"


#if defined(BORINGSSL_UNSAFE_FUZZER_MODE)
#define FUZZER_MODE true
#else
#define FUZZER_MODE false
#endif

namespace bssl {

SSLAEADContext::SSLAEADContext(uint16_t version_arg,
                               const SSL_CIPHER *cipher_arg)
    : cipher_(cipher_arg),
      version_(version_arg),
      variable_nonce_included_in_record_(false),
      random_variable_nonce_(false),
      omit_length_in_ad_(false),
      omit_version_in_ad_(false),
      omit_ad_(false),
      xor_fixed_nonce_(false) {
  OPENSSL_memset(fixed_nonce_, 0, sizeof(fixed_nonce_));
}

SSLAEADContext::~SSLAEADContext() {}

UniquePtr<SSLAEADContext> SSLAEADContext::CreateNullCipher() {
  return MakeUnique<SSLAEADContext>(0 /* version */, nullptr /* cipher */);
}

UniquePtr<SSLAEADContext> SSLAEADContext::Create(
    enum evp_aead_direction_t direction, uint16_t version, int is_dtls,
    const SSL_CIPHER *cipher, const uint8_t *enc_key, size_t enc_key_len,
    const uint8_t *mac_key, size_t mac_key_len, const uint8_t *fixed_iv,
    size_t fixed_iv_len) {
  const EVP_AEAD *aead;
  size_t expected_mac_key_len, expected_fixed_iv_len;
  if (!ssl_cipher_get_evp_aead(&aead, &expected_mac_key_len,
                               &expected_fixed_iv_len, cipher, version,
                               is_dtls) ||
      // Ensure the caller returned correct key sizes.
      expected_fixed_iv_len != fixed_iv_len ||
      expected_mac_key_len != mac_key_len) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
    return nullptr;
  }

  uint8_t merged_key[EVP_AEAD_MAX_KEY_LENGTH];
  if (mac_key_len > 0) {
    // This is a "stateful" AEAD (for compatibility with pre-AEAD cipher
    // suites).
    if (mac_key_len + enc_key_len + fixed_iv_len > sizeof(merged_key)) {
      OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
      return nullptr;
    }
    OPENSSL_memcpy(merged_key, mac_key, mac_key_len);
    OPENSSL_memcpy(merged_key + mac_key_len, enc_key, enc_key_len);
    OPENSSL_memcpy(merged_key + mac_key_len + enc_key_len, fixed_iv,
                   fixed_iv_len);
    enc_key = merged_key;
    enc_key_len += mac_key_len;
    enc_key_len += fixed_iv_len;
  }

  UniquePtr<SSLAEADContext> aead_ctx =
      MakeUnique<SSLAEADContext>(version, cipher);
  if (!aead_ctx) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
    return nullptr;
  }

  if (!EVP_AEAD_CTX_init_with_direction(
          aead_ctx->ctx_.get(), aead, enc_key, enc_key_len,
          EVP_AEAD_DEFAULT_TAG_LENGTH, direction)) {
    return nullptr;
  }

  assert(EVP_AEAD_nonce_length(aead) <= EVP_AEAD_MAX_NONCE_LENGTH);
  static_assert(EVP_AEAD_MAX_NONCE_LENGTH < 256,
                "variable_nonce_len doesn't fit in uint8_t");
  aead_ctx->variable_nonce_len_ = (uint8_t)EVP_AEAD_nonce_length(aead);
  if (mac_key_len == 0) {
    assert(fixed_iv_len <= sizeof(aead_ctx->fixed_nonce_));
    OPENSSL_memcpy(aead_ctx->fixed_nonce_, fixed_iv, fixed_iv_len);
    aead_ctx->fixed_nonce_len_ = fixed_iv_len;

    if (cipher->algorithm_enc & SSL_CHACHA20POLY1305) {
      // The fixed nonce into the actual nonce (the sequence number).
      aead_ctx->xor_fixed_nonce_ = true;
      aead_ctx->variable_nonce_len_ = 8;
    } else {
      // The fixed IV is prepended to the nonce.
      assert(fixed_iv_len <= aead_ctx->variable_nonce_len_);
      aead_ctx->variable_nonce_len_ -= fixed_iv_len;
    }

    // AES-GCM uses an explicit nonce.
    if (cipher->algorithm_enc & (SSL_AES128GCM | SSL_AES256GCM)) {
      aead_ctx->variable_nonce_included_in_record_ = true;
    }

    // The TLS 1.3 construction XORs the fixed nonce into the sequence number
    // and omits the additional data.
    if (version >= TLS1_3_VERSION) {
      aead_ctx->xor_fixed_nonce_ = true;
      aead_ctx->variable_nonce_len_ = 8;
      aead_ctx->variable_nonce_included_in_record_ = false;
      aead_ctx->omit_ad_ = true;
      assert(fixed_iv_len >= aead_ctx->variable_nonce_len_);
    }
  } else {
    assert(version < TLS1_3_VERSION);
    aead_ctx->variable_nonce_included_in_record_ = true;
    aead_ctx->random_variable_nonce_ = true;
    aead_ctx->omit_length_in_ad_ = true;
    aead_ctx->omit_version_in_ad_ = (version == SSL3_VERSION);
  }

  return aead_ctx;
}

size_t SSLAEADContext::ExplicitNonceLen() const {
  if (!FUZZER_MODE && variable_nonce_included_in_record_) {
    return variable_nonce_len_;
  }
  return 0;
}

bool SSLAEADContext::SuffixLen(size_t *out_suffix_len, const size_t in_len,
                               const size_t extra_in_len) const {
  if (is_null_cipher() || FUZZER_MODE) {
    *out_suffix_len = extra_in_len;
    return true;
  }
  return !!EVP_AEAD_CTX_tag_len(ctx_.get(), out_suffix_len, in_len,
                                extra_in_len);
}

size_t SSLAEADContext::MaxOverhead() const {
  return ExplicitNonceLen() +
         (is_null_cipher() || FUZZER_MODE
              ? 0
              : EVP_AEAD_max_overhead(EVP_AEAD_CTX_aead(ctx_.get())));
}

size_t SSLAEADContext::GetAdditionalData(uint8_t out[13], uint8_t type,
                                         uint16_t wire_version,
                                         const uint8_t seqnum[8],
                                         size_t plaintext_len) {
  if (omit_ad_) {
    return 0;
  }

  OPENSSL_memcpy(out, seqnum, 8);
  size_t len = 8;
  out[len++] = type;
  if (!omit_version_in_ad_) {
    out[len++] = static_cast<uint8_t>((wire_version >> 8));
    out[len++] = static_cast<uint8_t>(wire_version);
  }
  if (!omit_length_in_ad_) {
    out[len++] = static_cast<uint8_t>((plaintext_len >> 8));
    out[len++] = static_cast<uint8_t>(plaintext_len);
  }
  return len;
}

bool SSLAEADContext::Open(CBS *out, uint8_t type, uint16_t wire_version,
                          const uint8_t seqnum[8], uint8_t *in, size_t in_len) {
  if (is_null_cipher() || FUZZER_MODE) {
    // Handle the initial NULL cipher.
    CBS_init(out, in, in_len);
    return true;
  }

  // TLS 1.2 AEADs include the length in the AD and are assumed to have fixed
  // overhead. Otherwise the parameter is unused.
  size_t plaintext_len = 0;
  if (!omit_length_in_ad_) {
    size_t overhead = MaxOverhead();
    if (in_len < overhead) {
      // Publicly invalid.
      OPENSSL_PUT_ERROR(SSL, SSL_R_BAD_PACKET_LENGTH);
      return false;
    }
    plaintext_len = in_len - overhead;
  }
  uint8_t ad[13];
  size_t ad_len =
      GetAdditionalData(ad, type, wire_version, seqnum, plaintext_len);

  // Assemble the nonce.
  uint8_t nonce[EVP_AEAD_MAX_NONCE_LENGTH];
  size_t nonce_len = 0;

  // Prepend the fixed nonce, or left-pad with zeros if XORing.
  if (xor_fixed_nonce_) {
    nonce_len = fixed_nonce_len_ - variable_nonce_len_;
    OPENSSL_memset(nonce, 0, nonce_len);
  } else {
    OPENSSL_memcpy(nonce, fixed_nonce_, fixed_nonce_len_);
    nonce_len += fixed_nonce_len_;
  }

  // Add the variable nonce.
  if (variable_nonce_included_in_record_) {
    if (in_len < variable_nonce_len_) {
      // Publicly invalid.
      OPENSSL_PUT_ERROR(SSL, SSL_R_BAD_PACKET_LENGTH);
      return false;
    }
    OPENSSL_memcpy(nonce + nonce_len, in, variable_nonce_len_);
    in += variable_nonce_len_;
    in_len -= variable_nonce_len_;
  } else {
    assert(variable_nonce_len_ == 8);
    OPENSSL_memcpy(nonce + nonce_len, seqnum, variable_nonce_len_);
  }
  nonce_len += variable_nonce_len_;

  // XOR the fixed nonce, if necessary.
  if (xor_fixed_nonce_) {
    assert(nonce_len == fixed_nonce_len_);
    for (size_t i = 0; i < fixed_nonce_len_; i++) {
      nonce[i] ^= fixed_nonce_[i];
    }
  }

  // Decrypt in-place.
  size_t len;
  if (!EVP_AEAD_CTX_open(ctx_.get(), in, &len, in_len, nonce, nonce_len, in,
                         in_len, ad, ad_len)) {
    return false;
  }
  CBS_init(out, in, len);
  return true;
}

bool SSLAEADContext::SealScatter(uint8_t *out_prefix, uint8_t *out,
                                 uint8_t *out_suffix, uint8_t type,
                                 uint16_t wire_version, const uint8_t seqnum[8],
                                 const uint8_t *in, size_t in_len,
                                 const uint8_t *extra_in, size_t extra_in_len) {
  const size_t prefix_len = ExplicitNonceLen();
  size_t suffix_len;
  if (!SuffixLen(&suffix_len, in_len, extra_in_len)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_RECORD_TOO_LARGE);
    return false;
  }
  if ((in != out && buffers_alias(in, in_len, out, in_len)) ||
      buffers_alias(in, in_len, out_prefix, prefix_len) ||
      buffers_alias(in, in_len, out_suffix, suffix_len)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_OUTPUT_ALIASES_INPUT);
    return false;
  }

  if (is_null_cipher() || FUZZER_MODE) {
    // Handle the initial NULL cipher.
    OPENSSL_memmove(out, in, in_len);
    OPENSSL_memmove(out_suffix, extra_in, extra_in_len);
    return true;
  }

  uint8_t ad[13];
  size_t ad_len = GetAdditionalData(ad, type, wire_version, seqnum, in_len);

  // Assemble the nonce.
  uint8_t nonce[EVP_AEAD_MAX_NONCE_LENGTH];
  size_t nonce_len = 0;

  // Prepend the fixed nonce, or left-pad with zeros if XORing.
  if (xor_fixed_nonce_) {
    nonce_len = fixed_nonce_len_ - variable_nonce_len_;
    OPENSSL_memset(nonce, 0, nonce_len);
  } else {
    OPENSSL_memcpy(nonce, fixed_nonce_, fixed_nonce_len_);
    nonce_len += fixed_nonce_len_;
  }

  // Select the variable nonce.
  if (random_variable_nonce_) {
    assert(variable_nonce_included_in_record_);
    if (!RAND_bytes(nonce + nonce_len, variable_nonce_len_)) {
      return false;
    }
  } else {
    // When sending we use the sequence number as the variable part of the
    // nonce.
    assert(variable_nonce_len_ == 8);
    OPENSSL_memcpy(nonce + nonce_len, seqnum, variable_nonce_len_);
  }
  nonce_len += variable_nonce_len_;

  // Emit the variable nonce if included in the record.
  if (variable_nonce_included_in_record_) {
    assert(!xor_fixed_nonce_);
    if (buffers_alias(in, in_len, out_prefix, variable_nonce_len_)) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_OUTPUT_ALIASES_INPUT);
      return false;
    }
    OPENSSL_memcpy(out_prefix, nonce + fixed_nonce_len_,
                   variable_nonce_len_);
  }

  // XOR the fixed nonce, if necessary.
  if (xor_fixed_nonce_) {
    assert(nonce_len == fixed_nonce_len_);
    for (size_t i = 0; i < fixed_nonce_len_; i++) {
      nonce[i] ^= fixed_nonce_[i];
    }
  }

  size_t written_suffix_len;
  bool result = !!EVP_AEAD_CTX_seal_scatter(
      ctx_.get(), out, out_suffix, &written_suffix_len, suffix_len, nonce,
      nonce_len, in, in_len, extra_in, extra_in_len, ad, ad_len);
  assert(!result || written_suffix_len == suffix_len);
  return result;
}

bool SSLAEADContext::Seal(uint8_t *out, size_t *out_len, size_t max_out_len,
                          uint8_t type, uint16_t wire_version,
                          const uint8_t seqnum[8], const uint8_t *in,
                          size_t in_len) {
  const size_t prefix_len = ExplicitNonceLen();
  size_t suffix_len;
  if (!SuffixLen(&suffix_len, in_len, 0)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_RECORD_TOO_LARGE);
    return false;
  }
  if (in_len + prefix_len < in_len ||
      in_len + prefix_len + suffix_len < in_len + prefix_len) {
    OPENSSL_PUT_ERROR(CIPHER, SSL_R_RECORD_TOO_LARGE);
    return false;
  }
  if (in_len + prefix_len + suffix_len > max_out_len) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_BUFFER_TOO_SMALL);
    return false;
  }

  if (!SealScatter(out, out + prefix_len, out + prefix_len + in_len, type,
                   wire_version, seqnum, in, in_len, 0, 0)) {
    return false;
  }
  *out_len = prefix_len + in_len + suffix_len;
  return true;
}

bool SSLAEADContext::GetIV(const uint8_t **out_iv, size_t *out_iv_len) const {
  return !is_null_cipher() &&
         EVP_AEAD_CTX_get_iv(ctx_.get(), out_iv, out_iv_len);
}

}  // namespace bssl
