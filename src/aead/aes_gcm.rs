// Copyright 2015-2016 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

use {aead, bssl, c, error, polyfill};

/// AES-128 in GCM mode with 128-bit tags and 96 bit nonces.
///
/// C analog: `EVP_aead_aes_128_gcm`
///
/// Go analog: [`crypto.aes`](https://golang.org/pkg/crypto/aes/)
pub static AES_128_GCM: aead::Algorithm = aead::Algorithm {
    key_len: AES_128_KEY_LEN,
    init: aes_gcm_init,
    seal: aes_gcm_seal,
    open: aes_gcm_open,
    id: aead::AlgorithmID::AES_128_GCM,
};

/// AES-256 in GCM mode with 128-bit tags and 96 bit nonces.
///
/// C analog: `EVP_aead_aes_256_gcm`
///
/// Go analog: [`crypto.aes`](https://golang.org/pkg/crypto/aes/)
pub static AES_256_GCM: aead::Algorithm = aead::Algorithm {
    key_len: AES_256_KEY_LEN,
    init: aes_gcm_init,
    seal: aes_gcm_seal,
    open: aes_gcm_open,
    id: aead::AlgorithmID::AES_256_GCM,
};

fn aes_gcm_init(ctx_buf: &mut [u8], key: &[u8])
                -> Result<(), error::Unspecified> {
    bssl::map_result(unsafe {
        GFp_aes_gcm_init(ctx_buf.as_mut_ptr(), ctx_buf.len(), key.as_ptr(),
                         key.len())
    })
}

fn aes_gcm_seal(ctx: &[u64; aead::KEY_CTX_BUF_ELEMS],
                nonce: &[u8; aead::NONCE_LEN], ad: &[u8], in_out: &mut [u8],
                tag: &mut [u8; aead::TAG_LEN])
                -> Result<(), error::Unspecified> {
    let ctx = polyfill::slice::u64_as_u8(ctx);
    bssl::map_result(unsafe {
        GFp_aes_gcm_seal(ctx.as_ptr(), in_out.as_mut_ptr(), in_out.len(), tag,
                         nonce, ad.as_ptr(), ad.len())
    })
}

fn aes_gcm_open(ctx: &[u64; aead::KEY_CTX_BUF_ELEMS],
                nonce: &[u8; aead::NONCE_LEN], ad: &[u8], in_prefix_len: usize,
                in_out: &mut [u8], tag_out: &mut [u8; aead::TAG_LEN])
                -> Result<(), error::Unspecified> {
    let ctx = polyfill::slice::u64_as_u8(ctx);
    bssl::map_result(unsafe {
        GFp_aes_gcm_open(ctx.as_ptr(), in_out.as_mut_ptr(),
                         in_out.len() - in_prefix_len, tag_out, nonce,
                         in_out[in_prefix_len..].as_ptr(), ad.as_ptr(),
                         ad.len())
    })
}


const AES_128_KEY_LEN: usize = 128 / 8;
const AES_256_KEY_LEN: usize = 32; // 256 / 8

pub const AES_KEY_CTX_BUF_LEN: usize = AES_KEY_BUF_LEN + GCM128_SERIALIZED_LEN;

// Keep this in sync with `AES_KEY` in aes.h.
const AES_KEY_BUF_LEN: usize = (4 * 4 * (AES_MAX_ROUNDS + 1)) + 8;

// Keep this in sync with `AES_MAXNR` in aes.h.
const AES_MAX_ROUNDS: usize = 14;

// Keep this in sync with `GCM128_SERIALIZED_LEN` in gcm.h.
// TODO: test.
// TODO: some implementations of GCM don't require the buffer to be this big.
// We should shrink it down on those platforms since this is still huge.
const GCM128_SERIALIZED_LEN: usize = 16 * 16;


extern {
    fn GFp_aes_gcm_init(ctx_buf: *mut u8, ctx_buf_len: c::size_t,
                        key: *const u8, key_len: c::size_t) -> c::int;

    fn GFp_aes_gcm_seal(ctx_buf: *const u8, in_out: *mut u8,
                        in_out_len: c::size_t,
                        tag_out: &mut [u8; aead::TAG_LEN],
                        nonce: &[u8; aead::NONCE_LEN], ad: *const u8,
                        ad_len: c::size_t) -> c::int;

    fn GFp_aes_gcm_open(ctx_buf: *const u8, out: *mut u8,
                        in_out_len: c::size_t,
                        tag_out: &mut [u8; aead::TAG_LEN],
                        nonce: &[u8; aead::NONCE_LEN], in_: *const u8,
                        ad: *const u8, ad_len: c::size_t) -> c::int;
}


#[cfg(test)]
mod tests {
    use {c, test};
    use super::AES_MAX_ROUNDS;

    #[test]
    pub fn test_aes() {
        test::from_file("src/aead/aes_tests.txt", |section, test_case| {
            assert_eq!(section, "");
            let key = test_case.consume_bytes("Key");
            let input = test_case.consume_bytes("Input");
            let input = slice_as_array_ref!(&input, AES_BLOCK_SIZE).unwrap();
            let expected_output = test_case.consume_bytes("Output");
            let expected_output =
                slice_as_array_ref!(&expected_output, AES_BLOCK_SIZE).unwrap();

            // Key setup.
            let mut aes_key = AES_KEY {
                rd_key: [0u32; 4 * (AES_MAX_ROUNDS + 1)],
                rounds: 0,
            };
            let res = unsafe {
                GFp_AES_set_encrypt_key(key.as_ptr(), key.len() * 8,
                                        &mut aes_key)
            };
            assert_eq!(res, 0, "GFp_AES_set_encrypt_key failed.");

            // Test encryption into a separate buffer.
            let mut output_buf = [0u8; AES_BLOCK_SIZE];
            unsafe {
                GFp_AES_encrypt(input.as_ptr(), output_buf.as_mut_ptr(),
                                &aes_key);
            }
            assert_eq!(&output_buf[..], &expected_output[..]);

            // Test in-place encryption.
            output_buf.copy_from_slice(&input[..]);
            unsafe {
                GFp_AES_encrypt(output_buf.as_ptr(), output_buf.as_mut_ptr(),
                                &aes_key);
            }
            assert_eq!(&output_buf[..], &expected_output[..]);

            Ok(())
        })
    }

    const AES_BLOCK_SIZE: usize = 16;

    // Keep this in sync with AES_KEY in aes.h.
    #[repr(C)]
    pub struct AES_KEY {
        pub rd_key: [u32; 4 * (AES_MAX_ROUNDS + 1)],
        pub rounds: usize,
    }

    extern "C" {
        fn GFp_AES_set_encrypt_key(key: *const u8, bits: usize,
                                   aes_key: *mut AES_KEY) -> c::int;
        fn GFp_AES_encrypt(in_: *const u8, out: *mut u8, key: *const AES_KEY);
    }
}
