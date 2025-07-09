// Copyright 2018-2024 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

#![cfg(all(target_arch = "arm", target_endian = "little"))]

use super::{Counter, Overlapping, AES_KEY};
use core::mem::MaybeUninit;

/// SAFETY:
///   * The caller must ensure that if blocks > 0 then either `input` and
///     `output` do not overlap at all, or input == output.add(n) for some
///     (nonnegative) n.
///   * if blocks > 0, The caller must ensure `input` points to `blocks` blocks
///     and that `output` points to writable space for `blocks` blocks.
///   * The caller must ensure that `vpaes_key` was initialized with
///     `vpaes_set_encrypt_key`.
///   * Upon returning, `blocks` blocks will have been read from `input` and
///     written to `output`.
pub(super) unsafe fn ctr32_encrypt_blocks_with_vpaes_key(
    in_out: Overlapping<'_>,
    vpaes_key: &AES_KEY,
    ctr: &mut Counter,
) {
    prefixed_extern! {
        // bsaes_ctr32_encrypt_blocks requires transformation of an existing
        // VPAES key; there is no `bsaes_set_encrypt_key`.
        fn vpaes_encrypt_key_to_bsaes(bsaes_key: *mut AES_KEY, vpaes_key: &AES_KEY);
    }
    prefixed_extern_ctr32_encrypt_blocks! { bsaes_ctr32_encrypt_blocks }

    // SAFETY:
    //   * The caller ensures `vpaes_key` was initialized by
    //     `vpaes_set_encrypt_key`.
    //   * `bsaes_key was zeroed above, and `vpaes_encrypt_key_to_bsaes`
    //     is assumed to initialize `bsaes_key`.
    let bsaes_key = {
        let mut uninit = MaybeUninit::<AES_KEY>::uninit();
        unsafe { vpaes_encrypt_key_to_bsaes(uninit.as_mut_ptr(), vpaes_key) };
        unsafe { uninit.assume_init() }
    };

    // The code for `vpaes_encrypt_key_to_bsaes` notes "vpaes stores one
    // fewer round count than bsaes, but the number of keys is the same,"
    // so use this as a sanity check.
    debug_assert_eq!(bsaes_key.rounds(), vpaes_key.rounds() + 1);

    // SAFETY:
    //  * `bsaes_key` is in bsaes format after calling
    //    `vpaes_encrypt_key_to_bsaes`.
    //  * `bsaes_ctr32_encrypt_blocks` satisfies the contract for
    //    `ctr32_encrypt_blocks`.
    unsafe { bsaes_key.ctr32_encrypt_blocks(in_out, ctr, bsaes_ctr32_encrypt_blocks) }
}
