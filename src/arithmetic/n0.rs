// Copyright 2015-2022 Brian Smith.
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

use crate::limb::Limb;

#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct N0([Limb; N0::LIMBS_USED]);

match_target_word_bits! {
    64 => {
        impl N0 {
            pub(super) const LIMBS_USED: usize = 1;

            #[inline]
            pub const fn precalculated(n0: u64) -> Self {
                Self([n0])
            }
        }
    },
    32 => {
         impl N0 {
            pub(super) const LIMBS_USED: usize = 2;

            #[inline]
            pub const fn precalculated(n0: u64) -> Self {
                Self([n0 as Limb, (n0 >> crate::limb::LIMB_BITS) as Limb])
            }
         }
    },
}
