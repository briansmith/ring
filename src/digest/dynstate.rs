// Copyright 2015-2019 Brian Smith.
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

use super::{format_output, sha2, Output};

// SAFETY: When constructed with `new32` (resp. `new64`), `as32` (resp. `as64`)
// is fully initialized and is the active field. The active field never changes
// after initialization.
#[derive(Clone, Copy)] // XXX: Why do we need to be `Copy`?
#[repr(C)]
pub(super) union DynState {
    as64: sha2::State64,
    as32: sha2::State32,
}

impl DynState {
    pub const fn new32(initial_state: sha2::State32) -> Self {
        Self {
            as32: initial_state,
        }
    }

    pub const fn new64(initial_state: sha2::State64) -> Self {
        Self {
            as64: initial_state,
        }
    }

    pub(super) unsafe fn as32(&mut self) -> &mut sha2::State32 {
        unsafe { &mut self.as32 }
    }

    #[allow(dead_code)]
    pub(super) unsafe fn as64(&mut self) -> &mut sha2::State64 {
        unsafe { &mut self.as64 }
    }
}

pub(super) unsafe fn sha256_format_output(input: DynState) -> Output {
    let input = unsafe { input.as32 };
    format_output::<_, _, { core::mem::size_of::<u32>() }>(input, u32::to_be_bytes)
}

pub(super) unsafe fn sha512_format_output(input: DynState) -> Output {
    let input = unsafe { input.as64 };
    format_output::<_, _, { core::mem::size_of::<u64>() }>(input, u64::to_be_bytes)
}
