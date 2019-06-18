// Copyright 2016-2019 Brian Smith.
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

//! C types.
//!
//! The libc crate provide the C types for most, but not all, targets that
//! *ring* supports.

#[cfg(not(all(target_arch = "wasm32", target_env = "",)))]
use ::libc;

#[cfg(all(target_arch = "wasm32", target_env = ""))]
mod libc {
    //! The WASM32 ABI is described at
    //! https://github.com/WebAssembly/tool-conventions/blob/master/BasicCABI.md#data-representation

    pub(crate) type c_int = i32;
    pub(crate) type c_uint = u32;

    // "The size_t type is defined as unsigned long."
    // However, we must define it as an alias of `usize` for compatibility with `libc::size_t`.
    pub(crate) type size_t = usize;
}

pub(crate) type size_t = self::libc::size_t;
pub(crate) type int = self::libc::c_int;
pub(crate) type uint = self::libc::c_uint;

#[cfg(all(
    any(target_os = "android", target_os = "linux"),
    any(target_arch = "aarch64", target_arch = "arm")
))]
pub(crate) type ulong = libc::c_ulong;

#[cfg(any(target_os = "android", target_os = "linux"))]
pub(crate) type long = libc::c_long;
