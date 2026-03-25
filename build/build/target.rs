// Copyright 2015-2026 Brian Smith.
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

// Avoid `std::env` here. All configuration should be done through `Target`,
// `Profile`, and `Tools`.
use std::path::PathBuf;

pub const X86: &str = "x86";
pub const X86_64: &str = "x86_64";
pub const AARCH64: &str = "aarch64";
pub const ARM: &str = "arm";
pub const WASM32: &str = "wasm32";

pub const ANDROID: &str = "android";
pub const DRAGONFLY: &str = "dragonfly";
pub const FREEBSD: &str = "freebsd";
pub const FUCHSIA: &str = "fuchsia";
pub const HAIKU: &str = "haiku";
pub const HORIZON: &str = "horizon";
pub const HURD: &str = "hurd";
pub const ILLUMOS: &str = "illumos";
pub const LINUX: &str = "linux";
pub const NETBSD: &str = "netbsd";
pub const NTO: &str = "nto";
pub const OPENBSD: &str = "openbsd";
pub const REDOX: &str = "redox";
pub const SOLARIS: &str = "solaris";
pub const VITA: &str = "vita";

/// Operating systems that have the same ABI as macOS on every architecture
/// mentioned in `ASM_TARGETS`.
pub const APPLE_ABI: &[&str] = &["ios", "macos", "tvos", "visionos", "watchos"];

pub const WINDOWS: &str = "windows";
pub const CYGWIN: &str = "cygwin";

pub struct Target {
    pub arch: String,
    pub os: String,
    pub env: String,
    pub endian: Endian,
    pub out_dir: PathBuf,
}

pub enum Endian {
    Little,
    Other,
}
