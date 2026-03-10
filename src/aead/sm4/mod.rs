// Copyright 2026 The ring Authors.
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

//! SM4 分组密码核心 (GB/T 32907)
//!
//! SM4 is a 128-bit block cipher with a 128-bit key and 32 rounds.
//! This module implements the SM4 block cipher used as the basis for
//! SM4-GCM AEAD in [`super::sm4_gcm`].
//!
//! # Constant-time S-box
//! The S-box is implemented as a boolean circuit (bitslice), avoiding all
//! memory lookups and thus providing resistance against cache-timing attacks.
//!
//! # Standard
//! GB/T 32907-2016

// Placeholder for Phase 3 implementation.
