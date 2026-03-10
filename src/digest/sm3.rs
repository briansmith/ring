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

//! SM3 哈希算法 (GB/T 32905)
//!
//! SM3 is a cryptographic hash function producing a 256-bit digest.
//! It operates on 512-bit (64-byte) blocks with an 8×32-bit chaining state,
//! structurally identical to SHA-256.
//!
//! This module provides the SM3 compression function used by
//! [`super::super::SM3`] via the `block_data_order` dispatch mechanism.
//!
//! # Standard
//! GB/T 32905-2016 / ISO/IEC 10118-3

// Placeholder for Phase 2 implementation.
