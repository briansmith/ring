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

//! SM4-GCM: SM4 in Galois/Counter Mode
//!
//! Combines the SM4 block cipher ([`super::sm4`]) with ring's existing
//! GHASH/GCM infrastructure to produce an AEAD algorithm compatible with
//! [`crate::aead::Algorithm`].
//!
//! Key length: 128 bits. Nonce length: 96 bits. Tag length: 128 bits.
//!
//! # Standards
//! - SM4: GB/T 32907-2016
//! - GCM: NIST SP 800-38D
//! - SM4-GCM TLS cipher suite: RFC 8998

// Placeholder for Phase 3 implementation.
