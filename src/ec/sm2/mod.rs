// Copyright 2026 The ring Authors.
// Copyright 2026 The libsmx Authors.
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

//! SM2 椭圆曲线密码学 (GB/T 32918)
//!
//! SM2 is an elliptic curve public key cryptography standard based on a
//! 256-bit prime field curve defined in GB/T 32918.1-2016.
//! The curve has a = p - 3, analogous to NIST P-256's a = -3 mod p property.
//!
//! This module provides SM2 digital signature (GB/T 32918.2) and key
//! agreement (GB/T 32918.3) functionality.
//!
//! # OID
//! The SM2 curve OID is `1.2.156.10197.1.301` (curveSM2).
//! DER encoding: `06 08 2A 86 48 CE 3D 03 01 07` is P-256; SM2 is:
//! `06 08 2A 81 1C CF 55 01 82 2D`

/// DER-encoded OID for the SM2 curve: 1.2.156.10197.1.301
///
/// This is the curveSM2 object identifier as defined in GB/T 35276-2017
/// and registered in IANA.
#[allow(dead_code)] // Used in Phase 5 PKCS#8 template construction.
pub(crate) const CURVE_OID: &[u8] = &[
    0x06, 0x08, // OID tag + length (8 bytes)
    0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x82,
    0x2D,
    // 1.2.156.10197.1.301
    // = 1.2 -> 2a
    // 156   -> 81 1c
    // 10197 -> cf 55
    // 1     -> 01
    // 301   -> 82 2d
];

// Placeholder for Phase 4/5 implementation.
