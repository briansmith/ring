Version 0.17.12 (2025-03-05)
============================
Bug fix: https://github.com/briansmith/ring/pull/2447 for denial of service (DoS).

Fixes a panic in `ring::aead::quic::HeaderProtectionKey::new_mask()` when
integer overflow checking is enabled. Integer overflow checking is not enabled
in release mode by default, but `RUSTFLAGS="-C overflow-checks"` or
`overflow-checks = true` in the Cargo.toml profile can override this.

Fixes a panic in when using `ring::aead::{AES_128_GCM, AES_256_GCM}` when
integer overflow checking is enabled, when  encrypting/decrypting approximately
68,719,476,700 bytes (about 64 gigabytes) of data in a single chunk. Integer
overflow checking is not enabled in release mode by default, but
`RUSTFLAGS="-C overflow-checks"` or `overflow-checks = true` in the Cargo.toml
profile can override this.
