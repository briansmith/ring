Version 0.17.13 (2025-03-06)
============================
Increased MSRV to 1.66.0 to avoid bugs in earlier versions so that we can
safely use `core::arch::x86_64::__cpuid` and `core::arch::x86::__cpuid` from
Rust in future releases.

AVX2-based VAES-CLMUL implementation. This will be a notable performance
improvement for most newish x86-64 systems. This will likely raise the minimum
binutils version supported for very old Linux distros.

Version 0.17.12 (2025-03-05)
============================
Bug fix: https://github.com/briansmith/ring/pull/2447 for denial of service (DoS).

* Fixes a panic in `ring::aead::quic::HeaderProtectionKey::new_mask()` when
integer overflow checking is enabled. In the QUIC protocol, an attacker can
induce this panic by sending a specially-crafted packet. Even unintentionally
it is likely to occur in 1 out of every 2**32 packets sent and/or received.

* Fixes a panic on 64-bit targets in `ring::aead::{AES_128_GCM, AES_256_GCM}`
when overflow checking is enabled, when encrypting/decrypting approximately
68,719,476,700 bytes (about 64 gigabytes) of data in a single chunk. Protocols
like TLS and SSH are not affected by this because those protocols break large 
amounts of data into small chunks. Similarly, most applications will not
attempt to encrypt/decrypt 64GB of data in one chunk.

Overflow checking is not enabled in release mode by default, but
`RUSTFLAGS="-C overflow-checks"` or `overflow-checks = true` in the Cargo.toml
profile can override this. Overflow checking is usually enabled by default in
debug mode.
