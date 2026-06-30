// Run `cargo run -p ring-bindgen` in the Cargo workspace root directory.

fn main() {
    windows_bindgen::bindgen([
        "--out",
        "src/polyfill/aarch64_windows.rs",
        "--sys",
        "--no-deps",
        "--filter",
        "IsProcessorFeaturePresent",
        "PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE",
    ])
    .unwrap()
}
