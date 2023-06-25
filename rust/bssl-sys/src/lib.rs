#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

// Set in build.rs
include!(env!("BINDGEN_RS_FILE"));

// TODO(crbug.com/boringssl/596): Remove these wrappers.
pub fn ERR_GET_LIB(packed_error: u32) -> i32 {
    unsafe { ERR_GET_LIB_RUST(packed_error) }
}

pub fn ERR_GET_REASON(packed_error: u32) -> i32 {
    unsafe { ERR_GET_REASON_RUST(packed_error) }
}

pub fn ERR_GET_FUNC(packed_error: u32) -> i32 {
    unsafe { ERR_GET_FUNC_RUST(packed_error) }
}

pub use OPENSSL_sk_free as sk_free;
pub use OPENSSL_sk_new_null as sk_new_null;
pub use OPENSSL_sk_num as sk_num;
pub use OPENSSL_sk_pop as sk_pop;
pub use OPENSSL_sk_push as sk_push;
pub use OPENSSL_sk_value as sk_value;

pub fn init() {
    unsafe {
        CRYPTO_library_init();
    }
}
