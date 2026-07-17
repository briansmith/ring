#![allow(missing_docs)]

/// `compile_time_assert_core_error_error::<T>();` fails to compile if `T`
/// doesn't implement `core::error::Error`.
const fn compile_time_assert_core_error_error<T: core::error::Error>() {}

#[cfg(feature = "std")]
#[test]
fn error_impl_std_error_error_test() {
    use ring::error;
    #[allow(deprecated)]
    use ring::test;

    test::compile_time_assert_std_error_error::<error::Unspecified>();
    test::compile_time_assert_std_error_error::<error::KeyRejected>();
}

#[test]
fn error_impl_core_error_error_test() {
    use ring::error;

    compile_time_assert_core_error_error::<error::Unspecified>();
    compile_time_assert_core_error_error::<error::KeyRejected>();
}
