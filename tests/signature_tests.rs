extern crate ring;

use ring::signature;
use ring::test;

#[test]
fn signature_impl_test() {
    test::compile_time_assert_debug::<signature::KeyPair>();
    test::compile_time_assert_send::<signature::KeyPair>();

    test::compile_time_assert_clone::<signature::Signature>();
    test::compile_time_assert_copy::<signature::Signature>();
    test::compile_time_assert_send::<signature::Signature>();
    test::compile_time_assert_sync::<signature::Signature>();
}
