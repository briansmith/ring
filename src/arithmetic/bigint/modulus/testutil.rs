use super::super::super::montgomery::RR;
use super::*;
use crate::cpu;
use crate::error::{self, KeyRejected};

pub fn consume_modulus<M>(
    test_case: &mut crate::testutil::TestCase,
    name: &str,
) -> IntoMont<M, RR> {
    let value = test_case.consume_bytes(name);
    ValidatedInput::try_from_be_bytes(value.as_slice().into())
        .map_err(error::erase::<KeyRejected>)
        .unwrap()
        .build_value()
        .into_mont(cpu::features())
}
