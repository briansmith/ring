use super::super::super::montgomery::RR;
use super::*;
use crate::{
    cpu,
    error::{self, KeyRejected},
};

pub fn consume_modulus<'out, M>(
    out: &'out mut OversizedUninit,
    test_case: &mut crate::testutil::TestCase,
    name: &str,
) -> IntoMont<'out, M, RR> {
    let value = test_case.consume_bytes(name);
    ValidatedInput::try_from_be_bytes(value.as_slice().into())
        .map_err(error::erase::<KeyRejected>)
        .unwrap()
        .build_into_mont(out, cpu::features())
}
