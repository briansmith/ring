#[allow(unused_imports)]
use crate::polyfill::prelude::*;

use {
    super::{super::LimbSliceError, storage::LIMBS_PER_CHUNK},
    crate::{limb::Limb, window5::LeakyWindow5},
};

// `a` is the `i`th entry to store into `table`, where `i` is NOT secret.
// `table` has space for 32 entries the same size as `a`. Instead of storing
// entries consecutively row-wise, instead store them column-wise.
pub(in super::super::super) fn scatter5(
    a: &[[Limb; LIMBS_PER_CHUNK]],
    table: &mut [[Limb; LIMBS_PER_CHUNK]],
    i: LeakyWindow5,
) -> Result<(), LimbSliceError> {
    // Verify there are 32 elements the same length as `a`.
    let _num_limbs = super::storage::check_common(a, table)?;
    let i = i.leak_usize();
    table
        .as_flattened_mut()
        .iter_mut()
        .skip(i)
        .step_by(32)
        .zip(a.as_flattened())
        .for_each(|(t, &a)| {
            *t = a;
        });
    Ok(())
}
