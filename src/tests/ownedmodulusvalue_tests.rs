use crate::{
    arithmetic::{bigint::OwnedModulusValue, MIN_LIMBS},
    error::KeyRejected,
    limb::{LIMB_BITS, LIMB_BYTES},
};
use alloc::vec::Vec;

// XXX: This only tests the bit length calculation and error handling; it
// doesn't verify that the resultant modulus has the expected value.
#[test]
fn ownedmodulusvalue_from_be_bytes_test() {
    const LARGEST_TOO_SMALL: &[u8] = &[0xff; 3 * LIMB_BYTES];
    const LARGEST_TOO_SMALL_BITS: usize = LIMB_BITS * (MIN_LIMBS - 1);

    const CASES: &[(&[u8], Result<usize, KeyRejected>)] = &[
        (&[], Err(KeyRejected::too_small())),
        (&[0], Err(KeyRejected::too_small())),
        (&[1], Err(KeyRejected::too_small())),
        (&[2], Err(KeyRejected::too_small())),
        (&[3], Err(KeyRejected::too_small())),
        (&[0xff], Err(KeyRejected::too_small())),
        (&[0xff; 1 * LIMB_BYTES], Err(KeyRejected::too_small())),
        (&[0xff; 2 * LIMB_BYTES], Err(KeyRejected::too_small())),
        (LARGEST_TOO_SMALL, Err(KeyRejected::too_small())),
        (&[0xff; 4 * LIMB_BYTES], Ok(LIMB_BITS * MIN_LIMBS)),
    ];
    let cases: &[(&[u8], Result<usize, KeyRejected>)] = &[
        (
            &prepend(0, LARGEST_TOO_SMALL),
            Err(KeyRejected::invalid_encoding()),
        ),
        (
            &prepend(1, LARGEST_TOO_SMALL),
            Ok(LARGEST_TOO_SMALL_BITS + 1),
        ),
        (
            &append(LARGEST_TOO_SMALL, 0),
            Err(KeyRejected::invalid_component()), // Even
        ),
        (
            &append(LARGEST_TOO_SMALL, 1),
            Ok(LARGEST_TOO_SMALL_BITS + 8),
        ),
        (
            &append(LARGEST_TOO_SMALL, 2),
            Err(KeyRejected::invalid_component()), // Even
        ),
    ];
    struct M {}
    for (i, &(input, expected)) in CASES.iter().chain(cases).enumerate() {
        let actual = OwnedModulusValue::<M>::from_be_bytes(untrusted::Input::from(input))
            .map(|m| m.len_bits().as_bits());
        match (expected, actual) {
            (Ok(expected), Ok(actual)) if expected == actual => {} // passed
            (Err(expected), Err(actual)) if expected.eq(actual) => {} // passed
            (Err(expected), actual) => match actual {
                Ok(_) => panic!("case {i}: Expected error {expected}, got Ok"),
                Err(actual) => panic!("case {i}: Expected error {expected}, got error {actual}"),
            },
            (Ok(expected), Ok(actual)) => {
                panic!("case {i}: Expected Ok({expected}, got Ok({actual})");
            }
            (Ok(expected), Err(actual)) => {
                panic!("case {i}: Expected Ok({expected}), got error {actual}");
            }
        }
    }
}

fn prepend(a: u8, b: &[u8]) -> Vec<u8> {
    let mut r = Vec::with_capacity(b.len() + 1);
    r.push(a);
    r.extend_from_slice(b);
    r
}

fn append(a: &[u8], b: u8) -> Vec<u8> {
    let mut r = Vec::with_capacity(a.len() + 1);
    r.extend_from_slice(a);
    r.push(b);
    r
}
