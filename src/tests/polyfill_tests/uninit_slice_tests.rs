// Copyright 2025 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

use crate::error::LenMismatchError;
use crate::polyfill::{self, slice::Uninit, StartPtr};
use core::{mem::MaybeUninit, slice};

#[test]
fn test_write_fully_with_empty() {
    let mut uninit: [MaybeUninit<u8>; 0] = [];
    let uninit = Uninit::from(uninit.as_mut());
    let empty: &mut [u8] = &mut [];
    assert_eq!(
        Some(empty),
        uninit
            .write_fully_with(|u| {
                let (_ptr, len) = (u.start_ptr(), u.len());

                let r = &mut [];

                // We're testing the case where the lengths are zero, and the addresses don't
                // necessarily match. But...
                assert_eq!(len, 0);
                assert_eq!(r.len(), len);
                // ... we're not sure how to create a valid empty slice that definitely
                // doesn't have the same address, so punt on checking it.
                // See https://users.rust-lang.org/t/slice-from-raw-parts-returns-a-different-address-in-const-context/85692/11?u=mxk
                // and https://github.com/rust-lang/rust/issues/105536.
                // assert!(polyfill::ptr::addr_eq(r.as_ptr(), ptr));

                Ok(r)
            })
            .ok()
    );
}

#[test]
fn test_write_fully_with_nonempty() {
    let mut uninit: [MaybeUninit<u8>; 1] = [MaybeUninit::uninit(); 1];
    let uninit = Uninit::from(uninit.as_mut());
    const ARBITRARY: u8 = 1;
    assert_eq!(
        Some([ARBITRARY].as_mut_slice()),
        uninit
            .write_fully_with(|uninit| uninit.write_copy_of_slice_checked(&[ARBITRARY]))
            .ok()
    );
}

#[test]
fn test_write_fully_with_nonempty_empty() {
    let mut uninit: [MaybeUninit<u8>; 1] = [MaybeUninit::uninit(); 1];
    let uninit = Uninit::from(uninit.as_mut());
    assert!(uninit
        .write_fully_with(|uninit| uninit.write_copy_of_slice_checked(&[]))
        .is_err());
}

#[test]
fn test_write_fully_with_nonempty_short() {
    const LEN: usize = 3;
    let mut uninit: [MaybeUninit<u8>; 3] = [MaybeUninit::uninit(); LEN];
    let uninit = Uninit::from(uninit.as_mut());
    const ARBITRARY: [u8; LEN] = [1, 1, 3];
    assert!(uninit
        .write_fully_with(|u| {
            let (ptr, len) = (u.start_ptr(), u.len());

            let (_, r) = u
                .write_copy_of_slice_checked(&ARBITRARY)
                .unwrap_or_else(|LenMismatchError { .. }| unreachable!())
                .split_last_mut()
                .unwrap();

            // We're testing the case where the lengths don't match, but the addresses do.
            assert_ne!(r.len(), len);
            assert!(polyfill::ptr::addr_eq(r.as_ptr(), ptr));

            Ok(r)
        })
        .is_err());
}

#[cfg(feature = "alloc")]
#[test]
fn test_write_fully_with_nonempty_box_leak() {
    use alloc::boxed::Box;

    let mut uninit: [MaybeUninit<u8>; 1] = [MaybeUninit::uninit(); 1];
    let uninit = Uninit::from(uninit.as_mut());
    const ARBITRARY: u8 = 1;
    assert!(uninit
        .write_fully_with(|u| {
            let (ptr, len) = (u.start_ptr(), u.len());

            let r: &mut [_] = Box::leak(Box::new([ARBITRARY]));

            // We're testing the case where the lengths match, but the addresses don't.
            assert_eq!(r.len(), len);
            assert!(!polyfill::ptr::addr_eq(r.as_ptr(), ptr));

            Ok(r)
        })
        .is_err());
}

#[test]
fn test_write_fully_with_nonempty_leak_without_box_longer_lifetime() {
    const LEN: usize = 3;
    let mut non_empty: [u32; LEN] = [1, 2, 3];
    let longer_lifetime_non_empty: &mut [u32] = non_empty.as_mut_slice();

    {
        let mut uninit: [MaybeUninit<u32>; LEN] = [MaybeUninit::uninit(); LEN];
        let uninit = Uninit::from(uninit.as_mut());
        assert!(uninit
            .write_fully_with(|u: Uninit<'_, u32>| {
                let (ptr, len) = (u.start_ptr(), u.len());

                // SAFETY: This is safe because `longer_lifetime_non_empty` outlives `uninit`.
                let r = unsafe {
                    slice::from_raw_parts_mut(
                        longer_lifetime_non_empty.as_mut_ptr(),
                        longer_lifetime_non_empty.len(),
                    )
                };

                // We're testing the case where the lengths match, but the addresses don't.
                assert_eq!(r.len(), len);
                assert!(!polyfill::ptr::addr_eq(r.as_ptr(), ptr));

                Ok(r)
            })
            .is_err());
    }
}

#[test]
fn test_write_fully_with_nonempty_leak_without_box_same_lifeime() {
    const LEN: usize = 3;

    let mut uninit: [MaybeUninit<u32>; LEN * 2] = [MaybeUninit::uninit(); LEN * 2];
    let (uninit, after) = uninit.split_at_mut(LEN);

    let after = Uninit::from(after)
        .write_copy_of_slice_checked(&[1, 2, 3])
        .ok()
        .unwrap();
    assert_eq!(uninit.len(), after.len());

    let uninit = Uninit::from(uninit);
    assert!(uninit
        .write_fully_with(|u: Uninit<'_, u32>| {
            let (ptr, len) = (u.start_ptr(), u.len());

            // Transmute the lifetime.
            // SAFETY: This is safe because `after` has the same lifetime as it is part of the
            // same allocation.
            let r = unsafe { slice::from_raw_parts_mut(after.as_mut_ptr(), after.len()) };

            // We're testing the case where the lengths match, but the addresses don't.
            assert_eq!(r.len(), len);
            assert!(!polyfill::ptr::addr_eq(r.as_ptr(), ptr));

            Ok(r)
        })
        .is_err());
}
