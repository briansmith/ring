// Copyright 2018 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

/// An approximation of `core::convert::From` that lets us define our own
/// conversions between types defined outside this crate.
///
/// Do not use this this in situations where `From` could be used.
pub trait From_<F>: Sized {
    fn from_(value: F) -> Self;
}

pub trait Into_<T>
where
    T: Sized,
{
    fn into_(self) -> T;
}

impl<T, F> Into_<T> for F
where
    T: From_<F>,
{
    #[inline]
    fn into_(self) -> T { T::from_(self) }
}

/// An approximation of the unstable `core::convert::TryFrom`.
pub trait TryFrom_<T>: Sized {
    type Error;

    fn try_from_(value: T) -> Result<Self, Self::Error>;
}

/// An approximation of the unstable `core::convert::TryInto`.
pub trait TryInto_<T>
where
    T: Sized,
{
    type Error;

    fn try_into_(self) -> Result<T, Self::Error>;
}

impl<T, F> TryInto_<T> for F
where
    T: TryFrom_<F>,
{
    type Error = <T as TryFrom_<F>>::Error;

    #[inline]
    fn try_into_(self) -> Result<T, Self::Error> { T::try_from_(self) }
}

#[derive(Debug)]
pub struct TryFromSliceError(());

macro_rules! impl_array_try_from {
    ($ty:ty, $len:expr) => {
        impl<'a> TryFrom_<&'a [$ty]> for &'a [$ty; $len] {
            type Error = TryFromSliceError;

            #[inline]
            fn try_from_(slice: &'a [$ty]) -> Result<Self, Self::Error> {
                unsafe { transmute_slice::<[$ty; $len], $ty>(slice, $len) }
            }
        }

        impl<'a> TryFrom_<&'a mut [$ty]> for &'a mut [$ty; $len] {
            type Error = TryFromSliceError;

            #[inline]
            fn try_from_(slice: &'a mut [$ty]) -> Result<Self, Self::Error> {
                unsafe { transmute_slice_mut::<[$ty; $len], $ty>(slice, $len) }
            }
        }
    };
}

impl_array_try_from!(u8, 12);
impl_array_try_from!(u8, 16);
impl_array_try_from!(u8, 32);
impl_array_try_from!(u8, 64);

#[inline]
unsafe fn transmute_slice<A, T>(slice: &[T], expected_len: usize) -> Result<&A, TryFromSliceError> {
    if slice.len() != expected_len {
        return Err(TryFromSliceError(()));
    }
    Ok(core::mem::transmute(slice.as_ptr()))
}

unsafe fn transmute_slice_mut<A, T>(
    slice: &mut [T], expected_len: usize,
) -> Result<&mut A, TryFromSliceError> {
    if slice.len() != expected_len {
        return Err(TryFromSliceError(()));
    }
    Ok(core::mem::transmute(slice.as_ptr()))
}

macro_rules! impl_array_split {
    ($ty:ty, $first:expr, $second:expr) => {
        impl From_<&[$ty; $first + $second]> for (&[$ty; $first], &[$ty; $second]) {
            #[inline]
            fn from_(to_split: &[$ty; $first + $second]) -> Self {
                let first: *const u8 = &to_split[0];
                let split_at: *const u8 = &to_split[$first];
                unsafe { (core::mem::transmute(first), core::mem::transmute(split_at)) }
            }
        }

        impl From_<&mut [$ty; $first + $second]> for (&mut [$ty; $first], &mut [$ty; $second]) {
            #[inline]
            fn from_(to_split: &mut [$ty; $first + $second]) -> Self {
                let first: *mut u8 = &mut to_split[0];
                let split_at: *mut u8 = &mut to_split[$first];
                unsafe { (core::mem::transmute(first), core::mem::transmute(split_at)) }
            }
        }
    };
}

impl_array_split!(u8, 32, 32);
