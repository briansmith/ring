// TODO: header.

use crate::error;
use core::{convert::TryInto, marker::PhantomData, mem::MaybeUninit, ops::RangeFrom};

pub struct InOut<'i, 'o, T> {
    input: *const T,
    output: *mut MaybeUninit<T>,
    len: usize,
    _input: PhantomData<&'i [T]>,
    _output: PhantomData<&'o mut [T]>,
}

impl<T> InOut<'_, '_, T> {
    pub fn overwrite(in_out: &mut [T]) -> Self {
        Self {
            input: in_out.as_ptr(),
            output: in_out.as_mut_ptr().cast(),
            len: in_out.len(),
            _input: Default::default(),
            _output: Default::default(),
        }
    }

    pub fn overlapping(
        in_out: &mut [T],
        offset: RangeFrom<usize>,
    ) -> Result<Self, error::Unspecified> {
        let len = in_out
            .len()
            .checked_sub(offset.start)
            .ok_or(error::Unspecified)?;
        let offset: isize = offset.start.try_into().map_err(|_| error::Unspecified)?;
        let output_const = in_out.as_ptr();
        Ok(Self {
            input: unsafe { output_const.offset(offset) },
            output: in_out.as_mut_ptr().cast(),
            len,
            _input: PhantomData,
            _output: PhantomData,
        })
    }

    // TODO: guaranteed non-null if len > 0.
    #[inline(always)]
    pub fn input_ptr(&self) -> *const T {
        self.input
    }

    #[allow(dead_code)]
    #[inline(always)]
    pub fn output_ptr_less_safe(&self) -> *mut MaybeUninit<T> {
        self.output
    }

    #[allow(dead_code)]
    #[inline(always)]
    pub fn into_output_ptr(self) -> *mut MaybeUninit<T> {
        self.output
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.len
    }

    #[allow(clippy::needless_lifetimes)]
    pub fn advance_after<'s, R>(
        &'s mut self,
        amount: usize,
        f: impl FnOnce(Self) -> R,
    ) -> Result<R, error::Unspecified> {
        let new_len = self.len.checked_sub(amount).ok_or(error::Unspecified)?;
        let iamount: isize = amount.try_into().map_err(|_| error::Unspecified)?;

        let chunk = Self {
            len: amount,
            ..*self
        };
        let r = f(chunk);

        self.len = new_len;
        self.input = unsafe { self.input.offset(iamount) }; // TODO: wrapping?
        self.output = unsafe { self.output.offset(iamount) }; // TODO: wrapping?

        Ok(r)
    }

    #[cfg(target_arch = "x86_64")]
    pub fn advance_after_partial(
        &mut self,
        f: impl FnOnce(Self) -> usize,
    ) -> Result<(), error::Unspecified> {
        let chunk = Self { ..*self };
        let amount = f(chunk);
        let iamount: isize = amount.try_into().map_err(|_| {
            self.len = 0;
            error::Unspecified
        })?;
        self.len = self.len.checked_sub(amount).ok_or_else(|| {
            self.len = 0;
            error::Unspecified
        })?;
        self.input = unsafe { self.input.offset(iamount) }; // TODO: wrapping?
        self.output = unsafe { self.output.offset(iamount) }; // TODO: wrapping?

        Ok(())
    }
}

impl<'i, T> InOut<'i, '_, T> {
    // The slice does not outlive `self` so that `into_output()` is safe.
    #[allow(clippy::needless_lifetimes)]
    #[inline(always)]
    pub fn input<'s>(&'s self) -> &'s [T] {
        let input: &'i [T] = unsafe { core::slice::from_raw_parts(self.input, self.len) };
        let input: &'s [_] = input;
        input
    }
}

impl<'o, T> InOut<'_, 'o, T> {
    pub fn into_output(self) -> &'o mut [MaybeUninit<T>] {
        // TODO: Safety comment
        unsafe { core::slice::from_raw_parts_mut(self.output, self.len()) }
    }
}
