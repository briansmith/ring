//! Thread-safe, non-blocking, "first one wins" flavor of `OnceCell`.
//!
//! If two threads race to initialize a type from the `race` module, they
//! don't block, execute initialization function together, but only one of
//! them stores the result.
//!
//! This module does not require `std` feature.
//!
//! # Atomic orderings
//!
//! All types in this module use `Acquire` and `Release`
//! [atomic orderings](Ordering) for all their operations. While this is not
//! strictly necessary for types other than `OnceBox`, it is useful for users as
//! it allows them to be certain that after `get` or `get_or_init` returns on
//! one thread, any side-effects caused by the setter thread prior to them
//! calling `set` or `get_or_init` will be made visible to that thread; without
//! it, it's possible for it to appear as if they haven't happened yet from the
//! getter thread's perspective. This is an acceptable tradeoff to make since
//! `Acquire` and `Release` have very little performance overhead on most
//! architectures versus `Relaxed`.

// The "atomic orderings" section of the documentation above promises
// "happens-before" semantics. This drives the choice of orderings in the uses
// of `compare_exchange` below. On success, the value was zero/null, so there
// was nothing to acquire (there is never any `Ordering::Release` store of 0).
// On failure, the value was nonzero, so it was initialized previously (perhaps
// on another thread) using `Ordering::Release`, so we must use
// `Ordering::Acquire` to ensure that store "happens-before" this load.

// We always use 32-bit values so that there is no difference in behavior
// for targets with different `target_pointer_width`, e.g. ARM64_32 vs. ILP64.

#![cfg(target_has_atomic = "32")]

#[allow(unused_imports)]
use crate::polyfill::prelude::*;

use cfg_if::cfg_if;
use core::marker::PhantomData;
use core::num::NonZeroU32;
use core::sync::atomic::{self, AtomicU32};

pub trait Ordering {
    const ACQUIRE: atomic::Ordering;
    const RELEASE: atomic::Ordering;
}

cfg_if! {
    if #[cfg(any(all(target_arch = "arm", target_endian = "little"),
                 target_arch = "x86",
                 target_arch = "x86_64"))]
    {
        pub struct AcquireRelease(());

        impl Ordering for AcquireRelease {
            const ACQUIRE: atomic::Ordering = atomic::Ordering::Acquire;
            const RELEASE: atomic::Ordering = atomic::Ordering::Release;
        }
    }
}

cfg_if! {
    if #[cfg(all(target_arch = "aarch64", target_endian = "little"))] {
        pub struct Relaxed(());

        impl Ordering for Relaxed {
            const ACQUIRE: atomic::Ordering = atomic::Ordering::Relaxed;
            const RELEASE: atomic::Ordering = atomic::Ordering::Relaxed;
        }
    }
}

/// A thread-safe cell which can be written to only once.
pub struct OnceNonZeroU32<O> {
    inner: AtomicU32,
    ordering: PhantomData<O>,
}

impl<O: Ordering> OnceNonZeroU32<O> {
    /// Creates a new empty cell.
    #[inline]
    pub const fn new() -> Self {
        Self {
            inner: AtomicU32::new(0),
            ordering: PhantomData,
        }
    }

    /// Gets the underlying value.
    #[inline]
    pub fn get(&self) -> Option<NonZeroU32> {
        let val = self.inner.load(O::ACQUIRE);
        NonZeroU32::new(val)
    }

    /// Get the reference to the underlying value, without checking if the cell
    /// is initialized.
    ///
    /// # Safety
    ///
    /// Caller must ensure that the cell is in initialized state, and that
    /// the contents are acquired by (synchronized to) this thread.
    pub unsafe fn get_unchecked(&self) -> NonZeroU32 {
        // SAFETY: The caller is responsible for ensuring that the value
        // was initialized and that the contents have been acquired by
        // this thread. Assuming that, we can assume there will be no
        // conflicting writes to the value since the value will never
        // change once initialized. This relies on the statement in
        // https://doc.rust-lang.org/1.83.0/core/sync/atomic/ that "(A
        // `compare_exchange` or `compare_exchange_weak` that does not
        // succeed is not considered a write." See
        // https://github.com/rust-lang/rust/issues/138246.
        let val = {
            let p: *const u32 = self.inner.as_ptr().cast_const();
            unsafe { p.read() }
        };

        // SAFETY: The caller is responsible for ensuring the value is
        // initialized and thus not zero.
        unsafe { NonZeroU32::new_unchecked(val) }
    }

    /// Gets the contents of the cell, initializing it with `f` if the cell was
    /// empty.
    ///
    /// If several threads concurrently run `get_or_init`, more than one `f` can
    /// be called. However, all threads will return the same value, produced by
    /// some `f`.
    pub fn get_or_init<F>(&self, f: F) -> NonZeroU32
    where
        F: FnOnce() -> NonZeroU32,
    {
        match self.get() {
            Some(it) => it,
            None => self.init(f),
        }
    }

    #[cold]
    #[inline(never)]
    fn init(&self, f: impl FnOnce() -> NonZeroU32) -> NonZeroU32 {
        let nz = f();
        let mut val = nz.get();
        if let Err(old) = self.compare_exchange(nz) {
            val = old;
        }
        unsafe { NonZeroU32::new_unchecked(val) }
    }

    #[inline(always)]
    fn compare_exchange(&self, val: NonZeroU32) -> Result<u32, u32> {
        self.inner
            .compare_exchange(0, val.get(), O::RELEASE, O::ACQUIRE)
    }
}
