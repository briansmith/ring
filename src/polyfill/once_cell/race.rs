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

use core::sync::atomic;

use atomic::{AtomicUsize, Ordering};
use core::num::NonZeroUsize;

/// A thread-safe cell which can be written to only once.
pub struct OnceNonZeroUsize {
    inner: AtomicUsize,
}

impl OnceNonZeroUsize {
    /// Creates a new empty cell.
    #[inline]
    pub const fn new() -> OnceNonZeroUsize {
        OnceNonZeroUsize {
            inner: AtomicUsize::new(0),
        }
    }

    /// Get the reference to the underlying value, without checking if the cell
    /// is initialized.
    ///
    /// # Safety
    ///
    /// Caller must ensure that the cell is in initialized state, and that
    /// the contents are acquired by (synchronized to) this thread.
    pub unsafe fn get_unchecked(&self) -> NonZeroUsize {
        #[inline(always)]
        fn as_const_ptr(r: &AtomicUsize) -> *const usize {
            use core::mem::align_of;

            let p: *const AtomicUsize = r;
            // SAFETY: "This type has the same size and bit validity as
            // the underlying integer type, usize. However, the alignment of
            // this type is always equal to its size, even on targets where
            // usize has a lesser alignment."
            const _ALIGNMENT_COMPATIBLE: () =
                assert!(align_of::<AtomicUsize>() % align_of::<usize>() == 0);
            p.cast::<usize>()
        }

        // TODO(MSRV-1.70): Use `AtomicUsize::as_ptr().cast_const()`
        // See https://github.com/rust-lang/rust/issues/138246.
        let p = as_const_ptr(&self.inner);

        // SAFETY: The caller is responsible for ensuring that the value
        // was initialized and that the contents have been acquired by
        // this thread. Assuming that, we can assume there will be no
        // conflicting writes to the value since the value will never
        // change once initialized. This relies on the statement in
        // https://doc.rust-lang.org/1.83.0/core/sync/atomic/ that "(A
        // `compare_exchange` or `compare_exchange_weak` that does not
        // succeed is not considered a write."
        let val = unsafe { p.read() };

        // SAFETY: The caller is responsible for ensuring the value is
        // initialized and thus not zero.
        unsafe { NonZeroUsize::new_unchecked(val) }
    }

    /// Gets the contents of the cell, initializing it with `f` if the cell was
    /// empty.
    ///
    /// If several threads concurrently run `get_or_init`, more than one `f` can
    /// be called. However, all threads will return the same value, produced by
    /// some `f`.
    pub fn get_or_init<F>(&self, f: F) -> NonZeroUsize
    where
        F: FnOnce() -> NonZeroUsize,
    {
        let val = self.inner.load(Ordering::Acquire);
        match NonZeroUsize::new(val) {
            Some(it) => it,
            None => self.init(f),
        }
    }

    #[cold]
    #[inline(never)]
    fn init(&self, f: impl FnOnce() -> NonZeroUsize) -> NonZeroUsize {
        let mut val = f().get();
        let exchange = self
            .inner
            .compare_exchange(0, val, Ordering::Release, Ordering::Acquire);
        if let Err(old) = exchange {
            val = old;
        }
        unsafe { NonZeroUsize::new_unchecked(val) }
    }
}
