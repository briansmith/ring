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
        let p = self.inner.as_ptr();

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
            .compare_exchange(0, val, Ordering::AcqRel, Ordering::Acquire);
        if let Err(old) = exchange {
            val = old;
        }
        unsafe { NonZeroUsize::new_unchecked(val) }
    }
}
