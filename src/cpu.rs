// Copyright 2016 Brian Smith.
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

/// A witness indicating that CPU features have been detected and cached.
///
/// TODO: Eventually all feature detection logic should be done through
/// functions that accept a `Features` parameter, to guarantee that nothing
/// tries to read the cached values before they are written.
///
/// This is a zero-sized type so that it can be "stored" wherever convenient.
#[derive(Copy, Clone)]
pub(crate) struct Features(());

#[inline(always)]
pub(crate) fn features() -> Features {
    #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
    use arm::init_global_shared_with_assembly;

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    use intel::init_global_shared_with_assembly;

    #[cfg(any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "x86",
        target_arch = "x86_64",
    ))]
    {
        static INIT: spin::Once<()> = spin::Once::new();
        let () = INIT.call_once(|| unsafe { init_global_shared_with_assembly() });
    }

    Features(())
}

#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
pub mod arm;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod intel;
