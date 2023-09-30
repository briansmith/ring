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
    // TODO: The list of operating systems for `aarch64` should really be
    // "whatever has `std::arch::is_aarch64_feature_detected`".
    #[cfg(any(
        target_arch = "x86",
        target_arch = "x86_64",
        all(
            target_arch = "aarch64",
            any(
                target_os = "android",
                target_os = "dragonfly",
                target_os = "freebsd",
                target_os = "illumos",
                target_os = "ios",
                target_os = "linux",
                target_os = "macos",
                target_os = "netbsd",
                target_os = "openbsd",
                target_os = "redox",
                target_os = "solaris",
                target_os = "windows",
            )
        ),
        all(
            target_arch = "arm",
            any(
                target_os = "android",
                target_os = "fuchsia",
                target_os = "linux",
                target_os = "windows"
            )
        )
    ))]
    {
        static INIT: spin::Once<()> = spin::Once::new();
        let () = INIT.call_once(|| {
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            {
                prefixed_extern! {
                    fn OPENSSL_cpuid_setup();
                }
                unsafe {
                    OPENSSL_cpuid_setup();
                }
            }

            #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
            {
                arm::setup();
            }
        });
    }

    Features(())
}

pub mod arm;
pub mod intel;
