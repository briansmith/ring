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

pub(crate) use self::features::Features;
use core::mem::size_of;

macro_rules! impl_get_feature {
    { $feature:path => $T:ident } => {
        #[derive(Clone, Copy)]
        pub(crate) struct $T(crate::cpu::Features);

        impl crate::cpu::GetFeature<$T> for super::Features {
            fn get_feature(&self) -> Option<$T> {
                if $feature.available(*self) {
                    Some($T(*self))
                } else {
                    None
                }
            }
        }
    }
}

pub(crate) trait GetFeature<T> {
    fn get_feature(&self) -> Option<T>;
}

impl GetFeature<()> for Features {
    fn get_feature(&self) -> Option<()> {
        Some(())
    }
}

impl<A, B, T> GetFeature<(A, B)> for T
where
    T: GetFeature<A>,
    T: GetFeature<B>,
{
    fn get_feature(&self) -> Option<(A, B)> {
        match (self.get_feature(), self.get_feature()) {
            (Some(a), Some(b)) => Some((a, b)),
            _ => None,
        }
    }
}

impl<A, B, C, T> GetFeature<(A, B, C)> for T
where
    T: GetFeature<A>,
    T: GetFeature<B>,
    T: GetFeature<C>,
{
    fn get_feature(&self) -> Option<(A, B, C)> {
        match (self.get_feature(), self.get_feature(), self.get_feature()) {
            (Some(a), Some(b), Some(c)) => Some((a, b, c)),
            _ => None,
        }
    }
}

#[inline(always)]
pub(crate) fn features() -> Features {
    get_or_init_feature_flags()
}

mod features {
    use crate::polyfill::NotSend;

    /// A witness indicating that CPU features have been detected and cached.
    ///
    /// This is a zero-sized type so that it can be "stored" wherever convenient.
    #[derive(Copy, Clone)]
    pub(crate) struct Features(NotSend);

    cfg_if::cfg_if! {
        if #[cfg(any(all(target_arch = "aarch64", target_endian = "little"), all(target_arch = "arm", target_endian = "little"),
                     target_arch = "x86", target_arch = "x86_64"))] {
            impl Features {
                // SAFETY: This must only be called after CPU features have been written
                // and synchronized.
                pub(super) unsafe fn new_after_feature_flags_written_and_synced_unchecked() -> Self {
                    Self(NotSend::VALUE)
                }
            }
        } else {
            impl Features {
                pub(super) fn new_no_features_to_detect() -> Self {
                    Self(NotSend::VALUE)
                }
            }
        }
    }
}

const _: () = assert!(size_of::<Features>() == 0);

cfg_if::cfg_if! {
    if #[cfg(any(all(target_arch = "aarch64", target_endian = "little"), all(target_arch = "arm", target_endian = "little")))] {
        pub mod arm;
        use arm::featureflags::get_or_init as get_or_init_feature_flags;
    } else if #[cfg(any(target_arch = "x86", target_arch = "x86_64"))] {
        pub mod intel;
        use intel::featureflags::get_or_init as get_or_init_feature_flags;
    } else {
        pub(super) fn get_or_init_feature_flags() -> Features {
            Features::new_no_features_to_detect()
        }
    }
}
