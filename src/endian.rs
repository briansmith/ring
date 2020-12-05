use core::num::Wrapping;

/// An `Encoding` of a type `T` can be converted to/from its byte
/// representation without any byte swapping or other computation.
///
/// The `Self: Copy` constraint addresses `clippy::declare_interior_mutable_const`.
pub trait Encoding<T>: From<T> + Into<T>
where
    Self: Copy,
{
    const ZERO: Self;
}

/// Work around the inability to implement `AsRef` for arrays of `Encoding`s
/// due to the coherence rules.
pub trait ArrayEncoding<T> {
    fn as_byte_array(&self) -> &T;
}

/// Work around the inability to implement `from` for arrays of `Encoding`s
/// due to the coherence rules.
pub trait FromByteArray<T> {
    fn from_byte_array(a: &T) -> Self;
}

macro_rules! define_endian {
    ($endian:ident) => {
        #[repr(transparent)]
        pub struct $endian<T>(T);

        impl<T> Copy for $endian<T> where T: Copy {}

        impl<T> Clone for $endian<T>
        where
            T: Clone,
        {
            #[inline]
            fn clone(&self) -> Self {
                Self(self.0.clone())
            }
        }

        impl<T> core::ops::BitXorAssign for $endian<T>
        where
            T: core::ops::BitXorAssign,
        {
            #[inline(always)]
            fn bitxor_assign(&mut self, a: Self) {
                self.0 ^= a.0;
            }
        }
    };
}

macro_rules! impl_from_byte_array {
    ($endian:ident, $base:ident, $elems:expr) => {
        impl FromByteArray<[u8; $elems * core::mem::size_of::<$base>()]>
            for [$endian<$base>; $elems]
        {
            #[inline]
            fn from_byte_array(a: &[u8; $elems * core::mem::size_of::<$base>()]) -> Self {
                unsafe { core::mem::transmute_copy(a) }
            }
        }
    };
}

macro_rules! impl_array_encoding {
    ($endian:ident, $base:ident, $elems:expr) => {
        impl ArrayEncoding<[u8; $elems * core::mem::size_of::<$base>()]>
            for [$endian<$base>; $elems]
        {
            #[inline]
            fn as_byte_array(&self) -> &[u8; $elems * core::mem::size_of::<$base>()] {
                let as_bytes_ptr =
                    self.as_ptr() as *const [u8; $elems * core::mem::size_of::<$base>()];
                unsafe { &*as_bytes_ptr }
            }
        }

        impl_from_byte_array!($endian, $base, $elems);
    };
}

macro_rules! impl_endian {
    ($endian:ident, $base:ident, $to_endian:ident, $from_endian:ident, $size:expr) => {
        impl Encoding<$base> for $endian<$base> {
            const ZERO: Self = Self(0);
        }

        impl From<[u8; $size]> for $endian<$base> {
            #[inline]
            fn from(bytes: [u8; $size]) -> Self {
                Self($base::from_ne_bytes(bytes))
            }
        }

        impl From<$endian<$base>> for [u8; $size] {
            #[inline]
            fn from(encoded: $endian<$base>) -> Self {
                $base::to_ne_bytes(encoded.0)
            }
        }

        impl From<$base> for $endian<$base> {
            #[inline]
            fn from(value: $base) -> Self {
                Self($base::$to_endian(value))
            }
        }

        impl From<Wrapping<$base>> for $endian<$base> {
            #[inline]
            fn from(Wrapping(value): Wrapping<$base>) -> Self {
                Self($base::$to_endian(value))
            }
        }

        impl From<$endian<$base>> for $base {
            #[inline]
            fn from($endian(value): $endian<$base>) -> Self {
                $base::$from_endian(value)
            }
        }

        impl_array_encoding!($endian, $base, 1);
        impl_array_encoding!($endian, $base, 2);
        impl_array_encoding!($endian, $base, 3);
        impl_array_encoding!($endian, $base, 4);
        impl_array_encoding!($endian, $base, 8);
    };
}

define_endian!(BigEndian);
define_endian!(LittleEndian);
impl_endian!(BigEndian, u32, to_be, from_be, 4);
impl_endian!(BigEndian, u64, to_be, from_be, 8);
impl_endian!(LittleEndian, u32, to_le, from_le, 4);
impl_endian!(LittleEndian, u64, to_le, from_le, 8);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_big_endian() {
        let x = BigEndian::from(1u32);
        assert_eq!(u32::from(x), 1);
    }
}
