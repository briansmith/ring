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

macro_rules! define_endian {
    ($endian:ident) => {
        #[derive(Clone, Copy)]
        #[repr(transparent)]
        pub struct $endian<T>(T);
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
    };
}

define_endian!(BigEndian);
impl_endian!(BigEndian, u32, to_be, from_be, 4);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_big_endian() {
        let x = BigEndian::from(1u32);
        assert_eq!(u32::from(x), 1);
    }
}
