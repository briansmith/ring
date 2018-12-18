use crate::sealed;
use core::num::Wrapping;

pub trait Encoding<T>: Copy + From<T> + Sized + sealed::Sealed
where
    T: From<Self>,
{
    const ZERO: Self;
}

pub fn as_bytes<E: Encoding<T>, T>(x: &[E]) -> &[u8]
where
    T: From<E>,
{
    unsafe {
        core::slice::from_raw_parts(x.as_ptr() as *const u8, x.len() * core::mem::size_of::<E>())
    }
}

macro_rules! define_endian {
    ($endian:ident) => {
        #[repr(transparent)]
        #[derive(Copy, Clone)]
        pub struct $endian<T>(T)
        where
            T: Copy + Clone + Sized;

        impl<T> sealed::Sealed for $endian<T> where T: Copy + Clone + Sized {}
    };
}

macro_rules! impl_endian {
    ($endian:ident, $base:ident, $to_endian:ident, $from_endian:ident) => {
        impl Encoding<$base> for $endian<$base> {
            const ZERO: Self = $endian(0);
        }

        impl From<$base> for $endian<$base> {
            #[inline]
            fn from(value: $base) -> Self { $endian($base::$to_endian(value)) }
        }

        impl From<Wrapping<$base>> for $endian<$base> {
            #[inline]
            fn from(Wrapping(value): Wrapping<$base>) -> Self { $endian($base::$to_endian(value)) }
        }

        impl From<$endian<$base>> for $base {
            #[inline]
            fn from($endian(value): $endian<$base>) -> Self { $base::$from_endian(value) }
        }

        impl AsRef<[u8; core::mem::size_of::<Self>()]> for $endian<$base> {
            fn as_ref(&self) -> &[u8; core::mem::size_of::<Self>()] {
                unsafe { core::mem::transmute(self) }
            }
        }
    };
}

define_endian!(BigEndian);
define_endian!(LittleEndian);
impl_endian!(BigEndian, u32, to_be, from_be);
impl_endian!(BigEndian, u64, to_be, from_be);
impl_endian!(LittleEndian, u32, to_le, from_le);
impl_endian!(LittleEndian, u64, to_le, from_le);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_big_endian() {
        let x = BigEndian::from(1u32);
        assert_eq!(u32::from(x), 1);
    }
}
