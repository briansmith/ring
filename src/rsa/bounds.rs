use crate::bits;

/// The bounds that determine whether an RSA key is acceptable.
pub trait Bounds: crate::sealed::Sealed {
    /// The minimum length of the public modulus.
    fn n_min_bits(&self) -> bits::BitLength;

    /// The maximum length of the public modulus.
    fn n_max_bits(&self) -> bits::BitLength;

    /// The minimum length of the public exponent.
    fn e_min_value(&self) -> u64;
}
