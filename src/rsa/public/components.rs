/// RSA public key components
#[derive(Debug)]
pub struct Components<B: AsRef<[u8]> + core::fmt::Debug> {
    /// The public modulus, encoded in big-endian bytes without leading zeros.
    pub n: B,

    /// The public exponent, encoded in big-endian bytes without leading zeros.
    pub e: B,
}

impl<B: Copy> Copy for Components<B> where B: AsRef<[u8]> + core::fmt::Debug {}

impl<B: Clone> Clone for Components<B>
where
    B: AsRef<[u8]> + core::fmt::Debug,
{
    fn clone(&self) -> Self {
        Self {
            n: self.n.clone(),
            e: self.e.clone(),
        }
    }
}
