/// RSA key pair components.
pub struct Components<Public, Private = Public>
where
    Public: AsRef<[u8]> + core::fmt::Debug,
{
    /// The public key components.
    pub public_key: super::super::public::Components<Public>,

    /// The private exponent.
    pub d: Private,

    /// The first prime factor of `d`.
    pub p: Private,

    /// The second prime factor of `d`.
    pub q: Private,

    /// `p`'s public Chinese Remainder Theorem exponent.
    pub dP: Private,

    /// `q`'s public Chinese Remainder Theorem exponent.
    pub dQ: Private,

    /// `q**-1 mod p`.
    pub qInv: Private,
}

impl<Public, Private> Copy for Components<Public, Private>
where
    Public: AsRef<[u8]> + Copy + core::fmt::Debug,
    Private: Copy,
{
}

impl<Public, Private> Clone for Components<Public, Private>
where
    Public: AsRef<[u8]> + Clone + core::fmt::Debug,
    Private: Clone,
{
    fn clone(&self) -> Self {
        Self {
            public_key: self.public_key.clone(),
            d: self.d.clone(),
            p: self.p.clone(),
            q: self.q.clone(),
            dP: self.dP.clone(),
            dQ: self.dQ.clone(),
            qInv: self.qInv.clone(),
        }
    }
}

impl<Public, Private> core::fmt::Debug for Components<Public, Private>
where
    Public: AsRef<[u8]> + core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        // Non-public components are intentionally skipped
        f.debug_struct("Components")
            .field("public_key", &self.public_key)
            .finish()
    }
}
