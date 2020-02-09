use super::super::public;

/// RSA key pair components.
pub struct Components<B> {
    /// The public key components.
    pub public_key: public::Components<B>,

    /// The private exponent.
    pub d: B,

    /// The first prime factor of `d`.
    pub p: B,

    /// The second prime factor of `d`.
    pub q: B,

    /// `p`'s public Chinese Remainder Theorem exponent.
    pub dP: B,

    /// `q`'s public Chinese Remainder Theorem exponent.
    pub dQ: B,

    /// `q**-1 mod p`.
    pub qInv: B,
}

impl<B> Copy for Components<B> where B: Copy {}

impl<B> Clone for Components<B>
where
    B: Clone,
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

impl<B> core::fmt::Debug for Components<B>
where
    public::Components<B>: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        // Non-public components are intentionally skipped
        f.debug_struct("Components")
            .field("public_key", &self.public_key)
            .finish()
    }
}
