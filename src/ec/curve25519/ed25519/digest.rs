use crate::digest;

use super::super::ops::{Scalar, UnreducedScalar, SCALAR_LEN};

pub fn eddsa_digest(signature_r: &[u8], public_key: &[u8], msg: &[u8]) -> digest::Digest {
    let mut ctx = digest::Context::new(&digest::SHA512);
    ctx.update(signature_r);
    ctx.update(public_key);
    ctx.update(msg);
    ctx.finish()
}

pub fn digest_scalar(digest: digest::Digest) -> Scalar {
    let mut unreduced = [0u8; digest::SHA512_OUTPUT_LEN];
    unreduced.copy_from_slice(digest.as_ref());
    unsafe { GFp_x25519_sc_reduce(&mut unreduced) };
    let mut scalar = [0u8; SCALAR_LEN];
    scalar.copy_from_slice(&unreduced[..SCALAR_LEN]);
    scalar
}
extern "C" {
    fn GFp_x25519_sc_reduce(s: &mut UnreducedScalar);
}
