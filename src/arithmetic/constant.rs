use crate::limb::Limb;

const fn parse_digit(d: u8) -> u8 {
    match d.to_ascii_lowercase() {
        b'0'..=b'9' => d - b'0',
        b'a'..=b'f' => d - b'a' + 10,
        _ => panic!(),
    }
}

// TODO: this would be nicer as a trait, but currently traits don't support const functions
pub const fn limbs_from_hex<const LIMBS: usize>(hex: &str) -> [Limb; LIMBS] {
    let hex = hex.as_bytes();
    let mut limbs = [0; LIMBS];
    let limb_nibbles = core::mem::size_of::<Limb>() * 2;
    let mut i = 0;

    while i < hex.len() {
        let char = hex[hex.len() - 1 - i];
        let val = parse_digit(char);
        limbs[i / limb_nibbles] |= (val as Limb) << ((i % limb_nibbles) * 4);
        i += 1;
    }

    limbs
}
