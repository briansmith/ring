use c;
use core;
use polyfill;
use super::MAX_CHAINING_LEN;

pub const CHAINING_LEN: usize = 256 / 8;
pub const BLOCK_LEN: usize = 512 / 8;
const CHAINING_WORDS: usize = CHAINING_LEN / 4;

pub unsafe extern fn block_data_order(state: &mut [u64; MAX_CHAINING_LEN / 8],
                                      data: *const u8,
                                      num: c::size_t) {
    let data = data as *const [u8; BLOCK_LEN];
    let blocks = core::slice::from_raw_parts(data, num);
    block_data_order_safe(state, blocks);
}

const K: [u32; 64] =
    [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
     0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
     0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
     0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
     0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
     0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
     0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
     0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
     0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
     0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
     0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
     0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
     0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
     0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
     0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
     0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];

fn block_data_order_safe(state: &mut [u64; MAX_CHAINING_LEN / 8], blocks: &[[u8; BLOCK_LEN]]) {
    let state = polyfill::slice::u64_as_u32_mut(state);
    let state = &mut state[..CHAINING_WORDS];
    let state = slice_as_array_ref_mut!(state, CHAINING_WORDS).unwrap();

    for block in blocks {
        let mut w: [u32; 64] = [0; 64];
        for i in 0..16 {
            let offset = i * 4;
            let word = slice_as_array_ref!(&block[offset..][..4], 4).unwrap();
            w[i] = polyfill::slice::u32_from_be_u8(word);
        }

        for i in 16..64  {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let temp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2)  ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }
}


#[cfg(test)]
mod tests {

    use super::super::{digest, SHA256};

    #[test]
    fn sha256_foobar() {
        let expected: [u8; 32] = [
            0xc3, 0xab, 0x8f, 0xf1, 0x37, 0x20, 0xe8, 0xad,
            0x90, 0x47, 0xdd, 0x39, 0x46, 0x6b, 0x3c, 0x89,
            0x74, 0xe5, 0x92, 0xc2, 0xfa, 0x38, 0x3d, 0x4a,
            0x39, 0x60, 0x71, 0x4c, 0xae, 0xf0, 0xc4, 0xf2
        ];
        let input = "foobar";
        let output = digest(&SHA256, input.as_bytes());

        assert_eq!(expected, output.as_ref())
    }
}
