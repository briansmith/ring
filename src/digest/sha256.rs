use c;
use core;
use core::num::Wrapping;
use polyfill;
use super::MAX_CHAINING_LEN;

pub const CHAINING_LEN: usize = 256 / 8;
pub const BLOCK_LEN: usize = 512 / 8;
const CHAINING_WORDS: usize = CHAINING_LEN / 4;

type W32 = Wrapping<u32>;

pub unsafe extern fn block_data_order(state: &mut [u64; MAX_CHAINING_LEN / 8],
                                      data: *const u8,
                                      num: c::size_t) {
    let data = data as *const [u8; BLOCK_LEN];
    let blocks = core::slice::from_raw_parts(data, num);
    block_data_order_safe(state, blocks);
}

const K: [W32; 64] =
    [Wrapping(0x428a2f98), Wrapping(0x71374491), Wrapping(0xb5c0fbcf), Wrapping(0xe9b5dba5),
     Wrapping(0x3956c25b), Wrapping(0x59f111f1), Wrapping(0x923f82a4), Wrapping(0xab1c5ed5),
     Wrapping(0xd807aa98), Wrapping(0x12835b01), Wrapping(0x243185be), Wrapping(0x550c7dc3),
     Wrapping(0x72be5d74), Wrapping(0x80deb1fe), Wrapping(0x9bdc06a7), Wrapping(0xc19bf174),
     Wrapping(0xe49b69c1), Wrapping(0xefbe4786), Wrapping(0x0fc19dc6), Wrapping(0x240ca1cc),
     Wrapping(0x2de92c6f), Wrapping(0x4a7484aa), Wrapping(0x5cb0a9dc), Wrapping(0x76f988da),
     Wrapping(0x983e5152), Wrapping(0xa831c66d), Wrapping(0xb00327c8), Wrapping(0xbf597fc7),
     Wrapping(0xc6e00bf3), Wrapping(0xd5a79147), Wrapping(0x06ca6351), Wrapping(0x14292967),
     Wrapping(0x27b70a85), Wrapping(0x2e1b2138), Wrapping(0x4d2c6dfc), Wrapping(0x53380d13),
     Wrapping(0x650a7354), Wrapping(0x766a0abb), Wrapping(0x81c2c92e), Wrapping(0x92722c85),
     Wrapping(0xa2bfe8a1), Wrapping(0xa81a664b), Wrapping(0xc24b8b70), Wrapping(0xc76c51a3),
     Wrapping(0xd192e819), Wrapping(0xd6990624), Wrapping(0xf40e3585), Wrapping(0x106aa070),
     Wrapping(0x19a4c116), Wrapping(0x1e376c08), Wrapping(0x2748774c), Wrapping(0x34b0bcb5),
     Wrapping(0x391c0cb3), Wrapping(0x4ed8aa4a), Wrapping(0x5b9cca4f), Wrapping(0x682e6ff3),
     Wrapping(0x748f82ee), Wrapping(0x78a5636f), Wrapping(0x84c87814), Wrapping(0x8cc70208),
     Wrapping(0x90befffa), Wrapping(0xa4506ceb), Wrapping(0xbef9a3f7), Wrapping(0xc67178f2)];

/// rotate_right by n bits for u32 == rotate_left by 32 - n bits
#[inline]
fn rotate_right(w32: W32, bits: u32) -> W32 {
    polyfill::wrapping_rotate_left_u32(w32, 32 - bits)
}

#[inline]
fn shift_right(w32: W32, bits: usize) -> W32 {
    w32 >> bits
}

fn block_data_order_safe(state: &mut [u64; MAX_CHAINING_LEN / 8], blocks: &[[u8; BLOCK_LEN]]) {
    let state = polyfill::slice::u64_as_u32_mut(state);
    let state = polyfill::slice::as_wrapping_mut(state);
    let state = &mut state[..CHAINING_WORDS];
    let state = slice_as_array_ref_mut!(state, CHAINING_WORDS).unwrap();

    for block in blocks {
        let mut w: [W32; 64] = [Wrapping(0); 64];
        for i in 0..16 {
            let offset = i * 4;
            let word = slice_as_array_ref!(&block[offset..][..4], 4).unwrap();
            w[i] = Wrapping(polyfill::slice::u32_from_be_u8(word));
        }

        for i in 16..64  {
            let s0 = rotate_right(w[i - 15], 7) ^ rotate_right(w[i - 15], 18) ^ shift_right(w[i - 15], 3);
            let s1 = rotate_right(w[i - 2], 17) ^ rotate_right(w[i - 2], 19) ^ shift_right(w[i - 2], 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
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
            let s1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25);
            let ch = (e & f) ^ (!e & g);
            let temp1 = h + s1 + ch + K[i] + w[i];
            let s0 = rotate_right(a, 2)  ^ rotate_right(a, 13) ^ rotate_right(a, 22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0 + maj;
            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;
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
