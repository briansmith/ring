// Copyright 2016 Brian Smith.
// Portions Copyright (c) 2016, Google Inc.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

use crate::aead::aes::Variant;
use crate::aead::block::{Block, BLOCK_LEN};
use crate::aead::{Aad, KeyInner, Nonce, Tag};
use core::ops::{Range, RangeFrom};
use core::slice::ChunksExact;

const KEY_LEN: usize = 16;

/// AES-128 in CCM mode as described in [RFC 5116](https://datatracker.ietf.org/doc/html/rfc5116#section-5.3).
///
/// Generic CCM is described in both:
/// - [RFC 3610](https://datatracker.ietf.org/doc/html/rfc3610)
/// - [NIST 800-38c](https://csrc.nist.gov/publications/detail/sp/800-38c/final)
///
/// The variant here uses the following fixed parameters:
/// - M == 16 - number of octets in the authentication tag
/// - L == 3 - number of octets in the length field
///
/// This implies that the nonce length is 15 - 3 == 12
///
/// Note: CCM with these parameters is used in TLS 1.2 and 1.3
pub static AES_128_CCM: crate::aead::Algorithm = crate::aead::Algorithm {
    key_len: KEY_LEN,
    init: aes_128_ccm_init,
    seal: aes_128_ccm_seal,
    open: aes_128_ccm_open,
    id: crate::aead::AlgorithmID::AES_128_CCM,
    max_input_len: MAX_MESSAGE_LENGTH_PER_NONCE,
};

fn aes_128_ccm_init(
    key: &[u8],
    cpu_features: crate::cpu::Features,
) -> Result<KeyInner, crate::error::Unspecified> {
    crate::aead::aes::Key::new(key, Variant::AES_128, cpu_features).map(|k| KeyInner::AesCcm(k))
}

fn aes_128_ccm_seal(key: &KeyInner, nonce: Nonce, aad: Aad<&[u8]>, in_out: &mut [u8]) -> Tag {
    let key = match key {
        KeyInner::AesCcm(x) => x,
        _ => unreachable!(),
    };

    let tag = calc_auth_tag(key.clone(), &nonce, aad, in_out);

    let mut stream = BlockStream::new(key.clone(), &nonce);

    let tag = tag ^ stream.next_block();

    stream.apply(in_out, 0..);

    Tag::from(tag.as_ref().clone())
}

fn aes_128_ccm_open(
    key: &KeyInner,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    in_out: &mut [u8],
    src: RangeFrom<usize>,
) -> Tag {
    //  length of the ciphertext (and plaintext)
    let ct_len = in_out.len() - src.start;

    let key = match key {
        KeyInner::AesCcm(x) => x,
        _ => unreachable!(),
    };

    let mut stream = BlockStream::new(key.clone(), &nonce);

    // save this for after we calculate the tag
    let tag_block = stream.next_block();

    stream.apply(in_out, src);

    // calculate the tag over the plaintext
    let tag = calc_auth_tag(key.clone(), &nonce, aad, &in_out[..ct_len]) ^ tag_block;

    Tag::from(tag.as_ref().clone())
}

/// This limit is set by a 3-byte length encoding when calculating the
/// authentication tag.
///
/// 2^24 - 1
const MAX_MESSAGE_LENGTH_PER_NONCE: u64 = 16777215;

/// The auth flags
///
/// M' = (16-2) / 2 = 7
/// L' = 3 - 1 = 2
const AUTH_FLAGS_NO_DATA: u8 = (7 << 3) | 2;
const AUTH_FLAGS_WITH_DATA: u8 = AUTH_FLAGS_NO_DATA | (1 << 6);

struct AesCbcMac {
    state: Block,
    key: crate::aead::aes::Key,
}

impl AesCbcMac {
    fn new(key: crate::aead::aes::Key) -> Self {
        Self {
            state: Block::zero(),
            key,
        }
    }

    fn update(&mut self, block: Block) {
        self.state ^= block;
        self.state = self.key.encrypt_block(self.state);
    }

    /// consume the MAC and transform into a Tag
    fn finalize(self) -> Block {
        self.state
    }
}

struct Ranges {
    pos: usize,
    end: usize,
    chunk_size: usize,
}

impl Iterator for Ranges {
    type Item = Range<usize>;

    fn next(&mut self) -> Option<Self::Item> {
        let rem = self.end.checked_sub(self.pos)?;
        if rem == 0 {
            return None;
        }

        let chunk_len = rem.min(self.chunk_size);
        let ret = self.pos..self.pos + chunk_len;
        self.pos += chunk_len;
        Some(ret)
    }
}

fn ranges(
    start: usize,
    end: usize,
    chunk_size: usize,
) -> impl Iterator<Item = (Range<usize>, Range<usize>)> {
    let ranges = Ranges {
        pos: start,
        end,
        chunk_size,
    };

    ranges.map(move |x| (x.clone(), x.start - start..x.end - start))
}

/// block stream for encryption
struct BlockStream {
    counter: u32,
    key: crate::aead::aes::Key,
    state: [u8; BLOCK_LEN],
}

impl BlockStream {
    fn new(key: crate::aead::aes::Key, nonce: &Nonce) -> Self {
        let mut state = [0; BLOCK_LEN];

        state[0] = 2; // Flags = L' = L - 1
        state[1..13].copy_from_slice(nonce.as_ref());

        // the counter gets portion is written each time `next` is called

        Self {
            counter: 0,
            key,
            state,
        }
    }

    /// `src` has the same meaning as elsewhere in the aead module, namely
    /// it allows us to perform a shift when we decrypt to the front of `in_out`.
    fn apply(&mut self, in_out: &mut [u8], src: RangeFrom<usize>) {
        for (src, dest) in ranges(src.start, in_out.len(), BLOCK_LEN) {
            let mut block: [u8; BLOCK_LEN] = [0; BLOCK_LEN];
            block[..src.len()].copy_from_slice(&in_out[src.clone()]);
            let encrypted = Block::from(&block) ^ self.next_block();
            in_out[dest].copy_from_slice(&encrypted.as_ref()[..src.len()]);
        }
    }

    fn next_block(&mut self) -> Block {
        let ctr = self.next_counter();
        self.state[13..].copy_from_slice(&ctr);
        self.key.encrypt_block(Block::from(&self.state))
    }

    fn next_counter(&mut self) -> [u8; 3] {
        assert!(self.counter < 16777216); // counter must be < 2^24
        let bytes = self.counter.to_le_bytes();
        self.counter += 1;
        [bytes[2], bytes[1], bytes[0]]
    }
}

const fn auth_flags(a_data: &Aad<&[u8]>) -> u8 {
    if a_data.0.is_empty() {
        AUTH_FLAGS_NO_DATA
    } else {
        AUTH_FLAGS_WITH_DATA
    }
}

// this looks dangerous but there is a guard in the generic AEAD code that
// validates that the length is always less than the algorithm per-nonce maximum
fn get_length_be(input: &[u8]) -> [u8; 3] {
    // Just in case the ring code that guards this gets changed
    assert!(crate::polyfill::u64_from_usize(input.len()) <= MAX_MESSAGE_LENGTH_PER_NONCE);
    // it's simpler to do little endian and then swap the order
    let bytes = input.len().to_le_bytes();
    [bytes[2], bytes[1], bytes[0]]
}

fn calc_block_0(nonce: &Nonce, aad: Aad<&[u8]>, input: &[u8]) -> Block {
    let mut block: [u8; BLOCK_LEN] = [0; BLOCK_LEN];
    block[0] = auth_flags(&aad);
    // bytes 1 -> 12
    block[1..13].copy_from_slice(nonce.as_ref());
    // bytes 13 -> 15 are the big endian length
    block[13..].copy_from_slice(get_length_be(input).as_slice());
    Block::from(&block)
}

struct PaddedBlocks<'a> {
    chunks: ChunksExact<'a, u8>,
    remainder: Option<&'a [u8]>,
}

impl<'a> PaddedBlocks<'a> {
    fn new(input: &'a [u8]) -> Self {
        let exact = input.chunks_exact(BLOCK_LEN);
        let remainder = if exact.remainder().is_empty() {
            None
        } else {
            Some(exact.remainder())
        };
        Self {
            chunks: exact,
            remainder,
        }
    }
}

impl<'a> Iterator for PaddedBlocks<'a> {
    type Item = Block;

    fn next(&mut self) -> Option<Self::Item> {
        match self.chunks.next() {
            None => match self.remainder.take() {
                None => None,
                Some(x) => {
                    let mut block: [u8; BLOCK_LEN] = [0; BLOCK_LEN];
                    block[0..x.len()].copy_from_slice(x);
                    Some(Block::from(&block))
                }
            },
            Some(x) => {
                let mut block: [u8; BLOCK_LEN] = [0; BLOCK_LEN];
                block.copy_from_slice(x);
                Some(Block::from(&block))
            }
        }
    }
}

/// If aad is non-empty, return an iterator over the AD blocks
fn prepare_aad_blocks(aad: Aad<&[u8]>) -> Option<impl Iterator<Item = Block> + '_> {
    if aad.0.is_empty() {
        return None;
    }

    let mut block: [u8; BLOCK_LEN] = [0; BLOCK_LEN];

    let be_bytes: [u8; 8] = crate::polyfill::u64_from_usize(aad.0.len()).to_be_bytes();

    // copy the length representation into the block and get the
    // number of bytes in the representation
    let num_length_bytes: usize = if aad.0.len() < 65280 {
        // < 2^16 - 2^8
        block[0..2].copy_from_slice(&be_bytes[6..]);
        2
    } else if aad.0.len() < 4294967296 {
        // < 2^32
        block[0] = 0xFF;
        block[1] = 0xFE;
        block[2..6].copy_from_slice(&be_bytes[4..]);
        6
    } else {
        // otherwise it's the < 2^64 case
        block[0] = 0xFF;
        block[1] = 0xFF;
        block[2..10].copy_from_slice(&be_bytes);
        10
    };

    // how much space do we have left in B0?
    let block_unused_bytes = BLOCK_LEN - num_length_bytes;

    // put as much as we can of the AD in B0
    let aad_b0_len = aad.0.len().min(block_unused_bytes);
    let (b0_ad_bytes, remainder) = aad.0.split_at(aad_b0_len);
    block[num_length_bytes..num_length_bytes + aad_b0_len].copy_from_slice(b0_ad_bytes);

    Some(core::iter::once(Block::from(&block)).chain(PaddedBlocks::new(remainder)))
}

fn calc_auth_tag(
    key: crate::aead::aes::Key,
    nonce: &Nonce,
    aad: Aad<&[u8]>,
    input: &[u8],
) -> Block {
    let mut mac = AesCbcMac::new(key);

    // setup and mac the first block
    mac.update(calc_block_0(nonce, aad, input));

    // optional AAD blocks
    if let Some(blocks) = prepare_aad_blocks(aad) {
        for b in blocks {
            mac.update(b);
        }
    }

    // input blocks
    for b in PaddedBlocks::new(input) {
        mac.update(b);
    }

    mac.finalize()
}

#[cfg(test)]
mod tests {
    use crate::aead::aes_ccm::ranges;

    #[test]
    fn range_iterator_full_chunks() {
        let mut ranges = ranges(0, 6, 3);

        assert_eq!(ranges.next(), Some((0..3, 0..3)));
        assert_eq!(ranges.next(), Some((3..6, 3..6)));
        assert_eq!(ranges.next(), None);
    }

    #[test]
    fn range_iterator_partial_chunk() {
        let mut ranges = ranges(2, 10, 3);

        assert_eq!(ranges.next(), Some((2..5, 0..3)));
        assert_eq!(ranges.next(), Some((5..8, 3..6)));
        assert_eq!(ranges.next(), Some((8..10, 6..8)));
        assert_eq!(ranges.next(), None);
    }
}
