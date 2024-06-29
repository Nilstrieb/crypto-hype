//! https://datatracker.ietf.org/doc/html/rfc3174

use std::num::Wrapping;

use crate::utils::Fingerprint;

use crate::utils::WrappingExt;

const BYTES_IN_WORD: usize = 4;
const BITS_IN_BYTE: usize = 8;
const BLOCK_WORD_SIZE: usize = 16;

pub type Sha1Fingerprint = Fingerprint<20>;

pub fn hash(msg: &[u8]) -> Sha1Fingerprint {
    // Padding
    let msg = pad(msg);

    let mut h = [
        Wrapping(0x67452301_u32),
        Wrapping(0xEFCDAB89),
        Wrapping(0x98BADCFE),
        Wrapping(0x10325476),
        Wrapping(0xC3D2E1F0),
    ];

    let mut w = [Wrapping(0_u32); 80];

    let read_word = |idx: usize| {
        let bytes = &msg[(idx * BYTES_IN_WORD)..][..BYTES_IN_WORD];
        Wrapping(u32::from_be_bytes(bytes.try_into().unwrap()))
    };

    for block in 0..(msg.len() / (BLOCK_WORD_SIZE * BYTES_IN_WORD)) {
        for i in 0..16 {
            w[i] = read_word(BLOCK_WORD_SIZE * block + i);
        }

        for t in 16..=79 {
            w[t] = (w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]).w_rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for t in 0..=79 {
            let temp = a.w_rotate_left(5) + f(t, b, c, d) + e + w[t] + k(t);
            [e, d, c, b, a] = [d, c, b.w_rotate_left(30), a, temp];
        }

        h = [h[0] + a, h[1] + b, h[2] + c, h[3] + d, h[4] + e];
    }

    let mut result = [0; 20];
    for i in 0..5 {
        result[(BYTES_IN_WORD * i)..(BYTES_IN_WORD * (i + 1))]
            .copy_from_slice(&h[i].0.to_be_bytes());
    }

    Fingerprint(result)
}

fn f(t: usize, b: Wrapping<u32>, c: Wrapping<u32>, d: Wrapping<u32>) -> Wrapping<u32> {
    match t {
        0..=19 => (b & c) | (!b & d),
        20..=39 => b ^ c ^ d,
        40..=59 => (b & c) | (b & d) | (c & d),
        _ => b ^ c ^ d,
    }
}
fn k(t: usize) -> Wrapping<u32> {
    match t {
        0..=19 => Wrapping(0x5A827999),
        20..=39 => Wrapping(0x6ED9EBA1),
        40..=59 => Wrapping(0x8F1BBCDC),
        _ => Wrapping(0xCA62C1D6),
    }
}

fn pad(msg: &[u8]) -> Vec<u8> {
    // todo: this is pretty duplicated from md5 except len is BE.
    let mut msg_pad = msg.to_vec();
    msg_pad.push(0b10000000);

    const ALREADY_PADDED_ZERO_BITS: usize = 7;
    let len = (msg.len() * BITS_IN_BYTE) + 1; // We always pad a 1
    let rest = len % 512;

    let total_pad_zero_bits = 448_usize.wrapping_sub(rest) % 512;
    msg_pad.extend(
        std::iter::repeat(0).take((total_pad_zero_bits - ALREADY_PADDED_ZERO_BITS) / BITS_IN_BYTE),
    );
    msg_pad.extend_from_slice(&((msg.len() * BITS_IN_BYTE) as u64).to_be_bytes());
    assert!(msg_pad.len() % (512 / BITS_IN_BYTE) == 0);

    msg_pad
}

#[cfg(test)]
mod tests {
    use super::Sha1Fingerprint;
    use hex_literal::hex;
    use std::str::FromStr;

    #[test]
    fn pad() {
        let msg = [0b01100001, 0b01100010, 0b01100011, 0b01100100, 0b01100101];
        let padded = super::pad(&msg);
        assert_eq!(padded, hex!("61626364 65800000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000028"));
    }

    #[track_caller]
    fn assert_same(s: &str, fingerprint: &str) {
        assert_eq!(
            super::hash(s.as_bytes()),
            Sha1Fingerprint::from_str(fingerprint).unwrap()
        );
    }

    #[test]
    fn hashing() {
        assert_same("", "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_same("a", "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8");
        assert_same("abc", "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_same("message digest", "c12252ceda8be8994d5fa0290a47231c1d16aae3");
        assert_same(
            "abcdefghijklmnopqrstuvwxyz",
            "32d10c7b8cf96570ca04ce37f2a19d84240d3a89",
        );
        assert_same(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "761c457bf73b14d27e9e9265c46f4b4dda11f940",
        );
        assert_same(
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "50abf5706a150990a08b2c5ea40fa0e585554732",
        );
        assert_same(
            "8217498327598324983271489372149837214987239847239847238947239847983247298347298347238947238947289\
            3257239587348957432098574389257438957348975849357438957489357849357439857438957439857438957348957346\
            289053420574238574395743298543895743890574389574398057348957348957438957439857438957438957438957438\
            4290854390765493025784932574893578394758943578493574893758493758493758493574389574389573489574389574\
            4290854390765493025784932574893578394758943578493574893758493758493758493574389574389573489574389574\
            4290854390765493025784932574893578394758943578493574893758493758493758493574389574389573489574389574\
            4290854390765493025784932574893578394758943578493574893758493758493758493574389574389573489574389574\
            4290854390765493025784932574893578394758943578493574893758493758493758493574389574389573489574389574",
           "bce570bbcccdc49d51d2a8e09ea5000beed0f31e",
        );
    }
}
