//! https://www.ietf.org/rfc/rfc1321.txt

use crate::utils::{self, Fingerprint};

const BITS_IN_BYTE: usize = 8;
const BYTES_IN_WORD: usize = 4;

pub type Md5Fingerprint = Fingerprint<16>;

pub fn hash(msg: &[u8]) -> Md5Fingerprint {
    // 3.1 Step 1. Append Padding Bits
    let mut msg_pad = msg.to_vec();
    msg_pad.push(0b10000000);
    const ALREADY_PADDED_ZERO_BITS: usize = 7;
    let total_pad_zero_bits = pad_zero_amount(msg.len() * BITS_IN_BYTE);
    msg_pad.extend(
        std::iter::repeat(0).take((total_pad_zero_bits - ALREADY_PADDED_ZERO_BITS) / BITS_IN_BYTE),
    );

    // 3.2 Step 2. Append Length
    // We want truncation
    msg_pad.extend_from_slice(&((msg.len() * BITS_IN_BYTE) as u64).to_le_bytes());
    assert!(msg_pad.len() % (512 / BITS_IN_BYTE) == 0);

    let m = |idx: usize| {
        let bytes = &msg_pad[idx * BYTES_IN_WORD..][..BYTES_IN_WORD];
        u32::from_le_bytes(bytes.try_into().unwrap())
    };
    let n = msg_pad.len() / BYTES_IN_WORD;

    dbg!(&msg_pad);
    // We only access msg and msg_pad through m and n now.
    utils::undefine_variable!(msg);
    utils::undefine_variable!(msg_pad);

    // 3.3 Step 3. Initialize MD Buffer
    let mut a: u32 = 0x_67_45_23_01;
    let mut b: u32 = 0x_ef_cd_ab_89;
    let mut c: u32 = 0x_98_ba_dc_fe;
    let mut d: u32 = 0x_10_32_54_76;

    // 3.4 Step 4. Process Message in 16-Word Blocks
    // Process each 16-word block.
    for i in 0..(n / 16) {
        let block_offest = i * 16;

        let mut x = [0_u32; 16];

        for j in 0..16 {
            x[j] = m(block_offest + j);
        }

        let aa = a;
        let bb = b;
        let cc = c;
        let dd = d;

        let rotate_left = |x: u32, n: u32| (x << n) | (x >> (32 - n));

        macro_rules! op {
            ($func:ident: $a:ident $b:ident $c:ident $d:ident $k:literal $s:literal $ac:literal) => {
                $a = $a.wrapping_add($func($b, $c, $d).wrapping_add(x[$k]).wrapping_add($ac));
                $a = rotate_left($a, $s);
                $a = $a.wrapping_add($b);
            };
        }
        // Round 1.
        #[rustfmt::skip]
        {
            op!(F: a b c d  0  7 0xd76aa478);
            op!(F: d a b c  1 12 0xe8c7b756);
            op!(F: c d a b  2 17 0x242070db);
            op!(F: b c d a  3 22 0xc1bdceee);
            op!(F: a b c d  4  7 0xf57c0faf);
            op!(F: d a b c  5 12 0x4787c62a);
            op!(F: c d a b  6 17 0xa8304613);
            op!(F: b c d a  7 22 0xfd469501);
            op!(F: a b c d  8  7 0x698098d8);
            op!(F: d a b c  9 12 0x8b44f7af);
            op!(F: c d a b 10 17 0xffff5bb1);
            op!(F: b c d a 11 22 0x895cd7be);
            op!(F: a b c d 12  7 0x6b901122);
            op!(F: d a b c 13 12 0xfd987193);
            op!(F: c d a b 14 17 0xa679438e);
            op!(F: b c d a 15 22 0x49b40821);
        };

        // Round 2
        #[rustfmt::skip]
        {
            op!(G: a b c d  1  5 0xf61e2562);
            op!(G: d a b c  6  9 0xc040b340);
            op!(G: c d a b 11 14 0x265e5a51);
            op!(G: b c d a  0 20 0xe9b6c7aa);
            op!(G: a b c d  5  5 0xd62f105d); 
            op!(G: d a b c 10  9  0x2441453);
            op!(G: c d a b 15 14 0xd8a1e681);
            op!(G: b c d a  4 20 0xe7d3fbc8);
            op!(G: a b c d  9  5 0x21e1cde6); 
            op!(G: d a b c 14  9 0xc33707d6);
            op!(G: c d a b  3 14 0xf4d50d87);
            op!(G: b c d a  8 20 0x455a14ed);
            op!(G: a b c d 13  5 0xa9e3e905); 
            op!(G: d a b c  2  9 0xfcefa3f8);
            op!(G: c d a b  7 14 0x676f02d9);
            op!(G: b c d a 12 20 0x8d2a4c8a);
        };

        // Round 3
        #[rustfmt::skip]
        {
            op!(H: a b c d  5  4 0xfffa3942);
            op!(H: d a b c  8 11 0x8771f681);
            op!(H: c d a b 11 16 0x6d9d6122);
            op!(H: b c d a 14 23 0xfde5380c);
            op!(H: a b c d  1  4 0xa4beea44);
            op!(H: d a b c  4 11 0x4bdecfa9);
            op!(H: c d a b  7 16 0xf6bb4b60);
            op!(H: b c d a 10 23 0xbebfbc70);
            op!(H: a b c d 13  4 0x289b7ec6);
            op!(H: d a b c  0 11 0xeaa127fa);
            op!(H: c d a b  3 16 0xd4ef3085);
            op!(H: b c d a  6 23  0x4881d05);
            op!(H: a b c d  9  4 0xd9d4d039);
            op!(H: d a b c 12 11 0xe6db99e5);
            op!(H: c d a b 15 16 0x1fa27cf8);
            op!(H: b c d a  2 23 0xc4ac5665);
        };
        // Round 4
        #[rustfmt::skip]
        {
            op!(I: a b c d  0  6 0xf4292244);
            op!(I: d a b c  7 10 0x432aff97);
            op!(I: c d a b 14 15 0xab9423a7);
            op!(I: b c d a  5 21 0xfc93a039);
            op!(I: a b c d 12  6 0x655b59c3);
            op!(I: d a b c  3 10 0x8f0ccc92);
            op!(I: c d a b 10 15 0xffeff47d);
            op!(I: b c d a  1 21 0x85845dd1);
            op!(I: a b c d  8  6 0x6fa87e4f);
            op!(I: d a b c 15 10 0xfe2ce6e0);
            op!(I: c d a b  6 15 0xa3014314);
            op!(I: b c d a 13 21 0x4e0811a1);
            op!(I: a b c d  4  6 0xf7537e82);
            op!(I: d a b c 11 10 0xbd3af235);
            op!(I: c d a b  2 15 0x2ad7d2bb);
            op!(I: b c d a  9 21 0xeb86d391);
        };

        a = a.wrapping_add(aa);
        b = b.wrapping_add(bb);
        c = c.wrapping_add(cc);
        d = d.wrapping_add(dd);
    }

    // 3.5 Step 5. Output
    let mut result = [0; 16];
    result[(BYTES_IN_WORD * 0)..(BYTES_IN_WORD * 1)].copy_from_slice(&a.to_le_bytes());
    result[(BYTES_IN_WORD * 1)..(BYTES_IN_WORD * 2)].copy_from_slice(&b.to_le_bytes());
    result[(BYTES_IN_WORD * 2)..(BYTES_IN_WORD * 3)].copy_from_slice(&c.to_le_bytes());
    result[(BYTES_IN_WORD * 3)..(BYTES_IN_WORD * 4)].copy_from_slice(&d.to_le_bytes());

    Fingerprint(result)
}

#[allow(non_snake_case)]
fn F(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (!x & z)
}
#[allow(non_snake_case)]
fn G(x: u32, y: u32, z: u32) -> u32 {
    ((x) & (z)) | ((y) & (!z))
}
#[allow(non_snake_case)]
fn H(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}
#[allow(non_snake_case)]
fn I(x: u32, y: u32, z: u32) -> u32 {
    y ^ (x | !z)
}

fn pad_zero_amount(len_bits: usize) -> usize {
    let len = len_bits + 1; // We always padd a 1
    let rest = len % 512;
    448_usize.wrapping_sub(rest) % 512
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::Md5Fingerprint;

    #[track_caller]
    fn assert_same(s: &str, fingerprint: &str) {
        assert_eq!(
            super::hash(s.as_bytes()),
            Md5Fingerprint::from_str(fingerprint).unwrap()
        );
    }

    #[test]
    fn hashing() {
        //assert_same("", "d41d8cd98f00b204e9800998ecf8427e");
        assert_same("a", "0cc175b9c0f1b6a831c399e269772661");
        assert_same("abc", "900150983cd24fb0d6963f7d28e17f72");
        assert_same("message digest", "f96b697d7cb7938d525a2f31aaf161d0");
        assert_same(
            "abcdefghijklmnopqrstuvwxyz",
            "c3fcd3d76192e4007dfb496cca67e13b",
        );
        assert_same(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "d174ab98d277d9f5a5611c2c9f419d9f",
        );
        assert_same(
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "57edf4a22be3c955ac49da2e2107b67a",
        );
        // TODO: doesn't work yet
        // assert_same(
        //     include_str!("md5.rs"),
        //    "a1459b7404c1a426a759e0023460dc3d",
        // );
    }

    #[test]
    fn padding_lens() {
        assert_eq!(super::pad_zero_amount(100), (448 - 100 - 1));
        assert_eq!(super::pad_zero_amount(0), (448 - 1));
        assert_eq!(super::pad_zero_amount(512), (448 - 1));
        assert_eq!(super::pad_zero_amount(448), 511);
        assert_eq!(super::pad_zero_amount(512 + 448), 511);
    }
}
