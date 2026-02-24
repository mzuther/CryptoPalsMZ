use crate::crypto_vecs;

use indexmap::IndexMap;

// all valid hexadecimal characters
pub const HEXADECIMAL_VALID_CHARACTERS: &str =
    "0123456789abcdef";

// base64-encoded string containing complete base64 alphabet
pub const BASE64_COMPLETE_ALPHABET: &str =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// plain-text bytes which yields the base64-encoded string above
pub fn get_base64_complete_alphabet_as_bytes() -> Vec<u8> {
    vec![
        0x00, 0x10, 0x83, 0x10, 0x51, 0x87, 0x20, 0x92, 0x8b, 0x30, 0xd3, 0x8f, 0x41, 0x14, 0x93,
        0x51, 0x55, 0x97, 0x61, 0x96, 0x9b, 0x71, 0xd7, 0x9f, 0x82, 0x18, 0xa3, 0x92, 0x59, 0xa7,
        0xa2, 0x9a, 0xab, 0xb2, 0xdb, 0xaf, 0xc3, 0x1c, 0xb3, 0xd3, 0x5d, 0xb7, 0xe3, 0x9e, 0xbb,
        0xf3, 0xdf, 0xbf,
    ]
}

// plain-text hexadecimal string which yields the base64-encoded string above
pub const BASE64_COMPLETE_ALPHABET_HEX: &str = "00108310518720928b30d38f41149351559761969b71d79f8218a39259a7a29aabb2dbafc31cb3d35db7e39ebbf3dfbf";

// all valid base64 characters
pub const BASE64_VALID_CHARACTERS: &str =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

const ENGLISH_LETTER_FREQUENCIES: [(char, f64); 28] = [
    // https://web.archive.org/web/20170918020907/http://www.data-compression.com/english.html
    (' ', 0.200),
    ('e', 0.127),
    ('t', 0.091),
    ('a', 0.082),
    ('o', 0.075),
    ('i', 0.070),
    ('n', 0.067),
    ('s', 0.063),
    ('h', 0.061),
    ('r', 0.060),
    ('d', 0.043),
    ('l', 0.040),
    ('c', 0.028),
    ('u', 0.028),
    ('m', 0.024),
    ('w', 0.024),
    ('f', 0.022),
    ('g', 0.020),
    ('y', 0.020),
    ('p', 0.019),
    ('b', 0.015),
    ('v', 0.0098),
    ('k', 0.0077),
    ('j', 0.0016),
    ('x', 0.0015),
    ('q', 0.0012),
    ('z', 0.0007),
    // https://en.wikipedia.org/wiki/Letter_frequency#Relative_frequencies_of_the_first_letters_of_a_word_in_English_language
    ('*', 0.085),
];

pub fn get_english_letter_frequencies() -> IndexMap<u8, f64> {
    let mut english_letter_frequencies = IndexMap::new();

    for letter in ENGLISH_LETTER_FREQUENCIES {
        let key = letter.0 as u8;
        english_letter_frequencies.insert(key, letter.1);
    }

    english_letter_frequencies
}

pub const LOOKUP_BITS_IN_NIBBLE: [u32; 16] = [0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4];

#[derive(Debug, PartialEq, PartialOrd)]
pub struct ScoreXOR {
    pub score: f64,
    pub key: crypto_vecs::Bytes,
    pub plain_text: crypto_vecs::Bytes,
}

#[derive(Debug, PartialEq, PartialOrd)]
pub struct ScoreKeysize {
    pub score: f64,
    pub keysize: usize,
}
