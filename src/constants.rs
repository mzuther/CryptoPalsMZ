use std::collections::HashMap;

const ENGLISH_LETTER_FREQUENCIES: [(char, f64); 27] = [
    (' ', 0.250),
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
];

pub fn get_english_letter_frequencies() -> HashMap<u8, f64> {
    let mut english_letter_frequencies = HashMap::new();

    for letter in ENGLISH_LETTER_FREQUENCIES {
        let key = letter.0 as u8;
        english_letter_frequencies.insert(key, letter.1);
    }

    english_letter_frequencies
}

pub const LOOKUP_BITS_IN_NIBBLE: [u8; 16] = [0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4];

pub struct ScoreXOR {
    pub key: u8,
    pub score: f64,
    pub decoded: Vec<u8>,
}
