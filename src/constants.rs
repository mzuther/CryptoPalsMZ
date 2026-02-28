use indexmap;

// ----------------

pub const AES_128_BYTES_IN_KEY: usize = 16;

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

pub fn get_english_letter_frequencies() -> indexmap::IndexMap<u8, f64> {
    let mut english_letter_frequencies = indexmap::IndexMap::new();

    for letter in ENGLISH_LETTER_FREQUENCIES {
        let key = letter.0 as u8;
        english_letter_frequencies.insert(key, letter.1);
    }

    english_letter_frequencies
}
