use indexmap;
use std::{fmt, sync};

// ================

#[inline]
pub fn letter_frequencies_from_array(
    frequency_array: &[(char, f64)],
) -> indexmap::IndexMap<u8, f64> {
    indexmap::IndexMap::from_iter(
        frequency_array
            .iter()
            .cloned()
            .map(|(key, letter)| (key as u8, letter)),
    )
}

pub static ENGLISH_LETTER_FREQUENCIES: sync::LazyLock<indexmap::IndexMap<u8, f64>> =
    sync::LazyLock::new(|| {
        let english_letter_frequencies = [
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

        letter_frequencies_from_array(&english_letter_frequencies)
    });

// ----------------

#[derive(Debug, PartialEq)]
pub enum AesMode {
    ECB,
    NonECB,
}

impl fmt::Display for AesMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                AesMode::ECB => "ECB",
                AesMode::NonECB => "NonECB",
            }
        )
    }
}
