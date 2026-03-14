pub mod constants;
pub mod crypto_vecs;
pub mod oracles;

// ----------------

use std::{cmp, collections::HashMap, ops::Range};

use crate::crypto_vecs::traits::{LenBytes, ToBytes};
use crate::crypto_vecs::{BlockBytes, BytesType};

// ================

#[derive(Debug, PartialEq, PartialOrd)]
pub struct ScoreXOR {
    pub score: f64,
    pub key: BytesType,
    pub plain_text: BytesType,
}

#[derive(Debug, PartialEq, PartialOrd)]
pub struct ScoreKeysize {
    pub score: f64,
    pub keysize: usize,
}

// ================

pub fn find_lowest_score_xor(bytes: &BytesType) -> Vec<ScoreXOR> {
    let key_range = 0x00..0xff;

    let all_keys = key_range.fold(Vec::default(), |mut acc, key_byte| {
        acc.push(BytesType::from(key_byte));
        acc
    });

    all_keys.into_iter().fold(Vec::default(), |mut acc, key| {
        let bytes_xor = bytes.fixed_xor(&key);
        let score = self::score_letter_frequencies(&bytes_xor);

        let score = ScoreXOR {
            score,
            key,
            plain_text: bytes_xor,
        };

        acc.push(score);
        acc
    })
}

fn get_letter_frequencies(bytes: &BytesType) -> HashMap<u8, f64> {
    let percent_per_byte = 1.0 / (bytes.len_bytes() as f64);

    bytes.iter().fold(Default::default(), |mut acc, &byte| {
        let mut key = byte;

        // space
        if key == 0x20 {
        }
        // upper-case letters (convert to lower-case)
        else if (0x41..=0x5a).contains(&key) {
            key += 0x20;
        }
        // lower-case letters
        else if (0x61..=0x7a).contains(&key) {
        }
        // remaining characters (convert to "*")
        else {
            key = 0x2a;
        }

        let count = acc.entry(key).or_insert(0.0);
        *count += percent_per_byte;

        acc
    })
}

pub fn print_histogram(
    key: &BytesType,
    bytes: &BytesType,
    y_max: f64,
    magnification_factor: f64,
    rotate_histogram: bool,
    min_percentage_spaces: f64,
    min_important_letters: usize,
) {
    let letter_frequencies = self::get_letter_frequencies(bytes);

    if min_percentage_spaces > 0.0 {
        let space = b' ';
        let percentage_space = letter_frequencies.get(&space).copied().unwrap_or(0.0);

        if percentage_space < min_percentage_spaces {
            return;
        }
    }

    if min_important_letters > 0 {
        let important_letters = ['e', 't', 'a', 'o', 'n', 's', 'h', 'r'];

        let found_count = important_letters.iter().fold(0, |acc, &letter_char| {
            let letter = letter_char as u8;
            let percentage_letter = letter_frequencies.get(&letter).copied().unwrap_or(0.0);

            if percentage_letter > 0.0 {
                acc + 1
            } else {
                acc
            }
        });

        if found_count < min_important_letters {
            return;
        }
    }

    println!("{}", key);

    let english_letter_frequencies = &constants::ENGLISH_LETTER_FREQUENCIES;
    let max_bin_size = (magnification_factor * y_max) as i32;

    let mut bins = english_letter_frequencies.iter().fold(
        Vec::with_capacity(english_letter_frequencies.len()),
        |mut acc, (letter, percentage_expected)| {
            let percentage_found = letter_frequencies.get(letter).copied().unwrap_or(0.0);
            let mut letter = *letter;

            let value_found = cmp::min(
                (percentage_found * magnification_factor).round() as i32,
                max_bin_size,
            );
            let value_expected = (percentage_expected * magnification_factor).round() as i32;

            let bin_bottom = cmp::min(value_found, value_expected);
            let bin_middle = cmp::max(value_expected - value_found, 0);
            let bin_top = cmp::min(cmp::max(value_found - value_expected, 0), max_bin_size);
            let bin_fill_to_border = max_bin_size - cmp::max(value_found, value_expected);

            if letter == b' ' {
                letter = b'_';
            }

            let bin = format!(
                "{} {}{}{}{}",
                letter as char,
                "█".repeat(bin_bottom as usize),
                "░".repeat(bin_middle as usize),
                "🮮".repeat(bin_top as usize),
                " ".repeat(bin_fill_to_border as usize)
            );

            acc.push(bin);

            if rotate_histogram {
                let filler = " ".repeat((max_bin_size + 2) as usize);
                acc.push(filler);
            }

            acc
        },
    );

    if rotate_histogram {
        bins = self::transpose_strings_reverse(&bins);
    }

    for bin in bins {
        println!("{bin}");
    }

    // println!("{}", bytes.to_codepage_1252());
    println!();
}

fn score_letter_frequencies(bytes: &BytesType) -> f64 {
    let letter_frequencies = get_letter_frequencies(bytes);
    let english_letter_frequencies = &constants::ENGLISH_LETTER_FREQUENCIES;

    // bonus for letters matching expected frequency (lower is better)
    let total_score =
        english_letter_frequencies
            .iter()
            .fold(0.0, |acc, (letter, percentage_expected)| {
                let percentage_found = letter_frequencies.get(letter).copied().unwrap_or(0.0);

                // higher frequencies are just as bad as lower frequencies
                let score_diff = (percentage_expected - percentage_found).abs();
                let score_diff = score_diff.powi(4);

                acc + score_diff
            });

    // malus for non-letters
    english_letter_frequencies
        .iter()
        .fold(total_score, |mut acc, (&letter, percentage_found)| {
            // any character except lower-case letters
            if !(0x61..=0x7a).contains(&letter) {
                // with the exception of space, comma, and dot
                if letter != 0x20 && letter != 0x2c && letter != 0x2e {
                    acc += 2.0 * percentage_found;
                }
            }

            acc
        })
}

pub fn guess_keysize_from_hamming_distance(
    bytes: &BytesType,
    keysize_range: &Range<usize>,
    number_of_samples: usize,
) -> Vec<ScoreKeysize> {
    let number_of_keys = keysize_range.len();

    keysize_range
        .clone()
        .fold(Vec::with_capacity(number_of_keys), |mut acc, keysize| {
            acc.push(ScoreKeysize {
                score: bytes
                    .to_blocks(keysize)
                    .hamming_distance_average(number_of_samples),
                keysize,
            });

            acc
        })
}

// transpose strings clockwise
pub fn transpose_strings(strings: &[String]) -> Vec<String> {
    self::transpose_strings_internal(strings, false)
}

// transpose strings counterclockwise
pub fn transpose_strings_reverse(strings: &[String]) -> Vec<String> {
    self::transpose_strings_internal(strings, true)
}

fn transpose_strings_internal(strings: &[String], reverse_transposition: bool) -> Vec<String> {
    assert!(!strings.is_empty());

    let max_width = strings
        .iter()
        .map(|x| x.chars().count())
        .max()
        .expect("at least one line must exist");

    let height = strings.len();

    // convert lines to chars, fill with spaces to equal line length, and
    // concatenate them in a single vector
    let concatenated_lines =
        strings
            .iter()
            .fold(Vec::with_capacity(max_width * height), |mut acc, string| {
                let char_vec = Vec::from_iter(string.chars());
                let missing_spaces_at_end = max_width - char_vec.len();

                acc.extend(Vec::from_iter(char_vec));
                acc.extend(vec![' '; missing_spaces_at_end]);

                acc
            });

    let step_size = max_width;
    let steps_into_vector = 0..step_size;

    // transpose lines
    let transposed_lines =
        steps_into_vector
            .into_iter()
            .fold(Vec::with_capacity(height), |mut acc, chars_to_skip| {
                let transposed_line = concatenated_lines
                    .iter()
                    .skip(chars_to_skip)
                    .step_by(step_size);

                // rotate transposed string counterclockwise
                if reverse_transposition {
                    acc.push(Vec::from_iter(transposed_line));
                // rotate transposed string clockwise
                } else {
                    acc.push(Vec::from_iter(transposed_line.rev()));
                }

                acc
            });

    let transposed_lines_iter = if reverse_transposition {
        // rotate transposed string counterclockwise
        either::Either::Right(transposed_lines.into_iter().rev())
    } else {
        // rotate transposed string clockwise
        either::Either::Left(transposed_lines.into_iter())
    };

    transposed_lines_iter.fold(Vec::with_capacity(step_size), |mut acc, line| {
        acc.push(String::from_iter(line));
        acc
    })
}

// ----------------

// TODO: implement "skip_n_as_collection()" for "BlockBytes"
pub fn detect_aes_mode(cypher_blocks: &BlockBytes) -> constants::AesMode {
    let block_size = cypher_blocks.get_block_size();

    // remove any possible padding before detection
    for skipped_bytes in 0..block_size {
        let cypher_truncated = cypher_blocks
            .to_bytes()
            .skip_n_as_collection(skipped_bytes)
            .unwrap_or_default()
            .to_blocks(block_size);

        // detect repetitive blocks
        if cypher_truncated.find_duplicate_blocks().number_of_blocks() > 0 {
            return constants::AesMode::ECB;
        }
    }

    constants::AesMode::NonECB
}

// ================

#[cfg(test)]
mod tests {
    use super::*;

    // ----------------

    #[test]
    fn unit_library_fixed_xor_unicode() {
        let plain = BytesType::from_unicode_literal("Cooking MCs");
        let key = BytesType::from_unicode_literal("X");

        let expected_result = BytesType::from(vec![
            0x1b, 0x37, 0x37, 0x33, 0x31, 0x36, 0x3f, 0x78, 0x15, 0x1b, 0x2b,
        ]);

        let result = plain.fixed_xor(&key);

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_library_hamming_distance_unicode() {
        let bytes = BytesType::from_unicode_literal("this is a test");
        let other = BytesType::from_unicode_literal("wokka wokka!!!");

        let expected_result = 37;
        let expected_result_relative = expected_result as f64 / 112.0;

        let result = bytes.hamming_distance(&other);
        let result_relative = bytes.hamming_distance_normalized(&other);

        assert_eq!(result, expected_result);
        assert_eq!(result_relative, expected_result_relative);
    }

    // ----------------

    #[test]
    fn unit_library_transpose_strings() {
        let strings = vec![
            String::from("äßcd"),
            String::from("efgh"),
            String::from("ijkl"),
        ];

        let expected_result = vec!["ieä", "jfß", "kgc", "lhd"];

        let result = self::transpose_strings(&strings);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_library_transpose_strings_different_lengths() {
        let strings = vec![String::from("1"), String::from("2345"), String::from("678")];

        let expected_result = vec!["621", "73 ", "84 ", " 5 "];

        let result = self::transpose_strings(&strings);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_library_transpose_strings_reverse() {
        let strings = vec![
            String::from("äßcd"),
            String::from("efgh"),
            String::from("ijkl"),
        ];

        let expected_result = vec!["dhl", "cgk", "ßfj", "äei"];

        let result = self::transpose_strings_reverse(&strings);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_library_transpose_strings_reverse_different_lengths() {
        let strings = vec![String::from("1"), String::from("2345"), String::from("678")];

        let expected_result = vec![" 5 ", " 48", " 37", "126"];

        let result = self::transpose_strings_reverse(&strings);

        assert_eq!(result, expected_result);
    }
}
