pub mod constants;
pub mod crypto_vecs;
pub mod oracles;

// ----------------

use std::{cmp, collections::HashMap, ops};

use crate::crypto_vecs::traits::{
    AutoProbe, EncryptionOracle, InternalData, InternalDataVecMut, LenBytes, ToBytes,
};
use crate::crypto_vecs::{BlockBytes, Bytes};

// ================

#[derive(Debug, PartialEq, PartialOrd)]
pub struct ScoreXOR {
    pub score: f64,
    pub key: Bytes,
    pub plain_text: Bytes,
}

#[derive(Debug, PartialEq, PartialOrd)]
pub struct ScoreKeysize {
    pub score: f64,
    pub keysize: usize,
}

// ================

pub fn find_lowest_score_xor(bytes: &Bytes) -> Vec<ScoreXOR> {
    let key_range = 0x00..0xff;

    let all_keys = key_range.fold(Vec::default(), |mut acc, key_byte| {
        acc.push(Bytes::new_from(vec![key_byte]));
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

fn get_letter_frequencies(bytes: &Bytes) -> HashMap<u8, f64> {
    let percent_per_byte = 1.0 / (bytes.len_bytes() as f64);

    bytes.iter().fold(Default::default(), |mut acc, &byte| {
        let key = match byte {
            // space
            0x20 => byte,
            // upper-case letters (convert to lower-case)
            0x41..=0x5a => byte + 0x20,
            // lower-case letters
            0x61..=0x7a => byte,
            // remaining characters (convert to "*")
            _ => 0x2a,
        };

        let count = acc.entry(key).or_insert(0.0);
        *count += percent_per_byte;

        acc
    })
}

pub fn print_histogram(
    key: &Bytes,
    bytes: &Bytes,
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
            let percentage_letter =
                letter_frequencies.get(&letter).copied().unwrap_or(0.0);

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
            let value_expected =
                (percentage_expected * magnification_factor).round() as i32;

            let bin_bottom = cmp::min(value_found, value_expected);
            let bin_middle = cmp::max(value_expected - value_found, 0);
            let bin_top =
                cmp::min(cmp::max(value_found - value_expected, 0), max_bin_size);
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

fn score_letter_frequencies(bytes: &Bytes) -> f64 {
    let letter_frequencies = get_letter_frequencies(bytes);
    let english_letter_frequencies = &constants::ENGLISH_LETTER_FREQUENCIES;

    // bonus for letters matching expected frequency (lower is better)
    let total_score = english_letter_frequencies.iter().fold(
        0.0,
        |acc, (letter, percentage_expected)| {
            let percentage_found = letter_frequencies.get(letter).copied().unwrap_or(0.0);

            // higher frequencies are just as bad as lower frequencies
            let score_diff = (percentage_expected - percentage_found).abs();
            let score_diff = score_diff.powi(4);

            acc + score_diff
        },
    );

    // malus for non-letters
    english_letter_frequencies.iter().fold(
        total_score,
        |acc, (&letter, percentage_found)| {
            match letter {
                // space, comma and dot are fine
                0x20 | 0x2c | 0x2e => acc,
                // so are lower-case letters
                0x61..=0x7a => acc,
                // add malus
                _ => acc + 2.0 * percentage_found,
            }
        },
    )
}

pub fn guess_keysize_from_hamming_distance(
    bytes: &Bytes,
    keysize_range: &ops::Range<usize>,
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

fn transpose_strings_internal(
    strings: &[String],
    reverse_transposition: bool,
) -> Vec<String> {
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
    let transposed_lines = steps_into_vector.into_iter().fold(
        Vec::with_capacity(height),
        |mut acc, chars_to_skip| {
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
        },
    );

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

pub fn detect_aes_mode(cypher_blocks: &BlockBytes) -> constants::AesMode {
    let block_size = cypher_blocks.get_block_size();

    // remove padding of any possible length before detection
    for skipped_bytes in 0..block_size {
        let cypher_truncated = cypher_blocks.skip_n_as_collection(skipped_bytes).unwrap();

        // detect repetitive blocks
        if cypher_truncated.find_duplicate_blocks().number_of_blocks() > 0 {
            return constants::AesMode::ECB;
        }
    }

    constants::AesMode::NonECB
}

pub fn decypher_aes_ecb_via_oracle(oracle: &oracles::AesEcbSuffix) -> BlockBytes {
    let (_, detected_block_size) = oracle.detect_block_size().unwrap();

    // prevent overflow of ECB probe
    assert!(detected_block_size < 256);

    // create distinct and recognizable block: 0x00 0x01 0x02 0x03 ...
    let ecb_probe_block: Vec<_> = (0x00_u8..).take(detected_block_size).collect();
    let ecb_probe = Bytes::new_from(ecb_probe_block.repeat(3));
    let ecb_probe_blocks = ecb_probe.to_blocks(detected_block_size);

    let aes_mode = crate::detect_aes_mode(&ecb_probe_blocks);

    assert_eq!(aes_mode, constants::AesMode::ECB);

    let blocks_in_cypher = oracle
        .encrypt(Default::default())
        .unwrap()
        .number_of_blocks();

    // decypher block by block
    (0..blocks_in_cypher).fold(
        BlockBytes::new(detected_block_size),
        |mut acc, current_block_index| {
            acc.push(crate::decypher_aes_ecb_block_via_oracle(
                oracle,
                &acc,
                detected_block_size,
                current_block_index,
            ));

            acc
        },
    )
}

fn decypher_aes_ecb_block_via_oracle(
    oracle: &oracles::AesEcbSuffix,
    plain_part: &BlockBytes,
    block_size: usize,
    current_block_index: usize,
) -> Bytes {
    let bytes_to_skip = block_size * current_block_index;
    let mut current_pkcs7_byte = None;

    // decypyher block, byte by byte
    Bytes::new_auto_probe_repeat(b'A', block_size - 1, 0).fold(
        Bytes::default(),
        |mut acc, probe_padding| {
            let cypher_block_padding = oracle
                .encrypt(probe_padding.clone())
                .unwrap()
                .skip_n_as_collection(bytes_to_skip)
                .unwrap()
                .take_n_as_collection(block_size)
                .unwrap();

            let mut run_loop = true;

            while run_loop {
                run_loop = false;

                // detect plaintext byte by changing last byte of probe
                if let Some(padding_size) = current_pkcs7_byte {
                    // remove padding from last iteration (e.g. "0x02 0x02"), as it
                    // will interfere with detection in the current iteration
                    acc = acc
                        .rskip_n_as_collection(padding_size)
                        .expect("detected PKCS#7 incorrectly");

                    // correct padding for this iteration (e.g. "0x03 0x03")
                    let new_padding_size = padding_size + 1;
                    current_pkcs7_byte = Some(new_padding_size);

                    // add correct padding, but one byte short to allow detection
                    // of last byte
                    acc.extend(vec![new_padding_size as u8; new_padding_size - 1]);
                }

                let mut probe_padding_and_plain = probe_padding.clone();
                probe_padding_and_plain.extend(plain_part.to_bytes());
                probe_padding_and_plain.extend(&acc);

                let mut byte_detected = false;

                // detect plaintext byte by changing last byte of probe
                for last_byte in 0x00..=0xff {
                    let mut probe_current = probe_padding_and_plain.clone();
                    probe_current.push(last_byte);

                    let cypher_block_current = oracle
                        .encrypt(probe_current)
                        .unwrap()
                        .skip_n_as_collection(bytes_to_skip)
                        .unwrap()
                        .take_n_as_collection(block_size)
                        .unwrap();

                    if cypher_block_current == cypher_block_padding {
                        byte_detected = true;

                        acc.push(last_byte);
                        break;
                    }
                }

                if !byte_detected && current_pkcs7_byte.is_none() {
                    // re-run and try to detect PKCS#7
                    current_pkcs7_byte = Some(1);

                    run_loop = true;
                }
            }

            acc
        },
    )
}

// ================

#[cfg(test)]
mod tests {
    use super::*;

    // ----------------

    #[test]
    fn unit_library_fixed_xor_unicode() {
        let plain = Bytes::from_unicode_literal("Cooking MCs");
        let key = Bytes::from_unicode_literal("X");

        let expected_result = Bytes::new_from(vec![
            0x1b, 0x37, 0x37, 0x33, 0x31, 0x36, 0x3f, 0x78, 0x15, 0x1b, 0x2b,
        ]);

        let result = plain.fixed_xor(&key);

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_library_hamming_distance_unicode() {
        let bytes = Bytes::from_unicode_literal("this is a test");
        let other = Bytes::from_unicode_literal("wokka wokka!!!");

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
