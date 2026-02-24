use std::{cmp, collections::HashMap, ops::Range};

pub mod constants;
pub mod crypto_vecs;

pub fn find_lowest_score_xor(bytes: &crypto_vecs::Bytes) -> Vec<constants::ScoreXOR> {
    let key_range = 0x00..0xff;

    let all_keys = key_range.fold(Vec::new(), |mut acc, key_byte| {
        acc.push(crypto_vecs::Bytes::from(key_byte));
        acc
    });

    all_keys.into_iter().fold(Vec::new(), |mut acc, key| {
        let bytes_xor = bytes.fixed_xor(&key);
        let score = self::score_letter_frequencies(&bytes_xor);

        let score = constants::ScoreXOR {
            score: score,
            key: key,
            plain_text: bytes_xor,
        };

        acc.push(score);
        acc
    })
}

fn get_letter_frequencies(bytes: &crypto_vecs::Bytes) -> HashMap<u8, f64> {
    let mut letter_frequencies = HashMap::new();
    let percent_per_byte = 1.0 / (bytes.len() as f64);

    for &byte in bytes.iter() {
        let mut key = byte;

        // space
        if key == 0x20 {
        }
        // upper-case letters (convert to lower-case)
        else if key >= 0x41 && key <= 0x5a {
            key += 0x20;
        }
        // lower-case letters
        else if key >= 0x61 && key <= 0x7a {
        }
        // remaining characters (convert to "*")
        else {
            key = 0x2a;
        }

        let count = letter_frequencies.entry(key).or_insert(0.0);
        *count += percent_per_byte;
    }

    letter_frequencies
}

pub fn print_histogram(
    key: &crypto_vecs::Bytes,
    bytes: &crypto_vecs::Bytes,
    y_max: f64,
    magnification_factor: f64,
    rotate_histogram: bool,
    min_percentage_spaces: f64,
    min_important_letters: usize,
) {
    let letter_frequencies = self::get_letter_frequencies(&bytes);

    if min_percentage_spaces > 0.0 {
        let space = ' ' as u8;
        let percentage_space = letter_frequencies.get(&space).copied().unwrap_or(0.0);

        if percentage_space < min_percentage_spaces {
            return;
        }
    }

    if min_important_letters > 0 {
        let important_letters = vec!['e', 't', 'a', 'o', 'n', 's', 'h', 'r'];

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

    println!("{}", key.to_string());
    let max_bin_size = (magnification_factor * y_max) as i32;

    let english_letter_frequencies = constants::get_english_letter_frequencies();
    let mut bins = Vec::with_capacity(english_letter_frequencies.len());

    for (mut letter, percentage_expected) in english_letter_frequencies {
        let percentage_found = letter_frequencies.get(&letter).copied().unwrap_or(0.0);

        let value_found = cmp::min(
            (percentage_found * magnification_factor).round() as i32,
            max_bin_size,
        );
        let value_expected = (percentage_expected * magnification_factor).round() as i32;

        let bin_bottom = cmp::min(value_found, value_expected);
        let bin_middle = cmp::max(value_expected - value_found, 0);
        let bin_top = cmp::min(cmp::max(value_found - value_expected, 0), max_bin_size);
        let bin_fill_to_border = max_bin_size - cmp::max(value_found, value_expected);

        if letter == (' ' as u8) {
            letter = '_' as u8;
        }

        let bin = format!(
            "{} {}{}{}{}",
            letter as char,
            "█".repeat(bin_bottom as usize),
            "░".repeat(bin_middle as usize),
            "🮮".repeat(bin_top as usize),
            " ".repeat(bin_fill_to_border as usize)
        );

        bins.push(bin);

        if rotate_histogram {
            let filler = " ".repeat((max_bin_size + 2) as usize);
            bins.push(filler);
        }
    }

    if rotate_histogram {
        bins = self::transpose_strings_counterclockwise(&bins);
    }

    for bin in bins {
        println!("{bin}");
    }

    // println!("{}", bytes.to_iso_8859_1());
    println!("");
}

fn score_letter_frequencies(bytes: &crypto_vecs::Bytes) -> f64 {
    let letter_frequencies = get_letter_frequencies(&bytes);
    let english_letter_frequencies = constants::get_english_letter_frequencies();

    let mut total_score = 0.0;

    // bonus for letters matching expected frequency (lower is better)
    for (letter, percentage_expected) in english_letter_frequencies {
        let percentage_found = letter_frequencies.get(&letter).copied().unwrap_or(0.0);
        // higher frequencies are just as bad as lower frequencies
        let score_diff = (percentage_expected - percentage_found).abs();
        let score_diff = score_diff.powi(4);

        total_score += score_diff;
    }

    // malus for non-letters
    for (letter, percentage_found) in letter_frequencies {
        // any character except lower-case letters
        if letter < 0x61 || letter > 0x7a {
            // with the exception of space, comma, and dot
            if letter != 0x20 && letter != 0x2c && letter != 0x2e {
                total_score += 2.0 * percentage_found;
            }
        }
    }

    total_score
}

pub fn guess_keysize_from_hamming_distance(
    bytes: &crypto_vecs::Bytes,
    keysize_range: &Range<usize>,
    number_of_samples: u32,
) -> Vec<constants::ScoreKeysize> {
    let mut scores: Vec<constants::ScoreKeysize> = Vec::with_capacity(keysize_range.len());

    for keysize in keysize_range.clone() {
        let bytes_vec = bytes.to_vec();
        let mut iter_chunks = bytes_vec.chunks_exact(keysize);
        let mut edit_size = 0;

        let chunk_vec_1 = iter_chunks.next().expect("text should be long enough");
        let mut chunk_1 = crypto_vecs::Bytes::from(chunk_vec_1);

        for _ in 0..number_of_samples {
            let chunk_vec_2 = iter_chunks.next().expect("text should be long enough");
            let chunk_2 = crypto_vecs::Bytes::from(chunk_vec_2);

            edit_size += chunk_1.hamming_distance_bits(&chunk_2);

            chunk_1 = chunk_2;
        }

        let edit_size_average = (edit_size as f64) / (number_of_samples as f64);
        let edit_size_normalized = edit_size_average / (keysize as f64);

        let score = constants::ScoreKeysize {
            score: edit_size_normalized,
            keysize: keysize,
        };

        scores.push(score);
    }

    scores
}

pub fn transpose_strings_clockwise(strings: &Vec<String>) -> Vec<String> {
    self::transpose_strings(strings, true)
}

pub fn transpose_strings_counterclockwise(strings: &Vec<String>) -> Vec<String> {
    self::transpose_strings(strings, false)
}

fn transpose_strings(strings: &Vec<String>, transpose_clockwise: bool) -> Vec<String> {
    assert!(strings.len() > 0);

    let height = strings.len();

    let mut lines: Vec<Vec<char>> = Vec::with_capacity(height);
    for string in strings {
        lines.push(string.chars().collect());
    }

    let width = lines[0].len();

    let mut lines_transposed: Vec<Vec<char>> = Vec::with_capacity(width);
    for _ in 0..width {
        lines_transposed.push(Vec::with_capacity(height));
    }

    for (index, line) in lines.iter().enumerate() {
        assert_eq!(line.len(), width, "string #{} has incorrect size", index);

        for (index, &letter) in line.iter().enumerate() {
            lines_transposed[index].push(letter);
        }
    }

    let mut strings_transposed: Vec<String> = Vec::with_capacity(width);

    if transpose_clockwise {
        for line in lines_transposed {
            strings_transposed.push(String::from_iter(line.iter().rev()));
        }
    } else {
        for line in lines_transposed.iter().rev() {
            strings_transposed.push(String::from_iter(line));
        }
    }

    strings_transposed
}

#[cfg(test)]
mod tests {
    use crate::crypto_vecs::ToBytes;

    use super::*;

    #[test]
    fn unit_fixed_xor_unicode() {
        let unicode_plain = crypto_vecs::Unicode::from("Cooking MCs");
        let unicode_key = crypto_vecs::Unicode::from("X");
        let expected_result = crypto_vecs::Bytes::from(vec![
            0x1b, 0x37, 0x37, 0x33, 0x31, 0x36, 0x3f, 0x78, 0x15, 0x1b, 0x2b,
        ]);

        let plain = unicode_plain.to_bytes();
        let key = unicode_key.to_bytes();

        let result = plain.fixed_xor(&key);

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_hamming_distance_bits_unicode() {
        let unicode_bytes = crypto_vecs::Unicode::from("this is a test");
        let unicode_other = crypto_vecs::Unicode::from("wokka wokka!!!");
        let expected_result = 37;

        let bytes = unicode_bytes.to_bytes();
        let other = unicode_other.to_bytes();

        let result = bytes.hamming_distance_bits(&other);

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_transpose_strings_clockwise() {
        let strings = vec![
            String::from("äßcd"),
            String::from("efgh"),
            String::from("ijkl"),
        ];
        let expected_result = vec!["ieä", "jfß", "kgc", "lhd"];

        let result = self::transpose_strings_clockwise(&strings);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_transpose_strings_counterclockwise() {
        let strings = vec![
            String::from("äßcd"),
            String::from("efgh"),
            String::from("ijkl"),
        ];
        let expected_result = vec!["dhl", "cgk", "ßfj", "äei"];

        let result = self::transpose_strings_counterclockwise(&strings);

        assert_eq!(result, expected_result);
    }
}
