use std::cmp;
use std::collections::HashMap;
use std::ops::Range;

pub mod constants;
pub mod crypto_vecs;

pub fn fixed_xor_cryptovecs<T, U>(plain_text: &T, key: &U) -> crypto_vecs::Bytes
where
    T: crypto_vecs::ToBytes,
    U: crypto_vecs::ToBytes,
{
    self::fixed_xor(&plain_text.to_bytes(), &key.to_bytes())
}

pub fn fixed_xor(plain_text: &crypto_vecs::Bytes, key: &crypto_vecs::Bytes) -> crypto_vecs::Bytes {
    let mut bytes_xor = Vec::new();

    let key_bytes = key.to_vec();
    let mut key_iter = key_bytes.iter().cycle();

    for byte_plain in plain_text.to_vec() {
        let byte_key = key_iter.next().expect("infinite key was finite after all");
        let byte_xor = (byte_plain | byte_key) & !(byte_plain & byte_key);

        bytes_xor.push(byte_xor);
    }

    crypto_vecs::Bytes::from(bytes_xor)
}

pub fn find_lowest_score_xor_cryptovecs<T>(
    cryptovec: &T,
    keys_range_bytes: &Range<u8>,
) -> Vec<constants::ScoreXOR>
where
    T: crypto_vecs::ToBytes,
{
    self::find_lowest_score_xor(&cryptovec.to_bytes(), &keys_range_bytes)
}

pub fn find_lowest_score_xor(
    bytes: &crypto_vecs::Bytes,
    keys_range_bytes: &Range<u8>,
) -> Vec<constants::ScoreXOR> {
    let mut scores: Vec<constants::ScoreXOR> = Vec::with_capacity(keys_range_bytes.len());

    for key_byte in keys_range_bytes.clone() {
        let key = crypto_vecs::Bytes::from(key_byte);
        let bytes_xor = self::fixed_xor(&bytes, &key);
        let score = self::score_letter_frequencies(&bytes_xor);

        let score = constants::ScoreXOR {
            score: score,
            key: key,
            plain_text: bytes_xor,
        };

        scores.push(score);
    }

    // sort by score, resulting in lowest score first
    scores.sort_by(|a, b| a.partial_cmp(&b).unwrap());

    scores
}

fn get_letter_frequencies(bytes: &crypto_vecs::Bytes) -> HashMap<u8, f64> {
    let mut letter_frequencies = HashMap::new();
    let percent_per_byte = 1.0 / (bytes.len() as f64);

    for byte in bytes.to_vec() {
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
        let mut found_count = 0;

        for letter_char in important_letters {
            let letter = letter_char as u8;
            let percentage_letter = letter_frequencies.get(&letter).copied().unwrap_or(0.0);

            if percentage_letter > 0.0 {
                found_count += 1;
            }
        }

        if found_count < min_important_letters {
            return;
        }
    }

    println!("{}", key.to_string());
    let max_bin_size = (magnification_factor / 3.80) as i32;

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

    // println!("{}", crypto_vecs::Unicode::from(bytes.clone()));
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

pub fn hamming_distance_bits_cryptovecs<T, U>(cryptovec_1: &T, cryptovec_2: &U) -> u64
where
    T: crypto_vecs::ToBytes,
    U: crypto_vecs::ToBytes,
{
    self::hamming_distance_bits(&cryptovec_1.to_bytes(), &cryptovec_2.to_bytes())
}

pub fn hamming_distance_bits(bytes_1: &crypto_vecs::Bytes, bytes_2: &crypto_vecs::Bytes) -> u64 {
    let bytes_with_differing_bits = self::fixed_xor(&bytes_1, &bytes_2);

    let mut differing_bits = 0;

    for byte in bytes_with_differing_bits.to_vec() {
        let nibble_value_low = (byte as usize) & 0x0f;
        let nibble_value_high = (byte as usize) >> 4;

        let differing_bits_low = constants::LOOKUP_BITS_IN_NIBBLE
            .get(nibble_value_low)
            .expect("index is between 0 and 15");
        let differing_bits_high = constants::LOOKUP_BITS_IN_NIBBLE
            .get(nibble_value_high)
            .expect("index is between 0 and 15");

        differing_bits += *differing_bits_low as u64;
        differing_bits += *differing_bits_high as u64;
    }

    differing_bits
}

pub fn guess_keysize_from_hamming_distance(
    bytes: &crypto_vecs::Bytes,
    keysize_range: &Range<usize>,
    number_of_calculations: u32,
) -> Vec<constants::ScoreKeysize> {
    let mut scores: Vec<constants::ScoreKeysize> = Vec::with_capacity(keysize_range.len());

    for keysize in keysize_range.clone() {
        let mut edit_size = 0.0;

        let bytes_vec = bytes.to_vec();
        let mut iter_chunks = bytes_vec.chunks_exact(keysize);
        let mut chunk_vec_1 = iter_chunks.next().expect("text should be long enough");

        for _ in 0..number_of_calculations {
            let chunk_vec_2 = iter_chunks.next().expect("text should be long enough");

            edit_size += self::hamming_distance_bits(
                &crypto_vecs::Bytes::from(chunk_vec_1),
                &crypto_vecs::Bytes::from(chunk_vec_2),
            ) as f64;

            chunk_vec_1 = chunk_vec_2;
        }

        let edit_size_average = edit_size / (number_of_calculations as f64);
        let edit_size_normalized = edit_size_average / (keysize as f64);

        let score = constants::ScoreKeysize {
            score: edit_size_normalized,
            keysize: keysize,
        };

        scores.push(score);
    }

    // order by score, with lowest score first
    scores.sort_by(|a, b| a.partial_cmp(&b).unwrap());

    scores
}

pub fn transpose_bytes(
    bytes: &crypto_vecs::Bytes,
    number_of_blocks: usize,
) -> Vec<crypto_vecs::Bytes> {
    assert!(number_of_blocks > 0);

    // may come in useful for automatic processing (single-byte keys)
    if number_of_blocks == 1 {
        return vec![bytes.clone()];
    }

    let mut transposed_blocks_raw: Vec<Vec<u8>> = Vec::with_capacity(number_of_blocks);
    let block_capacity = (bytes.len() / number_of_blocks) + 1;

    for _ in 0..number_of_blocks {
        transposed_blocks_raw.push(Vec::with_capacity(block_capacity));
    }

    for (index, &byte) in bytes.to_vec().iter().enumerate() {
        // guard rail: may be lower than "keysize"
        let block_index = index % number_of_blocks;
        transposed_blocks_raw[block_index].push(byte);
    }

    let mut transposed_blocks: Vec<crypto_vecs::Bytes> = Vec::with_capacity(number_of_blocks);

    for block in transposed_blocks_raw {
        let bytes = crypto_vecs::Bytes::from(block);
        transposed_blocks.push(bytes);
    }

    transposed_blocks
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
    use super::*;

    #[test]
    fn unit_fixed_xor_single_byte_key() {
        let bytes_1 = crypto_vecs::Bytes::from(vec![
            0x1c, 0x01, 0x11, 0x00, 0x1f, 0xa2, 0x4b, 0x53, 0x98, 0xc5,
        ]);
        let bytes_2 = crypto_vecs::Bytes::from(0x74);
        let expected_result = crypto_vecs::Bytes::from(vec![
            0x68, 0x75, 0x65, 0x74, 0x6b, 0xd6, 0x3f, 0x27, 0xec, 0xb1,
        ]);

        let result = self::fixed_xor(&bytes_1, &bytes_2);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_fixed_xor_full_length_key() {
        let bytes_1 = crypto_vecs::Bytes::from(vec![
            0x1c, 0x01, 0x11, 0x00, 0x1f, 0x01, 0x01, 0x00, 0x06, 0x1a, 0x02, 0x4b, 0x53, 0x53,
            0x50, 0x09, 0x18, 0x1c,
        ]);
        let bytes_2 = crypto_vecs::Bytes::from(vec![
            0x68, 0x69, 0x74, 0x20, 0x74, 0x68, 0x65, 0x20, 0x62, 0x75, 0x6c, 0x6c, 0x27, 0x73,
            0x20, 0x65, 0x79, 0x65,
        ]);
        let expected_result = crypto_vecs::Bytes::from(vec![
            0x74, 0x68, 0x65, 0x20, 0x6b, 0x69, 0x64, 0x20, 0x64, 0x6f, 0x6e, 0x27, 0x74, 0x20,
            0x70, 0x6c, 0x61, 0x79,
        ]);

        let result = self::fixed_xor(&bytes_1, &bytes_2);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_fixed_xor_unicode() {
        let unicode = crypto_vecs::Unicode::from("Cooking MCs");
        let key_unicode = crypto_vecs::Unicode::from("X");
        let expected_result = crypto_vecs::Bytes::from(vec![
            0x1b, 0x37, 0x37, 0x33, 0x31, 0x36, 0x3f, 0x78, 0x15, 0x1b, 0x2b,
        ]);

        let result = self::fixed_xor_cryptovecs(&unicode, &key_unicode);

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_hamming_distance_bits_empty() {
        let bytes_1 = crypto_vecs::Bytes::new();
        let bytes_2 = crypto_vecs::Bytes::new();
        let expected_result = 0;

        let result = self::hamming_distance_bits(&bytes_1, &bytes_2);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_hamming_distance_bits_1() {
        // from u8
        let bytes_1 = crypto_vecs::Bytes::from(0x02);
        // from Vec<u8>
        let bytes_2 = crypto_vecs::Bytes::from(vec![0xa0]);
        let expected_result = 3;

        let result = self::hamming_distance_bits(&bytes_1, &bytes_2);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_hamming_distance_bits_2() {
        let bytes_1 = crypto_vecs::Bytes::from(vec![0x02, 0xb0]);
        let bytes_2 = crypto_vecs::Bytes::from(vec![0xa0, 0x01]);
        let expected_result = 7;

        let result = self::hamming_distance_bits(&bytes_1, &bytes_2);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_hamming_distance_bits_3() {
        let bytes_1 = crypto_vecs::Bytes::from(vec![0x1d, 0x42]);
        let bytes_2 = crypto_vecs::Bytes::from(vec![0x1f, 0x4d]);
        let expected_result = 5;

        let result = self::hamming_distance_bits(&bytes_1, &bytes_2);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_hamming_distance_bits_4() {
        let bytes_1 = crypto_vecs::Bytes::from(vec![0x1d, 0x42, 0x1f]);
        let bytes_2 = crypto_vecs::Bytes::from(vec![0x4d, 0x0b, 0x0f]);
        let expected_result = 6;

        let result = self::hamming_distance_bits(&bytes_1, &bytes_2);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_hamming_distance_bits_5() {
        let bytes_1 = crypto_vecs::Bytes::from(vec![0x1d, 0x42, 0x1f, 0x4d, 0x0b]);
        let bytes_2 = crypto_vecs::Bytes::from(vec![0x0f, 0x02, 0x1f, 0x4f, 0x13]);
        let expected_result = 6;

        let result = self::hamming_distance_bits(&bytes_1, &bytes_2);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_hamming_distance_bits_unicode() {
        let unicode_1 = crypto_vecs::Unicode::from("this is a test");
        let unicode_2 = crypto_vecs::Unicode::from("wokka wokka!!!");
        let expected_result = 37;

        let result = self::hamming_distance_bits_cryptovecs(&unicode_1, &unicode_2);

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_transpose_bytes_no_transposition() {
        let bytes = crypto_vecs::Bytes::from(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        let keysize = 1;

        let transposed_vecs = self::transpose_bytes(&bytes, keysize);

        assert_eq!(transposed_vecs.len(), keysize);
        assert_eq!(transposed_vecs[0], bytes);
    }

    #[test]
    fn unit_transpose_bytes_equal_distribution() {
        let bytes = crypto_vecs::Bytes::from(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        let keysize = 2;

        let transposed_vecs = self::transpose_bytes(&bytes, keysize);

        assert_eq!(transposed_vecs.len(), keysize);
        assert_eq!(
            transposed_vecs[0],
            crypto_vecs::Bytes::from(vec![1, 3, 5, 7, 9])
        );
        assert_eq!(
            transposed_vecs[1],
            crypto_vecs::Bytes::from(vec![2, 4, 6, 8, 10])
        );
    }

    #[test]
    fn unit_transpose_bytes_unequal_distribution() {
        let bytes = crypto_vecs::Bytes::from(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        let keysize = 3;

        let transposed_vecs = self::transpose_bytes(&bytes, keysize);

        assert_eq!(transposed_vecs.len(), keysize);
        assert_eq!(
            transposed_vecs[0],
            crypto_vecs::Bytes::from(vec![1, 4, 7, 10])
        );
        assert_eq!(transposed_vecs[1], crypto_vecs::Bytes::from(vec![2, 5, 8]));
        assert_eq!(transposed_vecs[2], crypto_vecs::Bytes::from(vec![3, 6, 9]));
    }

    #[test]
    fn unit_transpose_bytes_not_enough_elements() {
        let bytes = crypto_vecs::Bytes::from(vec![1, 2, 3]);
        let keysize = bytes.len() + 1;

        let transposed_vecs = self::transpose_bytes(&bytes, keysize);

        assert_eq!(transposed_vecs.len(), keysize);
        assert_eq!(transposed_vecs[0], crypto_vecs::Bytes::from(1));
        assert_eq!(transposed_vecs[1], crypto_vecs::Bytes::from(2));
        assert_eq!(transposed_vecs[2], crypto_vecs::Bytes::from(3));
        assert_eq!(transposed_vecs[3], crypto_vecs::Bytes::new());
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
