use std::cmp;
use std::collections::HashMap;
use std::ops::Range;

pub mod constants;
pub mod helpers;

pub fn fixed_xor_unicode(plain_text: &str, key: &str) -> Vec<u8> {
    fixed_xor_bytes(
        &crate::helpers::unicode_to_bytes(plain_text),
        &crate::helpers::unicode_to_bytes(key),
    )
}

pub fn fixed_xor_bytes(bytes_input: &[u8], bytes_key: &[u8]) -> Vec<u8> {
    let mut bytes_xor = Vec::new();
    let mut key_iter = bytes_key.iter().cycle();

    for &byte_input in bytes_input {
        let byte_key = key_iter.next().expect("infinite key was finite after all");
        let byte_xor = (byte_input | byte_key) & !(byte_input & byte_key);

        bytes_xor.push(byte_xor);
    }

    bytes_xor
}

pub fn find_lowest_score_xor_bytes(
    bytes: &[u8],
    keys_range_bytes: Range<u8>,
) -> Vec<crate::constants::ScoreXOR> {
    let mut scores: Vec<crate::constants::ScoreXOR> = Vec::with_capacity(keys_range_bytes.len());

    for key_byte in keys_range_bytes {
        let key_vector = vec![key_byte];
        let bytes_xor = fixed_xor_bytes(&bytes, &key_vector);
        let score = score_letter_frequencies(&bytes_xor);

        let score = crate::constants::ScoreXOR {
            score: score,
            key: key_byte,
            decoded: bytes_xor,
        };

        scores.push(score);
    }

    // sort by score, resulting in lowest score first
    scores.sort_by(|a, b| a.partial_cmp(&b).unwrap());

    scores
}

fn get_letter_frequencies(bytes: &[u8]) -> HashMap<u8, f64> {
    let mut letter_frequencies = HashMap::new();
    let percent_per_byte = 1.0 / (bytes.len() as f64);

    for &byte in bytes {
        let mut key = byte;

        // also count upper-case letters (convert to lower-case)
        if key >= 0x41 && key <= 0x5a {
            key += 0x20;
        }

        let count = letter_frequencies.entry(key).or_insert(0.0);
        *count += percent_per_byte;
    }

    letter_frequencies
}

pub fn print_histogram(
    key: &[u8],
    bytes: &[u8],
    min_percentage_spaces: f64,
    min_important_letters: usize,
) {
    let letter_frequencies = get_letter_frequencies(&bytes);

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

    println!("[0x{}]", crate::helpers::bytes_to_hex(key));
    let english_letter_frequencies = crate::constants::get_english_letter_frequencies();

    for (letter, percentage_expected) in english_letter_frequencies {
        let percentage_found = letter_frequencies.get(&letter).copied().unwrap_or(0.0);
        let magnification = 350.0;

        let histogram_found = (percentage_found * magnification).round() as i32;
        let histogram_expected = (percentage_expected * magnification).round() as i32;

        let histogram_low = cmp::min(histogram_found, histogram_expected);
        let histogram_med = cmp::max(histogram_expected - histogram_found, 0);
        let histogram_high = cmp::max(histogram_found - histogram_expected, 0);

        println!(
            "{}: {}{}{}",
            letter as char,
            "|".repeat(histogram_low as usize),
            "-".repeat(histogram_med as usize),
            "*".repeat(histogram_high as usize)
        );
    }

    // println!("{}", crate::helpers::bytes_to_ascii(&bytes));
    println!("");
}

fn score_letter_frequencies(bytes: &[u8]) -> f64 {
    let letter_frequencies = get_letter_frequencies(&bytes);
    let english_letter_frequencies = crate::constants::get_english_letter_frequencies();

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

pub fn hamming_distance_bits(string_1: &str, string_2: &str) -> u64 {
    hamming_distance_bits_bytes(
        &&crate::helpers::unicode_to_bytes(string_1),
        &crate::helpers::unicode_to_bytes(string_2),
    )
}

pub fn hamming_distance_bits_bytes(bytes_1: &[u8], bytes_2: &[u8]) -> u64 {
    let bytes_with_differing_bits = fixed_xor_bytes(&bytes_1, &bytes_2);

    let mut differing_bits = 0;

    for &byte in &bytes_with_differing_bits {
        let nibble_value_low = (byte as usize) & 0x0f;
        let nibble_value_high = (byte as usize) >> 4;

        let differing_bits_low = crate::constants::LOOKUP_BITS_IN_NIBBLE
            .get(nibble_value_low)
            .expect("index is between 0 and 15");
        let differing_bits_high = crate::constants::LOOKUP_BITS_IN_NIBBLE
            .get(nibble_value_high)
            .expect("index is between 0 and 15");

        differing_bits += *differing_bits_low as u64;
        differing_bits += *differing_bits_high as u64;
    }

    differing_bits
}

pub fn guess_keysize_from_hamming_distance(
    bytes: &[u8],
    keysize_range: Range<usize>,
) -> Vec<crate::constants::ScoreKeysize> {
    let mut scores: Vec<crate::constants::ScoreKeysize> = Vec::with_capacity(keysize_range.len());

    for keysize in keysize_range {
        let mut edit_size = 0.0;
        let number_of_calculations = 3;

        let mut iter_chunks = bytes.chunks_exact(keysize);
        let mut chunk_1 = iter_chunks.next().expect("text should be long enough");

        for _ in 0..number_of_calculations {
            let chunk_2 = iter_chunks.next().expect("text should be long enough");
            edit_size += crate::hamming_distance_bits_bytes(&chunk_1, &chunk_2) as f64;

            chunk_1 = chunk_2;
        }

        let edit_size_average = edit_size / (number_of_calculations as f64);
        let edit_size_normalized = edit_size_average / (keysize as f64);

        let score = crate::constants::ScoreKeysize {
            score: edit_size_normalized,
            keysize: keysize,
        };

        scores.push(score);
    }

    // order by score, with lowest score first
    scores.sort_by(|a, b| a.partial_cmp(&b).unwrap());

    scores
}

pub fn transpose_bytes(bytes: &[u8], keysize: usize) -> Vec<Vec<u8>> {
    assert!(keysize > 0);

    // may come in useful for automatic processing (single-byte keys)
    if keysize == 1 {
        return vec![bytes.to_vec()];
    }

    let mut transposed_blocks: Vec<Vec<u8>> = Vec::with_capacity(keysize);
    let block_capacity = (bytes.len() / keysize) + 1;

    for _ in 0..keysize {
        transposed_blocks.push(Vec::with_capacity(block_capacity));
    }

    for block in bytes.chunks(keysize) {
        // guard rail: may be lower than "keysize"
        for block_index in 0..block.len() {
            let element = block[block_index];
            transposed_blocks[block_index].push(element);
        }
    }

    transposed_blocks
}

#[cfg(test)]
mod tests {
    use std::vec;

    use super::*;

    #[test]
    fn unit_hamming_distance_bits() {
        let text_1 = "this is a test";
        let text_2 = "wokka wokka!!!";
        let expected_result = 37;

        let result = hamming_distance_bits(text_1, text_2);

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_transpose_bytes_no_transposition() {
        let bytes = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let keysize = 1;

        let transposed_vecs = transpose_bytes(&bytes, keysize);

        assert_eq!(transposed_vecs.len(), keysize);
        assert_eq!(transposed_vecs[0], bytes);
    }

    #[test]
    fn unit_transpose_bytes_equal_distribution() {
        let bytes = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let keysize = 2;

        let transposed_vecs = transpose_bytes(&bytes, keysize);

        assert_eq!(transposed_vecs.len(), keysize);
        assert_eq!(transposed_vecs[0], vec![1, 3, 5, 7, 9]);
        assert_eq!(transposed_vecs[1], vec![2, 4, 6, 8, 10]);
    }

    #[test]
    fn unit_transpose_bytes_unequal_distribution() {
        let bytes = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let keysize = 3;

        let transposed_vecs = transpose_bytes(&bytes, keysize);

        assert_eq!(transposed_vecs.len(), keysize);
        assert_eq!(transposed_vecs[0], vec![1, 4, 7, 10]);
        assert_eq!(transposed_vecs[1], vec![2, 5, 8]);
        assert_eq!(transposed_vecs[2], vec![3, 6, 9]);
    }

    #[test]
    fn unit_transpose_bytes_not_enough_elements() {
        let bytes = vec![1, 2, 3];
        let keysize = bytes.len() + 1;

        let transposed_vecs = transpose_bytes(&bytes, keysize);

        assert_eq!(transposed_vecs.len(), keysize);
        assert_eq!(transposed_vecs[0], vec![1]);
        assert_eq!(transposed_vecs[1], vec![2]);
        assert_eq!(transposed_vecs[2], vec![3]);
        assert_eq!(transposed_vecs[3], vec![]);
    }
}
