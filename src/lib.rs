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

pub fn fixed_xor_bytes(bytes_input: &Vec<u8>, bytes_key: &Vec<u8>) -> Vec<u8> {
    let mut bytes_xor = Vec::new();
    let mut key_iter = bytes_key.iter().cycle();

    for &byte_input in bytes_input {
        let byte_key = key_iter.next().expect("infinite key was finite after all");
        let byte_xor = (byte_input | byte_key) & !(byte_input & byte_key);

        bytes_xor.push(byte_xor);
    }

    bytes_xor
}

pub fn find_lowest_score_xor_hex(hex_encoded: &str, keys_range_bytes: Range<u8>) -> (char, f64, Vec<u8>) {
    let mut best_key = '*';
    let mut best_score = 1000.0;
    let mut best_decoded = Vec::new();

    for key_byte in keys_range_bytes {
        let key_char = key_byte as char;
        let key_hex = hex::encode(key_char.to_string());

        let bytes_xor = fixed_xor_bytes(
            &crate::helpers::hex_to_bytes(&hex_encoded),
            &crate::helpers::hex_to_bytes(&key_hex),
        );

        let score = score_letter_frequencies(&bytes_xor);

        if score < best_score {
            best_key = key_char;
            best_score = score;
            best_decoded = bytes_xor;
        }
    }

    (best_key, best_score, best_decoded)
}

fn score_letter_frequencies(bytes: &Vec<u8>) -> f64 {
    let mut letter_frequencies = HashMap::new();
    let percent_per_letter = 1.0 / (bytes.len() as f64);

    for &byte in bytes {
        let mut key = byte;

        // also count upper-case letters (convert to lower-case)
        if key >= 0x41 && key <= 0x5a {
            key += 0x20;
        }

        let count = letter_frequencies.entry(key).or_insert(0.0);
        *count += percent_per_letter;
    }

    let english_letter_frequencies = crate::constants::get_english_letter_frequencies();
    let mut score = 0.0;

    // bonus for letters matching expected frequency
    for (letter, percentage_expected) in english_letter_frequencies {
        let percentage_found = letter_frequencies.get(&letter).copied().unwrap_or(0.0);
        let score_diff = percentage_expected - percentage_found;

        // higher frequencies are just as bad as lower frequencies
        score += score_diff.abs();
    }

    // malus for non-letters
    for (letter, percentage_found) in letter_frequencies {
        // any character except lower-case letters
        if letter < 0x61 || letter > 0x7a {
            // with the exception of space, comma, and dot
            if letter != 0x20 && letter != 0x2c && letter != 0x2e {
                score += percentage_found;
            }
        }
    }

    score
}

pub fn hamming_distance_bits(string_1: &str, string_2: &str) -> u64 {
    let bytes_with_differing_bits = fixed_xor_bytes(
        &&crate::helpers::unicode_to_bytes(string_1),
        &crate::helpers::unicode_to_bytes(string_2),
    );

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
