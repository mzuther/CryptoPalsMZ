use std::ops::Range;
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

pub fn fixed_xor(bytes_input: &Vec<u8>, bytes_key: &Vec<u8>) -> Vec<u8> {
    let mut bytes_xor = Vec::new();
    let mut key_iter = bytes_key.iter().cycle();

    for &byte_input in bytes_input {
        let byte_key = key_iter.next().expect("no key left");
        let byte_xor = (byte_input | byte_key) & !(byte_input & byte_key);

        bytes_xor.push(byte_xor);
    }

    bytes_xor
}

pub fn repeating_key_xor(plain_text: &str, key: &str) -> String {
    let plain_text_bytes = string_to_bytes(plain_text, false);
    let key_bytes = string_to_bytes(key, false);

    let bytes_xor = fixed_xor(&plain_text_bytes, &key_bytes);
    let string_encoded = bytes_to_string(&bytes_xor, true);

    string_encoded
}

pub fn bytes_to_string(bytes_input: &Vec<u8>, is_hex_string: bool) -> String {
    let bytes_as_string;

    if is_hex_string {
        bytes_as_string = hex::encode(bytes_input);
    } else {
        unsafe { bytes_as_string = String::from_utf8_unchecked(bytes_input.clone()) }
    }

    bytes_as_string
}

pub fn string_to_bytes(string_input: &str, is_hex_string: bool) -> Vec<u8> {
    let string_bytes;

    if is_hex_string {
        string_bytes = hex::decode(string_input).expect("Broken conversion");
    } else {
        string_bytes = Vec::from(string_input);
    }

    string_bytes
}

fn split_bytes_into_segments(string_bytes: Vec<u8>, bits_per_segment: u8) -> (Vec<u8>, u8, u8) {
    let mut segments_to_encode = Vec::new();

    let bits_per_byte = 8;
    let mut bits_with_value = 0;
    let mut remainder = 0;

    for string_byte in &string_bytes {
        bits_with_value = (bits_with_value + bits_per_segment) % bits_per_byte;
        let bits_with_remainder = bits_per_byte - bits_with_value;

        let mask_remainder = (1 << bits_with_remainder) - 1;
        let mask_value = 0xff - mask_remainder;

        let value = ((string_byte & mask_value) >> bits_with_remainder) + remainder;
        remainder = (string_byte & mask_remainder) << (bits_per_segment - bits_with_remainder);

        segments_to_encode.push(value);

        if bits_with_value == (bits_per_byte - bits_per_segment) {
            bits_with_value = (bits_with_value + bits_per_segment) % bits_per_byte;

            segments_to_encode.push(remainder);
            remainder = 0;
        }
    }

    (segments_to_encode, bits_with_value, remainder)
}

pub fn string_to_base64(string_input: &str, is_hex_string: bool) -> String {
    let string_bytes = string_to_bytes(string_input, is_hex_string);

    let (mut segments_to_encode, bits_with_value, remainder) =
        split_bytes_into_segments(string_bytes, 6);

    // add padding character
    if bits_with_value > 0 {
        segments_to_encode.push(remainder);
        segments_to_encode.push(0xff);

        if bits_with_value == 6 {
            segments_to_encode.push(0xff);
        }
    }

    let mut encoded_string = String::new();

    for segment in &segments_to_encode {
        let mut char_int = *segment;

        if char_int < 26 {
            char_int += 65
        } else if char_int < 52 {
            char_int += 71
        // padding character (=)
        } else if char_int == 0xff {
            char_int = 61
        } else {
            char_int -= 4
        }

        let encoded_character = char_int as char;
        encoded_string.push(encoded_character);
    }

    encoded_string
}


pub fn find_lowest_score_xor(string_encoded: &str, keys_int: Range<u32>) -> (char, f64, String) {
    let mut best_code = '*';
    let mut best_score = 1000.0;
    let mut string_decoded = String::new();

    for key_int in keys_int {
        let key_char = char::from_u32(key_int).expect("invalid character");
        let key_hex = hex::encode(key_char.to_string());

        let bytes_encoded = string_to_bytes(string_encoded, true);
        let bytes_key = string_to_bytes(&key_hex, true);

        let bytes_xor = fixed_xor(&bytes_encoded, &bytes_key);
        let score = score_letter_frequencies(&bytes_xor);

        if score < best_score {
            best_code = key_char;
            best_score = score;
            string_decoded = bytes_to_string(&bytes_xor, false);
        }
    }

    (best_code, best_score, string_decoded)
}

fn score_letter_frequencies(bytes_input: &Vec<u8>) -> f64 {
    let mut letter_frequencies = HashMap::new();
    let percent_per_letter = 1.0 / (bytes_input.len() as f64);

    for &byte in bytes_input {
        let mut key = byte;

        // also count upper-case letters (convert to lower-case)
        if key >= 0x41 && key <= 0x5a {
            key += 0x20;
        }

        let count = letter_frequencies.entry(key).or_insert(0.0);
        *count += percent_per_letter;
    }

    let mut english_letter_frequencies = HashMap::new();

    for letter in ENGLISH_LETTER_FREQUENCIES {
        let key = letter.0 as u8;
        english_letter_frequencies.insert(key, letter.1);
    }

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
