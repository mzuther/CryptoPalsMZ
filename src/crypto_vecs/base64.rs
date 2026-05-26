/* ----------------------------------------------------------------------------

   CryptoPalsMZ
   ============
   My take on https://cryptopals.com/

   Copyright (c) 2026 Martin Zuther (http://www.mzuther.de/)

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.

   Thank you for using free software!

---------------------------------------------------------------------------- */

use regex::Regex;
use std::{convert, fmt};

use crate::crypto_vecs::Bytes;
use crate::crypto_vecs::traits::{CryptoVec, CryptoVecMut, LenBytes, ToBytes};

// ================

#[derive(Clone, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct Base64 {
    base64: String,
    element_cache: Vec<char>,
}

// ================

impl CryptoVec for Base64 {
    type Element = char;
    type Collection = String;

    fn new_from(data: Self::Collection) -> Self {
        match Self::clean_and_validate(data) {
            Ok(data) => Self {
                element_cache: data.chars().collect(),
                base64: data,
            },
            Err(error) => panic!("{}", error),
        }
    }

    fn new_from_elements(elements: &[Self::Element]) -> Self {
        Self::new_from(elements.iter().collect())
    }

    fn from_literal(string_literal: &str) -> Self {
        Self::new_from(string_literal.to_string())
    }

    fn with_capacity(capacity: usize) -> Self {
        Self::new_from(Self::Collection::with_capacity(capacity))
    }

    fn capacity(&self) -> usize {
        self.base64.capacity()
    }

    fn clean_and_validate(data: Self::Collection) -> Result<Self::Collection, String> {
        let string_without_whitespace = data
            .split_ascii_whitespace()
            .fold(String::default(), |acc, string_slice| acc + string_slice);

        if !string_without_whitespace.len().is_multiple_of(4) {
            return Err(format!(
                "base64 encodings are multiples of 4 characters, found {} characters",
                string_without_whitespace.len()
            ));
        }

        let regex_padding = Regex::new(r"(.?)([=]+)$").unwrap();

        if let Some(captures) = regex_padding.captures(&string_without_whitespace) {
            let last_letter = captures
                .get(1)
                .expect("there are two capture groups")
                .as_str()
                .chars()
                .nth(0)
                .unwrap_or(' ');

            let padding = captures
                .get(2)
                .expect("there are two capture groups")
                .as_str();

            let padding_length = padding.len();

            if padding_length > 2 {
                panic!("invalid base64 padding: {}", padding);
            } else if padding_length == 1
                && !Self::VALID_LAST_CHARACTERS_SINGLE_PADDING.contains(last_letter)
            {
                panic!(
                    "invalid base64 single-byte padding: {}{}",
                    last_letter, padding
                );
            } else if padding_length == 2
                && !Self::VALID_LAST_CHARACTERS_DOUBLE_PADDING.contains(last_letter)
            {
                panic!(
                    "invalid base64 double-byte padding: {}{}",
                    last_letter, padding
                );
            }
        }

        let invalid_characters: String = string_without_whitespace
            .chars()
            .filter(|c| !Base64::VALID_CHARACTERS.contains(*c))
            .collect();

        if invalid_characters.is_empty() {
            Ok(string_without_whitespace)
        } else {
            Err(format!(
                "found invalid base64 characters: {}",
                invalid_characters
            ))
        }
    }

    // ----------------

    // iterate over single characters (6 bits each)
    fn elements(&self) -> impl Iterator<Item = &Self::Element> {
        self.element_cache.iter()
    }

    fn collection(&self) -> Self::Collection {
        self.base64.clone()
    }

    fn collection_as_ref(&self) -> &Self::Collection {
        &self.base64
    }

    fn chunks(&self, chunk_size: usize) -> std::slice::Chunks<'_, Self::Element> {
        assert!(chunk_size > 0, "chunk size must be non-zero");

        self.element_cache.chunks(chunk_size)
    }

    fn rchunks(&self, chunk_size: usize) -> std::slice::RChunks<'_, Self::Element> {
        assert!(chunk_size > 0, "chunk size must be non-zero");

        self.element_cache.rchunks(chunk_size)
    }

    // ----------------

    fn representation_name(&self) -> &str {
        "Base64"
    }

    fn representation(&self) -> String {
        let block_size = 8;

        let base64_blocks: String = self.elements().enumerate().fold(
            Default::default(),
            |mut acc, (index, char)| {
                acc.push(*char);

                // separate blocks
                if index % block_size == block_size - 1 {
                    acc.push(' ');
                }

                acc
            },
        );

        String::from(base64_blocks.trim_end())
    }
}

// ----------------

impl LenBytes for Base64 {
    fn len_bytes(&self) -> usize {
        self.to_bytes().len_bytes()
    }
}

// ----------------

impl fmt::Display for Base64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}[{:02}] {{ {} }}",
            self.representation_name(),
            self.element_cache.len(),
            self.representation()
        )
    }
}

// ----------------

impl convert::AsRef<str> for Base64 {
    fn as_ref(&self) -> &str {
        self.base64.as_ref()
    }
}

// ----------------

impl convert::From<&Bytes> for Base64 {
    fn from(bytes: &Bytes) -> Self {
        let base64_segments = Self::split_bytes_into_segments(bytes, 6);

        let base64_string =
            base64_segments
                .iter()
                .fold(String::default(), |mut acc, &segment| {
                    acc.push(match segment {
                        // padding character (=)
                        None => 0x3d,
                        Some(byte) => {
                            match byte {
                                // upper case letter
                                0..26 => byte + 0x41,
                                // lower case letter
                                26..52 => byte + 0x47,
                                // digit
                                52..62 => byte - 0x04,
                                // plus
                                62 => 0x2b,
                                // slash
                                63 => 0x2f,
                                undefined => {
                                    panic!(
                                        "base64 bytes must be below 64, found {}",
                                        undefined
                                    )
                                }
                            }
                        }
                    } as char);

                    acc
                });

        Self::new_from(base64_string)
    }
}

// ----------------

impl ToBytes for Base64 {
    fn to_bytes_raw(&self) -> Bytes {
        let decoded_bytes =
            self.base64
                .bytes()
                .fold(Vec::default(), |mut acc, char_int| {
                    let char_option = match char_int {
                        // plus
                        0x2b => Some(62),
                        // slash
                        0x2f => Some(63),
                        // digit
                        0x30..=0x39 => Some(char_int + 4),
                        // padding character (=)
                        0x3d => None,
                        // upper case letter
                        0x41..=0x5a => Some(char_int - 65),
                        // lower case letter
                        0x61..=0x7a => Some(char_int - 71),
                        undefined => {
                            panic!("0x{} is not a valid base64 character", undefined)
                        }
                    };

                    assert!(
                        char_option.is_none_or(|x| x < 64),
                        "{:?} is not valid base64",
                        char_option
                    );

                    acc.push(char_option);
                    acc
                });

        Self::assemble_bytes_from_segments(&decoded_bytes, 6)
    }
}

// ----------------

impl Base64 {
    // valid base64 characters (including padding)
    const VALID_CHARACTERS: &str =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

    // valid base64 characters for single-byte padding (=)
    const VALID_LAST_CHARACTERS_SINGLE_PADDING: &str = "AQgw";

    // valid base64 characters for double-byte padding (==)
    const VALID_LAST_CHARACTERS_DOUBLE_PADDING: &str = "AEIMQUYcgkosw048";

    // base64-encoded string containing complete base64 alphabet
    pub const COMPLETE_ALPHABET: &str =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    // plain-text bytes which yield "COMPLETE_ALPHABET"
    pub const COMPLETE_ALPHABET_BYTES: [u8; 48] = [
        0x00, 0x10, 0x83, 0x10, 0x51, 0x87, 0x20, 0x92, 0x8b, 0x30, 0xd3, 0x8f, 0x41,
        0x14, 0x93, 0x51, 0x55, 0x97, 0x61, 0x96, 0x9b, 0x71, 0xd7, 0x9f, 0x82, 0x18,
        0xa3, 0x92, 0x59, 0xa7, 0xa2, 0x9a, 0xab, 0xb2, 0xdb, 0xaf, 0xc3, 0x1c, 0xb3,
        0xd3, 0x5d, 0xb7, 0xe3, 0x9e, 0xbb, 0xf3, 0xdf, 0xbf,
    ];

    // plain-text hexadecimal string which yields "COMPLETE_ALPHABET"
    pub const COMPLETE_ALPHABET_HEX: &str = "00108310518720928b30d38f41149351559761969b71d79f8218a39259a7a29aabb2dbafc31cb3d35db7e39ebbf3dfbf";

    // ----------------

    fn split_bytes_into_segments(bytes: &Bytes, bits_per_segment: u8) -> Vec<Option<u8>> {
        let bits_per_byte = 8;
        let mut bits_with_value = 0;
        let mut remainder = 0;

        let mut segments_to_encode =
            bytes.iter().fold(Vec::default(), |mut acc, &byte| {
                bits_with_value = (bits_with_value + bits_per_segment) % bits_per_byte;
                let bits_with_remainder = bits_per_byte - bits_with_value;

                let mask_remainder = (1 << bits_with_remainder) - 1;
                let mask_value = 0xff - mask_remainder;

                let value = ((byte & mask_value) >> bits_with_remainder) + remainder;
                remainder =
                    (byte & mask_remainder) << (bits_per_segment - bits_with_remainder);

                acc.push(Some(value));

                if bits_with_value == (bits_per_byte - bits_per_segment) {
                    bits_with_value =
                        (bits_with_value + bits_per_segment) % bits_per_byte;

                    acc.push(Some(remainder));
                    remainder = 0;
                }

                acc
            });

        // add padding characters
        if bits_with_value > 0 {
            segments_to_encode.push(Some(remainder));
            segments_to_encode.push(None);

            if bits_with_value == 6 {
                segments_to_encode.push(None);
            }
        }

        segments_to_encode
    }

    fn assemble_bytes_from_segments(bytes: &[Option<u8>], bits_per_segment: u8) -> Bytes {
        let bits_per_byte = 8;
        let mut inverted_bit_output = 0;
        let mut byte_in_progress = 0;

        bytes
            .iter()
            .fold(Default::default(), |mut acc, byte_input_option| {
                // padding
                if byte_input_option.is_none() {
                    return acc;
                }

                let byte_input = byte_input_option.unwrap();

                for inverted_bit_input in 0..bits_per_segment {
                    let current_bit_input = bits_per_segment - inverted_bit_input - 1;
                    let current_bit_output: u8 = bits_per_byte - inverted_bit_output - 1;

                    let current_mask_input = 1 << current_bit_input;
                    let current_mask_output = 1 << current_bit_output;

                    if (byte_input & current_mask_input) > 0 {
                        byte_in_progress += current_mask_output;
                    }

                    inverted_bit_output = (inverted_bit_output + 1) % bits_per_byte;

                    if inverted_bit_output == 0 {
                        acc.push(byte_in_progress);
                        byte_in_progress = 0;
                    }
                }

                acc
            })
    }
}

// ================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_vecs::{Hexadecimal, Unicode};

    // ----------------

    #[test]
    fn unit_base64_to_base64() {
        let bytes = Bytes::new_from_elements(&Base64::COMPLETE_ALPHABET_BYTES);
        let expected_result = Base64::from_literal(Base64::COMPLETE_ALPHABET);

        let result = bytes.to_base64();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_base64_to_base64_padding_one_byte() {
        let mut bytes_raw = Base64::COMPLETE_ALPHABET_BYTES.to_vec();
        bytes_raw.push(0x10);
        bytes_raw.push(0x10);

        let bytes = Bytes::new_from(bytes_raw);
        let expected_result =
            Base64::from_literal(&format!("{}EBA=", Base64::COMPLETE_ALPHABET));

        let result = bytes.to_base64();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_base64_to_base64_padding_two_bytes() {
        let mut bytes_raw = Base64::COMPLETE_ALPHABET_BYTES.to_vec();
        bytes_raw.push(0x00);

        let bytes = Bytes::new_from(bytes_raw);
        let expected_result =
            Base64::from_literal(&format!("{}AA==", Base64::COMPLETE_ALPHABET));

        let result = bytes.to_base64();

        assert_eq!(result, expected_result);
    }

    #[test]
    #[should_panic(expected = "found invalid base64 characters: ._.")]
    fn unit_base64_from_invalid_characters() {
        let _ = Base64::from_literal("HUIfTQ.sP_A.hxT9");
    }

    #[test]
    #[should_panic(expected = "base64 encodings are multiples of 4 characters")]
    fn unit_base64_from_invalid_length() {
        let _ = Base64::from_literal("HUIfTQsP Ah9");
    }

    #[test]
    #[should_panic(expected = "invalid base64 padding: ===")]
    fn unit_base64_from_too_much_padding() {
        let _ = Base64::from_literal("HUIfTQsP Ahxh9===");
    }

    #[test]
    #[should_panic(expected = "invalid base64 single-byte padding: 9=")]
    fn unit_base64_from_incorrect_padding_single() {
        let _ = Base64::from_literal("HUIfTQsP Ah9=");
    }

    #[test]
    #[should_panic(expected = "invalid base64 double-byte padding: h==")]
    fn unit_base64_from_incorrect_padding_double() {
        let _ = Base64::from_literal("HUIfTQsP Ah==");
    }

    #[test]
    fn unit_base64_to_bytes() {
        let base64 = Base64::from_literal(Base64::COMPLETE_ALPHABET);
        let expected_result = Bytes::new_from_elements(&Base64::COMPLETE_ALPHABET_BYTES);

        let result = base64.to_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_base64_to_bytes_padding_one_byte() {
        let mut expected_result_raw = Base64::COMPLETE_ALPHABET_BYTES.to_vec();
        expected_result_raw.push(0x10);
        expected_result_raw.push(0x10);

        let base64 = Base64::from_literal(&format!("{}EBA=", Base64::COMPLETE_ALPHABET));
        let expected_result = Bytes::new_from(expected_result_raw);

        let result = base64.to_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_base64_to_bytes_padding_two_bytes() {
        let mut expected_result_raw = Base64::COMPLETE_ALPHABET_BYTES.to_vec();
        expected_result_raw.push(0x00);

        let base64 = Base64::from_literal(&format!("{}AA==", Base64::COMPLETE_ALPHABET));
        let expected_result = Bytes::new_from(expected_result_raw);

        let result = base64.to_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_base64_to_string() {
        let base64 = Base64::from_literal(Base64::COMPLETE_ALPHABET);
        let expected_result = String::from(
            "Base64[64] { ABCDEFGH IJKLMNOP QRSTUVWX YZabcdef ghijklmn opqrstuv wxyz0123 456789+/ }",
        );

        let result = base64.to_string();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_base64_to_string_trim_whitespace() {
        let base64 = Base64::from_literal(
            "\r\nABCD\nEFGH\n  IJKL\nMNOP\t\nQRSTUV\nW\n\t XYZa\nbcdef\nghi\njklmn\nopqrstuv\nwxyz01234\n5\n67\n89+/\t",
        );
        let expected_result = String::from(
            "Base64[64] { ABCDEFGH IJKLMNOP QRSTUVWX YZabcdef ghijklmn opqrstuv wxyz0123 456789+/ }",
        );

        let result = base64.to_string();

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_base64_hex_to_base64_via_bytes() {
        let hexadecimal = Hexadecimal::from_literal(Base64::COMPLETE_ALPHABET_HEX);
        let expected_result = Base64::from_literal(Base64::COMPLETE_ALPHABET);

        let result = hexadecimal.to_base64();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_base64_to_hex_via_bytes() {
        let base64 = Base64::from_literal(Base64::COMPLETE_ALPHABET);
        let expected_result = Hexadecimal::from_literal(Base64::COMPLETE_ALPHABET_HEX);

        let result = base64.to_hexadecimal();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_base64_unicode_to_base64_via_bytes() {
        let unicode = Unicode::from_literal("Hi. Servus. Grüezi. 你好.");
        let expected_result =
            Base64::from_literal("SGkuIFNlcnZ1cy4gR3LDvGV6aS4g5L2g5aW9Lg==");

        let result = unicode.to_base64();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_base64_to_unicode_via_bytes() {
        let base64 = Base64::from_literal("SGkuIFNlcnZ1cy4gR3LDvGV6aS4g5L2g5aW9Lg==");
        let expected_result = Unicode::from_literal("Hi. Servus. Grüezi. 你好.");

        let result = base64.to_unicode();

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_base64_len() {
        let base64 = Base64::from_literal("SGkuIFNlcnZ1cy4gR3LDvGV6aS4g5L2g5aW9Lg==");

        let expected_result = 40;

        let result = base64.len();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_base64_len_bytes() {
        let base64 = Base64::from_literal("SGkuIFNlcnZ1cy4gR3LDvGV6aS4g5L2g5aW9Lg==");

        let expected_result = 28;

        let result = base64.len_bytes();

        assert_eq!(result, expected_result);
    }

    #[test]
    fn unit_base64_len_bits() {
        let base64 = Base64::from_literal("SGkuIFNlcnZ1cy4gR3LDvGV6aS4g5L2g5aW9Lg==");

        let expected_result = 224;

        let result = base64.len_bits();

        assert_eq!(result, expected_result);
    }

    // ----------------

    #[test]
    fn unit_base64_to_elements() {
        let base64 = Base64::from_literal("SGku");

        let expected_result = vec!['S', 'G', 'k', 'u'];

        let result = base64.to_elements();

        assert_eq!(result, expected_result);
    }
}
